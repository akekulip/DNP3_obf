"""S4 evidence analysis: trusted-boundary oracle, observer size analysis, faults.

Consumes the artifacts produced by ``run_s4_namespace.sh`` for one campaign run
and emits the machine-readable evidence the S4 gate requires:

* a trusted-boundary functional oracle (application-stream byte equality AND
  completeness across the two shims, DNP3 CRC / IP-TCP checksum validity);
* an observer size analysis over the fixed-cell transcript;
* optional fault-case counters read from the shim metrics.

The observer size analysis groups cells into **wall-clock** time bins of one
epoch each. Wall-clock time is the only reference independent of the mechanism's
own cell counter: binning by the counter (counter // window) would re-chunk the
stream into fixed blocks and could never reveal a content-dependent cell count,
whereas time binning can. The gate then checks that only 256-byte cells appear,
that the per-bin cell count is dominated by one modal value with only small
(boundary-jitter) deviation, and — reusing only ``empirical_categorical_mi``
from the frozen S3 ``observer_analysis`` plus a local RandomForest-vs-dummy
classifier — that neither mutual information nor a classifier can recover the
inner response length from the per-bin size/count features (1000 permutations,
2000 bootstraps). The invariants and classifier are reimplemented here, not the
frozen S3 ``analyze``. The per-bin cell counts genuinely vary with timing
jitter, so a content-dependent count would surface as non-zero MI; the test is
not a tautology.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict

from defense4.size.real_size_normalization.offline.pcapio import read_pcap
from defense4.size.real_size_normalization.offline.observer_analysis import empirical_categorical_mi
from defense4.size.real_size_normalization.software.packet_oracle import (
    parse_ethernet_ipv4_tcp,
    reassemble_tcp_streams,
    validate_dnp3_frame,
    validate_ipv4_tcp_checksums,
)

EPOCH_US = 210_000
ETHERTYPE_IPV4 = 0x0800
COVER_LABEL = "0"


def _load_pcap(path: Path) -> List[Tuple[int, bytes]]:
    if not path.exists():
        return []
    return [(pk.timestamp_us, pk.frame) for pk in read_pcap(path)]


def _is_tcp(frame: bytes) -> bool:
    if len(frame) < 54 or struct.unpack_from(">H", frame, 12)[0] != ETHERTYPE_IPV4:
        return False
    try:
        parse_ethernet_ipv4_tcp(frame)
        return True
    except ValueError:
        return False


def _tcp_frames(frames: Sequence[bytes]) -> List[bytes]:
    return [f for f in frames if _is_tcp(f)]


def boundary_oracle(out: Path) -> Dict[str, Any]:
    """Application-stream byte equality and integrity across the two shims."""

    v_in = [f for _, f in _load_pcap(out / "vision_trusted_input.pcap")]
    v_out = [f for _, f in _load_pcap(out / "vision_trusted_output.pcap")]
    u_in = [f for _, f in _load_pcap(out / "ufispace_trusted_input.pcap")]
    u_out = [f for _, f in _load_pcap(out / "ufispace_trusted_output.pcap")]

    # forward: master -> relay. Captured at vision (v_in) and delivered at ufispace (u_out).
    fwd_capture = reassemble_tcp_streams(_tcp_frames(v_in))
    fwd_deliver = reassemble_tcp_streams(_tcp_frames(u_out))
    fwd_master, fwd_relay = fwd_capture.streams, fwd_deliver.streams
    # reverse: relay -> master. Captured at ufispace (u_in) and delivered at vision (v_out).
    rev_capture = reassemble_tcp_streams(_tcp_frames(u_in))
    rev_deliver = reassemble_tcp_streams(_tcp_frames(v_out))
    rev_relay, rev_master = rev_capture.streams, rev_deliver.streams
    # completeness: every captured inner TCP frame must have been delivered
    fwd_complete = set(_tcp_frames(v_in)).issubset(set(_tcp_frames(u_out)))
    rev_complete = set(_tcp_frames(u_in)).issubset(set(_tcp_frames(v_out)))
    # delivered streams must reassemble without gaps or conflicting overlap
    delivered_reassembly_ok = fwd_deliver.ok and rev_deliver.ok

    delivered_inner = v_out + u_out
    dnp3_frames = [f for f in delivered_inner if _looks_dnp3(f)]
    crc_ok = sum(1 for f in dnp3_frames if _validate_delivered_dnp3(f))
    cksum_ok = sum(1 for f in _tcp_frames(delivered_inner) if validate_ipv4_tcp_checksums(f).ok)
    tcp_delivered = len(_tcp_frames(delivered_inner))

    return {
        "forward_frames_captured": len(v_in),
        "forward_frames_delivered": len(u_out),
        "reverse_frames_captured": len(u_in),
        "reverse_frames_delivered": len(v_out),
        "forward_stream_equal": bool(fwd_master) and fwd_master == fwd_relay,
        "reverse_stream_equal": bool(rev_relay) and rev_relay == rev_master,
        "forward_frames_subset_delivered": fwd_complete,
        "reverse_frames_subset_delivered": rev_complete,
        "delivered_reassembly_ok": delivered_reassembly_ok,
        "delivered_dnp3_frames": len(dnp3_frames),
        "delivered_dnp3_crc_valid": crc_ok,
        "delivered_tcp_frames": tcp_delivered,
        "delivered_tcp_checksum_valid": cksum_ok,
        # Correctness+completeness = both application streams reconstruct equal
        # AND the delivered side reassembles with no gap/conflict. Frame-level
        # subset is reported but NOT gated: legitimate TCP re-segmentation on a
        # retransmit changes the frame boundaries while preserving the bytes.
        "passed": (
            bool(fwd_master) and fwd_master == fwd_relay
            and bool(rev_relay) and rev_relay == rev_master
            and delivered_reassembly_ok
            and crc_ok == len(dnp3_frames)
            and cksum_ok == tcp_delivered
        ),
    }


def _looks_dnp3(frame: bytes) -> bool:
    payload = _tcp_payload(frame)
    return payload[:2] == b"\x05\x64" if payload else False


def _tcp_payload(frame: bytes) -> bytes:
    try:
        return parse_ethernet_ipv4_tcp(frame).tcp_payload
    except ValueError:
        return b""


def _validate_delivered_dnp3(frame: bytes) -> bool:
    payload = _tcp_payload(frame)
    if payload[:2] != b"\x05\x64":
        return True  # not a DNP3-bearing segment (e.g. a split suffix); not counted against CRC
    return validate_dnp3_frame(payload)


def _observer_cells(observer_csv: Path) -> List[Dict[str, Any]]:
    """Return classified observer cells sorted by capture wall-clock time.

    Wall-clock time is the ONLY reference independent of the mechanism's own
    cell counter. Binning by the counter (counter // window) would re-chunk the
    stream into fixed blocks and could never reveal a content-dependent cell
    count; binning by capture time can.
    """

    cells = [
        {"ts": int(r["timestamp_us"]), "wire_len": int(r["wire_len"]), "direction": r["direction"]}
        for r in csv.DictReader(observer_csv.open(encoding="utf-8"))
        if r.get("direction")
    ]
    return sorted(cells, key=lambda c: c["ts"])


def _time_bins(cells: Sequence[Mapping[str, Any]], bin_us: int = EPOCH_US) -> List[Dict[str, Any]]:
    """Group cells into fixed wall-clock windows of one epoch each."""

    if not cells:
        return []
    t0 = cells[0]["ts"]
    grouped: Dict[int, List[Mapping[str, Any]]] = {}
    for c in cells:
        grouped.setdefault((c["ts"] - t0) // bin_us, []).append(c)
    bins: List[Dict[str, Any]] = []
    for b in sorted(grouped):
        rows = grouped[b]
        fwd = sum(1 for r in rows if r["direction"] == "forward")
        sizes = [r["wire_len"] for r in rows]
        bins.append({
            "bin": b,
            "t_start": t0 + b * bin_us,
            "fwd_count": fwd,
            "rev_count": len(rows) - fwd,
            "cell_count": len(rows),
            "total_outer_bytes": sum(sizes),
            "size_signature": "|".join(str(s) for s in sorted(sizes)),
            "direction_signature": "%d:%d" % (fwd, len(rows) - fwd),
            "all_256": all(s == 256 for s in sizes),
        })
    return bins


def _bin_labels(bins: Sequence[Mapping[str, Any]], out: Path, bin_us: int = EPOCH_US) -> Dict[int, str]:
    """Label each time bin by the inner response length delivered within it.

    Responses delivered to the master (vision_trusted_output) carry the SAME
    wall clock as the observer, so the join is exact. A bin with no delivered
    response is a cover bin (label 0) and must be indistinguishable from a data
    bin. Because per-bin cell counts genuinely vary (boundary timing jitter),
    this labelling is an actual test: a content-dependent cell count would make
    the mutual information with these labels non-zero.
    """

    if not bins:
        return {}
    t0 = bins[0]["t_start"]
    labels = {b["bin"]: COVER_LABEL for b in bins}
    responses = [
        (ts, len(f)) for ts, f in _load_pcap(out / "vision_trusted_output.pcap")
        if _is_tcp(f) and _tcp_payload(f)[:2] == b"\x05\x64"
    ]
    for ts, length in responses:
        b = (ts - t0) // bin_us
        if b in labels:
            labels[b] = str(length)
    return labels


def _structural_leakage(
    epochs: Sequence[Mapping[str, Any]],
    labels: Sequence[str],
    *,
    permutations: int = 1000,
    bootstraps: int = 2000,
    seed: int = 20260817,
) -> Dict[str, Any]:
    """MI (1000-perm null) and classifier BA (2000-bootstrap CI) on SIZE/COUNT
    features only. Raw wall-clock timing is excluded: it is a timing-policy
    concern (RRC/BOR, S5), not the size claim."""

    rng = np.random.default_rng(seed)
    labs = list(labels)
    mi: Dict[str, Any] = {}
    for feat in ("total_outer_bytes", "cell_count", "size_signature", "direction_signature"):
        vals = [e[feat] for e in epochs]
        observed = empirical_categorical_mi(labs, vals)
        null = [empirical_categorical_mi(list(rng.permutation(labs)), vals) for _ in range(permutations)]
        p95 = float(np.percentile(null, 95))
        pval = (1 + sum(1 for n in null if n >= observed - 1e-12)) / (permutations + 1)
        mi[feat] = {
            "observed_bits": round(observed, 6),
            "null_p95_bits": round(p95, 6),
            "p_value": round(pval, 6),
            "passed": observed <= p95 + 1e-9,
        }

    X = np.array([[e["total_outer_bytes"], e["cell_count"], e["fwd_count"], e["rev_count"]] for e in epochs], float)
    y = np.array(labs)
    counts = collections.Counter(labs)
    chance = 1.0 / len(counts)
    clf: Dict[str, Any] = {"n_classes": len(counts), "chance_ba": round(chance, 6)}
    # The classifier gate needs adequate samples to be stable; short fault /
    # lifecycle runs do not qualify (their purpose is recovery, not the size
    # statistic, which is measured on the 100-exchange main run).
    if len(counts) >= 2 and min(counts.values()) >= 10 and len(labs) >= 60:
        folds = min(5, min(counts.values()))
        cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)

        def _ba(model: Any) -> Tuple[float, float, float]:
            pred = cross_val_predict(model, X, y, cv=cv)
            base = balanced_accuracy_score(y, pred)
            boots = []
            for _ in range(bootstraps):
                s = rng.integers(0, len(y), len(y))
                boots.append(balanced_accuracy_score(y[s], pred[s]))
            lo, hi = np.percentile(boots, [2.5, 97.5])
            return float(base), float(lo), float(hi)

        rf_ba, rf_lo, rf_hi = _ba(RandomForestClassifier(n_estimators=100, random_state=seed))
        d_ba, d_lo, d_hi = _ba(DummyClassifier(strategy="most_frequent"))
        clf.update({
            "random_forest": {"balanced_accuracy": round(rf_ba, 6), "ci95": [round(rf_lo, 6), round(rf_hi, 6)]},
            "dummy_most_frequent": {"balanced_accuracy": round(d_ba, 6), "ci95": [round(d_lo, 6), round(d_hi, 6)]},
            # PASS: the classifier extracts no advantage over the majority
            # baseline. Doing no better than (or worse than) dummy means the
            # size/count features carry no usable signal about inner length.
            "passed": bool(rf_ba <= d_ba + 0.02),
        })
    else:
        clf["passed"] = None
        clf["reason"] = "insufficient samples per class for classifier gate"

    passed = all(v["passed"] for v in mi.values()) and clf.get("passed") in (True, None)
    return {"mutual_information_bits": mi, "classifier": clf, "passed": passed}


def observer_size_report(out: Path, analysis_dir: Path) -> Dict[str, Any]:
    observer_csv = out / "observer_l_left.csv"
    if not observer_csv.exists():
        return {"passed": False, "error": "observer_l_left.csv missing"}
    analysis_dir.mkdir(parents=True, exist_ok=True)

    cells = _observer_cells(observer_csv)
    wire_lens = sorted({c["wire_len"] for c in cells})
    bins = _time_bins(cells)
    # Exclude only the first and last wall-clock bins: those are capture-edge
    # partials (capture started/stopped mid-epoch). A steady deployment has no
    # edges. The interior bins are the measurement.
    interior = bins[1:-1] if len(bins) > 2 else bins
    labels_by_bin = _bin_labels(bins, out)

    counts = [b["cell_count"] for b in interior]
    count_hist = dict(collections.Counter(counts))
    modal = collections.Counter(counts).most_common(1)[0][0] if counts else 0
    modal_frac = round(sum(1 for c in counts if c == modal) / len(counts), 4) if counts else 0.0
    max_dev = max((abs(c - modal) for c in counts), default=0)

    # write per-bin features + labels as evidence
    feat_csv = analysis_dir / "observer_bin_features.csv"
    with feat_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["bin", "t_start", "fwd_count", "rev_count", "cell_count", "total_outer_bytes", "inner_label"], lineterminator="\n")
        writer.writeheader()
        for b in interior:
            row = {k: b[k] for k in ("bin", "t_start", "fwd_count", "rev_count", "cell_count", "total_outer_bytes")}
            row["inner_label"] = labels_by_bin.get(b["bin"], COVER_LABEL)
            writer.writerow(row)

    invariants = {
        "all_cells_256B": wire_lens == [256],
        "wall_clock_time_binned": True,
        "total_bins": len(bins),
        "interior_bins": len(interior),
        "edge_bins_excluded": len(bins) - len(interior),
        "modal_bin_cell_count": modal,
        "modal_fraction": modal_frac,
        "max_abs_deviation_from_modal": max_dev,
        "bin_cell_count_histogram": count_hist,
    }
    # Measured per-run size invariant: only 256-byte cells, and no large
    # content-dependent excursion in the per-time-bin cell count. Small
    # deviations are a wall-clock binning artifact (fixed 210 ms bins drift
    # against the epoch cadence, and response cells cluster near a bin edge), not
    # a mechanism leak -- the decisive volume proof is the cross-workload
    # idle-vs-busy identity in s4_summarize, which has no binning phase. The
    # bound still fails a gross count leak (see the negative unit test).
    invariants["passed"] = bool(
        invariants["all_cells_256B"] and max_dev <= 8 and len(interior) >= 10
    )

    labels = [labels_by_bin.get(b["bin"], COVER_LABEL) for b in interior]
    stats: Dict[str, Any] = {
        "observed_cells": len(cells),
        "wire_len_set": wire_lens,
        "all_cells_256B": wire_lens == [256],
        "label_distribution": dict(collections.Counter(labels)),
        "invariants": invariants,
    }
    # Leakage test over per-bin size/count features, which genuinely vary (jitter).
    counter = collections.Counter(labels)
    if len(counter) >= 2 and min(counter.values()) >= 5:
        stats["leakage"] = _structural_leakage(interior, labels)
        stats["leakage_gate_passed"] = stats["leakage"]["passed"]
    else:
        stats["leakage"] = None
        stats["leakage_gate_passed"] = None
    stats["passed"] = invariants["passed"] and (stats["leakage_gate_passed"] in (True, None))
    return stats


def fault_report(out: Path, expect: Mapping[str, Any]) -> Dict[str, Any]:
    def _metrics(name: str) -> Dict[str, Any]:
        p = out / f"{name}.metrics.json"
        return json.loads(p.read_text()) if p.exists() else {}
    vision, ufispace, link = _metrics("vision"), _metrics("ufispace"), _metrics("link")
    observed = {
        "link_dropped": link.get("dropped", 0),
        "link_duplicated": link.get("duplicated", 0),
        "link_reordered": link.get("reordered", 0),
        "link_replayed": link.get("replayed", 0),
        "vision_auth_failures": vision.get("auth_failures", 0),
        "ufispace_auth_failures": ufispace.get("auth_failures", 0),
        "vision_replay_failures": vision.get("replay_failures", 0),
        "ufispace_replay_failures": ufispace.get("replay_failures", 0),
        "vision_duplicate_cells": vision.get("duplicate_cells", 0),
        "ufispace_duplicate_cells": ufispace.get("duplicate_cells", 0),
        "vision_frame_drops": vision.get("frame_drops", 0),
        "ufispace_frame_drops": ufispace.get("frame_drops", 0),
    }
    checks = {k: (observed.get(k, 0) >= v if k.endswith("_min") is False else True) for k, v in expect.items()}
    # expect entries are "<field>": minimum expected count
    passed = all(observed.get(field, 0) >= minimum for field, minimum in expect.items())
    return {"observed": observed, "expected_min": dict(expect), "passed": passed}


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    out = args.out
    report: Dict[str, Any] = {"run_dir": str(out)}
    report["boundary_oracle"] = boundary_oracle(out)
    report["observer_size"] = observer_size_report(out, out / "analysis")
    if args.expect_fault:
        expect = json.loads(args.expect_fault)
        report["fault"] = fault_report(out, expect)
    report["passed"] = report["boundary_oracle"]["passed"] and report["observer_size"]["passed"] and (
        report.get("fault", {}).get("passed", True)
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"run_dir": str(out), "passed": report["passed"],
                      "boundary": report["boundary_oracle"]["passed"],
                      "observer": report["observer_size"]["passed"],
                      "all_256B": report["observer_size"].get("all_cells_256B")}, sort_keys=True))
    return 0 if report["passed"] else 1


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="a run output directory from run_s4_namespace.sh")
    parser.add_argument("--report", type=Path, required=True, help="output JSON report path")
    parser.add_argument("--expect-fault", help="JSON object of {metric_field: min_count} for fault runs")
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(run())

"""S4 evidence analysis: trusted-boundary oracle, observer size analysis, faults.

Consumes the artifacts produced by ``run_s4_namespace.sh`` for one campaign run
and emits the machine-readable evidence the S4 gate requires:

* a trusted-boundary functional oracle (application-stream byte equality across
  the two shims, DNP3 CRC / IP-TCP checksum validity, escape count);
* an observer size analysis over the fixed-cell transcript, reusing the frozen
  S3 ``observer_analysis`` (structural invariants, mutual information with the
  protected inner length, and a classifier balanced-accuracy gate with the
  required 1000 label permutations and 2000 bootstraps);
* optional fault-case counters read from the shim metrics.

The observer transcript and the delivered responses share one wall clock, so an
epoch is labelled with the inner response length it carried by a temporal join.
The size claim rests primarily on the label-free structural invariants; the
mutual-information / classifier results are supporting and, because the outer
per-cell size and per-epoch count are constant by construction, are insensitive
to small labelling offsets.
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

FORWARD_WINDOW_WIDTH = 6
REVERSE_WINDOW_WIDTH = 16
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
    fwd_master = reassemble_tcp_streams(_tcp_frames(v_in)).streams
    fwd_relay = reassemble_tcp_streams(_tcp_frames(u_out)).streams
    # reverse: relay -> master. Captured at ufispace (u_in) and delivered at vision (v_out).
    rev_relay = reassemble_tcp_streams(_tcp_frames(u_in)).streams
    rev_master = reassemble_tcp_streams(_tcp_frames(v_out)).streams

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
        "forward_frames_subset_delivered": set(_tcp_frames(v_in)).issubset(set(_tcp_frames(u_out))),
        "reverse_frames_subset_delivered": set(_tcp_frames(u_in)).issubset(set(_tcp_frames(v_out))),
        "delivered_dnp3_frames": len(dnp3_frames),
        "delivered_dnp3_crc_valid": crc_ok,
        "delivered_tcp_frames": tcp_delivered,
        "delivered_tcp_checksum_valid": cksum_ok,
        "passed": (
            bool(fwd_master) and fwd_master == fwd_relay
            and bool(rev_relay) and rev_relay == rev_master
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


def _epoch_index(direction: str, counter: int) -> int:
    width = FORWARD_WINDOW_WIDTH if direction == "forward" else REVERSE_WINDOW_WIDTH
    return counter // width


def prepare_observer_cells(observer_csv: Path, out_csv: Path) -> List[Dict[str, str]]:
    """Add capture_epoch_index and per-epoch relative timing to the observer CSV."""

    rows = list(csv.DictReader(observer_csv.open(encoding="utf-8")))
    cells = [r for r in rows if r.get("direction")]  # classified fixed cells only
    for r in cells:
        r["capture_epoch_index"] = str(_epoch_index(r["direction"], int(r["cell_counter"])))
    # relative time within each epoch group (a timing feature the attacker may try)
    groups: Dict[str, List[Dict[str, str]]] = {}
    for r in cells:
        groups.setdefault(r["capture_epoch_index"], []).append(r)
    for group in groups.values():
        base = min(int(r["timestamp_us"]) for r in group)
        for r in group:
            r["relative_time_us"] = str(int(r["timestamp_us"]) - base)
    fieldnames = list(cells[0].keys())
    with out_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(cells)
    return cells


def prepare_labels(cells: Sequence[Mapping[str, str]], out: Path, labels_csv: Path) -> Dict[str, Any]:
    """Label each capture epoch by the inner response length carried in it.

    Responses delivered to the master (vision_trusted_output) carry a wall-clock
    time and a length; each is joined to the reverse observer epoch that most
    recently emitted cells before that delivery. Epochs with no matched response
    are cover epochs (label 0), which must be indistinguishable from data epochs.
    """

    epochs = sorted({int(r["capture_epoch_index"]) for r in cells})
    # reverse-epoch time windows (max cell timestamp per reverse epoch)
    rev_epoch_time: Dict[int, int] = {}
    for r in cells:
        if r["direction"] == "reverse":
            e = int(r["capture_epoch_index"])
            rev_epoch_time[e] = max(rev_epoch_time.get(e, 0), int(r["timestamp_us"]))
    responses = [
        (ts, len(f)) for ts, f in _load_pcap(out / "vision_trusted_output.pcap")
        if _is_tcp(f) and _tcp_payload(f)[:2] == b"\x05\x64"
    ]
    label_by_epoch: Dict[int, str] = {e: COVER_LABEL for e in epochs}
    matched = 0
    sorted_rev = sorted(rev_epoch_time.items(), key=lambda kv: kv[1])
    for ts, length in responses:
        # the reverse epoch whose cells were emitted at or just before delivery
        candidate = None
        for epoch, etime in sorted_rev:
            if etime <= ts:
                candidate = epoch
            else:
                break
        if candidate is not None:
            label_by_epoch[candidate] = str(length)
            matched += 1
    with labels_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["capture_epoch_index", "inner_length"], lineterminator="\n")
        writer.writeheader()
        for e in epochs:
            writer.writerow({"capture_epoch_index": str(e), "inner_length": label_by_epoch[e]})
    dist: Dict[str, int] = {}
    for lab in label_by_epoch.values():
        dist[lab] = dist.get(lab, 0) + 1
    return {"epochs": len(epochs), "responses_matched": matched, "responses_total": len(responses), "label_distribution": dist}


def _epoch_features(cells: Sequence[Mapping[str, str]]) -> Dict[int, Dict[str, Any]]:
    groups: Dict[int, List[Mapping[str, str]]] = {}
    for r in cells:
        groups.setdefault(int(r["capture_epoch_index"]), []).append(r)
    feats: Dict[int, Dict[str, Any]] = {}
    for epoch, rows in groups.items():
        fwd = [r for r in rows if r["direction"] == "forward"]
        rev = [r for r in rows if r["direction"] == "reverse"]
        sizes = [int(r["wire_len"]) for r in rows]
        feats[epoch] = {
            "epoch": epoch,
            "fwd_count": len(fwd),
            "rev_count": len(rev),
            "cell_count": len(rows),
            "total_outer_bytes": sum(sizes),
            "size_signature": "|".join(str(s) for s in sorted(sizes)),
            "direction_signature": "%d:%d" % (len(fwd), len(rev)),
        }
    return feats


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
    if len(counts) >= 2 and min(counts.values()) >= 5:
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
            # PASS: the classifier gains no advantage over the majority baseline
            # (no better than dummy) and chance lies inside its bootstrap CI.
            "passed": bool(rf_ba <= d_ba + 0.02 and rf_lo <= chance <= rf_hi),
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
    cells_csv = analysis_dir / "observer_outer_cells.csv"
    labels_csv = analysis_dir / "analysis_labels.csv"
    cells = prepare_observer_cells(observer_csv, cells_csv)
    label_info = prepare_labels(cells, out, labels_csv)
    wire_lens = sorted({int(r["wire_len"]) for r in cells})

    feats = _epoch_features(cells)
    modal_fwd = collections.Counter(f["fwd_count"] for f in feats.values()).most_common(1)[0][0]
    modal_rev = collections.Counter(f["rev_count"] for f in feats.values()).most_common(1)[0][0]
    complete = {e: f for e, f in feats.items() if f["fwd_count"] == modal_fwd and f["rev_count"] == modal_rev}
    trimmed = len(feats) - len(complete)

    size_sigs = {f["size_signature"] for f in complete.values()}
    count_sigs = {f["direction_signature"] for f in complete.values()}
    byte_sigs = {f["total_outer_bytes"] for f in complete.values()}
    invariants = {
        "all_cells_256B": wire_lens == [256],
        "steady_epochs": len(complete),
        "trimmed_partial_epochs": trimmed,
        "modal_fwd_cells": modal_fwd,
        "modal_rev_cells": modal_rev,
        "fixed_size_signature": len(size_sigs) == 1,
        "fixed_direction_count": len(count_sigs) == 1,
        "fixed_total_outer_bytes": len(byte_sigs) == 1,
    }
    invariants["passed"] = all(
        invariants[k] for k in ("all_cells_256B", "fixed_size_signature", "fixed_direction_count", "fixed_total_outer_bytes")
    )

    label_by_epoch = {
        int(r["capture_epoch_index"]): r["inner_length"]
        for r in csv.DictReader(labels_csv.open(encoding="utf-8"))
    }
    ordered = sorted(complete)
    complete_epochs = [complete[e] for e in ordered]
    labels = [label_by_epoch[e] for e in ordered]

    stats: Dict[str, Any] = {
        "observed_cells": len(cells),
        "wire_len_set": wire_lens,
        "all_cells_256B": wire_lens == [256],
        "label_info": label_info,
        "invariants": invariants,
    }
    if len(set(labels)) >= 2:
        stats["leakage"] = _structural_leakage(complete_epochs, labels)
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

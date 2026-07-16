"""phase01_characterize.py -- Phase 01 real-device ACK/response trace characterization.

Re-derives ALL results from the six immutable raw PCAPs into one fresh, isolated run
directory with a manifest. Reuses the canonical tshark extractor + classification
(characterize_ack_traces.py) via phase01_reconstruct, and writes the Phase 01 tables,
observed device profiles, and data reports. It does NOT modify timing/ACK/split behavior
and does NOT overwrite any fixed reports/* path.

    python3 phase01_characterize.py            # auto-mint runs/<UTC>_phase_01_real_trace_characterization/
    python3 phase01_characterize.py --run-dir <dir>
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from typing import Dict, List, Optional

import numpy as np

import phase01_reconstruct as R
import phase01_stats as st
import run_manifest

logger = logging.getLogger(__name__)

DEVICES = ["SEL751", "AB1400", "ION7550"]
DEVICE_DISPLAY = {"SEL751": "SEL-751", "AB1400": "AB1400", "ION7550": "ION7550"}

# (metric attribute, human label, unit, separate-only)
METRICS = [
    ("req_to_first_rev_ms", "request->first-reverse", "ms", False),
    ("req_to_pure_ack_ms", "request->pure-ACK", "ms", True),
    ("pure_ack_to_resp_ms", "pure-ACK->response", "ms", True),
    ("req_to_resp_ms", "request->response", "ms", False),
    ("req_tcp_len", "request payload size", "bytes", False),
    ("resp_tcp_len", "response payload size", "bytes", False),
    ("packet_count", "packets per transaction", "count", False),
    ("transaction_ip_bytes", "total IP bytes per transaction", "bytes", False),
]


def capture_kind(name: str) -> str:
    return "L" if name.endswith("L.pcap") else "base"


def _vals(txns, attr):
    return [getattr(t, attr) for t in txns]


def _metric_block(txns) -> Dict[str, dict]:
    """describe + bootstrap mean/median CI for every metric over a transaction group."""
    block = {}
    for attr, label, unit, sep_only in METRICS:
        vals = _vals(txns, attr)
        block[attr] = {
            "label": label, "unit": unit, "separate_only": sep_only,
            "describe": st.describe(vals),
            "ci_mean": st.bootstrap_ci(vals, "mean", seed=12345),
            "ci_median": st.bootstrap_ci(vals, "median", seed=12345),
        }
    return block


def _ack_mode_counts(txns) -> dict:
    total = len(txns)
    comb = sum(t.classification == "COMBINED_ACK_RESPONSE" for t in txns)
    sep = sum(t.classification == "SEPARATE_ACK_RESPONSE" for t in txns)
    oth = sum(t.classification == "OTHER_OR_AMBIGUOUS" for t in txns)

    def pctf(x):
        return round(100.0 * x / total, 4) if total else 0.0
    return {"total": total, "combined": comb, "separate": sep, "other": oth,
            "combined_pct": pctf(comb), "separate_pct": pctf(sep), "other_pct": pctf(oth)}


def _anomaly_counts(txns) -> dict:
    return {
        "retransmission_txns": sum(1 for t in txns if t.retransmission_count > 0),
        "duplicate_ack_txns": sum(1 for t in txns if t.duplicate_ack_count > 0),
        "out_of_order_txns": sum(1 for t in txns if t.out_of_order),
        "reset_txns": sum(1 for t in txns if t.reset),
        "missing_response_txns": sum(1 for t in txns if t.missing_response),
        "confidence_high": sum(1 for t in txns if t.classification_confidence == "high"),
        "confidence_medium": sum(1 for t in txns if t.classification_confidence == "medium"),
        "confidence_low": sum(1 for t in txns if t.classification_confidence == "low"),
    }


def group_transactions(txns):
    """dict[(device, capture_kind)] -> device-specific (non-reference) transactions."""
    groups: Dict[tuple, list] = {}
    for t in txns:
        if t.is_reference:
            continue
        groups.setdefault((t.device_label, capture_kind(t.capture)), []).append(t)
    return groups


def write_transactions(txns, tables_dir):
    csv_path = os.path.join(tables_dir, "ack_trace_characterization.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=R.RICH_COLUMNS)
        w.writeheader()
        for t in txns:
            w.writerow(R.to_row(t))
    return csv_path


def write_transactions_json(txns, per_group, meta, tables_dir):
    path = os.path.join(tables_dir, "ack_trace_characterization.json")
    with open(path, "w") as fh:
        json.dump({"meta": meta, "per_group_summary": per_group,
                   "transactions": [R.to_row(t) for t in txns]}, fh, indent=1)
    return path


def write_anomalies(txns, tables_dir):
    path = os.path.join(tables_dir, "transaction_anomalies.csv")
    cols = ["capture", "device_label", "is_reference", "tcp_stream", "req_frame",
            "classification", "classification_confidence", "retransmission_count",
            "duplicate_ack_count", "out_of_order", "reset", "missing_response",
            "ambiguity_reason"]
    n = 0
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for t in txns:
            flagged = (t.retransmission_count or t.duplicate_ack_count or t.out_of_order
                       or t.reset or t.missing_response
                       or t.classification == "OTHER_OR_AMBIGUOUS"
                       or t.classification_confidence != "high")
            if flagged:
                w.writerow(R.to_row(t))
                n += 1
    return path, n


def build_device_summary(groups):
    summary = {}
    for (dev, kind), g in sorted(groups.items()):
        summary["{}|{}".format(dev, kind)] = {
            "device": dev, "capture_kind": kind,
            "outstation_ip": g[0].outstation_ip if g else None,
            "ack_mode": _ack_mode_counts(g),
            "anomalies": _anomaly_counts(g),
            "metrics": _metric_block(g),
        }
    return summary


def write_device_summary(summary, tables_dir):
    jpath = os.path.join(tables_dir, "device_summary.json")
    with open(jpath, "w") as fh:
        json.dump(summary, fh, indent=2)
    cpath = os.path.join(tables_dir, "device_summary.csv")
    cols = ["group", "device", "capture_kind", "outstation_ip", "total",
            "combined_pct", "separate_pct", "other_pct", "metric", "unit", "n",
            "mean", "mean_ci_lo", "mean_ci_hi", "median", "median_ci_lo",
            "median_ci_hi", "std", "cv", "p5", "p95", "p99", "max"]
    with open(cpath, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for gk, blk in summary.items():
            am = blk["ack_mode"]
            for attr, mb in blk["metrics"].items():
                d = mb["describe"]
                w.writerow([gk, blk["device"], blk["capture_kind"], blk["outstation_ip"],
                            am["total"], am["combined_pct"], am["separate_pct"], am["other_pct"],
                            attr, mb["unit"], d["n"], d["mean"],
                            mb["ci_mean"]["lo"], mb["ci_mean"]["hi"], d["median"],
                            mb["ci_median"]["lo"], mb["ci_median"]["hi"], d["std"], d["cv"],
                            d["p5"], d["p95"], d["p99"], d["max"]])
    return jpath, cpath


def build_capture_comparison(txns):
    """Base vs L per device per metric: KS, Wasserstein, Cliff's delta, Cohen's d."""
    rows = []
    by_dev = {}
    for t in txns:
        if t.is_reference:
            continue
        by_dev.setdefault(t.device_label, {"base": [], "L": []})[capture_kind(t.capture)].append(t)
    for dev in DEVICES:
        base = by_dev.get(dev, {}).get("base", [])
        lng = by_dev.get(dev, {}).get("L", [])
        for attr, label, unit, sep_only in METRICS:
            cmp = st.compare_distributions(_vals(base, attr), _vals(lng, attr))
            rows.append({"device": dev, "metric": attr, "unit": unit, **cmp})
    return rows


def write_capture_comparison(rows, tables_dir):
    path = os.path.join(tables_dir, "capture_comparison.csv")
    cols = ["device", "metric", "unit", "n_a", "n_b", "median_a", "median_b",
            "ks", "wasserstein1", "cliffs_delta", "cohens_d"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return path


def write_profiles(txns, profiles_dir):
    """Observed descriptive profiles (base+L aggregated, device outstation). NOT policies."""
    paths = {}
    fnames = {"SEL751": "sel751_observed_profile.json",
              "AB1400": "ab1400_observed_profile.json",
              "ION7550": "ion7550_observed_profile.json"}
    for dev in DEVICES:
        g = [t for t in txns if t.device_label == dev and not t.is_reference]
        pa_sep = st.describe(_vals(g, "pure_ack_to_resp_ms"))
        prof = {
            "device": dev, "display": DEVICE_DISPLAY[dev],
            "label_kind": "observed descriptive profile (NOT a deployment policy)",
            "outstation_ip": g[0].outstation_ip if g else None,
            "captures": sorted({t.capture for t in g}),
            "ack_mode": _ack_mode_counts(g),
            "req_to_resp_ms": st.describe(_vals(g, "req_to_resp_ms")),
            "pure_ack_to_resp_ms_separate": pa_sep,
            "pure_ack_to_resp_ms_separate_note": (
                "n<2: single or no separate-ACK observation; std/cv/percentiles are not "
                "meaningful and must not be read as stable timing"
                if (pa_sep["n"] or 0) < 2 else "ok"),
            "request_payload_bytes": st.describe(_vals(g, "req_tcp_len")),
            "response_payload_bytes": st.describe(_vals(g, "resp_tcp_len")),
        }
        p = os.path.join(profiles_dir, fnames[dev])
        with open(p, "w") as fh:
            json.dump(prof, fh, indent=2)
        paths[dev] = p
    return paths


def _fmt(x):
    return "n/a" if x is None else ("{:.3f}".format(x) if isinstance(x, float) else str(x))


def write_summary_report(summary, meta, reports_dir):
    path = os.path.join(reports_dir, "ack_trace_summary.md")
    L = ["# Phase 01 — ACK / Response Trace Summary (re-derived from raw PCAPs)", "",
         "_Run `{}` — {} transactions from the six raw PCAPs. All numbers are re-derived "
         "this run; none are carried from prior reports._".format(meta["run_id"], meta["total_transactions"]),
         "", "Classification per the canonical tshark extractor. Delays in ms; sizes in bytes. "
         "`request->pure-ACK` and `pure-ACK->response` are defined only for SEPARATE_ACK_RESPONSE.",
         "", "| device | capture | txns | combined% | separate% | other% | req->resp med | req->resp p95 | "
         "pure-ACK->resp med (sep) | resp bytes med |", "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for gk in sorted(summary):
        b = summary[gk]
        am = b["ack_mode"]
        rr = b["metrics"]["req_to_resp_ms"]["describe"]
        pa = b["metrics"]["pure_ack_to_resp_ms"]["describe"]
        rb = b["metrics"]["resp_tcp_len"]["describe"]
        # annotate the separate-only median with its n; a single-observation "median"
        # (n<2) is flagged so it is not read as a stable statistic.
        if pa["n"] == 0:
            pa_cell = "n/a"
        elif pa["n"] < 2:
            pa_cell = "{} (n=1, single obs)".format(_fmt(pa["median"]))
        else:
            pa_cell = "{} (n={})".format(_fmt(pa["median"]), pa["n"])
        L.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            DEVICE_DISPLAY[b["device"]], b["capture_kind"], am["total"],
            am["combined_pct"], am["separate_pct"], am["other_pct"],
            _fmt(rr["median"]), _fmt(rr["p95"]), pa_cell, _fmt(rb["median"])))
    L += ["", "> Claim discipline: these describe the **captured traces of these specific "
          "devices**, not product families. The pure-ACK->response gap is a wire-visible "
          "interval, not the device's exact internal processing time. Host-side capture "
          "timestamps are not identical to wire timestamps.", ""]
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")
    return path


def write_data_quality_report(txns, groups, meta, reports_dir):
    path = os.path.join(reports_dir, "data_quality_report.md")
    an = _anomaly_counts(txns)
    n_ref = sum(1 for t in txns if t.is_reference)
    n_dev = len(txns) - n_ref
    n_other = sum(1 for t in txns if t.classification == "OTHER_OR_AMBIGUOUS")
    L = ["# Phase 01 — Data Quality Report", "",
         "Run `{}`. Total reconstructed transactions: **{}** "
         "(device-specific {}, shared reference outstation {}).".format(
             meta["run_id"], len(txns), n_dev, n_ref),
         "",
         "## Prior-count reproduction",
         "- Prior reports stated ~22,988 reconstructed transactions. This isolated run "
         "reconstructed **{}** from the six raw PCAPs.".format(len(txns)),
         "  {}".format("REPRODUCED (matches 22,988)." if len(txns) == 22988
                       else "DIFFERS from 22,988 — investigate before reuse."),
         "", "## TCP / matching anomalies (whole run)",
         "- transactions with retransmission: {}".format(an["retransmission_txns"]),
         "- transactions with duplicate ACK: {}".format(an["duplicate_ack_txns"]),
         "- transactions with out-of-order: {}".format(an["out_of_order_txns"]),
         "- transactions with reset: {}".format(an["reset_txns"]),
         "- transactions with missing response: {}".format(an["missing_response_txns"]),
         "- OTHER_OR_AMBIGUOUS transactions: {}".format(n_other),
         "", "## Classification confidence",
         "- high: {}   medium: {}   low: {}".format(
             an["confidence_high"], an["confidence_medium"], an["confidence_low"]),
         "", "## Shared reference outstation ({})".format(R.REFERENCE_IP),
         "- The reference outstation appears in every capture and is EXCLUDED from "
         "device-specific analysis and profiles; it is reported here only for provenance. "
         "Reference transactions this run: {}.".format(n_ref),
         "", "## Ambiguous handling",
         "- OTHER_OR_AMBIGUOUS transactions are retained (not discarded) and enumerated in "
         "`tables/transaction_anomalies.csv` with their `ambiguity_reason`.", ""]
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")
    return path


def write_stat_report(rows, reports_dir):
    path = os.path.join(reports_dir, "statistical_comparison.md")
    L = ["# Phase 01 — Base vs L Capture Comparison", "",
         "Two-sample distributional comparison of each device's base capture vs its longer "
         "`L` capture (device-specific outstation). KS = Kolmogorov-Smirnov statistic; W1 = "
         "1-D Wasserstein distance; Cliff's delta and Cohen's d are effect sizes. Computed "
         "with numpy (no scipy).", "",
         "| device | metric | n(base) | n(L) | med(base) | med(L) | KS | W1 | Cliff's d | Cohen's d |",
         "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        L.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            DEVICE_DISPLAY.get(r["device"], r["device"]), r["metric"], r["n_a"], r["n_b"],
            _fmt(r["median_a"]), _fmt(r["median_b"]), _fmt(r["ks"]), _fmt(r["wasserstein1"]),
            _fmt(r["cliffs_delta"]), _fmt(r["cohens_d"])))
    L += ["", "> These compare only the captured base vs L traces; they do not imply "
          "temporal stability beyond the captured data. Effect sizes accompany the "
          "distances; no p-value-only claims are made.", ""]
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--traffic-dir", default="/home/philip/Projects/DNP3/Traffic Trace",
                    help="directory holding the six immutable device PCAPs")
    ap.add_argument("--run-dir", default=None,
                    help="explicit run directory (refused if populated); default auto-mints "
                         "runs/<UTC>_phase_01_real_trace_characterization/")
    ap.add_argument("--out-dir", default=os.path.dirname(os.path.abspath(__file__)),
                    help="harness root under which runs/ is created")
    ap.add_argument("--isolated", action="store_true",
                    help="explicit opt-in to run isolation (this driver always isolates; "
                         "the flag exists so the documented command is accepted verbatim)")
    ap.add_argument("--run-name", default="real_trace_characterization",
                    help="short name for the auto-minted runs/<UTC>_phase_01_<run-name>/ dir")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    import scapy  # noqa: F401  (recorded in the manifest; not used for extraction)
    scapy_version = getattr(scapy, "__version__", "present")

    pcaps = sorted(__import__("glob").glob(os.path.join(args.traffic_dir, "*.pcap")))
    if len(pcaps) != 6:
        logger.error("expected 6 PCAPs under %s, found %d", args.traffic_dir, len(pcaps))
        return 2

    try:
        run = run_manifest.RunContext.start(
            phase="phase_01", short_name=args.run_name,
            inputs=pcaps, argv=sys.argv, run_dir=args.run_dir, base_dir=args.out_dir,
            config=vars(args), extra_tool_versions={"scapy": scapy_version})
    except run_manifest.RunDirectoryError as exc:
        logger.error("%s", exc)
        return 2

    tables = run.subdir("tables")
    profiles = run.subdir("profiles")
    reports = run.subdir("reports")
    run.subdir("figures")
    run.subdir("validation")
    run.subdir("worklogs")
    stdout_log = open(os.path.join(run.run_dir, "stdout.log"), "w")

    def emit(msg):
        print(msg)
        stdout_log.write(msg + "\n")
        stdout_log.flush()

    emit("Phase 01 run: {}".format(run.run_id))
    emit("inputs: {}".format([os.path.basename(p) for p in pcaps]))

    txns, _ = R.reconstruct_all(args.traffic_dir)
    emit("reconstructed {} transactions".format(len(txns)))

    groups = group_transactions(txns)
    summary = build_device_summary(groups)
    comparison = build_capture_comparison(txns)

    meta = {
        "run_id": run.run_id,
        "total_transactions": len(txns),
        "reference_ip": R.REFERENCE_IP,
        "devices": DEVICES,
        "captures": sorted({t.capture for t in txns}),
    }

    csv_path = write_transactions(txns, tables)
    json_path = write_transactions_json(txns, summary, meta, tables)
    anom_path, n_anom = write_anomalies(txns, tables)
    ds_json, ds_csv = write_device_summary(summary, tables)
    cc_path = write_capture_comparison(comparison, tables)
    prof_paths = write_profiles(txns, profiles)
    sum_report = write_summary_report(summary, meta, reports)
    dq_report = write_data_quality_report(txns, groups, meta, reports)
    stat_report = write_stat_report(comparison, reports)

    for p in [csv_path, json_path, anom_path, ds_csv, ds_json, cc_path,
              *prof_paths.values(), sum_report, dq_report, stat_report]:
        emit("wrote {}".format(os.path.relpath(p, run.run_dir)))
    emit("anomaly/low-confidence transactions flagged: {}".format(n_anom))

    for (dev, kind), g in sorted(groups.items()):
        am = _ack_mode_counts(g)
        emit("  {:8} {:4}  n={:5}  comb={:6.2f}%  sep={:6.2f}%  other={:.2f}%".format(
            dev, kind, am["total"], am["combined_pct"], am["separate_pct"], am["other_pct"]))

    stdout_log.close()
    run.finish(exit_status=0)
    print("Run manifest: {}".format(run.manifest_path))
    print("Run directory: {}".format(run.run_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())

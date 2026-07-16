"""phase03_analyze.py -- Phase 03A ACK-mode + timing analysis of captured PCAPs.

Reads one PCAP per config (or per delay), reconstructs every transaction with the VALIDATED
Phase 01 extractor (`phase01_reconstruct`, which classifies COMBINED_ACK_RESPONSE /
SEPARATE_ACK_RESPONSE / OTHER_OR_AMBIGUOUS and records request->ACK / ACK->response /
request->response), and reports per-config ACK-mode counts and fractions with **Wilson 95%
CIs**, the timing distributions, and retransmission / duplicate-ACK / reset rates.

This analysis is environment-agnostic: it works on any capture (loopback, rig, or bridge). The
capture step itself needs a capture-capable environment (see phase03_capture.py) -- it does not
run here without packet-capture permission.

    # validate on the existing real-device captures (SEL-751 separate, AB1400 combined):
    python3 phase03_analyze.py --run-dir <dir> --exclude-reference \
        --pcap SEL751="../Traffic Trace/SEL751.pcap" --pcap AB1400="../Traffic Trace/AB1400.pcap"
    # Phase 03A wire matrix (one pcap per config):
    python3 phase03_analyze.py --run-dir <dir> --pcap-dir <run>/pcaps
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import sys
from typing import Dict, List, Tuple

import characterize_ack_traces as C
import phase01_reconstruct as R
import phase01_stats as st

CLS_COMBINED = "COMBINED_ACK_RESPONSE"
CLS_SEPARATE = "SEPARATE_ACK_RESPONSE"
CLS_OTHER = "OTHER_OR_AMBIGUOUS"
TIMING = ["req_to_first_rev_ms", "req_to_pure_ack_ms", "pure_ack_to_resp_ms", "req_to_resp_ms"]


def analyze(pairs: List[Tuple[str, str]], exclude_reference: bool = False):
    """pairs = [(label, pcap_path), ...] -> (all_transactions, per_label_summary)."""
    all_txns = []
    summary = {}
    for label, pcap in pairs:
        txns = R.build_rich_transactions(C.run_tshark(pcap), pcap, label)
        if exclude_reference:
            txns = [t for t in txns if not t.is_reference]
        for t in txns:
            row = R.to_row(t); row["config"] = label
            all_txns.append(row)
        n = len(txns)
        n_sep = sum(1 for t in txns if t.classification == CLS_SEPARATE)
        n_comb = sum(1 for t in txns if t.classification == CLS_COMBINED)
        n_oth = sum(1 for t in txns if t.classification == CLS_OTHER)
        summary[label] = {
            "n": n, "combined": n_comb, "separate": n_sep, "other": n_oth,
            "separate_fraction_wilson95": st.wilson_ci(n_sep, n),
            "combined_fraction_wilson95": st.wilson_ci(n_comb, n),
            "other_fraction_wilson95": st.wilson_ci(n_oth, n),
            "timing_ms": {m: st.describe([getattr(t, m) for t in txns]) for m in TIMING},
            "retransmission_rate": round(sum(1 for t in txns if t.retransmission_count > 0) / n, 4) if n else None,
            "duplicate_ack_rate": round(sum(1 for t in txns if t.duplicate_ack_count > 0) / n, 4) if n else None,
            "reset_rate": round(sum(1 for t in txns if t.reset) / n, 4) if n else None,
        }
    return all_txns, summary


def _pairs_from_args(args) -> List[Tuple[str, str]]:
    pairs = []
    for spec in (args.pcap or []):
        if "=" not in spec:
            raise SystemExit("--pcap expects label=path, got %r" % spec)
        label, path = spec.split("=", 1)
        pairs.append((label, path))
    if args.pcap_dir:
        for p in sorted(glob.glob(os.path.join(args.pcap_dir, "*.pcap")) +
                        glob.glob(os.path.join(args.pcap_dir, "*.pcapng"))):
            pairs.append((os.path.splitext(os.path.basename(p))[0], p))
    return pairs


def write_outputs(all_txns, summary, run_dir):
    tdir = os.path.join(run_dir, "tables"); os.makedirs(tdir, exist_ok=True)
    tx_csv = os.path.join(tdir, "phase03_ack_transactions.csv")
    if all_txns:
        cols = ["config"] + [c for c in all_txns[0] if c != "config"]
        with open(tx_csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader()
            for r in all_txns:
                w.writerow(r)
    sm_csv = os.path.join(tdir, "phase03_ack_summary.csv")
    with open(sm_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["config", "n", "combined", "separate", "other", "separate_frac",
                    "separate_lo", "separate_hi", "req_to_resp_med_ms", "req_to_ack_med_ms",
                    "ack_to_resp_med_ms", "retrans_rate", "dup_ack_rate", "reset_rate"])
        for cfg, s in summary.items():
            sep = s["separate_fraction_wilson95"]
            w.writerow([cfg, s["n"], s["combined"], s["separate"], s["other"],
                        sep["p"], sep["lo"], sep["hi"],
                        s["timing_ms"]["req_to_resp_ms"]["median"],
                        s["timing_ms"]["req_to_pure_ack_ms"]["median"],
                        s["timing_ms"]["pure_ack_to_resp_ms"]["median"],
                        s["retransmission_rate"], s["duplicate_ack_rate"], s["reset_rate"]])
    with open(os.path.join(tdir, "phase03_ack_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    return tx_csv, sm_csv


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", action="append", help="label=path (repeatable)")
    ap.add_argument("--pcap-dir", default=None, help="directory of per-config pcaps")
    ap.add_argument("--exclude-reference", action="store_true",
                    help="drop the shared reference outstation (for the device-pcap validation)")
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    pairs = _pairs_from_args(args)
    if not pairs:
        sys.stderr.write("no pcaps given (--pcap label=path or --pcap-dir)\n"); return 2
    all_txns, summary = analyze(pairs, exclude_reference=args.exclude_reference)
    tx_csv, sm_csv = write_outputs(all_txns, summary, args.run_dir)
    print("analyzed %d configs / %d transactions" % (len(pairs), len(all_txns)))
    for cfg, s in summary.items():
        sep = s["separate_fraction_wilson95"]
        print("  %-22s n=%d separate=%d (%.1f%%, Wilson95 [%.3f,%.3f]) combined=%d other=%d" % (
            cfg, s["n"], s["separate"], 100 * (sep["p"] or 0), sep["lo"] or 0, sep["hi"] or 0,
            s["combined"], s["other"]))
    print("wrote", tx_csv, "and", sm_csv)
    return 0


if __name__ == "__main__":
    sys.exit(main())

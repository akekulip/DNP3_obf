#!/usr/bin/env python3
"""phase04b_dcrn_attacker_eval.py -- DCRN timing attacker evaluation (corrective.md sec 15).

Runs UNPRIVILEGED on the campaign PCAPs. Maps each condition capture's TCP streams back to device
profiles via the spec session order (streams appear in connection order == session order), extracts the
timing feature families the spec defines, and runs a leakage-safe grouped classifier (train on some
sessions, test on disjoint sessions). Reports accuracy / balanced accuracy / macro-F1 with the correct
0.333 chance line.

Expected reading (sec 15): mode_only stays ~0.667 (DCRN preserves ACK mode), timing families approach
0.333, size unchanged, all-features stays above chance (mode + size remain). DCRN is NOT failed because
mode and size persist.

  python3 phase04b_dcrn_attacker_eval.py --run-dir /tmp/phase04b_campaign
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

import numpy as np
import pandas as pd

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
import characterize_ack_traces as C

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score
    _SK = True
except ImportError:
    _SK = False

PCAPS = ["SEL751.pcap", "SEL751L.pcap", "AB1400.pcap", "AB1400L.pcap", "ION7550.pcap", "ION7550L.pcap"]
DEVICES = ["AB1400", "ION7550", "SEL751"]
# timing-only families (sec 15); mode/size reported for context but DCRN targets timing.
FAMILIES = {
    "mode_only": ["is_separate"],
    "ack_event_timing": ["req_to_ack_event_ms"],
    "response_timing": ["req_to_resp_ms"],
    "timing_all": ["req_to_ack_event_ms", "req_to_resp_ms"],
    "size": ["resp_size"],
    "all": ["is_separate", "req_to_ack_event_ms", "req_to_resp_ms", "resp_size"],
}


def rows_for_capture(pcap: str, spec: dict) -> list:
    """Map streams->sessions (spec order) -> device profile; emit per-txn feature rows with a session id."""
    txns = C.build_transactions(C.run_tshark(pcap), os.path.basename(pcap), "SEL751")
    streams = {}
    for t in txns:
        streams.setdefault(t.stream, []).append(t)
    order = sorted(streams, key=lambda s: min(x.req_frame for x in streams[s]))
    sess = list(spec["pcaps"])                      # native-only spec: one session per pcap in order
    rows = []
    for k, s in enumerate(order):
        pcap_name = sess[k % len(sess)]; dev = C.device_from_pcap(pcap_name)
        st = streams[s]; first = min(x.req_frame for x in st)
        for t in st:
            if t.classification not in (C.CLS_COMBINED, C.CLS_SEPARATE) or t.req_frame == first:
                continue
            if t.req_to_resp_ms is None:
                continue
            ack_event = t.req_to_ack_ms if (t.first_rev_is_pure_ack and t.req_to_ack_ms is not None) else t.req_to_resp_ms
            rows.append({"device_label": dev, "session": k,
                         "is_separate": 1 if t.first_rev_is_pure_ack else 0,
                         "req_to_ack_event_ms": ack_event, "req_to_resp_ms": t.req_to_resp_ms,
                         "resp_size": t.resp_size})
    return rows


def grouped_eval(df: pd.DataFrame) -> dict:
    """Leakage-safe grouped split: train on even sessions, test on odd sessions (disjoint)."""
    tr = df[df["session"] % 2 == 0]; te = df[df["session"] % 2 == 1]
    if tr.empty or te.empty or te["device_label"].nunique() < 2:
        return {"error": "insufficient grouped train/test"}
    y_tr, y_te = tr["device_label"].values, te["device_label"].values
    chance = round(float(max(np.bincount([DEVICES.index(v) for v in y_te])) / len(y_te)), 4)
    out = {"chance": chance, "n_train": int(len(tr)), "n_test": int(len(te)), "split": "grouped by session parity"}
    for fam, cols in FAMILIES.items():
        sc = StandardScaler().fit(tr[cols].values)
        clf = RandomForestClassifier(n_estimators=200, random_state=0).fit(sc.transform(tr[cols].values), y_tr)
        pred = clf.predict(sc.transform(te[cols].values))
        out[fam] = {"accuracy": round(float(accuracy_score(y_te, pred)), 4),
                    "balanced_accuracy": round(float(balanced_accuracy_score(y_te, pred)), 4),
                    "macro_f1": round(float(f1_score(y_te, pred, average="macro")), 4)}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    if not _SK:
        sys.stderr.write("scikit-learn required (system python3).\n"); return 2
    spec_path = os.path.join(args.run_dir, "spec.json")
    if not os.path.exists(spec_path):
        sys.stderr.write("spec.json missing in run-dir (build it with phase04b_dcrn_harness.py).\n"); return 2
    spec = json.load(open(spec_path))
    result = {"chance_uniform": round(1 / 3, 4), "conditions": {}}
    for pcap in sorted(glob.glob(os.path.join(args.run_dir, "*.pcap"))):
        cond = os.path.splitext(os.path.basename(pcap))[0]
        df = pd.DataFrame(rows_for_capture(pcap, spec))
        result["conditions"][cond] = grouped_eval(df) if not df.empty else {"error": "no rows"}
        r = result["conditions"][cond]
        if "all" in r:
            print("[%s] mode_only=%.3f timing_all=%.3f size=%.3f all=%.3f (chance %.3f)"
                  % (cond, r["mode_only"]["balanced_accuracy"], r["timing_all"]["balanced_accuracy"],
                     r["size"]["balanced_accuracy"], r["all"]["balanced_accuracy"], r["chance"]))
    dst = os.path.join(args.run_dir, "phase04b_classifier_metrics.json")
    json.dump(result, open(dst, "w"), indent=2)
    print("wrote", dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())

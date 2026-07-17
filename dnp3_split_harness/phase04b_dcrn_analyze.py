#!/usr/bin/env python3
"""phase04b_dcrn_analyze.py -- DCRN timing-effectiveness + transport-health analysis (sec 14, 16).

Runs UNPRIVILEGED on the campaign PCAPs (produced by the PI-run scripts). For each capture it rebuilds
transactions (reusing characterize_ack_traces), computes the timing distributions the spec requires
(request->ACK-event, request->response, separate ACK->response gap), transport health (retrans / dup-ACK
/ resets, ACK-before-response ordering), and -- in --gate-b mode -- checks the Gate-B pass criteria.

  Gate-B single-capture:  python3 phase04b_dcrn_analyze.py --pcap X.pcap --condition DCRN_FIXED --gate-b --out r.json
  Full campaign:          python3 phase04b_dcrn_analyze.py --run-dir /tmp/phase04b_campaign
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

import numpy as np

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
import characterize_ack_traces as C

TARGET_MS = 32.39
QS = [("n", None), ("min", 0), ("median", 50), ("mean", "mean"), ("std", "std"),
      ("p90", 90), ("p95", 95), ("p99", 99), ("max", 100)]


def qstats(vals):
    a = np.asarray([v for v in vals if v is not None], float)
    if a.size == 0:
        return {k: (0 if k == "n" else None) for k, _ in QS}
    out = {"n": int(a.size)}
    for k, q in QS:
        if k == "n":
            continue
        out[k] = round(float(a.mean() if q == "mean" else a.std(ddof=0) if q == "std" else np.percentile(a, q)), 4)
    return out


def analyze_capture(pcap: str, name: str):
    """Per-capture timing + health, excluding the first txn per stream (connection-start artifact)."""
    txns = C.build_transactions(C.run_tshark(pcap), name, "SEL751")  # device label unused here
    first = {}
    for t in txns:
        first.setdefault(t.stream, t.req_frame)
        first[t.stream] = min(first[t.stream], t.req_frame)
    req_resp, req_ack, gap = [], [], []
    retrans = resets = dupack = ack_after_resp = n = 0
    for t in txns:
        if t.classification not in (C.CLS_COMBINED, C.CLS_SEPARATE):
            continue
        if t.req_frame == first[t.stream]:
            continue
        n += 1
        retrans += int(t.retransmission); resets += int(t.reset); dupack += int(t.duplicate_ack)
        if t.req_to_resp_ms is not None:
            req_resp.append(t.req_to_resp_ms)
        # ACK event = pure ACK (separate) or the response itself (combined)
        if t.first_rev_is_pure_ack and t.req_to_ack_ms is not None:
            req_ack.append(t.req_to_ack_ms)
            if t.ack_to_resp_ms is not None:
                gap.append(t.ack_to_resp_ms)
                if t.ack_to_resp_ms < 0:
                    ack_after_resp += 1
        elif t.req_to_resp_ms is not None:
            req_ack.append(t.req_to_resp_ms)   # combined: ACK event == response
    return {
        "n": n, "request_to_response_ms": qstats(req_resp), "request_to_ack_event_ms": qstats(req_ack),
        "separate_ack_to_response_gap_ms": qstats(gap),
        "transport": {"retransmissions": retrans, "resets": resets, "duplicate_acks": dupack,
                      "ack_after_response_violations": ack_after_resp},
    }


def gate_b(res: dict) -> dict:
    rr = res["request_to_response_ms"]; tr = res["transport"]
    checks = {
        "request_to_response_near_target": rr["median"] is not None and abs(rr["median"] - TARGET_MS) <= 5.0,
        "no_retransmissions": tr["retransmissions"] == 0,
        "no_resets": tr["resets"] == 0,
        "no_ack_after_response": tr["ack_after_response_violations"] == 0,
        "sufficient_sample": res["n"] >= 30,
    }
    return {"checks": checks, "pass": all(checks.values())}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap"); ap.add_argument("--condition", default="?")
    ap.add_argument("--gate-b", action="store_true"); ap.add_argument("--out")
    ap.add_argument("--run-dir")
    args = ap.parse_args()

    if args.run_dir:
        out = {"target_ms": TARGET_MS, "conditions": {}}
        for pcap in sorted(glob.glob(os.path.join(args.run_dir, "*.pcap"))):
            cond = os.path.splitext(os.path.basename(pcap))[0]
            out["conditions"][cond] = analyze_capture(pcap, cond)
            print("[%s] req->resp median=%s  retrans=%d resets=%d"
                  % (cond, out["conditions"][cond]["request_to_response_ms"]["median"],
                     out["conditions"][cond]["transport"]["retransmissions"],
                     out["conditions"][cond]["transport"]["resets"]))
        dst = os.path.join(args.run_dir, "phase04b_timing_summary.json")
        json.dump(out, open(dst, "w"), indent=2)
        print("wrote", dst)
        return 0

    if not args.pcap:
        ap.error("need --pcap or --run-dir")
    res = analyze_capture(args.pcap, args.condition)
    if args.gate_b:
        res["gate_b"] = gate_b(res)
    if args.out:
        json.dump(res, open(args.out, "w"), indent=2)
        print("wrote", args.out)
    print("req->resp median=%s ms | retrans=%d resets=%d | gate_b=%s"
          % (res["request_to_response_ms"]["median"], res["transport"]["retransmissions"],
             res["transport"]["resets"], res.get("gate_b", {}).get("pass", "n/a")))
    return 0 if (not args.gate_b or res["gate_b"]["pass"]) else 1


if __name__ == "__main__":
    sys.exit(main())

"""phase02_projected_leakage.py -- projected timing-leakage reduction (Phase 02, RQ1/RQ4).

Drives the SHIPPED scheduler (`timing_policy.ReleaseScheduler.decide`, not a re-implementation)
over the real Phase 01 device-specific COMBINED transactions, using each transaction's captured
native request->response time as the response-ready time. It measures how the visible
request->response time's dependence on response size and on the native ready time changes
under native / fixed / bounded normalization, plus deadline-miss rate and native-tail.

LABEL: this is a **PROJECTED** policy-property measurement (the shipped scheduler applied to
captured timestamps), NOT a wire capture. It shows what the *policy* does to the observable;
it does not by itself prove enforcement on the wire (see phase02_normalize_experiment.py for
the loopback end-to-end enforcement, and the rig for wire PCAP).

    python3 phase02_projected_leakage.py --run-dir <phase02 run dir>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List

import numpy as np

import phase01_reconstruct as R
import phase01_stats as st
import timing_policy as TP

MODES = [
    ("native", dict(mode="native")),
    ("fixed25", dict(mode="fixed", target_delay_ms=25.0)),
    ("bounded20-30", dict(mode="bounded", target_min_ms=20.0, target_max_ms=30.0, seed=12345)),
]


def _corr(xs, ys):
    x = np.array(xs, float); y = np.array(ys, float)
    if x.size < 3 or np.std(x) == 0 or np.std(y) == 0:
        return None
    return round(float(np.corrcoef(x, y)[0, 1]), 4)


def project(txns) -> Dict[str, dict]:
    """For each mode, run the shipped scheduler over the transactions and summarize.

    Uses each transaction's REAL request timestamp as request_received (per device flow,
    time-ordered) so the per-flow FIFO reflects genuine arrivals rather than collapsing
    every transaction onto one instant.
    """
    ordered = sorted((t for t in txns if t.req_to_resp_ms is not None),
                     key=lambda t: (t.device_label, t.req_time_epoch))
    out = {}
    for label, kw in MODES:
        profile = TP.TimingProfile(**kw)
        sched = TP.ReleaseScheduler(profile)
        visible, size, native, misses = [], [], [], 0
        for i, t in enumerate(ordered):
            recv_ns = int(t.req_time_epoch * 1e9)
            ready_ns = recv_ns + int(t.req_to_resp_ms * TP.MS_TO_NS)
            d = sched.decide(flow_id=t.device_label, transaction_id=i,
                             request_received_ns=recv_ns, response_ready_ns=ready_ns,
                             request_size=t.req_tcp_len, response_size=t.resp_tcp_len or 0)
            visible.append(d.visible_delay_ns * TP.NS_TO_MS)
            size.append(t.resp_tcp_len or 0)
            native.append(t.req_to_resp_ms)
            misses += 1 if d.deadline_missed else 0
        out[label] = {
            "n": len(visible),
            "visible_ms": st.describe(visible),
            "corr_visible_vs_response_size": _corr(size, visible),
            "corr_visible_vs_native_ready": _corr(native, visible),
            "deadline_miss_rate": round(misses / len(visible), 4) if visible else None,
            "native_tail_over_target": (
                None if label == "native"
                else round(sum(1 for v in native if v > (25.0 if label == "fixed25" else 20.0)) / len(native), 4)),
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--traffic-dir", default="/home/philip/Projects/DNP3/Traffic Trace")
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    if not os.path.isdir(args.run_dir):
        sys.stderr.write("run-dir not found: %s\n" % args.run_dir)
        return 2

    txns, _ = R.reconstruct_all(args.traffic_dir)
    combined = [t for t in txns if not t.is_reference and t.classification == "COMBINED_ACK_RESPONSE"]
    result = {"n_combined_transactions": len(combined),
              "note": "PROJECTED: shipped timing_policy scheduler applied to captured native "
                      "request->response times of device-specific COMBINED transactions "
                      "(AB1400 + ION7550). Not a wire capture.",
              "by_mode": project(combined)}

    tables = os.path.join(args.run_dir, "tables")
    os.makedirs(tables, exist_ok=True)
    with open(os.path.join(tables, "phase02_projected_leakage.json"), "w") as fh:
        json.dump(result, fh, indent=2)

    reports = os.path.join(args.run_dir, "reports")
    os.makedirs(reports, exist_ok=True)
    L = ["# Phase 02 — Projected Timing-Leakage Reduction (RQ1/RQ4)", "",
         "> **PROJECTED / NOT WIRE-VALIDATED.** The shipped `timing_policy` scheduler is "
         "applied to the captured native request→response times of the %d device-specific "
         "COMBINED transactions (AB1400 + ION7550). It shows what the *policy* does to the "
         "observable; enforcement on the wire is shown separately by the loopback experiment "
         "and requires the rig / PCAP to confirm at packet level." % len(combined), "",
         "| mode | n | visible med (ms) | corr(visible, resp size) | corr(visible, native) | deadline-miss | native>target |",
         "|---|---:|---:|---:|---:|---:|---:|"]
    for label, _ in MODES:
        m = result["by_mode"][label]
        L.append("| %s | %d | %s | %s | %s | %s | %s |" % (
            label, m["n"],
            "%.3f" % m["visible_ms"]["median"] if m["visible_ms"]["median"] is not None else "n/a",
            "n/a" if m["corr_visible_vs_response_size"] is None else "%.3f" % m["corr_visible_vs_response_size"],
            "n/a" if m["corr_visible_vs_native_ready"] is None else "%.3f" % m["corr_visible_vs_native_ready"],
            "n/a" if m["deadline_miss_rate"] is None else "%.3f" % m["deadline_miss_rate"],
            "n/a" if m["native_tail_over_target"] is None else "%.3f" % m["native_tail_over_target"]))
    L += ["", "Interpretation: under `native` the visible time equals the native ready time "
          "(correlation with native = 1.0 by construction). Under `fixed`/`bounded` the visible "
          "time is pinned to the class-independent target for every transaction whose native "
          "time is below the target, dropping its dependence on the native time and response "
          "size. `deadline-miss` / `native>target` count the transactions whose native ready "
          "time already exceeds the target (the residual native tail that normalization cannot "
          "hide downward without dropping bytes).", "",
          "> Note: the real device COMBINED traffic is homogeneous (Phase 01: median ~16 ms, "
          "response ~37 B), so native size/time spread is small; the loopback experiment (wide "
          "response sizes 17 B–2407 B) exercises decorrelation more strongly.", ""]
    with open(os.path.join(reports, "phase02_projected_leakage.md"), "w") as fh:
        fh.write("\n".join(L) + "\n")
    print("projected leakage: %d combined transactions; wrote tables/phase02_projected_leakage.json + report" % len(combined))
    return 0


if __name__ == "__main__":
    sys.exit(main())

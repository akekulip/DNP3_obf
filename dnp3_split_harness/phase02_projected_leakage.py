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
        # per-mode target bounds (None for native)
        lower = kw.get("target_min_ms", kw.get("target_delay_ms"))
        upper = kw.get("target_max_ms", kw.get("target_delay_ms"))
        n = len(visible)

        def rate(pred_bound):
            if pred_bound is None or not native:
                return None
            return round(sum(1 for v in native if v > pred_bound) / len(native), 4)

        out[label] = {
            "n": n,
            "visible_ms": st.describe(visible),
            "corr_visible_vs_response_size": _corr(size, visible),
            "corr_visible_vs_native_ready": _corr(native, visible),
            # native_ready > the transaction's OWN selected target (the scheduler's deadline_missed).
            "actual_deadline_miss_rate": round(misses / n, 4) if n else None,
            # native_ready > the configured lower/upper bounds (NOT the same as > selected target
            # for bounded, where the selected target sits between the two bounds).
            "native_above_lower_bound_rate": rate(lower),
            "native_above_upper_bound_rate": rate(upper),
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
         "| mode | n | visible med (ms) | corr(visible, resp size) | corr(visible, native) | "
         "deadline-miss (native>selected target) | native>lower bound | native>upper bound |",
         "|---|---:|---:|---:|---:|---:|---:|---:|"]

    def _p(x):
        return "n/a" if x is None else "%.4f" % x
    for label, _ in MODES:
        m = result["by_mode"][label]
        L.append("| %s | %d | %s | %s | %s | %s | %s | %s |" % (
            label, m["n"],
            "%.3f" % m["visible_ms"]["median"] if m["visible_ms"]["median"] is not None else "n/a",
            _p(m["corr_visible_vs_response_size"]), _p(m["corr_visible_vs_native_ready"]),
            _p(m["actual_deadline_miss_rate"]), _p(m["native_above_lower_bound_rate"]),
            _p(m["native_above_upper_bound_rate"])))
    L += ["", "Three tail metrics are reported separately (they are NOT the same thing):",
          "- **deadline-miss** = native ready time > the transaction's OWN selected target "
          "(the scheduler's `deadline_missed`). This is the true residual: the response was "
          "already slower than the target, so normalization cannot hold it *down* without "
          "dropping bytes; its visible time stays = native.",
          "- **native>lower bound** = native > `target_min` (20 ms for bounded, 25 ms for fixed).",
          "- **native>upper bound** = native > `target_max` (30 ms for bounded, 25 ms for fixed).",
          "",
          "Why the earlier bounded run reported deadline-miss 0.0032 (0.32%) and \"native tail\" "
          "0.0095 (0.95%): the 0.95% figure counted native > **20 ms** (the lower bound) but was "
          "mislabeled \"native > target\". Because each bounded transaction's selected target sits "
          "between 20 and 30 ms, fewer transactions exceed their (higher) selected target (0.32%) "
          "than exceed the 20 ms lower bound (0.95%). The two are now reported as distinct "
          "columns; only `deadline-miss` is the true over-selected-target rate.", "",
          "Interpretation: under `native` visible = native (correlation 1.0 by construction). "
          "Under `fixed`/`bounded` the visible time is pinned to the class-independent target for "
          "every transaction below the target, dropping its dependence on native time and size; "
          "the residual native correlation comes from the deadline-miss tail (visible = native "
          "there).", "",
          "> Note: the real device COMBINED traffic is homogeneous (Phase 01: median ~16 ms, "
          "response ~37 B), so native size/time spread is small; the loopback experiment (wide "
          "response sizes 17 B–2407 B) exercises decorrelation more strongly.", ""]
    with open(os.path.join(reports, "phase02_projected_leakage.md"), "w") as fh:
        fh.write("\n".join(L) + "\n")
    print("projected leakage: %d combined transactions; wrote tables/phase02_projected_leakage.json + report" % len(combined))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
run_timing_experiment.py -- reproducible Phase-1 response-time-normalization matrix.

Drives split_server.py over the loopback replay exchange across a matrix of timing
configurations (native / fixed / bounded), N repetitions each, and reports:

  - client-visible request->response time (median / p95 / p99 / max) for the timed
    READ transaction, the observable an attacker fingerprints;
  - server-side hold time, deadline-miss rate, and bypass rate parsed from the
    server's own timing_decisions.jsonl;
  - byte-identity pass/fail for every transaction (the harness invariant).

Loopback is a smoke/mechanism check, NOT wire truth -- the rig run on Vision/Hulk
is the real bar. Outputs go to reports/ with fresh files each run (no stale reuse).

Run:  python3 run_timing_experiment.py            # default matrix, 20 reps
      python3 run_timing_experiment.py --reps 50
"""

import argparse
import json
import os
import shutil
import statistics
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HARNESS, "tests"))
from loopback_smoke import run_one  # noqa: E402  (loopback driver: launch server + replay master)

REPORTS = os.path.join(HARNESS, "reports")

# (label, delivery, timing args). Bounds chosen under the measured ~211 ms RTO floor.
DEFAULT_MATRIX = [
    ("native", "full", ["--timing-mode", "native"]),
    ("fixed-10ms", "full", ["--timing-mode", "fixed", "--target-delay-ms", "10"]),
    ("fixed-25ms", "full", ["--timing-mode", "fixed", "--target-delay-ms", "25"]),
    ("bounded-10-15ms", "full",
     ["--timing-mode", "bounded", "--target-min-ms", "10", "--target-max-ms", "15",
      "--timing-seed", "20260714"]),
    ("bounded-15-25ms", "full",
     ["--timing-mode", "bounded", "--target-min-ms", "15", "--target-max-ms", "25",
      "--timing-seed", "20260714"]),
    ("native-crc-split", "crc-boundary", ["--timing-mode", "native"]),
    ("bounded-15-25ms-crc-split", "crc-boundary",
     ["--timing-mode", "bounded", "--target-min-ms", "15", "--target-max-ms", "25",
      "--timing-seed", "20260714"]),
]


def _pct(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    k = min(len(s) - 1, int(round(q * (len(s) - 1))))
    return s[k]


def read_decisions(log_dir):
    """Parse the server's timing_decisions.jsonl (all reps appended)."""
    path = os.path.join(log_dir, "timing_decisions.jsonl")
    out = []
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def run_config(label, delivery, targs, reps, port0):
    log_dir = os.path.join(HARNESS, "logs", "timing_exp", label)
    shutil.rmtree(log_dir, ignore_errors=True)      # no stale reuse
    os.makedirs(log_dir, exist_ok=True)

    visible_read = []
    byte_ok = True
    port = port0
    for _ in range(reps):
        recs = run_one(port, delivery, targs, log_dir)
        port += 1
        byte_ok = byte_ok and all(r["byte_identical"] and r["recv_len"] == r["resp_len"]
                                  for r in recs)
        read_rec = max(recs, key=lambda r: r["resp_len"])
        if read_rec["visible_first_byte_ms"] is not None:
            visible_read.append(read_rec["visible_first_byte_ms"])

    decisions = read_decisions(log_dir)
    non_native = [d for d in decisions if d["timing_mode"] != "native"]
    holds = [d["hold_delay_ms"] for d in decisions]
    n_dec = len(decisions) or 1
    return {
        "config": label,
        "delivery": delivery,
        "timing_args": " ".join(targs),
        "reps": reps,
        "byte_identity_all_pass": byte_ok,
        "visible_read_ms": {
            "n": len(visible_read),
            "median": round(statistics.median(visible_read), 3) if visible_read else None,
            "p95": round(_pct(visible_read, 0.95), 3) if visible_read else None,
            "p99": round(_pct(visible_read, 0.99), 3) if visible_read else None,
            "max": round(max(visible_read), 3) if visible_read else None,
        },
        "server_side": {
            "decisions": len(decisions),
            "hold_ms_median": round(statistics.median(holds), 3) if holds else None,
            "hold_ms_max": round(max(holds), 3) if holds else None,
            "deadline_miss_rate": round(sum(1 for d in decisions if d["deadline_missed"]) / n_dec, 4),
            "bypass_rate": round(sum(1 for d in decisions if d["bypassed"]) / n_dec, 4),
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Phase-1 timing-normalization experiment matrix (loopback).")
    ap.add_argument("--reps", type=int, default=20, help="repetitions per config (>=30 preferred on the rig).")
    ap.add_argument("--port0", type=int, default=20100, help="base loopback port.")
    args = ap.parse_args()

    os.makedirs(REPORTS, exist_ok=True)
    results = []
    port = args.port0
    print("Running {} configs x {} reps on loopback...".format(len(DEFAULT_MATRIX), args.reps))
    for label, delivery, targs in DEFAULT_MATRIX:
        r = run_config(label, delivery, targs, args.reps, port)
        port += args.reps + 2
        results.append(r)
        v = r["visible_read_ms"]
        print("  {:26s} bytes={:4s} visible_read median={} p95={} max={}  hold_med={} miss={} bypass={}".format(
            label, "OK" if r["byte_identity_all_pass"] else "FAIL",
            v["median"], v["p95"], v["max"],
            r["server_side"]["hold_ms_median"],
            r["server_side"]["deadline_miss_rate"], r["server_side"]["bypass_rate"]))

    meta = {"generated_note": "loopback smoke; rig (Vision/Hulk) is the real bar",
            "reps": args.reps, "results": results}
    with open(os.path.join(REPORTS, "timing_experiment_results.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    # CSV
    cols = ["config", "delivery", "reps", "byte_identity_all_pass",
            "visible_median_ms", "visible_p95_ms", "visible_p99_ms", "visible_max_ms",
            "hold_median_ms", "hold_max_ms", "deadline_miss_rate", "bypass_rate", "timing_args"]
    with open(os.path.join(REPORTS, "timing_experiment_results.csv"), "w") as fh:
        fh.write(",".join(cols) + "\n")
        for r in results:
            v, s = r["visible_read_ms"], r["server_side"]
            row = [r["config"], r["delivery"], r["reps"], r["byte_identity_all_pass"],
                   v["median"], v["p95"], v["p99"], v["max"],
                   s["hold_ms_median"], s["hold_ms_max"], s["deadline_miss_rate"], s["bypass_rate"],
                   '"%s"' % r["timing_args"]]
            fh.write(",".join(str(x) for x in row) + "\n")

    print("\nWrote reports/timing_experiment_results.{json,csv}")
    all_ok = all(r["byte_identity_all_pass"] for r in results)
    print("BYTE-IDENTITY across matrix: {}".format("ALL PASS" if all_ok else "FAILURES"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

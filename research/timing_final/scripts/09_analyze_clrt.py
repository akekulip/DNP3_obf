#!/usr/bin/env python3
"""09_analyze_clrt.py — thin gating wrapper over scripts/analyze_clrt.py.

analyze_clrt.py (reused unchanged) produces transactions.csv / summary.json /
validation.json and RECORDS a tshark cross-check. This wrapper makes the cross-check
GATE (review W3): the headline CLRT must not depend on one parser, so if the in-house
and tshark medians disagree by more than --tol-us, or tshark is unavailable when
--require-tshark is set, we exit non-zero instead of quietly reporting a number.

Everything else is delegated to analyze_clrt.py; this only adds the gate.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ANALYZE = os.path.join(HERE, "analyze_clrt.py")


def main():
    ap = argparse.ArgumentParser(description="gating wrapper over analyze_clrt.py (review W3)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--outstation-ip", default=os.environ.get("SEL_IP", "192.168.10.7"))
    ap.add_argument("--label", default="run")
    ap.add_argument("--g-ms", type=float, default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--require-tshark", action="store_true",
                    help="fail if tshark is unavailable (default: warn only)")
    ap.add_argument("--tol-us", type=float, default=float(os.environ.get("TSHARK_TOL_US", "50")),
                    help="max in-house vs tshark median disagreement (µs) before FAIL")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    cmd = ["python3", ANALYZE, "--pcap", a.pcap, "--outstation-ip", a.outstation_ip,
           "--label", a.label, "--tshark-crosscheck"]
    if a.g_ms is not None:
        cmd += ["--g-ms", str(a.g_ms)]
    if a.out:
        cmd += ["--out", a.out]
    print("RUN: %s" % " ".join(cmd))
    if a.dry_run:
        print("DRYRUN: would run analyze_clrt.py then GATE on tshark agreement within %.0f µs "
              "(and on tshark availability if --require-tshark)." % a.tol_us)
        return 0
    if not os.path.exists(a.pcap):
        sys.exit("FATAL: missing pcap %s" % a.pcap)

    rc = subprocess.run(cmd).returncode
    if rc != 0:
        sys.exit("FATAL: analyze_clrt.py exited %d" % rc)

    out = a.out or os.path.splitext(a.pcap)[0]
    summ = json.load(open(out + ".summary.json"))
    xc = summ.get("tshark_crosscheck", {})

    have_tshark = shutil.which("tshark") is not None
    if not have_tshark or not xc.get("available"):
        msg = "tshark cross-check unavailable (tshark installed=%s)" % have_tshark
        if a.require_tshark:
            sys.exit("FATAL (W3): %s — headline CLRT would rest on one parser." % msg)
        print("WARN (W3): %s — reporting in-house numbers only (not cross-checked)." % msg)
        return 0

    own = summ.get("clrt_ms", {}).get("median")
    ts_med = xc.get("median_ms")
    if own is None or ts_med is None:
        if a.require_tshark:
            sys.exit("FATAL (W3): no comparable medians (own=%s tshark=%s)." % (own, ts_med))
        print("WARN (W3): no comparable medians (own=%s tshark=%s)." % (own, ts_med))
        return 0

    disagree_us = abs(own - ts_med) * 1000.0
    print("W3 cross-check: in-house median=%.4f ms  tshark median=%.4f ms  |Δ|=%.1f µs (tol %.0f µs)"
          % (own, ts_med, disagree_us, a.tol_us))
    if disagree_us > a.tol_us:
        sys.exit("FATAL (W3): in-house vs tshark CLRT medians disagree by %.1f µs > %.0f µs — "
                 "the two parsers do not agree; do not trust the headline number." % (disagree_us, a.tol_us))
    print("W3 cross-check: PASS (medians agree within tolerance).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

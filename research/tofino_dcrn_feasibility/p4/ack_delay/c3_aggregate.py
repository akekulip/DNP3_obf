#!/usr/bin/env python3
"""c3_aggregate.py — summarize the C3 matrix from /tmp/c3res/<mode>_<rms>ms_<i>.{pcap,tel.json}.

Per (mode, readiness) reports: N valid, CLRT median/IQR, ACK-hold median, byte-identity rate,
clean-transport rate, and the evstat stop-condition tallies (ACK_RELEASED / *_MAXPASS from the
AUTHORITATIVE evstat registers, not the flaky events Counter). The headline is native vs Case-A CLRT.
"""
import glob
import json
import os
import re
import statistics as st
import subprocess
import sys

RES = sys.argv[1] if len(sys.argv) > 1 else "/tmp/c3res"
ANALYZER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c3_analyze_pcap.py")
RP = os.path.expanduser("~/.venvs/research/bin/python")


def analyze(pcap):
    try:
        out = subprocess.check_output([RP, ANALYZER, pcap, "--json"], stderr=subprocess.DEVNULL)
        return json.loads(out)
    except Exception:
        return None


def med(xs):
    return st.median(xs) if xs else float("nan")


def main():
    rows = {}   # (mode, rms) -> list of dicts
    for pcap in sorted(glob.glob(os.path.join(RES, "*.pcap"))):
        m = re.match(r"(native|case-a)_(\d+)ms_(\d+)\.pcap$", os.path.basename(pcap))
        if not m:
            continue
        mode, rms, i = m.group(1), int(m.group(2)), int(m.group(3))
        v = analyze(pcap)
        if not v:
            continue
        tel = {}
        tp = pcap[:-5] + ".tel.json"
        if os.path.exists(tp):
            try:
                tel = json.load(open(tp)).get("evstat", {})
            except Exception:
                pass
        v["evstat"] = tel
        rows.setdefault((mode, rms), []).append(v)

    print("%-8s %5s %4s %10s %10s %9s %8s %8s %10s %9s" %
          ("mode", "rdy", "N", "CLRT_med", "CLRT_IQR", "hold_med", "byte_ok", "clean", "ACK_RELd", "MAXPASS"))
    print("-" * 96)
    for (mode, rms) in sorted(rows, key=lambda k: (k[0], k[1])):
        v = rows[(mode, rms)]
        valid = [x for x in v if x.get("complete")]
        clrt = [x["clrt_ms"] for x in valid if x.get("clrt_ms") is not None]
        hold = [x["ack_hold_ms"] for x in valid if x.get("ack_hold_ms") is not None]
        byte_ok = sum(1 for x in valid if x.get("resp_bytes_ok"))
        clean = sum(1 for x in valid if x.get("clean_transport"))
        ack_rel = sum(int(x["evstat"].get("ACK_RELEASED", 0) or 0) for x in valid)
        maxpass = sum(int(x["evstat"].get("ACK_MAXPASS", 0) or 0) + int(x["evstat"].get("RESP_MAXPASS", 0) or 0) for x in valid)
        clrt_s = sorted(clrt)
        iqr = "%.2f-%.2f" % (clrt_s[len(clrt_s)//4], clrt_s[(3*len(clrt_s))//4]) if len(clrt_s) >= 4 else "-"
        print("%-8s %4dms %4d %9.3f %10s %8.2f %5d/%-2d %4d/%-3d %10d %9d" %
              (mode, rms, len(valid), med(clrt), iqr, med(hold), byte_ok, len(valid), clean, len(valid), ack_rel, maxpass))
    print("-" * 96)
    print("CLRT_med: Formby CLRT median (ms). native ~= readiness; case-a should COLLAPSE to ~guard delta.")
    print("byte_ok/clean out of N; ACK_RELd = sum evstat ACK_RELEASED (case-a: ~N); MAXPASS must be 0.")


if __name__ == "__main__":
    main()

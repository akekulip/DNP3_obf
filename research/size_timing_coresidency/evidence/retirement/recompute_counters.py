#!/usr/bin/env python3
"""Recompute the Defense 4 lifecycle counters per mode, directly from the committed
per-block evidence dumps (ev_pre_*.json / ev_post_*.json), for the pre-fix and post-fix
campaigns. Nothing here reads a scorer summary or a prose report.

Usage:  python3 recompute_counters.py [DNP3_ROOT]

Emits, for each campaign and mode, the delta of the load-bearing counters:
  cf.RESP_HOLD_EARLY / cf.RESP_HOLD_LATE / cf.RESP_BYPASS  (RESPONSE disposition)
  cd.ACK_RELEASE / cd.ACK_REL_RETIRE                        (which ACK-release path ran)
  cd.RELEASE_DEADLINE / cd.RELEASE_FAILOPEN                 (held-RESPONSE release cause)
and the native-CLRT exceedance P(CLRT_native > D_A) that predicts the bypass fraction.
"""
import glob
import json
import os
import sys
import statistics as st

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/home/philip/Projects/DNP3"
EV = os.path.join(ROOT, "defense4/timing/evidence")

WANT_CF = ["ARM_FRESH", "ACK_HOLD", "RESP_HOLD_EARLY", "RESP_HOLD_LATE", "RESP_BYPASS",
           "RESP_DUP_SUPP", "UNSUP_SEG"]
WANT_CD = ["RELEASE_DEADLINE", "RELEASE_FAILOPEN", "ACK_RELEASE", "ACK_REL_RETIRE"]

CAMPAIGNS = [
    ("PRE-FIX  A (d6A, binary 0ec4e452)", "campaign_d6A_20260807T032304Z/ev_pre_A_%s_*.json",
     "campaign_d6A_20260807T032304Z/block_A_%s_*.json"),
    ("PRE-FIX  B (d6B, binary 0ec4e452)", "campaign_d6B_20260807T032904Z/ev_pre_B_%s_*.json",
     "campaign_d6B_20260807T032904Z/block_B_%s_*.json"),
    ("POST-FIX A (binary 97175e7d)", "final_run/campaignA_corrected_binary/ev_pre_CA_%s_*.json",
     "final_run/campaignA_corrected_binary/block_CA_%s_*.json"),
    ("POST-FIX B (binary 97175e7d)", "final_run/campaignB_corrected_binary_seed20260807/ev_pre_CB_%s_*.json",
     "final_run/campaignB_corrected_binary_seed20260807/block_CB_%s_*.json"),
]
MODES = ["OFF", "D1", "D2", "D3", "D4"]


def counters(pat):
    tot, n = {}, 0
    for f in sorted(glob.glob(os.path.join(EV, pat))):
        pre = json.load(open(f))
        post = json.load(open(f.replace("ev_pre", "ev_post")))
        n += 1
        for k in WANT_CF:
            d = post["cf"].get(k, 0) - pre["cf"].get(k, 0)
            if d:
                tot["cf." + k] = tot.get("cf." + k, 0) + d
        for k in WANT_CD:
            d = post["cd"].get(k, 0) - pre["cd"].get(k, 0)
            if d:
                tot["cd." + k] = tot.get("cd." + k, 0) + d
    return n, tot


def params(pat):
    for f in sorted(glob.glob(os.path.join(EV, pat))):
        b = json.load(open(f))
        return b.get("d_a_ms"), b.get("d_r_ms"), b.get("N")
    return None, None, None


def native_clrt():
    vals = []
    for pat in ("campaign_d6A_20260807T032304Z/block_A_OFF_*.json",
                "campaign_d6B_20260807T032904Z/block_B_OFF_*.json"):
        for f in glob.glob(os.path.join(EV, pat)):
            for r in json.load(open(f))["rows"]:
                if r.get("clrt_ms") is not None:
                    vals.append(r["clrt_ms"])
    return sorted(vals)


def segments():
    dist, tot = {}, 0
    for pat in ("campaign_*/block_*.json", "final_run/*/block_*.json"):
        for f in glob.glob(os.path.join(EV, pat)):
            try:
                rows = json.load(open(f))["rows"]
            except Exception:
                continue
            for r in rows:
                s = r.get("resp_segments")
                if s is not None:
                    dist[s] = dist.get(s, 0) + 1
                    tot += 1
    return dist, tot


def main():
    for name, evpat, blkpat in CAMPAIGNS:
        print("=== %s" % name)
        for m in MODES:
            n, tot = counters(evpat % m)
            da, dr, N = params(blkpat % m)
            print("  %-4s blocks=%d D_A=%s D_R=%s N=%s  %s" % (m, n, da, dr, N, tot))
        print()

    off = native_clrt()
    n = len(off)
    print("Native (OFF) CLRT, pre-fix campaigns A+B, n=%d:" % n)
    print("  median %.2f ms  p25 %.2f  p75 %.2f  p95 %.2f  max %.2f"
          % (st.median(off), off[n // 4], off[3 * n // 4], off[int(0.95 * n)], off[-1]))
    for thr in (0, 4, 8):
        k = sum(1 for x in off if x > thr)
        print("  P(CLRT_native > %d ms) = %d/%d = %.1f%%" % (thr, k, n, 100.0 * k / n))

    dist, tot = segments()
    print("\nresp_segments over every committed campaign row: %s (total %d)" % (dist, tot))


if __name__ == "__main__":
    main()

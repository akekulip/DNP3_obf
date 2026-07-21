#!/usr/bin/env python3
"""determine_queue_pattern.py — determine the TM-queue TIMING pattern from the SEL-751 pcap traces.

Step 1 of the queue work (Philip 2026-07-21): "run the pcap traces and determine the pattern for the
TM queue." This is the timing analogue of Ditto's offline pattern computation (NDSS'22 §V, eqn 2:
P_i = percentile_{(i+1)*100/L}(D)) applied to OUR data.

For Defense 2 (forward the ACK, delay the response) the TM queue holds the response and releases it at
`t_ack + G`, so the attacker-observed CLRT = G. The "pattern" is therefore an ordered set of TARGET
CLRT values (release gaps relative to the pure ACK). A response whose native readiness-relative-to-ACK
(= its native CLRT) is r is released at the smallest pattern slot >= r (monotone "next-larger" slot,
Ditto M3 — the queue can only ADD delay, never release before the response is ready); if r exceeds the
top slot it fails open (released at its natural readiness). The output CLRT then follows the pattern for
all but that fail-open tail.

Input distribution D = the native SEL-751 CLRT (ACK->response) distribution, pooled over BOTH real
captures (SEL751.pcap, SEL751L.pcap). Constraints:
  - floor  : a slot must be >= the native readiness it covers (else it is already late).
  - ceiling: every slot must stay < RTO_MIN - margin, or the outstation retransmits mid-hold.
             RTO_MIN measured ~207 ms (ASSUMPTIONS_AND_UNKNOWNS.md #12); margin default 20 ms.

Outputs candidate patterns (L=1 fixed, bounded band, Ditto L=3/L=6 percentile schedule) with the real
numbers, a recommended FIRST-implementation pattern (clearly labelled trace-derived, to be re-validated
on the physical SEL-751 at Phase 4.5/5.5), and a JSON the queue control plane can load.

Usage: $RESEARCH_PYTHON determine_queue_pattern.py \
         --pcap "/home/philip/Projects/DNP3/Traffic Trace/SEL751.pcap" \
         --pcap "/home/philip/Projects/DNP3/Traffic Trace/SEL751L.pcap" \
         [--rto-min-ms 207] [--margin-ms 20] [--json queue_pattern.json]
"""
import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sel751_extract import extract  # noqa: E402


def pctl(a, q):
    return float(np.percentile(a, q)) if len(a) else float("nan")


def describe(name, a):
    a = np.asarray(sorted(a), dtype=float)
    n = len(a)
    row = dict(name=name, n=n, min=float(a[0]), p25=pctl(a, 25), median=pctl(a, 50),
               p75=pctl(a, 75), p90=pctl(a, 90), p95=pctl(a, 95), p99=pctl(a, 99),
               max=float(a[-1]), mean=float(a.mean()), std=float(a.std(ddof=1)) if n > 1 else 0.0)
    print("  %-22s n=%d min=%.2f p25=%.2f p50=%.2f p75=%.2f p90=%.2f p95=%.2f p99=%.2f max=%.2f mean=%.2f std=%.2f"
          % (name, n, row["min"], row["p25"], row["median"], row["p75"], row["p90"],
             row["p95"], row["p99"], row["max"], row["mean"], row["std"]))
    return row


def ditto_pattern(D, L):
    """Ditto eqn (2): P_i = percentile_{(i+1)*100/L}(D), i=0..L-1. Ascending slot values (ms)."""
    return [round(pctl(D, (i + 1) * 100.0 / L), 3) for i in range(L)]


def assign_and_eval(D, slots, fail_open=True):
    """Assign each native CLRT r to smallest slot >= r; return (output_clrt list, fail_open count)."""
    out, fo = [], 0
    top = slots[-1]
    for r in D:
        if r > top:
            fo += 1
            if fail_open:
                out.append(r)          # released at natural readiness (cannot go back in time)
            continue
        out.append(next(s for s in slots if s >= r))
    return out, fo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", action="append", required=True, help="repeatable; SEL-751 capture(s)")
    ap.add_argument("--out", default="10.0.0.1")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--rto-min-ms", type=float, default=207.0)
    ap.add_argument("--margin-ms", type=float, default=20.0)
    ap.add_argument("--json")
    a = ap.parse_args()

    ceiling = a.rto_min_ms - a.margin_ms

    # --- pool the native CLRT distribution over all captures ---
    clrt_all, lat_all, per_cap = [], [], []
    for path in a.pcap:
        txns = extract(path, a.out, a.port)
        sep = [t for t in txns if t["separate_ack"] and t["native_clrt_ms"] is not None]
        clrt = [t["native_clrt_ms"] for t in sep]
        lat = [t["readiness_ms"] for t in txns]
        per_cap.append((os.path.basename(path), len(txns), len(sep)))
        clrt_all += clrt
        lat_all += lat
        print("=== %s: %d txns, %d separate-ACK w/ CLRT ===" % (os.path.basename(path), len(txns), len(sep)))
        describe("native CLRT (ms)", clrt)
        describe("readiness req->resp", lat)
        print()

    print("=== POOLED native SEL-751 distribution (both captures) ===")
    clrt_row = describe("native CLRT (ms)", clrt_all)
    lat_row = describe("readiness req->resp", lat_all)
    D = sorted(clrt_all)
    print("  RTO_MIN=%.0f ms  margin=%.0f ms  ->  slot ceiling < %.0f ms" % (a.rto_min_ms, a.margin_ms, ceiling))
    print("  max native CLRT = %.2f ms (a slot must reach this to cover every response without fail-open)" % D[-1])
    print()

    # --- candidate patterns ---
    patterns = {}

    # P-A fixed (L=1): one target G. Present coverage/latency for p90/p95/p99/max.
    print("=== P-A  FIXED single target G (output CLRT = G for all covered; tail fails open) ===")
    fixed = {}
    for tag, g in [("p90", clrt_row["p90"]), ("p95", clrt_row["p95"]),
                   ("p99", clrt_row["p99"]), ("max", clrt_row["max"])]:
        g = round(g, 3)
        out, fo = assign_and_eval(D, [g])
        cov = 100.0 * (len(D) - fo) / len(D)
        safe = g < ceiling
        print("   G=%-8.3f (=%s)  covers %.1f%% (fail-open tail=%d)  added-latency@median=%.2f ms  RTO-safe=%s"
              % (g, tag, cov, fo, g - clrt_row["median"], safe))
        fixed[tag] = dict(G_ms=g, coverage_pct=round(cov, 2), fail_open=fo, rto_safe=safe)
    patterns["P_A_fixed"] = fixed
    print()

    # P-B bounded band: [p50, p95] common band (values a device-independent policy could draw from).
    band = [round(clrt_row["median"], 3), round(clrt_row["p95"], 3)]
    print("=== P-B  BOUNDED band [low, high] = [%.3f, %.3f] ms  (draw target from this common band) ==="
          % (band[0], band[1]))
    print("   band max %.3f ms  RTO-safe=%s" % (band[1], band[1] < ceiling))
    patterns["P_B_bounded"] = dict(low_ms=band[0], high_ms=band[1], rto_safe=band[1] < ceiling)
    print()

    # P-C Ditto-style repeating schedule (L=3, L=6): percentile slots, monotone next-slot assignment.
    for L in (3, 6):
        slots = ditto_pattern(D, L)
        out, fo = assign_and_eval(D, slots)
        out = np.asarray(out)
        cov = 100.0 * (len(D) - fo) / len(D)
        top_safe = slots[-1] < ceiling
        print("=== P-C  DITTO L=%d schedule  slots(ms)=%s ===" % (L, slots))
        print("   next-slot assignment: output CLRT mean=%.2f median=%.2f max=%.2f  fail-open tail=%d (%.1f%% covered)  top-slot RTO-safe=%s"
              % (out.mean(), float(np.median(out)), out.max(), fo, cov, top_safe))
        print("   added latency vs native: mean +%.2f ms (median native CLRT %.2f -> shaped)"
              % (out.mean() - np.mean(D), clrt_row["median"]))
        patterns["P_C_ditto_L%d" % L] = dict(
            slots_ms=slots, coverage_pct=round(cov, 2), fail_open=fo,
            out_clrt_mean_ms=round(float(out.mean()), 3), out_clrt_median_ms=round(float(np.median(out)), 3),
            top_slot_rto_safe=top_safe)
        print()

    # --- recommended FIRST-implementation pattern (trace-derived; re-validate on physical device) ---
    rec_g = round(clrt_row["p99"], 3)
    rec = dict(policy="P-A fixed (calibration/first-impl)", G_ms=rec_g,
               rationale="covers p99 of the pooled native CLRT, stays well under RTO ceiling; "
                         "simplest to implement + measure first; NOT the final defensible policy",
               coverage_pct=patterns["P_A_fixed"]["p99"]["coverage_pct"],
               rto_safe=rec_g < ceiling)
    print("=== RECOMMENDED first-implementation pattern (trace-derived, caveated) ===")
    print("   %s  G=%.3f ms  coverage=%.1f%%  RTO-safe=%s" % (rec["policy"], rec_g, rec["coverage_pct"], rec["rto_safe"]))
    print("   NOTE: this is a FIRST pattern to implement+measure the queue with; the final defensible")
    print("   policy is chosen at Phase 4.5/5.5 using the microbench precision + the PHYSICAL SEL-751")
    print("   readiness distribution (do NOT reuse a trace-derived constant as the final policy).")

    if a.json:
        out = dict(source_captures=[dict(name=n, txns=t, sep_ack=s) for (n, t, s) in per_cap],
                   pooled_native_clrt_ms=clrt_row, pooled_readiness_ms=lat_row,
                   rto_min_ms=a.rto_min_ms, margin_ms=a.margin_ms, slot_ceiling_ms=ceiling,
                   patterns=patterns, recommended_first_impl=rec)
        json.dump(out, open(a.json, "w"), indent=2)
        print("\n  pattern -> %s" % a.json)


if __name__ == "__main__":
    main()

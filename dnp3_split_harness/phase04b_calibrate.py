#!/usr/bin/env python3
"""phase04b_calibrate.py -- DCRN target calibration from the authoritative native PCAPs (spec sec 5).

Computes, for the eligible transaction class (routine solicited READ, function code 1), the
request->response *readiness* distribution per device profile and pooled across profiles, split into
first-in-connection vs non-first transactions, with the full quantile set the spec requires
(min/median/mean/std/p90/p95/p99/p99.9/max). From the pooled distribution and the measured effective
TCP RTO it derives a safe common target window:

    Dlow  >= pooled p99.9 readiness + scheduler_guard      (hide native speed for ~all transactions)
    Dhigh <  effective RTO - rto_safety_guard              (a hold never risks a retransmission)

Native tails above Dlow are RETAINED and reported as expected deadline misses (spec sec 5) -- never
silently discarded. No target is hard-coded; every number is derived here from the real captures.

Outputs: reports/phases/phase_04b_dual_case_timing/{calibration.json, calibration.md,
tables/phase04b_target_calibration.csv}
"""
from __future__ import annotations
import csv
import json
import os
import sys

import numpy as np

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
import characterize_ack_traces as C

TRAFFIC = "/home/philip/Projects/DNP3/Traffic Trace"
PCAPS = ["SEL751.pcap", "SEL751L.pcap", "AB1400.pcap", "AB1400L.pcap", "ION7550.pcap", "ION7550L.pcap"]
READ_FC = 1                         # routine solicited READ request function code
EFFECTIVE_RTO_MS = 211.0            # measured via rto_probe.py (TCP_RTO_MIN); re-measure on Vision (PI)
RTO_SAFETY_GUARD_MS = 60.0          # keep Dhigh well under RTO
SCHEDULER_GUARD_MS = 3.0            # provisional; re-derive from a real scheduler calibration run (PI)
OUT = os.path.join(HARNESS, "reports", "phases", "phase_04b_dual_case_timing")

Q = [("count", None), ("min", 0), ("median", 50), ("mean", "mean"), ("std", "std"),
     ("p90", 90), ("p95", 95), ("p99", 99), ("p99_9", 99.9), ("max", 100)]


def quantiles(vals):
    a = np.asarray([v for v in vals if v is not None], dtype=float)
    out = {"count": int(a.size)}
    if a.size == 0:
        return {k: (0 if k == "count" else None) for k, _ in Q}
    for name, q in Q:
        if name == "count":
            continue
        if q == "mean":
            out[name] = round(float(a.mean()), 4)
        elif q == "std":
            out[name] = round(float(a.std(ddof=0)), 4)
        else:
            out[name] = round(float(np.percentile(a, q)), 4)
    return out


def collect():
    """Per profile: readiness (req->resp), req->pure-ack, pure-ack->resp, split first/non-first, READ only."""
    profiles = {}
    for name in PCAPS:
        dev = C.device_from_pcap(name)
        ip = C.DEVICE_OUTSTATION_IP[dev]
        packets = C.run_tshark(os.path.join(TRAFFIC, name))
        txns = C.build_transactions(packets, name, dev)
        first = {}
        for t in txns:
            if t.stream not in first or t.req_frame < first[t.stream]:
                first[t.stream] = t.req_frame
        p = profiles.setdefault(dev, {"readiness": {"first": [], "nonfirst": []},
                                      "req_to_ack": [], "ack_to_resp": [],
                                      "ack_mode": {"SEPARATE": 0, "COMBINED": 0}, "n_read": 0})
        for t in txns:
            if t.outstation_ip != ip:
                continue
            if t.classification not in (C.CLS_COMBINED, C.CLS_SEPARATE):
                continue
            if t.req_func != READ_FC:
                continue
            p["n_read"] += 1
            bucket = "first" if t.req_frame == first[t.stream] else "nonfirst"
            if t.req_to_resp_ms is not None:
                p["readiness"][bucket].append(t.req_to_resp_ms)
            p["ack_mode"]["SEPARATE" if t.classification == C.CLS_SEPARATE else "COMBINED"] += 1
            if t.first_rev_is_pure_ack:
                if t.req_to_ack_ms is not None:
                    p["req_to_ack"].append(t.req_to_ack_ms)
                if t.ack_to_resp_ms is not None:
                    p["ack_to_resp"].append(t.ack_to_resp_ms)
    return profiles


def main():
    os.makedirs(os.path.join(OUT, "tables"), exist_ok=True)
    profiles = collect()

    pooled = {"first": [], "nonfirst": []}
    per_profile = {}
    for dev, p in profiles.items():
        pooled["first"] += p["readiness"]["first"]
        pooled["nonfirst"] += p["readiness"]["nonfirst"]
        allr = p["readiness"]["first"] + p["readiness"]["nonfirst"]
        per_profile[dev] = {
            "ack_mode": p["ack_mode"], "n_read": p["n_read"],
            "readiness_all": quantiles(allr),
            "readiness_first": quantiles(p["readiness"]["first"]),
            "readiness_nonfirst": quantiles(p["readiness"]["nonfirst"]),
            "req_to_pure_ack": quantiles(p["req_to_ack"]),
            "pure_ack_to_resp": quantiles(p["ack_to_resp"]),
        }
    pooled_all = quantiles(pooled["first"] + pooled["nonfirst"])
    pooled_first = quantiles(pooled["first"])
    pooled_nonfirst = quantiles(pooled["nonfirst"])

    # Target window derivation
    p99_9 = pooled_all["p99_9"]
    dlow_ideal = round(p99_9 + SCHEDULER_GUARD_MS, 2)
    dhigh = round(EFFECTIVE_RTO_MS - RTO_SAFETY_GUARD_MS, 2)
    # deadline-miss projection if we picked Dlow = p99 (a defensible high quantile below the extreme tail)
    dlow_p99 = round(pooled_all["p99"] + SCHEDULER_GUARD_MS, 2)
    allvals = np.asarray(pooled["first"] + pooled["nonfirst"], dtype=float)
    miss_ideal = float((allvals > dlow_ideal).mean()) if allvals.size else None
    miss_p99 = float((allvals > dlow_p99).mean()) if allvals.size else None
    feasible = dlow_ideal < dhigh

    recommendation = {
        "eligible_class": "routine_solicited_read (req_func=1)",
        "effective_rto_ms": EFFECTIVE_RTO_MS,
        "rto_source": "rto_probe.py (TCP_RTO_MIN); MUST be re-measured on the Vision master before rig runs",
        "scheduler_guard_ms": SCHEDULER_GUARD_MS,
        "scheduler_guard_source": "PROVISIONAL; re-derive from a real fq/EDT scheduler calibration run (PI-run, sudo)",
        "rto_safety_guard_ms": RTO_SAFETY_GUARD_MS,
        "pooled_p99_ms": pooled_all["p99"], "pooled_p99_9_ms": p99_9, "pooled_max_ms": pooled_all["max"],
        "Dhigh_ms": dhigh,
        "Dlow_if_cover_p99_9_ms": dlow_ideal, "deadline_miss_rate_if_p99_9": round(miss_ideal, 6) if miss_ideal is not None else None,
        "Dlow_if_cover_p99_ms": dlow_p99, "deadline_miss_rate_if_p99": round(miss_p99, 6) if miss_p99 is not None else None,
        "window_feasible_p99_9": feasible,
        "recommended_P1_FIXED_target_ms": dlow_ideal if feasible else dhigh,
        "recommended_P2_BOUNDED_ms": [dlow_ideal, min(round(dlow_ideal + 10, 2), dhigh)] if feasible else None,
        "note": ("Targets DERIVED from data, not hard-coded. Covering pooled p99.9 (%.2f ms) leaves a "
                 "deadline-miss rate of %.4f%%; the residual tail (chiefly the SEL-751 slow responses up "
                 "to %.1f ms) is RETAINED and passed native as a reported deadline miss, never discarded."
                 % (p99_9, (miss_ideal or 0) * 100, pooled_all["max"])),
    }

    result = {
        "eligible_class": "routine_solicited_read (req_func=1)",
        "source_pcaps": PCAPS,
        "per_profile": per_profile,
        "pooled_readiness": {"all": pooled_all, "first": pooled_first, "nonfirst": pooled_nonfirst},
        "target_recommendation": recommendation,
        "policy_invariant": "target depends only on the public transaction class + experiment seed; NEVER on device/size/native-mode/native-time.",
    }
    with open(os.path.join(OUT, "calibration.json"), "w") as fh:
        json.dump(result, fh, indent=2)

    # CSV table
    with open(os.path.join(OUT, "tables", "phase04b_target_calibration.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scope", "metric", "count", "min", "median", "mean", "std", "p90", "p95", "p99", "p99_9", "max"])
        def row(scope, metric, d):
            w.writerow([scope, metric] + [d.get(k) for k in ["count", "min", "median", "mean", "std", "p90", "p95", "p99", "p99_9", "max"]])
        for dev, pp in per_profile.items():
            row(dev, "readiness_all", pp["readiness_all"])
            row(dev, "readiness_first", pp["readiness_first"])
            row(dev, "readiness_nonfirst", pp["readiness_nonfirst"])
            if pp["req_to_pure_ack"]["count"]:
                row(dev, "req_to_pure_ack", pp["req_to_pure_ack"])
                row(dev, "pure_ack_to_resp", pp["pure_ack_to_resp"])
        row("POOLED", "readiness_all", pooled_all)
        row("POOLED", "readiness_first", pooled_first)
        row("POOLED", "readiness_nonfirst", pooled_nonfirst)

    # Markdown
    L = ["# Phase 04B — DCRN Target Calibration\n",
         "_Derived from the six authoritative device PCAPs; eligible class = routine solicited READ "
         "(function code 1). No target is hard-coded; every value below comes from the real captures._\n",
         "## Effective RTO and guards",
         "- Measured effective TCP RTO: **%.0f ms** (`rto_probe.py`, TCP_RTO_MIN). **Must be re-measured "
         "on the Vision master before the rig runs.**" % EFFECTIVE_RTO_MS,
         "- Scheduler guard: **%.1f ms** (PROVISIONAL — re-derive from a real fq/EDT calibration run)." % SCHEDULER_GUARD_MS,
         "- RTO safety guard: **%.1f ms** → **Dhigh < %.1f ms**.\n" % (RTO_SAFETY_GUARD_MS, dhigh),
         "## Pooled request→response readiness (all three profiles, READ class)\n",
         "| bucket | n | median | p90 | p95 | p99 | p99.9 | max |",
         "|---|--:|--:|--:|--:|--:|--:|--:|"]
    for b, d in (("all", pooled_all), ("first-in-connection", pooled_first), ("non-first", pooled_nonfirst)):
        L.append("| %s | %d | %.2f | %.2f | %.2f | %.2f | %.2f | %.2f |" %
                 (b, d["count"], d["median"], d["p90"], d["p95"], d["p99"], d["p99_9"], d["max"]))
    L.append("\n## Per-profile readiness (median / p99 / max, ms) and ACK mode\n")
    L.append("| profile | READ txns | ACK mode | median | p99 | max |")
    L.append("|---|--:|---|--:|--:|--:|")
    for dev, pp in per_profile.items():
        r = pp["readiness_all"]; am = pp["ack_mode"]
        mode = "separate" if am["SEPARATE"] > am["COMBINED"] else "combined"
        L.append("| %s | %d | %s (%d sep / %d comb) | %.2f | %.2f | %.2f |" %
                 (dev, pp["n_read"], mode, am["SEPARATE"], am["COMBINED"], r["median"], r["p99"], r["max"]))
    rec = recommendation
    L += ["\n## Derived target window\n",
          "- Pooled **p99 = %.2f ms**, **p99.9 = %.2f ms**, **max = %.2f ms**." % (pooled_all["p99"], p99_9, pooled_all["max"]),
          "- **Cover p99.9:** Dlow = p99.9 + guard = **%.2f ms** → deadline-miss rate **%.4f%%**." % (rec["Dlow_if_cover_p99_9_ms"], (miss_ideal or 0) * 100),
          "- **Cover p99:** Dlow = p99 + guard = **%.2f ms** → deadline-miss rate **%.4f%%**." % (rec["Dlow_if_cover_p99_ms"], (miss_p99 or 0) * 100),
          "- **Window feasible below RTO:** %s (Dlow %.2f < Dhigh %.2f)." % (feasible, rec["Dlow_if_cover_p99_9_ms"], dhigh),
          "\n**Recommendation:** P1_FIXED target **%s ms**; P2_COMMON_BOUNDED **%s ms** — one distribution "
          "for every profile, seeded, never device-dependent. The residual tail above the target "
          "(chiefly SEL-751 slow responses up to %.1f ms) is retained and passed native as a **reported "
          "deadline miss**." % (rec["recommended_P1_FIXED_target_ms"], rec["recommended_P2_BOUNDED_ms"], pooled_all["max"]),
          "\n```\nSTOP: calibration only. Targets derived, not yet applied. eBPF DCRN implementation + PI-run wire campaign pending.\n```"]
    with open(os.path.join(OUT, "calibration.md"), "w") as fh:
        fh.write("\n".join(L) + "\n")

    print("pooled readiness (all): median=%.2f p99=%.2f p99.9=%.2f max=%.2f  n=%d"
          % (pooled_all["median"], pooled_all["p99"], p99_9, pooled_all["max"], pooled_all["count"]))
    print("Dhigh=%.1f  Dlow(p99.9)=%.2f miss=%.4f%%  Dlow(p99)=%.2f miss=%.4f%%  feasible=%s"
          % (dhigh, rec["Dlow_if_cover_p99_9_ms"], (miss_ideal or 0) * 100,
             rec["Dlow_if_cover_p99_ms"], (miss_p99 or 0) * 100, feasible))
    print("recommended P1_FIXED=%s ms  P2_BOUNDED=%s ms" % (rec["recommended_P1_FIXED_target_ms"], rec["recommended_P2_BOUNDED_ms"]))
    print("wrote calibration.{json,md} + tables/phase04b_target_calibration.csv")


if __name__ == "__main__":
    main()

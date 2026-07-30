#!/usr/bin/env python3
"""
analyze_check2.py — score CHECK 2, PRODUCTION BLOCKER-START LATENCY.

`meeting_direction.md` (2026-07-29) forbids delaying the synthetic ACK to let the
reservoir start until it is known whose latency the ~1 ms observed in the first working
Gate 2 is. This file turns the `--check2` manifests into that verdict.

THE DIRECTION'S DECISION RULE, implemented literally:

  * production full-reservoir startup SAFELY BELOW the physical ACK floor
        -> the 1 ms is a SYNTHETIC-HARNESS SCHEDULING ERROR; correct the synthetic
           event schedule.
  * production startup NEAR 1 ms
        -> ARCHITECTURE FAILURE. Do not hide it by scheduling the ACK later; go
           microbenchmark a faster Tofino-only trigger.

"Safely below" is not left to judgement. Two independent bars, both required:
  (a) every clean trial's READ-to-full-reservoir is under the pre-registered
      CONSENSUS R2 bound of 100 us — the bound that already exists for this exact
      quantity, chosen before any of these numbers were seen; and
  (b) the MAXIMUM is under the physical READ->ACK MINIMUM (~0.400 ms), because the
      reservoir has to be standing before the EARLIEST protected ACK, not before the
      median one.

STDLIB ONLY. Touches no hardware.

    python3 analysis/analyze_check2.py <check2.json> [...]
    python3 analysis/analyze_check2.py --self-test
"""

import argparse
import glob
import json
import os
import sys

TWO32 = 1 << 32
TWO31 = 1 << 31

R2_BOUND_NS = 100000          # CONSENSUS §7 R2, pre-registered
ACK_FLOOR_NS = 400000         # measured physical READ->ACK MINIMUM
ACK_MEDIAN_NS = 505000        # measured physical READ->ACK median
NEAR_1MS_NS = 500000          # at or above this, the direction's "near 1 ms" branch

K_DEFAULT = 64


def dt(a, b):
    """b - a as a SIGNED 32-bit ns difference (the instrument wraps every ~4.295 s).
    ZERO IS A SENTINEL, NOT AN INSTANT: every timestamp register in the program is
    write-if-zero, so 0 means 'this never happened' and must not be differenced."""
    if a in (None, 0) or b in (None, 0):
        return None
    return ((int(b) - int(a) + TWO31) % TWO32) - TWO31


def pct(vals, p):
    """Nearest-rank percentile on a sorted copy. No interpolation: with 100 samples
    an interpolated p99 invents a value between the two largest, and the whole point
    of p99 here is to be an OBSERVED number."""
    if not vals:
        return None
    s = sorted(vals)
    if p <= 0:
        return s[0]
    if p >= 100:
        return s[-1]
    import math
    idx = int(math.ceil(p / 100.0 * len(s))) - 1
    return s[max(0, min(len(s) - 1, idx))]


def stats(vals):
    if not vals:
        return {"n": 0}
    s = sorted(vals)
    n = len(s)
    med = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0
    return {"n": n, "min": s[0], "median": med, "p95": pct(s, 95),
            "p99": pct(s, 99), "max": s[-1],
            "mean": sum(s) / float(n)}


def _g(d, *path, **kw):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return kw.get("default")
        cur = cur[p]
    return cur


def score_trial(t, k=K_DEFAULT):
    """Derive one trial's intervals and decide whether it is CLEAN.

    A trial is clean only if it fired EXACTLY once and admitted exactly K tokens.
    Anything else is excluded from the statistics and reported separately — the
    direction asks for 100 CLEAN trials, and silently averaging a double-fire in
    would be the same class of error as the harness fault under investigation."""
    r = t.get("registers", {}) or {}
    cf = _g(t, "counters", "fresh", default={}) or {}
    cd = _g(t, "counters", "deq", default={}) or {}
    ab = t.get("app_block", {}) or {}
    ae = t.get("app_event", {}) or {}

    d = {
        "index": t.get("index"),
        "t_read": r.get("reg_ts_read"),
        "t_clone": r.get("reg_ts_clone"),
        "t_first_block": r.get("reg_ts_first_block"),
        "t_last_block": r.get("reg_ts_last_block"),
        "reg_tag_after": r.get("reg_tag"),
    }
    d["read_to_clone_ns"] = dt(d["t_read"], d["t_clone"])
    d["clone_to_first_ns"] = dt(d["t_clone"], d["t_first_block"])
    d["read_to_first_ns"] = dt(d["t_read"], d["t_first_block"])
    d["read_to_full_ns"] = dt(d["t_read"], d["t_last_block"])
    d["burst_span_ns"] = dt(d["t_first_block"], d["t_last_block"])

    d["admitted"] = cf.get("PKTGEN_ADMIT")
    d["dropped"] = cf.get("PKTGEN_DROP")
    d["arm_fresh"] = cf.get("ARM_FRESH")
    d["arm_dup"] = cf.get("ARM_DUP")
    d["arm_busy"] = cf.get("ARM_BUSY")
    d["clone_seen"] = cf.get("CLONE_SEEN")
    d["bad_port"] = cf.get("BAD_PORT")
    d["block_trigger"] = ab.get("trigger_counter")
    d["block_batch"] = ab.get("batch_counter")
    d["block_pkts"] = ab.get("pkt_counter")
    d["event_pkts"] = ae.get("pkt_counter")
    d["event_trigger"] = ae.get("trigger_counter")
    d["term_stale"] = cd.get("BLOCK_TERM_STALE")
    d["term_dl"] = cd.get("BLOCK_TERM_DL")
    d["term_tmo"] = cd.get("BLOCK_TERM_TMO")
    qd = []
    for qn, q in (t.get("queues", {}) or {}).items():
        if isinstance(q, dict):
            qd.append((qn, q.get("drop_count_packets")))
    d["queue_drops"] = qd

    why = []
    if t.get("error"):
        why.append("harness error: %s" % t["error"])
    if t.get("n_fail_config"):
        why.append("%d failed configuration check(s)" % t["n_fail_config"])
    if d["arm_fresh"] != 1 or d["arm_dup"] or d["arm_busy"]:
        why.append("ARM_FRESH=%s DUP=%s BUSY=%s"
                   % (d["arm_fresh"], d["arm_dup"], d["arm_busy"]))
    if d["block_trigger"] != 1 or d["block_batch"] != 1:
        why.append("app1 trigger=%s batch=%s (want 1/1)"
                   % (d["block_trigger"], d["block_batch"]))
    if d["block_pkts"] != k:
        why.append("app1 pkt_counter=%s (want %d)" % (d["block_pkts"], k))
    if d["admitted"] != k or d["dropped"]:
        why.append("admitted=%s dropped=%s (want %d/0)"
                   % (d["admitted"], d["dropped"], k))
    if d["clone_seen"] != 1:
        why.append("CLONE_SEEN=%s (want 1)" % d["clone_seen"])
    if d["bad_port"]:
        why.append("BAD_PORT=%s (off-topology packet)" % d["bad_port"])
    if any(v not in (0, None) for _q, v in qd):
        why.append("queue drops %s" % qd)
    for nm in ("read_to_first_ns", "read_to_full_ns"):
        if d[nm] is None:
            why.append("%s indeterminate (a timestamp was never written)" % nm)
        elif d[nm] < 0:
            why.append("%s is NEGATIVE (%s)" % (nm, d[nm]))
    d["clean"] = not why
    d["excluded_because"] = why
    return d


def score_arm(arm, k=K_DEFAULT):
    trials = [score_trial(t, k) for t in arm.get("trial_records", [])]
    clean = [t for t in trials if t["clean"]]
    out = {
        "arm": arm.get("arm"), "why": arm.get("why"),
        "n_events": arm.get("n_events"), "ipg_ns": arm.get("ipg_ns"),
        "trials_run": len(trials), "trials_clean": len(clean),
        "excluded": [{"index": t["index"], "because": t["excluded_because"]}
                     for t in trials if not t["clean"]],
        "read_to_first_ns": stats([t["read_to_first_ns"] for t in clean]),
        "read_to_full_ns": stats([t["read_to_full_ns"] for t in clean]),
        "read_to_clone_ns": stats([t["read_to_clone_ns"] for t in clean
                                   if t["read_to_clone_ns"] is not None]),
        "clone_to_first_ns": stats([t["clone_to_first_ns"] for t in clean
                                    if t["clone_to_first_ns"] is not None]),
        "burst_span_ns": stats([t["burst_span_ns"] for t in clean
                                if t["burst_span_ns"] is not None]),
    }
    # first-trial-after-load vs warm: the direction asks for them separately, because
    # a cold first trial is exactly where a one-off setup cost would hide.
    if clean:
        first = [t for t in clean if t["index"] == 0]
        warm = [t for t in clean if t["index"] != 0]
        out["cold_first_trial"] = ({"read_to_first_ns": first[0]["read_to_first_ns"],
                                    "read_to_full_ns": first[0]["read_to_full_ns"]}
                                   if first else None)
        out["warm_trials"] = {
            "read_to_first_ns": stats([t["read_to_first_ns"] for t in warm]),
            "read_to_full_ns": stats([t["read_to_full_ns"] for t in warm]),
        }
    out["packets"] = {
        "app1_pkt_counter": sorted({t["block_pkts"] for t in trials}),
        "admitted": sorted({t["admitted"] for t in trials}),
        "app2_pkt_counter": sorted({t["event_pkts"] for t in trials}),
        "terminations": {
            "stale": sorted({t["term_stale"] for t in trials}),
            "deadline": sorted({t["term_dl"] for t in trials}),
            "budget_failopen": sorted({t["term_tmo"] for t in trials}),
        },
    }
    out["queue_drops_all_zero"] = all(
        v in (0, None) for t in trials for _q, v in t["queue_drops"])
    # the fail-open retire, observed: with no ACK every trial must end idle. This is
    # the silicon confirmation of the CHECK 1 TAG_NO_WRITE repair.
    out["reg_tag_after_values"] = sorted({t["reg_tag_after"] for t in trials})
    return out


def verdict(prod, ack_floor_ns=ACK_FLOOR_NS, r2_bound_ns=R2_BOUND_NS):
    """The direction's branch, applied to the production arm."""
    full = prod.get("read_to_full_ns", {})
    if not full.get("n"):
        return ("INDETERMINATE",
                "no clean production trial produced a full-reservoir interval")
    mx, p99 = full["max"], full["p99"]
    if mx >= NEAR_1MS_NS:
        return ("ARCHITECTURE_FAILURE",
                "READ-to-full-reservoir max = %d ns, at or above the %d ns 'near "
                "1 ms' threshold. The direction is explicit: do NOT hide this by "
                "scheduling the synthetic ACK later. Microbenchmark a faster "
                "Tofino-only trigger." % (mx, NEAR_1MS_NS))
    if mx >= ack_floor_ns:
        return ("ARCHITECTURE_FAILURE",
                "READ-to-full-reservoir max = %d ns, which does NOT beat the "
                "physical READ->ACK MINIMUM of %d ns. The reservoir must stand "
                "before the EARLIEST protected ACK." % (mx, ack_floor_ns))
    if mx >= r2_bound_ns:
        return ("MARGINAL",
                "READ-to-full-reservoir max = %d ns beats the %d ns ACK floor but "
                "exceeds the pre-registered R2 bound of %d ns. Not a harness "
                "verdict and not an architecture verdict: report both and decide "
                "explicitly." % (mx, ack_floor_ns, r2_bound_ns))
    return ("HARNESS_SCHEDULING_ERROR",
            "READ-to-full-reservoir max = %d ns and p99 = %d ns, both under the "
            "pre-registered R2 bound of %d ns and %.0fx under the physical "
            "READ->ACK minimum of %d ns. The production trigger chain is NOT the "
            "source of the 1 ms; the synthetic event schedule is. Correct the "
            "schedule." % (mx, p99, r2_bound_ns, ack_floor_ns / float(max(mx, 1)),
                           ack_floor_ns))


def attribution(prod, batches):
    """Convict or acquit the harness EXPLICITLY rather than by elimination.

    If READ-to-first-blocker in the 3-event arms tracks 2*ipg — the SPAN of app 2's
    batch — while the 1-event arm is microseconds, then the generator does not start
    app 1's triggered batch until app 2's batch has finished, and the 1 ms was the
    batch span. Two ipg points are what separates that from a constant offset."""
    lines = []
    pf = prod.get("read_to_first_ns", {})
    rows = []
    for b in batches:
        s = b.get("read_to_first_ns", {})
        if not s.get("n"):
            continue
        span = 2 * int(b["ipg_ns"])          # READ at t0, last event at t0 + 2*ipg
        rows.append((b["ipg_ns"], span, s["median"], s["min"], s["max"]))
    if not rows or not pf.get("n"):
        return {"conclusive": False, "rows": rows,
                "note": "not enough clean trials in both arm types to attribute"}
    tracks = all(abs(med - span) < max(20000, 0.05 * span)
                 for _ipg, span, med, _mn, _mx in rows)
    ratio = (min(med for _i, _s, med, _m, _x in rows) / float(max(pf["median"], 1)))
    return {
        "conclusive": bool(tracks),
        "rows": [{"ipg_ns": i, "batch_span_ns": s, "median_read_to_first_ns": m,
                  "min": mn, "max": mx} for i, s, m, mn, mx in rows],
        "production_median_ns": pf["median"],
        "slowdown_vs_production": round(ratio, 1),
        "note": ("READ-to-first-blocker tracks 2*ipg (the batch span) in every "
                 "3-event arm while the 1-event arm is %d ns: the generator will not "
                 "start app 1's triggered batch until app 2's batch has finished, so "
                 "the 1 ms belonged to the harness schedule."
                 % pf["median"]) if tracks else
                ("READ-to-first-blocker does NOT track the batch span, so batch "
                 "occupancy is not the explanation and the latency must be "
                 "attributed elsewhere before the schedule is changed."),
    }


def render(rec, args):
    k = _g(rec, "params", "k", default=K_DEFAULT)
    c2 = rec.get("check2") or {}
    arms = [score_arm(a, k) for a in c2.get("arms", [])]
    prod = next((a for a in arms if a["arm"] == "production"), None)
    batches = [a for a in arms if a["arm"] != "production"]

    L = []
    L.append("=" * 78)
    L.append("CHECK 2 — PRODUCTION BLOCKER-START LATENCY")
    L.append("=" * 78)
    L.append("physical baseline: READ->ACK minimum %d ns, median %d ns"
             % (c2.get("physical_ack_floor_ns", ACK_FLOOR_NS),
                c2.get("physical_ack_median_ns", ACK_MEDIAN_NS)))
    L.append("fail-open horizon H = B*K/rate = %s ns; per-trial dwell %s s"
             % (c2.get("failopen_horizon_ns"), c2.get("wait_s")))
    L.append("")

    for a in arms:
        L.append("-" * 78)
        L.append("ARM %s   (n_events=%s, ipg=%s ns)   %d/%d clean"
                 % (a["arm"], a["n_events"], a["ipg_ns"],
                    a["trials_clean"], a["trials_run"]))
        if a["why"]:
            L.append("  purpose: %s" % a["why"])
        for name, label in (("read_to_clone_ns", "READ -> clone (t_pktgen_trigger)"),
                            ("clone_to_first_ns", "clone -> first blocker"),
                            ("read_to_first_ns", "READ -> FIRST blocker"),
                            ("read_to_full_ns", "READ -> FULL reservoir"),
                            ("burst_span_ns", "burst span (first -> last)")):
            s = a[name]
            if not s.get("n"):
                L.append("  %-34s (no clean samples)" % label)
                continue
            L.append("  %-34s n=%-4d min %9.0f  med %9.0f  p95 %9.0f  "
                     "p99 %9.0f  max %9.0f"
                     % (label, s["n"], s["min"], s["median"], s["p95"],
                        s["p99"], s["max"]))
        if a.get("cold_first_trial"):
            cf = a["cold_first_trial"]
            wm = a["warm_trials"]["read_to_full_ns"]
            L.append("  first trial after load: READ->first %s ns, READ->full %s ns"
                     % (cf["read_to_first_ns"], cf["read_to_full_ns"]))
            L.append("  warm trials:            READ->full median %s ns, max %s ns"
                     % (wm.get("median"), wm.get("max")))
        L.append("  packets: app1 pkt_counter %s, admitted %s, app2 pkt_counter %s"
                 % (a["packets"]["app1_pkt_counter"], a["packets"]["admitted"],
                    a["packets"]["app2_pkt_counter"]))
        L.append("  terminations: stale %s, deadline %s, budget/fail-open %s"
                 % (a["packets"]["terminations"]["stale"],
                    a["packets"]["terminations"]["deadline"],
                    a["packets"]["terminations"]["budget_failopen"]))
        L.append("  queue drops all zero: %s   reg_tag after trial: %s"
                 % (a["queue_drops_all_zero"], a["reg_tag_after_values"]))
        if a["excluded"]:
            L.append("  EXCLUDED %d trial(s):" % len(a["excluded"]))
            for e in a["excluded"][:8]:
                L.append("    #%s: %s" % (e["index"], "; ".join(e["because"])[:150]))
    L.append("-" * 78)

    att = attribution(prod or {}, batches)
    L.append("ATTRIBUTION")
    for r in att.get("rows", []):
        L.append("  ipg %7d ns -> batch span %7d ns, READ->first median %9d ns"
                 % (r["ipg_ns"], r["batch_span_ns"],
                    r["median_read_to_first_ns"]))
    L.append("  %s" % att["note"])
    L.append("")

    v, why = verdict(prod or {},
                     c2.get("physical_ack_floor_ns", ACK_FLOOR_NS),
                     args.r2_bound_ns)
    L.append("=" * 78)
    L.append("VERDICT: %s" % v)
    L.append("  %s" % why)
    L.append("=" * 78)
    return "\n".join(L), {"arms": arms, "attribution": att,
                          "verdict": v, "verdict_reason": why}


def self_test():
    """Controls for the decision rule. A verdict function that cannot say
    ARCHITECTURE_FAILURE is not a decision rule."""
    def arm(vals, ipg=500000, n=1, name="production"):
        return {"arm": name, "n_events": n, "ipg_ns": ipg, "why": "",
                "trial_records": [
                    {"index": i,
                     "registers": {"reg_ts_read": 1000, "reg_ts_clone": 1000 + 400,
                                   "reg_ts_first_block": 1000 + v // 2,
                                   "reg_ts_last_block": 1000 + v,
                                   "reg_tag": 0x00, "reg_deadline": 0},
                     "counters": {"fresh": {"PKTGEN_ADMIT": 64, "PKTGEN_DROP": 0,
                                            "ARM_FRESH": 1, "ARM_DUP": 0,
                                            "ARM_BUSY": 0, "CLONE_SEEN": 1,
                                            "BAD_PORT": 0},
                                  "deq": {"BLOCK_TERM_STALE": 0, "BLOCK_TERM_DL": 0,
                                          "BLOCK_TERM_TMO": 64}},
                     "app_block": {"trigger_counter": 1, "batch_counter": 1,
                                   "pkt_counter": 64},
                     "app_event": {"trigger_counter": 1, "pkt_counter": n},
                     "queues": {"qid7": {"drop_count_packets": 0},
                                "qid1": {"drop_count_packets": 0}},
                     "n_fail_config": 0}
                    for i, v in enumerate(vals)]}

    cases = [
        ("fast reservoir (3-6 us)", [3000, 4000, 5000, 6000],
         "HARNESS_SCHEDULING_ERROR"),
        ("reservoir at 1 ms", [999000, 1000012, 1000100],
         "ARCHITECTURE_FAILURE"),
        ("reservoir at 450 us (misses the 400 us floor)",
         [430000, 450000, 449000], "ARCHITECTURE_FAILURE"),
        ("reservoir at 150 us (beats the floor, misses R2)",
         [120000, 150000, 140000], "MARGINAL"),
    ]
    bad = 0
    print("=" * 74)
    for label, vals, want in cases:
        a = score_arm(arm(vals))
        got, why = verdict(a)
        ok = got == want
        bad += 0 if ok else 1
        print("%-6s %-46s %s" % ("PASS" if ok else "FAIL", label,
                                 got if ok else "%s (want %s)" % (got, want)))
    # attribution: 3-event arms whose READ->first tracks 2*ipg must be conclusive
    prod = score_arm(arm([4000, 5000]))
    b = [score_arm(arm([2 * 200000] * 3, ipg=200000, n=3, name="b200")),
         score_arm(arm([2 * 500000] * 3, ipg=500000, n=3, name="b500"))]
    # score_arm derives read_to_first from t_first_block = read + v//2, so feed the
    # batch span as v so that v//2 ... use read_to_full instead for the check below
    att = attribution(prod, [{"ipg_ns": x["ipg_ns"],
                              "read_to_first_ns": x["read_to_full_ns"]} for x in b])
    ok = att["conclusive"]
    bad += 0 if ok else 1
    print("%-6s %-46s %s" % ("PASS" if ok else "FAIL",
                             "attribution: tracks 2*ipg at two points",
                             "conclusive" if ok else "not conclusive"))
    # a trial that fired twice must be EXCLUDED, not averaged in
    dbl = arm([4000, 5000])
    dbl["trial_records"][1]["app_block"]["trigger_counter"] = 2
    a = score_arm(dbl)
    ok = a["trials_clean"] == 1 and a["trials_run"] == 2
    bad += 0 if ok else 1
    print("%-6s %-46s %s" % ("PASS" if ok else "FAIL",
                             "a double fire is EXCLUDED, not averaged",
                             "%d/%d clean" % (a["trials_clean"], a["trials_run"])))
    print("-" * 74)
    print("SELF-TEST: %d control(s), %d bad" % (len(cases) + 2, bad))
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--evidence-dir", default=None)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--r2-bound-ns", type=int, default=R2_BOUND_NS)
    ap.add_argument("--json-out", default=None)
    a = ap.parse_args(argv if argv is not None else sys.argv[1:])

    if a.self_test:
        return self_test()

    paths = list(a.files)
    if a.evidence_dir:
        paths += sorted(glob.glob(os.path.join(a.evidence_dir, "*.json")))
    if not paths:
        print("no input", file=sys.stderr)
        return 2

    rc = 0
    allout = []
    for p in paths:
        try:
            rec = json.load(open(p))
        except Exception as e:                       # noqa: BLE001
            print("%s: unreadable (%s)" % (p, e), file=sys.stderr)
            rc = 1
            continue
        if not rec.get("check2"):
            continue
        text, data = render(rec, a)
        print(text)
        data["file"] = p
        allout.append(data)
        if data["verdict"] not in ("HARNESS_SCHEDULING_ERROR",):
            rc = 1
    if a.json_out and allout:
        with open(a.json_out, "w") as fh:
            json.dump({"schema": "d3_check2/1", "results": allout}, fh,
                      indent=2, default=str)
    if not allout:
        print("no --check2 manifest among the inputs", file=sys.stderr)
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main())

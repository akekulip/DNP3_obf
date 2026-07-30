#!/usr/bin/env python3
"""
analyze_dsweep.py — score the physical D-sweep campaign.

The observable is the WIRE, so every concealment number comes from the Vision-side
capture. CONSENSUS §9's constraints are enforced here, not left to the reader:

  * the arms are INTERLEAVED round by round, and every comparison is made WITHIN the
    session, because native-vs-native drift on this relay has reached AUROC 0.985
    across sessions;
  * a NATIVE-vs-NATIVE AUROC is reported as the DRIFT FLOOR, so no arm's AUROC can be
    read without knowing what zero looks like;
  * D = 1 ms is a PRE-REGISTERED NULL CONTROL, not a treatment arm;
  * AUROC-vs-native is printed BESIDE every concealment number;
  * ATTEMPTED transactions are counted, with the disposition of all of them;
  * no binned entropy anywhere -- AUROC is computed on the RAW feature, which also
    avoids the KDE-degeneracy trap where a fully clamped feature returns accuracy 1.000
    through density degeneracy rather than through information.
"""
import json, math, statistics as st, sys

def auroc(pos, neg):
    """P(a random `pos` sample > a random `neg` sample), ties at 0.5 (Mann-Whitney)."""
    if not pos or not neg:
        return None
    wins = 0.0
    for a in pos:
        for b in neg:
            wins += 1.0 if a > b else (0.5 if a == b else 0.0)
    return wins / (len(pos) * len(neg))

def sep(pos, neg):
    """AUROC folded to a SEPARABILITY in [0.5, 1.0]: an adversary is free to invert
    its decision rule, so 0.0 is as informative as 1.0."""
    a = auroc(pos, neg)
    return None if a is None else max(a, 1.0 - a)

def q(v, p):
    if not v: return None
    s = sorted(v); k = max(0, min(len(s)-1, int(math.ceil(p/100.0*len(s)))-1))
    return s[k]

def desc(v):
    if not v: return {"n": 0}
    return {"n": len(v), "min": min(v), "median": st.median(v), "p95": q(v, 95),
            "max": max(v), "sd": (st.stdev(v) if len(v) > 1 else 0.0)}

blocks = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
arms = {}
for b in blocks:
    a = arms.setdefault(b["arm"], {"d_ms": b["d_ms"], "armed": b["reservoir_armed"],
                                   "attempted": 0, "responded": 0, "rows": [],
                                   "blocks": [], "ctr": []})
    bl = b.get("block", {})
    a["attempted"] += bl.get("attempted", 0)
    a["responded"] += bl.get("responded", 0)
    a["rows"] += [r for r in bl.get("rows", [])]
    a["blocks"].append(b["label"])
    a["ctr"].append(b.get("counters", {}))

# per-arm CLRT (ACK -> RESPONSE on the wire) and READ -> ACK
for nm, a in arms.items():
    a["clrt"] = [r["clrt_ms"] for r in a["rows"] if r.get("clrt_ms") is not None]
    a["r2a"] = [r["read_to_ack_ms"] for r in a["rows"] if r.get("read_to_ack_ms") is not None]
    a["ack_first"] = [r["ack_before_resp"] for r in a["rows"] if r.get("ack_before_resp") is not None]

nat = arms.get("native", {})
NC = nat.get("clrt", [])
# the DRIFT FLOOR: native split into its own halves, within the same session
half = len(NC) // 2
drift = sep(NC[:half], NC[half:])

print("=" * 96)
print("PHYSICAL D-SWEEP CAMPAIGN — Case A Defense 3 vs a real SEL-751, D on the runtime path")
print("=" * 96)
tot_att = sum(a["attempted"] for a in arms.values())
tot_res = sum(a["responded"] for a in arms.values())
print("ATTEMPTED transactions: %d   responded: %d   unanswered: %d   rounds interleaved: %d"
      % (tot_att, tot_res, tot_att - tot_res,
         len(set(l.split("_")[0] for a in arms.values() for l in a["blocks"]))))
print("NATIVE-vs-NATIVE separability (the DRIFT FLOOR, within session): %s"
      % ("n/a" if drift is None else "%.3f" % drift))
print()
hdr = ("arm", "D ms", "att", "resp", "CLRT med", "CLRT p95", "CLRT max", "CLRT sd",
       "coll<0.1ms", "READ→ACK med", "sep vs native")
print("%-7s %5s %4s %5s %9s %9s %9s %8s %10s %13s %14s" % hdr)
print("-" * 96)
order = ["native", "d1", "d2", "d4", "d8", "d16"]
rows_out = {}
for nm in order:
    if nm not in arms: continue
    a = arms[nm]; c = a["clrt"]; d = desc(c)
    coll = sum(1 for x in c if x < 0.1)
    s = "—" if nm == "native" else ("n/a" if sep(c, NC) is None else "%.3f" % sep(c, NC))
    print("%-7s %5.0f %4d %5d %9.3f %9.3f %9.3f %8.3f %5d/%-4d %13.3f %14s"
          % (nm, a["d_ms"], a["attempted"], a["responded"], d["median"], d["p95"],
             d["max"], d["sd"], coll, len(c), st.median(a["r2a"]), s))
    rows_out[nm] = {"d_ms": a["d_ms"], "attempted": a["attempted"],
                    "responded": a["responded"], "clrt": d,
                    "collapsed_under_0p1ms": coll, "clrt_n": len(c),
                    "read_to_ack_median_ms": st.median(a["r2a"]),
                    "separability_vs_native": None if nm == "native" else sep(c, NC),
                    "ack_before_resp_all": all(a["ack_first"]),
                    "ack_before_resp_n": len(a["ack_first"])}
print("-" * 96)
print("ORDERING INVARIANT — ACK committed before the RESPONSE, every transaction:")
for nm in order:
    if nm in arms:
        a = arms[nm]
        print("  %-7s %d/%d  %s" % (nm, sum(1 for x in a["ack_first"] if x),
                                    len(a["ack_first"]),
                                    "OK" if all(a["ack_first"]) else "*** VIOLATED ***"))
print()
print("MECHANISM, summed over each arm's blocks (armed arms should show 64 admits per txn):")
print("%-7s %9s %9s %9s %7s %7s %9s %9s %7s" %
      ("arm", "ADMIT", "TERM_DL", "ARM_FRESH", "STALE", "TMO", "FAILOPEN", "DUP_SUPP", "qdrops"))
mech = {}
for nm in order:
    if nm not in arms: continue
    f = lambda k, grp: sum((c.get(grp, {}) or {}).get(k, 0) or 0 for c in arms[nm]["ctr"])
    qd = sum(v or 0 for c in arms[nm]["ctr"] for v in (c.get("qdrops", {}) or {}).values())
    row = {"PKTGEN_ADMIT": f("PKTGEN_ADMIT", "fresh"), "BLOCK_TERM_DL": f("BLOCK_TERM_DL", "deq"),
           "ARM_FRESH": f("ARM_FRESH", "fresh"), "BLOCK_TERM_STALE": f("BLOCK_TERM_STALE", "deq"),
           "BLOCK_TERM_TMO": f("BLOCK_TERM_TMO", "deq"),
           "RELEASE_FAILOPEN": f("RELEASE_FAILOPEN", "deq"),
           "RESP_DUP_SUPP": f("RESP_DUP_SUPP", "fresh"), "qdrops": qd,
           "PKTGEN_DROP": f("PKTGEN_DROP", "fresh"), "ARM_BUSY": f("ARM_BUSY", "fresh"),
           "ACK_REJECT": f("ACK_REJECT", "fresh"),
           "RESP_HOLD_EARLY": f("RESP_HOLD_EARLY", "fresh"),
           "RESP_BYPASS": f("RESP_BYPASS", "fresh"),
           "ACK_RELEASE": f("ACK_RELEASE", "deq"), "ACK_REL_RETIRE": f("ACK_REL_RETIRE", "deq")}
    mech[nm] = row
    print("%-7s %9d %9d %9d %7d %7d %9d %9d %7d" %
          (nm, row["PKTGEN_ADMIT"], row["BLOCK_TERM_DL"], row["ARM_FRESH"],
           row["BLOCK_TERM_STALE"], row["BLOCK_TERM_TMO"], row["RELEASE_FAILOPEN"],
           row["RESP_DUP_SUPP"], row["qdrops"]))
json.dump({"schema": "d3_dsweep/1", "attempted": tot_att, "responded": tot_res,
           "drift_floor_separability": drift, "arms": rows_out, "mechanism": mech},
          open(sys.argv[2], "w"), indent=2, default=str)
print()
print("wrote", sys.argv[2])

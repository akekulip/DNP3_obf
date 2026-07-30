#!/usr/bin/env python3
"""
analyze_observer.py — what a PASSIVE OBSERVER actually gets from the D-sweep campaign.

The campaign reported concealment on ONE feature, the CLRT. A real adversary sees every
wire-visible timing of the transaction, and Defense 3 CREATES one: READ->ACK becomes
D + a constant. This scores each feature the observer has, and then a held-out threshold
classifier, so the multi-feature number is not fitted and tested on the same data
(CONSENSUS §9). No model is fitted on the test half and no binned entropy is used.
"""
import json, math, statistics as st, sys

def auroc(pos, neg):
    if not pos or not neg: return None
    w = 0.0
    for a in pos:
        for b in neg: w += 1.0 if a > b else (0.5 if a == b else 0.0)
    return w / (len(pos) * len(neg))

def sep(p, n):
    a = auroc(p, n)
    return None if a is None else max(a, 1.0 - a)

blocks = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
# features per transaction, tagged with arm and round so the split can be blocked
F = ("read_to_ack_ms", "clrt_ms", "read_to_resp_ms")
data = {}
for b in blocks:
    rnd = b["label"].split("_")[0]
    for r in b.get("block", {}).get("rows", []):
        if any(r.get(f) is None for f in F): continue
        data.setdefault(b["arm"], []).append({"rnd": rnd, **{f: r[f] for f in F}})

NAT = data.get("native", [])
order = [a for a in ("d1", "d2", "d4", "d8", "d16") if a in data]
print("=" * 92)
print("WHAT THE OBSERVER GETS — per-feature separability vs native (folded AUROC)")
print("=" * 92)
print("drift floor, native vs native, per feature:")
h = len(NAT) // 2
for f in F:
    print("   %-16s %.3f" % (f, sep([x[f] for x in NAT[:h]], [x[f] for x in NAT[h:]])))
print()
print("%-6s %5s %16s %16s %16s   %s" % ("arm", "D", "READ->ACK", "CLRT", "READ->RESP",
                                        "BEST feature"))
print("-" * 92)
out = {}
for a in order:
    d = data[a]; dms = {"d1":1,"d2":2,"d4":4,"d8":8,"d16":16}[a]
    s = {f: sep([x[f] for x in d], [x[f] for x in NAT]) for f in F}
    best = max(s, key=lambda k: s[k])
    print("%-6s %5d %16.3f %16.3f %16.3f   %s (%.3f)" %
          (a, dms, s["read_to_ack_ms"], s["clrt_ms"], s["read_to_resp_ms"], best, s[best]))
    out[a] = {"d_ms": dms, "per_feature_separability": s, "best_feature": best,
              "best_separability": s[best]}
print("-" * 92)
print()
print("HELD-OUT THRESHOLD CLASSIFIER on the best feature: threshold chosen on rounds 1-2,")
print("scored on rounds 3-4. Balanced accuracy, so the class sizes cannot flatter it.")
print("%-6s %5s %14s %12s %14s %14s" % ("arm", "D", "feature", "thresh", "bal.acc TEST",
                                        "n test (p/n)"))
print("-" * 92)
TR, TE = ("r1", "r2"), ("r3", "r4")
for a in order:
    d = data[a]; f = out[a]["best_feature"]
    ptr = [x[f] for x in d if x["rnd"] in TR]; ntr = [x[f] for x in NAT if x["rnd"] in TR]
    pte = [x[f] for x in d if x["rnd"] in TE]; nte = [x[f] for x in NAT if x["rnd"] in TE]
    if not (ptr and ntr and pte and nte): continue
    # midpoint between the two training medians; direction from the training medians
    thr = (st.median(ptr) + st.median(ntr)) / 2.0
    pos_above = st.median(ptr) > st.median(ntr)
    tp = sum(1 for v in pte if (v > thr) == pos_above)
    tn = sum(1 for v in nte if (v > thr) != pos_above)
    ba = 0.5 * (tp / len(pte) + tn / len(nte))
    print("%-6s %5d %14s %12.3f %14.3f %14s" %
          (a, out[a]["d_ms"], f.replace("_ms", ""), thr, ba,
           "%d/%d" % (len(pte), len(nte))))
    out[a]["heldout"] = {"feature": f, "threshold_ms": thr, "balanced_accuracy": ba,
                         "n_test_pos": len(pte), "n_test_neg": len(nte)}
json.dump({"schema": "d3_observer/1", "arms": out}, open(sys.argv[2], "w"), indent=2)
print()
print("wrote", sys.argv[2])

"""How much does an adversary gain by watching more than one exchange?

The paper's leakage result is per exchange. A reconnaissance adversary watches a whole poll
cycle, so this pools k consecutive same-class exchanges from one capture into a single decision
and asks what balanced accuracy the same forest reaches. Windows are non-overlapping and never
cross a capture or a class, so no window mixes traffic the adversary could not group itself.
"""
import csv, json, sys
from collections import defaultdict
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score

CLASSES = ["READ", "SELECT", "OPERATE"]
KS = [1, 2, 5, 10, 20]
# The same forest the single-exchange result uses, balanced for the same reason.
RF = dict(n_estimators=200, min_samples_leaf=5, random_state=0, n_jobs=-1,
          class_weight="balanced")

rows = list(csv.DictReader(open(sys.argv[1])))
groups = defaultdict(list)
for r in rows:
    groups[(r["arm"], r["run"], r["capture"], r["txn_class"])].append(
        (int(r["idx"]), float(r["ack_ms"]), float(r["clrt_ms"])))

def windows(arm, k):
    runs, cls, feats = [], [], []
    for (a, run, _cap, c), v in groups.items():
        if a != arm:
            continue
        v.sort()
        for i in range(0, len(v) - k + 1, k):
            w = np.array([[x[1], x[2]] for x in v[i:i + k]])
            runs.append(run); cls.append(c)
            # mean, spread and extremes of each interval: more than an adversary needs, so the
            # answer is an upper bound on what pooling buys rather than one aggregation's luck.
            feats.append(np.concatenate([w.mean(0), w.std(0), w.min(0), w.max(0)]))
    return np.array(runs), np.array(cls), np.array(feats)

COLS = {"clrt": [1, 3, 5, 7], "ack_clrt": [0, 1, 2, 3, 4, 5, 6, 7]}
out = {"seed": 0, "classifier": "RandomForest " + repr(RF), "note": "non-overlapping windows of k same-class exchanges from one capture; "
               "features are mean, sd, min and max of each interval over the window",
       "k_values": KS, "results": {}}
for fname, idx in COLS.items():
    for arm in ("native", "obfuscated"):
        for k in KS:
            runs, cls, X = windows(arm, k)
            scores = []
            for r in sorted(set(runs)):
                te, tr = runs == r, runs != r
                if len(set(cls[te])) < 3:
                    continue
                m = RandomForestClassifier(**RF).fit(X[tr][:, idx], cls[tr])
                scores.append(balanced_accuracy_score(cls[te], m.predict(X[te][:, idx])))
            out["results"][f"{fname}/{arm}/k{k}"] = {
                "balanced_accuracy_mean": round(float(np.mean(scores)), 4),
                "min": round(float(np.min(scores)), 4), "max": round(float(np.max(scores)), 4),
                "n_folds": len(scores), "n_windows": int(len(cls))}
            print(f"{fname:9s} {arm:11s} k={k:<3d} BA={np.mean(scores):.4f} "
                  f"[{np.min(scores):.3f},{np.max(scores):.3f}] windows={len(cls)}")
json.dump(out, open(sys.argv[2], "w"), indent=1)

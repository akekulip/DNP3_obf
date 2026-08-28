"""Corrected leakage analysis: mutual information in bits, and two attacker models.

Corrections applied relative to the earlier analysis:
  1. sklearn's mutual_info_classif returns nats. Every value is converted to bits.
  2. Marginal per-feature MI values are never summed. MI is reported for CLRT alone.
  3. The feature vector uses only the two independent intervals, request-to-ACK and
     ACK-to-response. Total response latency is their sum and is therefore redundant.
  4. Two attacker models are evaluated: a fixed classifier trained on Timing OFF traffic
     and applied unchanged to obfuscated traffic, and an adaptive classifier retrained on
     obfuscated traffic. The threat model describes the first.
  5. Confusion matrices aggregate all 22 held-out grouped runs.
"""
from __future__ import annotations
import csv, json, sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, confusion_matrix
from sklearn.feature_selection import mutual_info_classif

CLASSES = ["READ", "SELECT", "OPERATE"]
SEED = 20260828
N_PERM = 1000
N_BOOT = 2000
LN2 = np.log(2.0)
RF = dict(n_estimators=200, min_samples_leaf=5, random_state=0, n_jobs=-1)
FEATURES = {"clrt": ["clrt_ms"], "ack_clrt": ["ack_ms", "clrt_ms"]}


def load(path):
    runs, arms, cls, feats = [], [], [], []
    with open(path) as f:
        for r in csv.DictReader(f):
            runs.append(r["run"]); arms.append(r["arm"]); cls.append(r["txn_class"])
            feats.append((float(r["ack_ms"]), float(r["clrt_ms"])))
    return (np.array(runs), np.array(arms), np.array(cls),
            np.array(feats, dtype=float))


def mi_bits(X, y, seed=0):
    return float(mutual_info_classif(X, y, random_state=seed)[0]) / LN2


def mi_block(X, y, runs, rng):
    """Point estimate, permutation null, and grouped-run bootstrap, all in bits."""
    obs = mi_bits(X, y)
    null = np.empty(N_PERM)
    uniq = np.unique(runs)
    for i in range(N_PERM):
        yp = y.copy()
        for r in uniq:                       # shuffle within each run: class counts preserved
            m = runs == r
            yp[m] = rng.permutation(yp[m])
        null[i] = mi_bits(X, yp)
    # Uncertainty by grouped-run JACKKNIFE, not bootstrap. Resampling runs with
    # replacement duplicates identical feature values, and a nearest-neighbour MI
    # estimator reads tied points as extra dependence: duplicating one run here raises
    # the estimate from 0.374 to 0.493 bits. The jackknife leaves one run out and so
    # never duplicates a value.
    jk = np.array([mi_bits(X[runs != r], y[runs != r]) for r in uniq])
    n = uniq.size
    pseudo = n * obs - (n - 1) * jk
    se = float(pseudo.std(ddof=1) / np.sqrt(n))
    return dict(observed_bits=round(obs, 5),
                jackknife_bias_corrected_bits=round(float(pseudo.mean()), 5),
                jackknife_se_bits=round(se, 5),
                jackknife_ci95_bits=[round(float(pseudo.mean() - 1.96 * se), 5),
                                     round(float(pseudo.mean() + 1.96 * se), 5)],
                n_jackknife_runs=int(n),
                uncertainty_note=("within-campaign only; not evidence of generalization "
                                  "across days, devices, or deployments"),
                null_mean_bits=round(float(null.mean()), 5),
                null_p95_bits=round(float(np.percentile(null, 95)), 5),
                null_p99_bits=round(float(np.percentile(null, 99)), 5),
                null_max_bits=round(float(null.max()), 5),
                n_permutations=N_PERM,
                monte_carlo_resolution=round(1.0 / N_PERM, 5),
                exceeds_null_p99=bool(obs > np.percentile(null, 99)))


def folds(runs, arms, cls, X, feat_idx):
    uniq = sorted(set(runs))
    out = {"A_fixed": {"off": [], "obf": []}, "B_adaptive": {"obf": []}}
    cmA_off = cmA_obf = cmB = np.zeros((3, 3))
    for r in uniq:
        te, tr = runs == r, runs != r
        off, obf = arms == "native", arms == "obfuscated"
        # Attacker A: trained once on Timing OFF, then applied unchanged to both arms.
        a = RandomForestClassifier(**RF).fit(X[tr & off][:, feat_idx], cls[tr & off])
        p_off = a.predict(X[te & off][:, feat_idx])
        p_obf = a.predict(X[te & obf][:, feat_idx])
        out["A_fixed"]["off"].append(balanced_accuracy_score(cls[te & off], p_off))
        out["A_fixed"]["obf"].append(balanced_accuracy_score(cls[te & obf], p_obf))
        cmA_off = cmA_off + confusion_matrix(cls[te & off], p_off, labels=CLASSES)
        cmA_obf = cmA_obf + confusion_matrix(cls[te & obf], p_obf, labels=CLASSES)
        # Attacker B: retrained on obfuscated traffic.
        b = RandomForestClassifier(**RF).fit(X[tr & obf][:, feat_idx], cls[tr & obf])
        p_b = b.predict(X[te & obf][:, feat_idx])
        out["B_adaptive"]["obf"].append(balanced_accuracy_score(cls[te & obf], p_b))
        cmB = cmB + confusion_matrix(cls[te & obf], p_b, labels=CLASSES)
    return out, cmA_off, cmA_obf, cmB


def boot_ci(vals, rng):
    v = np.asarray(vals)
    bs = [np.mean(rng.choice(v, v.size, replace=True)) for _ in range(N_BOOT)]
    return [round(float(np.percentile(bs, 2.5)), 4), round(float(np.percentile(bs, 97.5)), 4)]


def main(canon, out):
    runs, arms, cls, X = load(canon)
    rng = np.random.default_rng(SEED)
    res = {"seed": SEED, "chance_balanced_accuracy": round(1 / 3, 4),
           "n_folds": len(set(runs)), "classifier": "RandomForest " + json.dumps(RF),
           "mutual_information": {}, "classifiers": {}, "confusion_all_folds": {}}
    print("=== Mutual information, CLRT only, in bits (nats / ln 2) ===")
    for arm in ("native", "obfuscated"):
        m = arms == arm
        d = mi_block(X[m][:, [1]], cls[m], runs[m], rng)
        res["mutual_information"][arm] = d
        print(f"  {arm:11s} observed {d['observed_bits']:.4f} bits   "
              f"null p99 {d['null_p99_bits']:.4f}   jackknife se {d['jackknife_se_bits']:.4f}   "
              f"above null: {d['exceeds_null_p99']}")
    for fname, cols in FEATURES.items():
        idx = [0, 1] if fname == "ack_clrt" else [1]
        f, cmA_off, cmA_obf, cmB = folds(runs, arms, cls, X, idx)
        res["classifiers"][fname] = {
            "features": cols,
            "A_fixed_native_trained": {
                "tested_on_timing_off": {"balanced_accuracy": round(float(np.mean(f["A_fixed"]["off"])), 4),
                                         "ci95": boot_ci(f["A_fixed"]["off"], rng)},
                "tested_on_obfuscated": {"balanced_accuracy": round(float(np.mean(f["A_fixed"]["obf"])), 4),
                                         "ci95": boot_ci(f["A_fixed"]["obf"], rng)}},
            "B_adaptive_obfuscated_trained": {
                "tested_on_obfuscated": {"balanced_accuracy": round(float(np.mean(f["B_adaptive"]["obf"])), 4),
                                         "ci95": boot_ci(f["B_adaptive"]["obf"], rng)}}}
        for tag, cm in (("A_off", cmA_off), ("A_obf", cmA_obf), ("B_obf", cmB)):
            res["confusion_all_folds"][f"{fname}/{tag}"] = (
                cm / cm.sum(axis=1, keepdims=True)).round(4).tolist()
        a = res["classifiers"][fname]
        print(f"\n=== Features: {cols} ===")
        print(f"  A fixed, tested on Timing OFF : {a['A_fixed_native_trained']['tested_on_timing_off']['balanced_accuracy']:.3f} "
              f"{a['A_fixed_native_trained']['tested_on_timing_off']['ci95']}")
        print(f"  A fixed, applied to Obfuscated: {a['A_fixed_native_trained']['tested_on_obfuscated']['balanced_accuracy']:.3f} "
              f"{a['A_fixed_native_trained']['tested_on_obfuscated']['ci95']}")
        print(f"  B adaptive, on Obfuscated     : {a['B_adaptive_obfuscated_trained']['tested_on_obfuscated']['balanced_accuracy']:.3f} "
              f"{a['B_adaptive_obfuscated_trained']['tested_on_obfuscated']['ci95']}")
    with open(out, "w") as f:
        json.dump(res, f, indent=1)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

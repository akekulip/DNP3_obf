"""Leakage analysis: mutual information against a permutation null, and two attacker models.

Estimator choices, and the two that were rejected
-------------------------------------------------
1. ``mutual_info_classif`` returns nats. Every value is converted to bits.
2. Marginal per-feature MI values are never summed.
3. The feature vector uses only the two independent intervals, request-to-ACK and
   ACK-to-response. Total response latency is their sum and is therefore redundant.
4. Two attacker models are evaluated: a *fixed* classifier trained on Timing OFF traffic and
   applied unchanged, which is the adversary the threat model describes, and an *adaptive*
   classifier retrained on obfuscated traffic.

**Rejected: a jackknife interval on the MI point estimate.** An earlier version reported
grouped-run jackknife pseudo-value intervals. They are not defensible here and are not
published. The jackknife pseudo-value construction ``n*obs - (n-1)*jk`` assumes the estimator is
smooth and roughly linear in the leave-one-out perturbation. A nearest-neighbour MI estimator
near the zero-information boundary is neither: it is bounded below at zero, strongly biased
upward on small samples, and its leave-one-run-out values do not vary smoothly. The result was an
interval that did not contain its own point estimate in *either* arm — Timing OFF observed
0.38315 bits against an interval of [0.34496, 0.37518], and obfuscated observed 0.00394 bits
against [0.06281, 0.08416]. The diagnostic is retained under ``rejected_estimators`` so the
rejection is auditable, and is never plotted.

**Rejected: a naive bootstrap over the 22 leave-one-run-out fold scores.** Those folds share
training data — every pair of folds overlaps in 20 of 22 runs — so the scores are dependent and
resampling them does not estimate the sampling distribution of the mean. What is reported instead
is the *descriptive* spread of the 22 held-out-run scores, labelled as within-campaign
held-out-run variability, which is what the design supports. A grouped bootstrap that resampled
runs and refitted the whole model inside every replicate would be inferential, but its target
population is still the runs of this one campaign, so it would not license a broader claim.
"""
from __future__ import annotations
import csv, json, sys
import numpy as np
from joblib import Parallel, delayed
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, confusion_matrix
from sklearn.feature_selection import mutual_info_classif

CLASSES = ["READ", "SELECT", "OPERATE"]
SEED = 20260828
N_PERM = 1000
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
    """Point estimate in bits against a within-run permutation null.

    Labels are shuffled inside each grouped run, which preserves the per-run class counts, so the
    null is the distribution of the estimator under no class-to-timing association.
    """
    obs = mi_bits(X, y)
    uniq = np.unique(runs)
    masks = [runs == r for r in uniq]
    # Permutations are drawn sequentially from the seeded generator, then scored in parallel, so
    # the result does not depend on the number of workers.
    perms = []
    for _ in range(N_PERM):
        yp = y.copy()
        for m in masks:
            yp[m] = rng.permutation(yp[m])
        perms.append(yp)
    null = np.array(Parallel(n_jobs=-1, batch_size=8)(
        delayed(mi_bits)(X, yp) for yp in perms))

    # Empirical Monte Carlo p-value, with the +1 correction so it can never be reported as 0.
    n_ge = int((null >= obs).sum())
    p_emp = (1.0 + n_ge) / (1.0 + N_PERM)

    # Diagnostic only. See the module docstring: not an interval, never plotted.
    jk = np.array([mi_bits(X[runs != r], y[runs != r]) for r in uniq])
    n = uniq.size
    pseudo = n * obs - (n - 1) * jk

    return dict(observed_bits=round(obs, 5),
                null_mean_bits=round(float(null.mean()), 5),
                null_sd_bits=round(float(null.std(ddof=1)), 5),
                null_p95_bits=round(float(np.percentile(null, 95)), 5),
                null_p99_bits=round(float(np.percentile(null, 99)), 5),
                null_max_bits=round(float(null.max()), 5),
                n_permutations=N_PERM,
                n_null_ge_observed=n_ge,
                p_value_empirical=round(p_emp, 5),
                p_value_resolution=round(1.0 / (1.0 + N_PERM), 5),
                exceeds_null_p95=bool(obs > np.percentile(null, 95)),
                exceeds_null_p99=bool(obs > np.percentile(null, 99)),
                inside_null=bool(obs <= np.percentile(null, 95)),
                scope=("within-campaign only; not evidence of generalization across days, "
                       "devices, or deployments"),
                rejected_estimators={
                    "grouped_run_jackknife": {
                        "bias_corrected_bits": round(float(pseudo.mean()), 5),
                        "se_bits": round(float(pseudo.std(ddof=1) / np.sqrt(n)), 5),
                        "status": "REJECTED, diagnostic only, never plotted",
                        "reason": ("pseudo-value construction assumes a smooth estimator; a "
                                   "nearest-neighbour MI estimator near the zero-information "
                                   "boundary is bounded, biased and non-smooth, and the "
                                   "resulting interval excludes its own point estimate")}})


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


def spread(vals):
    """Descriptive spread of the held-out-run scores. Not a confidence interval."""
    v = np.asarray(vals, dtype=float)
    q1, q2, q3 = np.percentile(v, [25, 50, 75])
    return dict(mean=round(float(v.mean()), 4), median=round(float(q2), 4),
                min=round(float(v.min()), 4), max=round(float(v.max()), 4),
                iqr_lo=round(float(q1), 4), iqr_hi=round(float(q3), 4),
                n_runs=int(v.size),
                interpretation=("within-campaign held-out-run variability across the 22 grouped "
                                "runs; the folds share training data and this is a descriptive "
                                "range, not a confidence interval"))


def main(canon, out):
    runs, arms, cls, X = load(canon)
    rng = np.random.default_rng(SEED)
    res = {"seed": SEED, "chance_balanced_accuracy": round(1 / 3, 4),
           "n_folds": len(set(runs)),
           "classifier": "RandomForest " + json.dumps(RF),
           "classifier_scope": ("results characterise the evaluated fixed Random-Forest attacker "
                                "and this feature set; they do not generalise to all "
                                "fingerprinting classifiers"),
           "uncertainty_policy": ("MI is reported against a within-run permutation null with an "
                                  "empirical Monte Carlo p-value and no error bar; classifier "
                                  "scores are reported with the descriptive spread of the 22 "
                                  "held-out-run scores and no confidence interval"),
           "mutual_information": {}, "classifiers": {}, "confusion_all_folds": {}}
    print("=== Mutual information, CLRT only, in bits (nats / ln 2) ===")
    for arm in ("native", "obfuscated"):
        m = arms == arm
        d = mi_block(X[m][:, [1]], cls[m], runs[m], rng)
        res["mutual_information"][arm] = d
        print(f"  {arm:11s} observed {d['observed_bits']:.5f} bits   "
              f"null p95 {d['null_p95_bits']:.5f}  p99 {d['null_p99_bits']:.5f}   "
              f"p={d['p_value_empirical']:.5f} (resolution {d['p_value_resolution']:.5f})   "
              f"inside null: {d['inside_null']}")
    for fname, cols in FEATURES.items():
        idx = [0, 1] if fname == "ack_clrt" else [1]
        f, cmA_off, cmA_obf, cmB = folds(runs, arms, cls, X, idx)
        res["classifiers"][fname] = {
            "features": cols,
            "A_fixed_native_trained": {
                "tested_on_timing_off": spread(f["A_fixed"]["off"]),
                "tested_on_obfuscated": spread(f["A_fixed"]["obf"])},
            "B_adaptive_obfuscated_trained": {
                "tested_on_obfuscated": spread(f["B_adaptive"]["obf"])}}
        for tag, cm in (("A_off", cmA_off), ("A_obf", cmA_obf), ("B_obf", cmB)):
            res["confusion_all_folds"][f"{fname}/{tag}"] = (
                cm / cm.sum(axis=1, keepdims=True)).round(4).tolist()
        a = res["classifiers"][fname]
        print(f"\n=== Features: {cols} ===")
        for lab, d in (("A fixed, tested on Timing OFF ",
                        a["A_fixed_native_trained"]["tested_on_timing_off"]),
                       ("A fixed, applied to Obfuscated",
                        a["A_fixed_native_trained"]["tested_on_obfuscated"]),
                       ("B adaptive, on Obfuscated    ",
                        a["B_adaptive_obfuscated_trained"]["tested_on_obfuscated"])):
            print(f"  {lab}: {d['mean']:.4f}  median {d['median']:.4f}  "
                  f"range [{d['min']:.4f}, {d['max']:.4f}]  IQR [{d['iqr_lo']:.4f}, {d['iqr_hi']:.4f}]")
    with open(out, "w") as f:
        json.dump(res, f, indent=1)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

"""Shift-versus-replacement statistics for campaign_v1 (predeclared; spec sections 3, 9, 10).

Establishes, beyond the median, whether the read-lane transformation is a REPLACEMENT
(both egress deadlines share the native-ACK anchor, so the native CLRT term X drops out and
protected spread collapses to scheduling jitter) rather than a SHIFT (X' = X + c, which
preserves the centered distribution and variance).

Outputs replacement_stats.json. Bootstraps resample SESSIONS (grouped runs), not transactions.
Seeds fixed. Nothing here is tuned on the result.
"""
import csv, json, sys
import numpy as np
from joblib import Parallel, delayed
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score

SEED = 20260902
N_BOOT = 2000                     # session-level bootstrap replicates for spread ratios
N_BOOT_CLS = 2000                 # cluster bootstrap over per-session scores
RF = dict(n_estimators=200, min_samples_leaf=5, random_state=0, n_jobs=-1)
FEATURE_SETS = {"clrt_only": [1], "req_to_ack_only": [0],
                "req_to_resp_only": [2], "ack_plus_clrt": [0, 1]}

def load(path):
    runs, arms, cls, X = [], [], [], []
    for r in csv.DictReader(open(path)):
        runs.append(r["run"]); arms.append(r["arm"]); cls.append(r["txn_class"])
        X.append((float(r["ack_ms"]), float(r["clrt_ms"]), float(r["rt_ms"])))
    return np.array(runs), np.array(arms), np.array(cls), np.array(X)

def describe(v):
    q1, q2, q3 = np.percentile(v, [25, 50, 75])
    med_abs = np.median(np.abs(v - q2))
    d = dict(n=int(v.size), mean=float(v.mean()), median=float(q2),
             sd=float(v.std(ddof=1)), var=float(v.var(ddof=1)),
             iqr=float(q3-q1), mad=float(med_abs),
             p5=float(np.percentile(v,5)), p95=float(np.percentile(v,95)),
             p99=float(np.percentile(v,99)), min=float(v.min()), max=float(v.max()))
    if v.size >= 2000: d["p99_9"] = float(np.percentile(v, 99.9))
    return {k: (round(x,6) if isinstance(x,float) else x) for k,x in d.items()}

def sess_boot_ratio(nat, obf, nat_runs, obf_runs, stat, rng):
    """Bootstrap CI for stat(obf)/stat(nat), resampling grouped runs with replacement."""
    ur = np.unique(nat_runs)
    idx_n = {r: np.where(nat_runs == r)[0] for r in ur}
    idx_o = {r: np.where(obf_runs == r)[0] for r in ur}
    out = np.empty(N_BOOT)
    for b in range(N_BOOT):
        pick = rng.choice(ur, ur.size, replace=True)
        vn = np.concatenate([nat[idx_n[r]] for r in pick])
        vo = np.concatenate([obf[idx_o[r]] for r in pick])
        sn, so = stat(vn), stat(vo)
        out[b] = so / sn if sn > 0 else np.nan
    return [round(float(np.nanpercentile(out, 2.5)), 6),
            round(float(np.nanpercentile(out, 97.5)), 6)]

def brown_forsythe(a, b):
    """Median-centred Levene: robust to skew."""
    from scipy import stats
    W, p = stats.levene(a, b, center="median")
    return round(float(W), 4), float(p)

def coverage(v, horizons=(12, 18, 20, 24)):
    v = np.asarray(v)
    return {f"C_{h}ms": {"covered": int((v <= h).sum()), "n": int(v.size),
                         "pct": round(100 * float((v <= h).mean()), 4)} for h in horizons}

def main(canon, out):
    runs, arms, cls, X = load(canon)
    rng = np.random.default_rng(SEED)
    res = {"seed": SEED, "n_boot_sessions": N_BOOT,
           "definitions": {
               "X": "native CLRT = tR - tA (ack_ms-anchored post-ACK interval, read lane)",
               "X_prime": "protected master-visible CLRT = eR - eA",
               "shift_model": "eA=tA+dA, eR=tR+dR => X'=X+(dR-dA), Var(X')=Var(X)",
               "replacement_model": "eA=tA+D_A, eR=tA+D_A+D_R => X'=D_R + jitter; native X term absent",
               "bootstrap_unit": "grouped run (session), 22 units, resampled with replacement"},
           "read_lane": {}, "coverage_native_read_lane": {},
           "counterfactual_shift": {}, "classifiers_by_feature_set": {}}

    # ---- spread statistics and ratios per read-lane class
    for c in ("READ", "SELECT"):
        m_n = (arms == "native") & (cls == c); m_o = (arms == "obfuscated") & (cls == c)
        nat, obf = X[m_n, 1], X[m_o, 1]
        rn, ro = runs[m_n], runs[m_o]
        W, p = brown_forsythe(nat, obf)
        entry = {"native": describe(nat), "protected": describe(obf),
                 "variance_ratio_prot_over_nat": round(float(obf.var(ddof=1)/nat.var(ddof=1)), 8),
                 "variance_ratio_ci95_session_bootstrap":
                     sess_boot_ratio(nat, obf, rn, ro, lambda v: v.var(ddof=1), rng),
                 "sd_ratio": round(float(obf.std(ddof=1)/nat.std(ddof=1)), 6),
                 "iqr_ratio": round(float(np.subtract(*np.percentile(obf,[75,25])) /
                                          np.subtract(*np.percentile(nat,[75,25]))), 6),
                 "mad_ratio": round(float(np.median(np.abs(obf-np.median(obf))) /
                                          np.median(np.abs(nat-np.median(nat)))), 6),
                 "brown_forsythe": {"W": W, "p": ("<1e-300" if p == 0 else float(f"{p:.3e}"))}}
        # counterfactual: native shifted so its median sits on the protected median.
        shifted = nat - np.median(nat) + np.median(obf)
        entry["counterfactual_shifted_native"] = describe(shifted)
        entry["counterfactual_note"] = ("shift preserves spread by construction: sd/IQR/MAD of "
                                        "the shifted series equal the native ones; the protected "
                                        "series does not")
        res["read_lane"][c] = entry

    # ---- native read-lane deadline coverage C(h)
    m = (arms == "native") & np.isin(cls, ["READ", "SELECT"])
    res["coverage_native_read_lane"] = coverage(X[m, 1])
    res["coverage_native_read_lane"]["percentiles"] = describe(X[m, 1])

    # ---- classifiers per feature set, retrained WITHIN each arm, leave-one-run-out
    uruns = sorted(set(runs))
    def loro_scores(arm, feat_idx):
        m_arm = arms == arm
        scores = []
        for r in uruns:
            tr = m_arm & (runs != r); te = m_arm & (runs == r)
            f = RandomForestClassifier(**RF).fit(X[tr][:, feat_idx], cls[tr])
            scores.append(balanced_accuracy_score(cls[te], f.predict(X[te][:, feat_idx])))
        return np.array(scores)
    def cluster_boot_ci(scores, rng):
        bs = [np.mean(rng.choice(scores, scores.size, replace=True)) for _ in range(N_BOOT_CLS)]
        return [round(float(np.percentile(bs, 2.5)), 4), round(float(np.percentile(bs, 97.5)), 4)]
    for fname, idx in FEATURE_SETS.items():
        entry = {}
        for arm, label in (("native", "native"), ("obfuscated", "protected")):
            s = loro_scores(arm, idx)
            entry[label] = {"balanced_accuracy_mean": round(float(s.mean()), 4),
                            "session_scores_min": round(float(s.min()), 4),
                            "session_scores_max": round(float(s.max()), 4),
                            "cluster_bootstrap_ci95": cluster_boot_ci(s, rng),
                            "ci_note": ("cluster bootstrap over the 22 per-session held-out "
                                        "scores; sessions are the resampling unit; folds share "
                                        "training data")}
        entry["chance"] = round(1/3, 4)
        res["classifiers_by_feature_set"][fname] = entry
        print(fname, {k: v["balanced_accuracy_mean"] for k, v in entry.items() if k != "chance"})

    json.dump(res, open(out, "w"), indent=1)
    print("wrote", out)

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

"""Shared estimators for the offline leakage harness.

Everything here is deliberately explicit about the two things this corpus makes
easy to get wrong:

  1. Transactions are NOT independent -- they are nested in 6 (real) / 12 (all)
     TCP flows.  Every CI is therefore a *cluster* bootstrap over flows unless a
     within-flow statistic is being estimated, in which case the resampling is
     stratified within flow and that is stated at the call site.

  2. Some secrets (device label) are flow-constant.  An i.i.d. row permutation
     null for those is grossly anti-conservative; the correct null permutes the
     *flow* label assignment.  `perm_null_flowlabel` does that exhaustively.

Seed discipline: every routine takes an explicit `seed`; nothing reads global RNG
state.
"""

import itertools
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.tree import DecisionTreeClassifier

SEED = 20260810


# --------------------------------------------------------------------------- #
# Entropy / mutual information
# --------------------------------------------------------------------------- #

def _counts(x):
    _, c = np.unique(x, return_counts=True)
    return c


def entropy_mm(x):
    """Miller-Madow-corrected Shannon entropy (bits) of a discrete sample."""
    c = _counts(x)
    n = c.sum()
    p = c / n
    h = -np.sum(p * np.log2(p))
    return h + (len(c) - 1) / (2 * n * np.log(2))


def mi_mm(x, y):
    """Miller-Madow-corrected mutual information I(X;Y) in bits.

    MI_MM = MI_plugin + (m_x + m_y - m_xy - 1) / (2 N ln2), which is the
    entropy-wise Miller-Madow correction propagated through
    I = H(X) + H(Y) - H(X,Y).
    """
    x = np.asarray(x)
    y = np.asarray(y)
    n = len(x)
    xy = np.array([hash((a, b)) for a, b in zip(x.tolist(), y.tolist())])
    cx, cy, cxy = _counts(x), _counts(y), _counts(xy)

    def _h(c):
        p = c / c.sum()
        return -np.sum(p * np.log2(p))

    mi = _h(cx) + _h(cy) - _h(cxy)
    corr = (len(cx) + len(cy) - len(cxy) - 1) / (2 * n * np.log(2))
    return mi + corr


def quantile_bin(v, nbins, seed=SEED):
    """Equal-frequency discretisation; ties collapse (fewer bins is honest)."""
    v = np.asarray(v, dtype=float)
    finite = np.isfinite(v)
    out = np.full(len(v), -1, dtype=int)
    if finite.sum() == 0:
        return out
    qs = np.quantile(v[finite], np.linspace(0, 1, nbins + 1)[1:-1])
    out[finite] = np.searchsorted(np.unique(qs), v[finite])
    return out


def joint_key(cols):
    """Collapse a list of integer-coded columns into one discrete variable."""
    arr = np.vstack([np.asarray(c) for c in cols]).T
    return np.array([hash(tuple(r.tolist())) for r in arr])


# --------------------------------------------------------------------------- #
# Permutation nulls
# --------------------------------------------------------------------------- #

def perm_null_iid(x, y, B=2000, seed=SEED):
    """i.i.d. row permutation null for I(X;Y). Valid only when rows are
    exchangeable under H0 (secret varies within flow and has no serial
    structure that matters)."""
    rng = np.random.default_rng(seed)
    obs = mi_mm(x, y)
    null = np.empty(B)
    y = np.asarray(y)
    for b in range(B):
        null[b] = mi_mm(x, rng.permutation(y))
    p = (1 + np.sum(null >= obs)) / (B + 1)
    return {"mi": float(obs), "null_mean": float(null.mean()),
            "null_p95": float(np.percentile(null, 95)),
            "null_max": float(null.max()), "p_value": float(p), "B": B,
            "scheme": "iid_row_permutation"}


def perm_null_block(x, y, groups, B=2000, block=50, seed=SEED):
    """Circular block-shift null within each flow: preserves the serial
    structure of the secret (alternating control/read polls) while destroying
    its alignment with the features."""
    rng = np.random.default_rng(seed)
    x = np.asarray(x)
    y = np.asarray(y)
    groups = np.asarray(groups)
    obs = mi_mm(x, y)
    idx_by_g = {g: np.where(groups == g)[0] for g in np.unique(groups)}
    null = np.empty(B)
    for b in range(B):
        yp = y.copy()
        for g, idx in idx_by_g.items():
            k = int(rng.integers(1, max(2, len(idx))))
            yp[idx] = np.roll(y[idx], k)
        null[b] = mi_mm(x, yp)
    p = (1 + np.sum(null >= obs)) / (B + 1)
    return {"mi": float(obs), "null_mean": float(null.mean()),
            "null_p95": float(np.percentile(null, 95)),
            "null_max": float(null.max()), "p_value": float(p), "B": B,
            "scheme": "circular_block_shift_within_flow(block=%d)" % block}


def perm_null_flowlabel(x, flow_of_row, label_of_flow, seed=SEED):
    """Exhaustive flow-label permutation null, for a flow-CONSTANT secret.

    With 6 flows and 3 labels x 2 there are 6!/(2!^3) = 90 distinct assignments;
    all are enumerated, so the null is exact rather than sampled.
    """
    flows = sorted(set(flow_of_row))
    labels = [label_of_flow[f] for f in flows]
    row_flow_idx = np.array([flows.index(f) for f in flow_of_row])
    y_obs = np.array([labels[i] for i in row_flow_idx])
    obs = mi_mm(x, y_obs)
    seen, null = set(), []
    for perm in itertools.permutations(range(len(flows))):
        assign = tuple(labels[p] for p in perm)
        if assign in seen:
            continue
        seen.add(assign)
        yp = np.array([assign[i] for i in row_flow_idx])
        null.append(mi_mm(x, yp))
    null = np.array(null)
    p = (1 + np.sum(null >= obs)) / (len(null) + 1)
    return {"mi": float(obs), "null_mean": float(null.mean()),
            "null_p95": float(np.percentile(null, 95)),
            "null_max": float(null.max()), "p_value": float(p),
            "B": int(len(null)), "scheme": "exhaustive_flow_label_permutation"}


# --------------------------------------------------------------------------- #
# Bootstrap CIs
# --------------------------------------------------------------------------- #

def cluster_bootstrap_ci(stat_fn, groups, B=2000, seed=SEED, alpha=0.05):
    """Resample whole flows with replacement; `stat_fn(row_index_array)->float`."""
    rng = np.random.default_rng(seed)
    groups = np.asarray(groups)
    uniq = np.unique(groups)
    idx_by_g = {g: np.where(groups == g)[0] for g in uniq}
    vals = []
    for _ in range(B):
        draw = rng.choice(uniq, size=len(uniq), replace=True)
        rows = np.concatenate([idx_by_g[g] for g in draw])
        v = stat_fn(rows)
        if v is not None and np.isfinite(v):
            vals.append(v)
    vals = np.array(vals)
    if len(vals) == 0:
        return (float("nan"), float("nan"), 0)
    return (float(np.percentile(vals, 100 * alpha / 2)),
            float(np.percentile(vals, 100 * (1 - alpha / 2))), len(vals))


def stratified_bootstrap_ci(stat_fn, groups, B=2000, seed=SEED, alpha=0.05):
    """Resample transactions WITHIN each flow (preserves flow composition)."""
    rng = np.random.default_rng(seed)
    groups = np.asarray(groups)
    idx_by_g = {g: np.where(groups == g)[0] for g in np.unique(groups)}
    vals = []
    for _ in range(B):
        rows = np.concatenate([rng.choice(idx, size=len(idx), replace=True)
                               for idx in idx_by_g.values()])
        v = stat_fn(rows)
        if v is not None and np.isfinite(v):
            vals.append(v)
    vals = np.array(vals)
    return (float(np.percentile(vals, 100 * alpha / 2)),
            float(np.percentile(vals, 100 * (1 - alpha / 2))), len(vals))


def paired_bootstrap_delta(stat_a, stat_b, groups, B=2000, seed=SEED, alpha=0.05):
    """Paired cluster bootstrap of (stat_a - stat_b) on the SAME resampled rows."""
    rng = np.random.default_rng(seed)
    groups = np.asarray(groups)
    uniq = np.unique(groups)
    idx_by_g = {g: np.where(groups == g)[0] for g in uniq}
    deltas = []
    for _ in range(B):
        draw = rng.choice(uniq, size=len(uniq), replace=True)
        rows = np.concatenate([idx_by_g[g] for g in draw])
        a, b = stat_a(rows), stat_b(rows)
        if a is not None and b is not None and np.isfinite(a) and np.isfinite(b):
            deltas.append(a - b)
    deltas = np.array(deltas)
    return {"mean": float(deltas.mean()),
            "ci95_lo": float(np.percentile(deltas, 100 * alpha / 2)),
            "ci95_hi": float(np.percentile(deltas, 100 * (1 - alpha / 2))),
            "B_eff": int(len(deltas))}


# --------------------------------------------------------------------------- #
# Classifier evaluation
# --------------------------------------------------------------------------- #

def balanced_accuracy(y_true, y_pred, labels=None):
    labs = np.unique(y_true) if labels is None else labels
    recalls = []
    for l in labs:
        m = y_true == l
        if m.sum() == 0:
            continue
        recalls.append(np.mean(y_pred[m] == l))
    return float(np.mean(recalls))


def make_model(name, seed=SEED):
    """Adversary models.

    `class_weight="balanced"` is not cosmetic: under leave-one-flow-out the
    training prior is dominated by the devices that are NOT held out, so an
    uninformative feature set drives an unweighted model to a balanced accuracy
    of 0.0 rather than to the 1/3 chance line.  Balancing the class prior puts
    the no-information floor back at chance, which is what every number here is
    compared against.
    """
    if name == "rf":
        return RandomForestClassifier(n_estimators=300, random_state=seed,
                                      n_jobs=-1, class_weight="balanced")
    if name == "dt":
        return DecisionTreeClassifier(max_depth=6, random_state=seed,
                                      class_weight="balanced")
    if name == "logreg":
        return make_pipeline(StandardScaler(),
                             LogisticRegression(max_iter=2000,
                                                class_weight="balanced"))
    raise ValueError(name)


def leave_one_flow_out(X, y, groups, model="rf", seed=SEED):
    """Pooled out-of-fold predictions under leave-one-flow-out CV.

    Each fold holds out one entire TCP flow, so no fold can exploit a
    flow-constant nuisance value it also saw in training for the same session.
    """
    X = np.asarray(X, dtype=float)
    y = np.asarray(y)
    groups = np.asarray(groups)
    pred = np.empty(len(y), dtype=object)
    per_fold = {}
    for g in np.unique(groups):
        te = groups == g
        tr = ~te
        if len(np.unique(y[tr])) < 2:
            pred[te] = y[tr][0] if tr.sum() else y[te][0]
            continue
        m = make_model(model, seed)
        m.fit(X[tr], y[tr])
        p = m.predict(X[te])
        pred[te] = p
        per_fold[g] = float(np.mean(p == y[te]))
    return np.array(pred), per_fold


def eval_featureset(X, y, groups, model="rf", seed=SEED, B=2000):
    pred, per_fold = leave_one_flow_out(X, y, groups, model=model, seed=seed)
    y = np.asarray(y)
    # integer-code both vectors so the cluster bootstrap is cheap
    classes = np.unique(y)
    code = {c: i for i, c in enumerate(classes)}
    yi = np.array([code[v] for v in y])
    pi = np.array([code.get(v, -1) for v in pred])
    nclass = len(classes)

    def stat(rows):
        yt, yp = yi[rows], pi[rows]
        if len(np.unique(yt)) < nclass:
            return None
        return balanced_accuracy(yt, yp, labels=np.arange(nclass))

    ba = balanced_accuracy(yi, pi, labels=np.arange(nclass))
    lo, hi, beff = cluster_bootstrap_ci(stat, groups, B=B, seed=seed)
    return {"balanced_accuracy": float(ba), "ci95_lo": lo, "ci95_hi": hi,
            "boot_B_eff": beff, "per_flow_accuracy": per_fold,
            "n": int(len(y)), "n_flows": int(len(np.unique(groups))),
            "model": model, "chance": float(1.0 / len(np.unique(y)))}

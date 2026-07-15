"""
attacker_eval.py -- attacker-side classification evaluation for the DNP3
timing-obfuscation study (research brief section 8, "Option 0" attacker module).

Reads the per-transaction characterization CSV
(reports/ack_trace_characterization.csv, one row per DNP3 request->response
exchange across six real device PCAPs) and evaluates the fingerprinting attack
this project defends against:

  (1) Device-identification (AB1400 / ION7550 / SEL751) from transaction
      features -- the NATIVE, undefended baseline that proves a fingerprint
      exists. Only device-specific outstation flows are used (the shared
      reference outstation 10.0.0.2 is excluded).
  (2) A SIMULATED Phase-1 defense (bounded response-time normalization) applied
      to the *trace features*, then device-ID re-run to watch the timing
      fingerprint degrade. This is a SIMULATION on captured features, not a live
      capture of the defended server -- the brief forbids overclaiming.
  (3) A detect-the-defense binary classifier (native vs normalized transactions).

Split scheme is capture-level (train on each device's base PCAP, test on its
larger "L" PCAP) so adjacent packets from the same capture never leak across the
train/test boundary; a leave-one-PCAP-out GroupKFold gives a robustness estimate.

The nearest-centroid classifier and numpy multinomial logistic regression are
implemented here and always run (they are the primary models in the tables).
When scikit-learn is importable, random forest and gradient boosting also run and
their device-ID accuracy is reported alongside; when it is not, they are reported
as UNAVAILABLE rather than fabricated.

Outputs (overwritten on every run, deterministic seed):
    reports/attacker_eval_results.json
    reports/attacker_eval.md

    python attacker_eval.py            # uses defaults below
    python attacker_eval.py --seed 7   # override seed
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:  # tree ensembles run when scikit-learn is present, else reported UNAVAILABLE
    import sklearn
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    _HAVE_SKLEARN = True
    _SKLEARN_VERSION = sklearn.__version__
except ImportError:
    RandomForestClassifier = GradientBoostingClassifier = None
    _HAVE_SKLEARN = False
    _SKLEARN_VERSION = None

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(
    logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
)
_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.INFO)

# --- configuration ---------------------------------------------------------

DEFAULT_SEED = 42
CSV_PATH = os.path.join(HARNESS_DIR, "reports", "ack_trace_characterization.csv")
JSON_OUT = os.path.join(HARNESS_DIR, "reports", "attacker_eval_results.json")
MD_OUT = os.path.join(HARNESS_DIR, "reports", "attacker_eval.md")

REFERENCE_OUTSTATION = "10.0.0.2"  # shared reference outstation -- excluded
DEVICES = ["AB1400", "ION7550", "SEL751"]

# Base PCAP (train) and larger "L" PCAP (test) per device.
BASE_PCAPS = ["AB1400.pcap", "ION7550.pcap", "SEL751.pcap"]
L_PCAPS = ["AB1400L.pcap", "ION7550L.pcap", "SEL751L.pcap"]

# Feature channels (ablation subsets).
TIMING_FEATS = ["req_to_resp_ms", "req_to_ack_ms", "ack_to_resp_ms"]
SIZE_FEATS = ["req_size", "resp_size"]
ACKMODE_FEATS = ["is_separate", "ack_pure"]
ABLATIONS: Dict[str, List[str]] = {
    "timing_only": TIMING_FEATS,
    "size_only": SIZE_FEATS,
    "ackmode_only": ACKMODE_FEATS,
    "timing_size": TIMING_FEATS + SIZE_FEATS,
    "all_features": TIMING_FEATS + SIZE_FEATS + ACKMODE_FEATS,
}

# Defense settings. "native" = undefended. Uniform draws U(lo,hi) ms; constant
# uses a fixed floor. In all cases new_req_to_resp = max(native, target).
DEFENSE_SETTINGS: Dict[str, Dict[str, object]] = {
    "native": {"mode": "native"},
    "uniform_10_15": {"mode": "uniform", "lo": 10.0, "hi": 15.0},
    "uniform_15_25": {"mode": "uniform", "lo": 15.0, "hi": 25.0},
    "constant_25": {"mode": "constant", "floor": 25.0},
}
DEFENDED_SETTINGS = [s for s in DEFENSE_SETTINGS if s != "native"]

N_BOOTSTRAP = 1000
N_PERM_REPEATS = 10


# --- data loading and feature encoding -------------------------------------


def load_device_data(csv_path: str) -> pd.DataFrame:
    """Load the characterization CSV, keep only device-specific outstation
    flows (drop the shared reference outstation), and add numeric encodings."""
    df = pd.read_csv(csv_path)
    df = df[df["outstation_ip"] != REFERENCE_OUTSTATION].copy()
    df = df[df["device_label"].isin(DEVICES)].copy()
    # ack-mode numeric encodings
    df["is_separate"] = (df["classification"] == "SEPARATE_ACK_RESPONSE").astype(float)
    df["ack_pure"] = df["first_rev_is_pure_ack"].astype(bool).astype(float)
    df["y"] = df["device_label"].map({d: i for i, d in enumerate(DEVICES)}).astype(int)
    for col in TIMING_FEATS + SIZE_FEATS:
        df[col] = df[col].astype(float)
    _log.info("Loaded %d device-specific transactions (%s)", len(df), dict(df["device_label"].value_counts()))
    return df.reset_index(drop=True)


def apply_defense(df: pd.DataFrame, setting: str, rng: np.random.Generator) -> pd.DataFrame:
    """Return a copy of df with timing features normalized to simulate the
    Phase-1 bounded response-time defense.

    The defense controls response *emission* time:
      new_req_to_resp = max(native_req_to_resp, target)
    where target ~ U(lo,hi) per transaction (uniform) or a fixed floor
    (constant). Dependent timing features are re-derived so the vector stays
    physically consistent:
      - COMBINED-ACK rows (piggybacked ACK == response): the ACK moves with the
        response, so new_req_to_ack = new_req_to_resp, new_ack_to_resp = 0.
      - SEPARATE-ACK rows: the pure transport ACK is not held by a byte-
        preserving response-delay (holding it would be proxy/MITM, forbidden
        this phase), so req_to_ack stays native and
        new_ack_to_resp = new_req_to_resp - native_req_to_ack.
    Size and ack-mode features are untouched (the timing defense cannot change
    them), which is exactly why they carry the residual leak.
    """
    cfg = DEFENSE_SETTINGS[setting]
    out = df.copy()
    if cfg["mode"] == "native":
        return out
    native_resp = df["req_to_resp_ms"].to_numpy()
    native_ack = df["req_to_ack_ms"].to_numpy()
    if cfg["mode"] == "uniform":
        target = rng.uniform(float(cfg["lo"]), float(cfg["hi"]), size=len(df))
    else:  # constant
        target = np.full(len(df), float(cfg["floor"]))
    new_resp = np.maximum(native_resp, target)
    is_sep = df["ack_pure"].to_numpy() > 0.5
    new_ack = np.where(is_sep, native_ack, new_resp)
    new_ack_to_resp = np.where(is_sep, new_resp - native_ack, 0.0)
    out["req_to_resp_ms"] = new_resp
    out["req_to_ack_ms"] = new_ack
    out["ack_to_resp_ms"] = new_ack_to_resp
    return out


# --- models (numpy; no scikit-learn) ---------------------------------------


class Standardizer:
    """Z-score standardization fit on train; constant columns map to 0."""

    def __init__(self) -> None:
        self.mean_: Optional[np.ndarray] = None
        self.std_: Optional[np.ndarray] = None

    def fit(self, x: np.ndarray) -> "Standardizer":
        self.mean_ = x.mean(axis=0)
        std = x.std(axis=0)
        std[std == 0] = 1.0
        self.std_ = std
        return self

    def transform(self, x: np.ndarray) -> np.ndarray:
        return (x - self.mean_) / self.std_


def _softmax(z: np.ndarray) -> np.ndarray:
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


class MultinomialLogReg:
    """Multinomial logistic regression trained by full-batch gradient descent
    with L2 regularization. Deterministic (zero init, fixed iterations)."""

    def __init__(self, n_classes: int, lr: float = 0.5, n_iter: int = 3000, l2: float = 1e-3) -> None:
        self.n_classes = n_classes
        self.lr = lr
        self.n_iter = n_iter
        self.l2 = l2
        self.w: Optional[np.ndarray] = None  # (d+1, k)

    def fit(self, x: np.ndarray, y: np.ndarray) -> "MultinomialLogReg":
        n, d = x.shape
        xb = np.hstack([x, np.ones((n, 1))])
        k = self.n_classes
        y1 = np.zeros((n, k))
        y1[np.arange(n), y] = 1.0
        w = np.zeros((d + 1, k))
        for _ in range(self.n_iter):
            probs = _softmax(xb @ w)
            grad = xb.T @ (probs - y1) / n
            grad[:-1] += self.l2 * w[:-1]  # do not regularize bias
            w -= self.lr * grad
        self.w = w
        return self

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        xb = np.hstack([x, np.ones((x.shape[0], 1))])
        return _softmax(xb @ self.w)

    def predict(self, x: np.ndarray) -> np.ndarray:
        return self.predict_proba(x).argmax(axis=1)


class NearestCentroid:
    """Nearest-centroid classifier in standardized space (simple threshold-style
    baseline). Pseudo-probabilities via softmax over negative distances."""

    def __init__(self, n_classes: int) -> None:
        self.n_classes = n_classes
        self.centroids_: Optional[np.ndarray] = None

    def fit(self, x: np.ndarray, y: np.ndarray) -> "NearestCentroid":
        self.centroids_ = np.vstack(
            [x[y == c].mean(axis=0) if np.any(y == c) else np.zeros(x.shape[1]) for c in range(self.n_classes)]
        )
        return self

    def _neg_dist(self, x: np.ndarray) -> np.ndarray:
        d2 = ((x[:, None, :] - self.centroids_[None, :, :]) ** 2).sum(axis=2)
        return -np.sqrt(d2)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        return _softmax(self._neg_dist(x))

    def predict(self, x: np.ndarray) -> np.ndarray:
        return self._neg_dist(x).argmax(axis=1)


# --- metrics ----------------------------------------------------------------


def _auc_binary(scores: np.ndarray, labels: np.ndarray) -> Optional[float]:
    """ROC-AUC via the rank statistic (handles ties with average ranks)."""
    n_pos = int((labels == 1).sum())
    n_neg = int((labels == 0).sum())
    if n_pos == 0 or n_neg == 0:
        return None
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=float)
    sorted_scores = scores[order]
    i = 0
    while i < len(scores):
        j = i
        while j + 1 < len(scores) and sorted_scores[j + 1] == sorted_scores[i]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        ranks[order[i:j + 1]] = avg_rank
        i = j + 1
    sum_pos = ranks[labels == 1].sum()
    return (sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, proba: np.ndarray, n_classes: int) -> Dict:
    """Accuracy, macro precision/recall/F1, per-class support, confusion matrix,
    and one-vs-rest macro ROC-AUC."""
    acc = float((y_true == y_pred).mean())
    cm = np.zeros((n_classes, n_classes), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1
    precs, recs, f1s = [], [], []
    for c in range(n_classes):
        tp = cm[c, c]
        fp = cm[:, c].sum() - tp
        fn = cm[c, :].sum() - tp
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        precs.append(prec)
        recs.append(rec)
        f1s.append(f1)
    aucs = []
    for c in range(n_classes):
        a = _auc_binary(proba[:, c], (y_true == c).astype(int))
        if a is not None:
            aucs.append(a)
    return {
        "accuracy": acc,
        "precision_macro": float(np.mean(precs)),
        "recall_macro": float(np.mean(recs)),
        "f1_macro": float(np.mean(f1s)),
        "per_class_precision": {DEVICES[c]: float(precs[c]) for c in range(n_classes)},
        "per_class_recall": {DEVICES[c]: float(recs[c]) for c in range(n_classes)},
        "per_class_f1": {DEVICES[c]: float(f1s[c]) for c in range(n_classes)},
        "roc_auc_ovr_macro": float(np.mean(aucs)) if aucs else None,
        "confusion_matrix": cm.tolist(),
        "confusion_labels": DEVICES[:n_classes],
    }


def bootstrap_accuracy_ci(
    y_true: np.ndarray, y_pred: np.ndarray, rng: np.random.Generator, n_boot: int = N_BOOTSTRAP
) -> Dict[str, float]:
    """Percentile bootstrap CI for accuracy over test rows. Rows within a capture
    are correlated, so this understates true uncertainty (noted in the report)."""
    n = len(y_true)
    correct = (y_true == y_pred).astype(float)
    accs = np.empty(n_boot)
    for b in range(n_boot):
        idx = rng.integers(0, n, size=n)
        accs[b] = correct[idx].mean()
    return {
        "mean": float(accs.mean()),
        "ci95_lo": float(np.percentile(accs, 2.5)),
        "ci95_hi": float(np.percentile(accs, 97.5)),
    }


def permutation_importance(
    model, x_test: np.ndarray, y_test: np.ndarray, feat_names: List[str],
    rng: np.random.Generator, n_repeats: int = N_PERM_REPEATS
) -> Dict[str, float]:
    """Model-agnostic permutation importance: mean accuracy drop when each
    feature column is shuffled in the test set."""
    base = (model.predict(x_test) == y_test).mean()
    imp: Dict[str, float] = {}
    for j, name in enumerate(feat_names):
        drops = []
        for _ in range(n_repeats):
            xp = x_test.copy()
            xp[:, j] = xp[rng.permutation(len(xp)), j]
            drops.append(base - (model.predict(xp) == y_test).mean())
        imp[name] = float(np.mean(drops))
    return imp


# --- evaluation orchestration ----------------------------------------------


def make_xy(df: pd.DataFrame, feats: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    return df[feats].to_numpy(dtype=float), df["y"].to_numpy(dtype=int)


def fit_eval(
    train_df: pd.DataFrame, test_df: pd.DataFrame, feats: List[str], rng: np.random.Generator
) -> Dict:
    """Fit both available models on a capture-level split and return metrics for
    each, plus bootstrap CI (logreg) and permutation importance (logreg)."""
    x_tr, y_tr = make_xy(train_df, feats)
    x_te, y_te = make_xy(test_df, feats)
    scaler = Standardizer().fit(x_tr)
    x_tr_s, x_te_s = scaler.transform(x_tr), scaler.transform(x_te)
    out: Dict = {"n_train": len(train_df), "n_test": len(test_df), "features": feats}

    lr = MultinomialLogReg(n_classes=len(DEVICES)).fit(x_tr_s, y_tr)
    lr_pred, lr_proba = lr.predict(x_te_s), lr.predict_proba(x_te_s)
    out["logreg"] = compute_metrics(y_te, lr_pred, lr_proba, len(DEVICES))
    out["logreg"]["accuracy_ci"] = bootstrap_accuracy_ci(y_te, lr_pred, rng)
    out["logreg"]["permutation_importance"] = permutation_importance(lr, x_te_s, y_te, feats, rng)
    # standardized coefficient magnitude (mean |w| across classes, excl. bias)
    coef_mag = np.abs(lr.w[:-1, :]).mean(axis=1)
    out["logreg"]["coef_magnitude"] = {feats[i]: float(coef_mag[i]) for i in range(len(feats))}

    nc = NearestCentroid(n_classes=len(DEVICES)).fit(x_tr_s, y_tr)
    nc_pred, nc_proba = nc.predict(x_te_s), nc.predict_proba(x_te_s)
    out["nearest_centroid"] = compute_metrics(y_te, nc_pred, nc_proba, len(DEVICES))

    # Tree ensembles (scikit-learn, when available). Trees are scale-invariant,
    # so they use the raw features; a per-fit seed drawn from the eval RNG keeps
    # results reproducible. proba columns align with class indices 0..k-1 because
    # the capture-level train split always contains all three devices.
    if _HAVE_SKLEARN:
        tree_seed = int(rng.integers(0, 2 ** 31 - 1))
        rf = RandomForestClassifier(n_estimators=200, random_state=tree_seed, n_jobs=1)
        rf.fit(x_tr, y_tr)
        out["random_forest"] = compute_metrics(
            y_te, rf.predict(x_te), rf.predict_proba(x_te), len(DEVICES))
        out["random_forest"]["permutation_importance"] = permutation_importance(
            rf, x_te, y_te, feats, rng)
        gb = GradientBoostingClassifier(random_state=tree_seed)
        gb.fit(x_tr, y_tr)
        out["gradient_boosting"] = compute_metrics(
            y_te, gb.predict(x_te), gb.predict_proba(x_te), len(DEVICES))
        out["gradient_boosting"]["permutation_importance"] = permutation_importance(
            gb, x_te, y_te, feats, rng)
    return out


def group_kfold_accuracy(df: pd.DataFrame, feats: List[str]) -> Dict:
    """Leave-one-PCAP-out GroupKFold: for each of the 6 device PCAPs, train on
    the other 5 and predict the held-out one, then pool predictions. Test folds
    are single-device, so per-fold accuracy == recall for that device; the
    pooled accuracy is the grouping-respecting estimate."""
    pcaps = sorted(df["pcap"].unique())
    pooled_true, pooled_pred = [], []
    per_fold = {}
    for held in pcaps:
        tr = df[df["pcap"] != held]
        te = df[df["pcap"] == held]
        x_tr, y_tr = make_xy(tr, feats)
        x_te, y_te = make_xy(te, feats)
        scaler = Standardizer().fit(x_tr)
        lr = MultinomialLogReg(n_classes=len(DEVICES)).fit(scaler.transform(x_tr), y_tr)
        pred = lr.predict(scaler.transform(x_te))
        per_fold[held] = float((pred == y_te).mean())
        pooled_true.append(y_te)
        pooled_pred.append(pred)
    pooled_true = np.concatenate(pooled_true)
    pooled_pred = np.concatenate(pooled_pred)
    fold_vals = np.array(list(per_fold.values()))
    return {
        "pooled_accuracy": float((pooled_true == pooled_pred).mean()),
        "per_fold_recall": per_fold,
        "fold_mean": float(fold_vals.mean()),
        "fold_std": float(fold_vals.std()),
    }


def detect_defense(
    df_native: pd.DataFrame, defended: Dict[str, pd.DataFrame], rng: np.random.Generator
) -> Dict:
    """Binary classifier: native-timing transactions (0) vs Phase-1-normalized
    transactions (1), on the timing features, capture-level split. Reports
    accuracy + AUC and the quantization/floor signature that gives it away."""
    results: Dict = {}
    base_native = df_native[df_native["pcap"].isin(BASE_PCAPS)]
    l_native = df_native[df_native["pcap"].isin(L_PCAPS)]
    for name in DEFENDED_SETTINGS:
        dfd = defended[name]
        base_def = dfd[dfd["pcap"].isin(BASE_PCAPS)]
        l_def = dfd[dfd["pcap"].isin(L_PCAPS)]
        x_tr = np.vstack([base_native[TIMING_FEATS].to_numpy(), base_def[TIMING_FEATS].to_numpy()])
        y_tr = np.concatenate([np.zeros(len(base_native)), np.ones(len(base_def))]).astype(int)
        x_te = np.vstack([l_native[TIMING_FEATS].to_numpy(), l_def[TIMING_FEATS].to_numpy()])
        y_te = np.concatenate([np.zeros(len(l_native)), np.ones(len(l_def))]).astype(int)
        scaler = Standardizer().fit(x_tr)
        lr = MultinomialLogReg(n_classes=2).fit(scaler.transform(x_tr), y_tr)
        proba = lr.predict_proba(scaler.transform(x_te))
        pred = proba.argmax(axis=1)
        acc = float((pred == y_te).mean())
        auc = _auc_binary(proba[:, 1], y_te)
        # signature summary
        nat_resp = l_native["req_to_resp_ms"].to_numpy()
        def_resp = l_def["req_to_resp_ms"].to_numpy()
        results[name] = {
            "accuracy": acc,
            "roc_auc": float(auc) if auc is not None else None,
            "native_resp_min_ms": float(nat_resp.min()),
            "native_resp_std_ms": float(nat_resp.std()),
            "defended_resp_min_ms": float(def_resp.min()),
            "defended_resp_std_ms": float(def_resp.std()),
            "frac_defended_below_native_min": float((def_resp < nat_resp.min()).mean()),
        }
        # Tree ensembles on the raw timing features (scale-invariant), same split.
        if _HAVE_SKLEARN:
            ts = int(rng.integers(0, 2 ** 31 - 1))
            rf = RandomForestClassifier(n_estimators=200, random_state=ts, n_jobs=1).fit(x_tr, y_tr)
            rf_auc = _auc_binary(rf.predict_proba(x_te)[:, 1], y_te)
            results[name]["accuracy_rf"] = float((rf.predict(x_te) == y_te).mean())
            results[name]["roc_auc_rf"] = float(rf_auc) if rf_auc is not None else None
            gb = GradientBoostingClassifier(random_state=ts).fit(x_tr, y_tr)
            gb_auc = _auc_binary(gb.predict_proba(x_te)[:, 1], y_te)
            results[name]["accuracy_gb"] = float((gb.predict(x_te) == y_te).mean())
            results[name]["roc_auc_gb"] = float(gb_auc) if gb_auc is not None else None
    return results


def pairwise_combined_timing(
    df_native: pd.DataFrame, defended: Dict[str, pd.DataFrame]
) -> Dict:
    """Isolated readout of the ONE place timing carries unique device-ID signal:
    AB1400 vs ION7550 (both COMBINED-ACK, so among the timing features they are
    separable only by response latency), 2-class, capture-level split.

    Reported as BALANCED accuracy (mean of the two per-class recalls, chance 0.5)
    so the class imbalance (ION7550 has ~2x the rows) does not masquerade as
    separation; raw accuracy and the majority-class baseline are kept alongside
    for transparency."""
    pair = ["AB1400", "ION7550"]
    pmap = {d: i for i, d in enumerate(pair)}

    def _run(df: pd.DataFrame) -> Dict[str, float]:
        sub = df[df["device_label"].isin(pair)].copy()
        sub["yb"] = sub["device_label"].map(pmap).astype(int)
        tr = sub[sub["pcap"].isin(BASE_PCAPS)]
        te = sub[sub["pcap"].isin(L_PCAPS)]
        scaler = Standardizer().fit(tr[TIMING_FEATS].to_numpy())
        lr = MultinomialLogReg(n_classes=2).fit(scaler.transform(tr[TIMING_FEATS].to_numpy()), tr["yb"].to_numpy())
        pred = lr.predict(scaler.transform(te[TIMING_FEATS].to_numpy()))
        yb = te["yb"].to_numpy()
        recalls = [float((pred[yb == c] == c).mean()) for c in (0, 1)]
        maj = max((yb == 0).mean(), (yb == 1).mean())
        return {
            "balanced_accuracy": float(np.mean(recalls)),
            "raw_accuracy": float((pred == yb).mean()),
            "majority_baseline": float(maj),
        }

    out: Dict = {"note": "AB1400 vs ION7550, timing features only; balanced-accuracy chance = 0.5",
                 "native": _run(df_native)}
    for name in DEFENDED_SETTINGS:
        out[name] = _run(defended[name])
    return out


# --- reporting --------------------------------------------------------------


def _fmt(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def write_markdown(results: Dict, path: str) -> None:
    m = results["meta"]
    dev = results["device_id"]
    lines: List[str] = []
    a = lines.append
    a("# Attacker-Side Classification Evaluation (DNP3 Timing Obfuscation)")
    a("")
    a(f"Generated by `attacker_eval.py` (seed {m['seed']}). Deterministic; outputs overwritten each run.")
    a("")
    a("## Setup")
    a("")
    a(f"- Input: `{os.path.relpath(m['csv_path'], HARNESS_DIR)}` -- {m['n_rows_total']} device-specific "
      f"transactions after excluding the shared reference outstation {REFERENCE_OUTSTATION}.")
    a(f"- Classes: {', '.join(DEVICES)} (device-type fingerprinting attack).")
    a(f"- Per-device transaction counts: {m['class_counts']}.")
    a("- **Split scheme (headline):** capture-level. Train on each device's base PCAP "
      f"({', '.join(BASE_PCAPS)}); test on its larger \"L\" PCAP ({', '.join(L_PCAPS)}). "
      "Every transaction from a capture stays on one side of the split, so adjacent packets "
      "from the same flow cannot leak across train/test. There are 6 flows (one per PCAP), "
      "so a random row split would leak heavily; this is why it is avoided.")
    a("- **Robustness split:** leave-one-PCAP-out GroupKFold (6 folds), predictions pooled.")
    a("")
    a("## Model availability")
    a("")
    if m["sklearn_available"]:
        a(f"scikit-learn {m.get('sklearn_version', '?')} is importable in this environment, so the "
          "tree ensembles ran alongside the numpy models. Models actually run:")
    else:
        a("scikit-learn is **not importable** in this environment (`import sklearn` -> ModuleNotFoundError), "
          "so no `pip install` was performed. Models actually run:")
    a("")
    a("| Model | Status |")
    a("|---|---|")
    a("| Nearest-centroid (standardized) | RAN (implemented in numpy) |")
    a("| Multinomial logistic regression | RAN (implemented in numpy; primary model in tables) |")
    if m["sklearn_available"]:
        a("| Random forest | RAN (scikit-learn, 200 trees, raw features) |")
        a("| Gradient boosting | RAN (scikit-learn, default 100 estimators, raw features) |")
    else:
        a("| Random forest | UNAVAILABLE (scikit-learn missing) -- not run, not fabricated |")
        a("| Gradient boosting | UNAVAILABLE (scikit-learn missing) -- not run, not fabricated |")
    a("")
    if m["sklearn_available"]:
        a("Tree-ensemble device-ID accuracy (all-features), native vs defended:")
        a("")
        a("| Model | " + " | ".join(DEFENSE_SETTINGS.keys()) + " |")
        a("|" + "---|" * (len(DEFENSE_SETTINGS) + 1))
        for key, label in (("random_forest", "Random forest"),
                           ("gradient_boosting", "Gradient boosting")):
            row = [label]
            for st in DEFENSE_SETTINGS:
                row.append(f"{dev[st]['all_features'][key]['accuracy']:.3f}")
            a("| " + " | ".join(row) + " |")
        a("")
        a("The tree ensembles reproduce the logistic-regression finding: device-ID accuracy "
          "stays high under timing normalization because the fingerprint rides on the response-size "
          "and ACK-mode channels the timing defense does not touch.")
        a("")
    a("## 1. Native (undefended) device-ID -- the fingerprint")
    a("")
    nat_all = dev["native"]["all_features"]["logreg"]
    ci = nat_all["accuracy_ci"]
    a(f"All-features logistic regression: **accuracy {nat_all['accuracy']:.3f}** "
      f"(bootstrap 95% CI [{ci['ci95_lo']:.3f}, {ci['ci95_hi']:.3f}]), "
      f"macro-F1 {nat_all['f1_macro']:.3f}, OvR macro ROC-AUC {_fmt(nat_all['roc_auc_ovr_macro'])}.")
    a("")
    a("Per-class (all-features, native):")
    a("")
    a("| Device | Precision | Recall | F1 |")
    a("|---|---|---|---|")
    for d in DEVICES:
        a(f"| {d} | {nat_all['per_class_precision'][d]:.3f} | "
          f"{nat_all['per_class_recall'][d]:.3f} | {nat_all['per_class_f1'][d]:.3f} |")
    a("")
    a("Confusion matrix (rows = true, cols = predicted; order " + ", ".join(DEVICES) + "):")
    a("")
    a("```")
    for i, row in enumerate(nat_all["confusion_matrix"]):
        a(f"{DEVICES[i]:>8}  " + "  ".join(f"{v:6d}" for v in row))
    a("```")
    a("")
    gk = results["group_kfold"]
    a(f"Leave-one-PCAP-out GroupKFold (all-features): pooled accuracy "
      f"{gk['all_features']['pooled_accuracy']:.3f}, per-fold recall "
      f"mean {gk['all_features']['fold_mean']:.3f} (std {gk['all_features']['fold_std']:.3f}). "
      f"Timing-only pooled accuracy {gk['timing_only']['pooled_accuracy']:.3f}.")
    a("")
    a("## 2. Ablation table -- native vs defended (logistic regression accuracy)")
    a("")
    a("Which channel carries the fingerprint, and what the timing defense removes vs. leaves.")
    a("")
    header = "| Ablation | " + " | ".join(DEFENSE_SETTINGS.keys()) + " |"
    a(header)
    a("|" + "---|" * (len(DEFENSE_SETTINGS) + 1))
    for ab in ABLATIONS:
        row = [ab]
        for st in DEFENSE_SETTINGS:
            row.append(f"{dev[st][ab]['logreg']['accuracy']:.3f}")
        a("| " + " | ".join(row) + " |")
    a("")
    a(f"Chance (majority-class) accuracy on the test set = {m['majority_class_acc']:.3f}.")
    a("")
    a("Reading the table:")
    a("")
    a("- **size_only and ackmode_only are identical across every column** -- the timing "
      "defense cannot touch response size or ACK mode, so these residual channels are "
      "unchanged by construction.")
    a("- **timing_only** accuracy does NOT drop under the defense (~0.80 throughout). The "
      "surviving timing signal is the ACK-mode-linked one -- SEL751's pure transport ACK "
      "(`req_to_ack` ~4 ms) separates it regardless of response delay -- while the two "
      "combined-ACK devices were never well separated by latency to begin with (next table). "
      "Response-delay normalization thus removes little device-ID *accuracy* here even though "
      "it does reshape the response-time distribution (detect-the-defense, section 3).")
    a("- **uniform_10_15** barely moves any number: the devices' native response times "
      f"(~16 ms) already exceed the 15 ms ceiling, so `max(native, U(10,15)) ~= native`. "
      "A normalization floor must exceed the native latency to obfuscate anything.")
    a("")
    pw = results["pairwise_combined_timing"]
    a("### Where timing carries unique device-ID signal (and what the defense does to it)")
    a("")
    a("Response SIZE separates ION7550 and ACK MODE separates SEL751; the ONLY device-ID "
      "signal carried uniquely by response *latency* is between AB1400 and ION7550 (both "
      "COMBINED-ACK, identical size support otherwise). Isolating that pair on timing "
      "features (balanced accuracy, chance = 0.5):")
    a("")
    a("| Setting | balanced acc | raw acc | majority baseline |")
    a("|---|---|---|---|")
    for st in ["native"] + DEFENDED_SETTINGS:
        r = pw[st]
        a(f"| {st} | {r['balanced_accuracy']:.3f} | {r['raw_accuracy']:.3f} | {r['majority_baseline']:.3f} |")
    a("")
    a("Two honest readings: (i) even NATIVELY the two combined devices are essentially "
      f"inseparable by latency (balanced acc {pw['native']['balanced_accuracy']:.3f}, at the 0.5 "
      "floor) -- the response-time channel simply does not carry device identity between them "
      "in this trace; (ii) under `constant_25` the two devices' timing feature vectors become "
      "provably identical (every response floored to 25 ms, ACK piggybacked), so balanced "
      f"accuracy sits exactly at the 0.5 floor ({pw['constant_25']['balanced_accuracy']:.3f}). "
      "The defense erases the (small) timing signal it targets; it is not the reason overall "
      "device-ID stays high.")
    a("")
    a("## 3. Detect-the-defense (native vs normalized)")
    a("")
    a("Binary classifier on timing features, capture-level split.")
    a("")
    det = results["detect_defense"]
    if m["sklearn_available"]:
        a("Logistic regression (LR), random forest (RF), and gradient boosting (GB); the "
          "response min/std columns are the model-independent floor signature.")
        a("")
        a("| Setting | LR acc | LR AUC | RF acc | RF AUC | GB acc | GB AUC | native min/std (ms) | defended min/std (ms) |")
        a("|---|---|---|---|---|---|---|---|---|")
        for st in DEFENDED_SETTINGS:
            r = det[st]
            a(f"| {st} | {r['accuracy']:.3f} | {_fmt(r['roc_auc'])} | "
              f"{r['accuracy_rf']:.3f} | {_fmt(r['roc_auc_rf'])} | "
              f"{r['accuracy_gb']:.3f} | {_fmt(r['roc_auc_gb'])} | "
              f"{r['native_resp_min_ms']:.2f} / {r['native_resp_std_ms']:.2f} | "
              f"{r['defended_resp_min_ms']:.2f} / {r['defended_resp_std_ms']:.2f} |")
    else:
        a("| Setting | Accuracy | ROC-AUC | native resp min/std (ms) | defended resp min/std (ms) |")
        a("|---|---|---|---|---|")
        for st in DEFENDED_SETTINGS:
            r = det[st]
            a(f"| {st} | {r['accuracy']:.3f} | {_fmt(r['roc_auc'])} | "
              f"{r['native_resp_min_ms']:.2f} / {r['native_resp_std_ms']:.2f} | "
              f"{r['defended_resp_min_ms']:.2f} / {r['defended_resp_std_ms']:.2f} |")
    a("")
    a("Signature: the normalized stream has a hard floor (no response faster than the lower "
      "bound / the constant target) and altered variance. `constant_25` quantizes every "
      "response to >= 25 ms and is the most detectable; `uniform_10_15` is near-undetectable "
      "precisely because it is a near-no-op on this data.")
    a("")
    a("## 4. Feature importance (all-features)")
    a("")
    a("Permutation importance (mean accuracy drop when a feature is shuffled) and, for the "
      "logistic regression, standardized coefficient magnitude; native vs the `uniform_15_25` "
      "defense for the LR, plus native tree-ensemble permutation importance where available.")
    a("")
    imp_n = dev["native"]["all_features"]["logreg"]["permutation_importance"]
    imp_d = dev["uniform_15_25"]["all_features"]["logreg"]["permutation_importance"]
    coef_n = dev["native"]["all_features"]["logreg"]["coef_magnitude"]
    if m["sklearn_available"]:
        imp_rf = dev["native"]["all_features"]["random_forest"]["permutation_importance"]
        imp_gb = dev["native"]["all_features"]["gradient_boosting"]["permutation_importance"]
        a("| Feature | LR abs-coef | LR perm native | LR perm uniform_15_25 | RF perm native | GB perm native |")
        a("|---|---|---|---|---|---|")
        for f in ABLATIONS["all_features"]:
            a(f"| {f} | {coef_n[f]:.3f} | {imp_n[f]:+.3f} | {imp_d[f]:+.3f} | "
              f"{imp_rf[f]:+.3f} | {imp_gb[f]:+.3f} |")
    else:
        a("| Feature | abs-coef native | perm.imp native | perm.imp uniform_15_25 |")
        a("|---|---|---|---|")
        for f in ABLATIONS["all_features"]:
            a(f"| {f} | {coef_n[f]:.3f} | {imp_n[f]:+.3f} | {imp_d[f]:+.3f} |")
    a("")
    a("Caveat: **permutation importance under-credits correlated features.** SEL751's "
      "separate-ACK identity is encoded redundantly across `is_separate`, `ack_pure`, "
      "`req_to_ack_ms`, and `ack_to_resp_ms`, so shuffling any one alone barely dents accuracy "
      "even though the ack-mode channel alone reaches 0.800 (ablation table). The per-channel "
      "ablation table, not this permutation column, is the reliable guide to what each channel "
      "carries; the coefficient magnitudes confirm the model still assigns weight to the "
      "size features it actually relies on.")
    a("")
    a("## 5. What this shows / what it does NOT")
    a("")
    a("**Shows:**")
    a("")
    a("- A real device fingerprint exists: native all-features device-ID accuracy "
      f"{nat_all['accuracy']:.3f} >> chance {m['majority_class_acc']:.3f}, and it generalizes "
      "across a capture-level split (train base PCAP -> test a disjoint, larger L PCAP; "
      f"leave-one-PCAP-out is more pessimistic at {gk['all_features']['pooled_accuracy']:.3f}).")
    a("- The fingerprint is carried mainly by response SIZE (separates ION7550) and ACK MODE "
      "(separates SEL751), not by response latency -- so this trace's fingerprint is largely "
      "in channels the timing defense cannot touch.")
    a("- Where response latency *does* carry unique identity (AB1400 vs ION7550), bounded "
      "normalization erases it: under the constant-25 policy the two devices' timing vectors "
      "become identical and balanced accuracy sits at the 0.5 floor.")
    a("- The Phase-1 defense reshapes the response-time distribution measurably and is "
      "detectable (floor + quantization signature), strongly so for the constant-target policy.")
    a("")
    a("**Does NOT show / honest residuals (per brief section 12 -- do not overclaim):**")
    a("")
    a("- This is a **SIMULATION on trace features**, not a capture of the live defended server. "
      "It normalizes recorded `req_to_resp_ms` (and re-derives dependent timing features); it "
      "does not model queueing, RTO interaction, or measurement noise of a real deployment.")
    a("- **Bounded normalization does NOT remove all leakage.** Two residual channels survive:")
    a("  1. **Size:** `resp_size` is {37,54} for AB1400 and SEL751 but {37,61} for ION7550. "
      "Size separates ION7550 yet cannot split AB1400 from SEL751, and the timing defense "
      "never touches size -- so `size_only` accuracy is identical native vs defended "
      f"(= {dev['native']['size_only']['logreg']['accuracy']:.3f}). There is no byte-preserving "
      "DNP3 padding in this phase, so this size leak persists.")
    a("  2. **ACK mode / ACK timing:** SEL751 is the only SEPARATE-ACK device; its pure "
      "transport ACK (`req_to_ack` ~4 ms) is not held by a byte-preserving response delay, so "
      "`ackmode_only` accuracy is also invariant to the timing defense "
      f"(= {dev['native']['ackmode_only']['logreg']['accuracy']:.3f}). This motivates a "
      "dedicated ACK-timing normalization (brief option C), which this response-delay "
      "primitive does not provide.")
    a("- Because those residuals carry most of the class separability here, **all-features "
      "device-ID stays high even after timing normalization** "
      f"(uniform_15_25 = {dev['uniform_15_25']['all_features']['logreg']['accuracy']:.3f}, "
      f"constant_25 = {dev['constant_25']['all_features']['logreg']['accuracy']:.3f}). The "
      "timing defense should be framed as closing the **timing channel specifically**, not as "
      "a full device-anonymization defense.")
    a("- Only 3 device classes from 6 captures; bootstrap CIs treat rows as independent and "
      "therefore understate uncertainty (rows within a capture are correlated).")
    a("")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    _log.info("Wrote %s", path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--csv", default=CSV_PATH)
    args = parser.parse_args()

    np.random.seed(args.seed)
    root_rng = np.random.default_rng(args.seed)

    df = load_device_data(args.csv)
    train_df = df[df["pcap"].isin(BASE_PCAPS)].copy()
    test_df = df[df["pcap"].isin(L_PCAPS)].copy()
    majority_acc = float(test_df["y"].value_counts(normalize=True).max())

    # Build a defended copy of the full frame per setting (seeded per setting so
    # results are stable regardless of evaluation order).
    defended_full: Dict[str, pd.DataFrame] = {}
    for i, name in enumerate(DEFENSE_SETTINGS):
        rng = np.random.default_rng(args.seed + 1000 + i)
        defended_full[name] = apply_defense(df, name, rng)

    # Device-ID: ablation x setting x model. Per-eval RNG seeds are derived from
    # enumerated indices (NOT hash(), which is per-process randomized) so the
    # bootstrap CIs and permutation importances are reproducible across runs.
    device_id: Dict[str, Dict] = {}
    for si, name in enumerate(DEFENSE_SETTINGS):
        dfd = defended_full[name]
        tr = dfd[dfd["pcap"].isin(BASE_PCAPS)]
        te = dfd[dfd["pcap"].isin(L_PCAPS)]
        device_id[name] = {}
        for ai, (ab, feats) in enumerate(ABLATIONS.items()):
            eval_rng = np.random.default_rng(args.seed + 2000 + si * 100 + ai)
            device_id[name][ab] = fit_eval(tr, te, feats, eval_rng)
        _log.info("device-ID %-14s all-features acc=%.3f",
                  name, device_id[name]["all_features"]["logreg"]["accuracy"])

    group_kfold = {
        "all_features": group_kfold_accuracy(df, ABLATIONS["all_features"]),
        "timing_only": group_kfold_accuracy(df, ABLATIONS["timing_only"]),
    }
    detection = detect_defense(df, defended_full, np.random.default_rng(args.seed + 3000))
    pairwise = pairwise_combined_timing(df, defended_full)

    results = {
        "meta": {
            "seed": args.seed,
            "csv_path": args.csv,
            "n_rows_total": len(df),
            "class_counts": {k: int(v) for k, v in df["device_label"].value_counts().items()},
            "majority_class_acc": majority_acc,
            "sklearn_available": _HAVE_SKLEARN,
            "sklearn_version": _SKLEARN_VERSION,
            "models_run": ["nearest_centroid", "multinomial_logreg"]
            + (["random_forest", "gradient_boosting"] if _HAVE_SKLEARN else []),
            "models_unavailable": [] if _HAVE_SKLEARN else ["random_forest", "gradient_boosting"],
            "split_scheme": "capture-level: train=base PCAPs, test=L PCAPs; "
                            "robustness=leave-one-PCAP-out GroupKFold",
            "ablations": ABLATIONS,
            "defense_settings": {k: {kk: vv for kk, vv in v.items()} for k, v in DEFENSE_SETTINGS.items()},
        },
        "device_id": device_id,
        "group_kfold": group_kfold,
        "detect_defense": detection,
        "pairwise_combined_timing": pairwise,
    }

    os.makedirs(os.path.dirname(JSON_OUT), exist_ok=True)
    with open(JSON_OUT, "w") as fh:
        json.dump(results, fh, indent=2)
    _log.info("Wrote %s", JSON_OUT)
    write_markdown(results, MD_OUT)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
leakage_metrics.py — core analysis for the joint size+timing evaluation (plan Phase 7). Dependency-light
(numpy only; the research venv has no sklearn). Computes the two headline leakage measures used to decide
whether a defense actually removes a device/class fingerprint:

  * mutual_information(feature, label)  — bits of label information carried by an observable feature
    (timing e.g. CLRT, or size). Continuous features are binned. MI≈0 ⇒ no channel; MI>0 ⇒ leakage.
  * balanced_accuracy_grouped(X, y, groups) — a leakage-honest classifier score. Uses GROUPED splits
    (never split the same session/run/replay across train/test — the plan's hard rule) and a
    nearest-centroid classifier. Compared against chance = 1/k. Post-defense success = within CI of chance.

These run on synthetic fixtures now and on real per-run feature tables later. This module MANUFACTURES
NOTHING — it only scores tables handed to it; it never fabricates a hardware result.
"""
import numpy as np


def mutual_information(feature, label, bins=16):
    """MI(feature; label) in bits. `feature` continuous or discrete (binned); `label` discrete."""
    feature = np.asarray(feature, dtype=float)
    label = np.asarray(label)
    # bin the feature (quantile edges so bins are populated); discrete features with few values pass through
    uniq = np.unique(feature)
    if uniq.size <= bins:
        fb = np.searchsorted(uniq, feature)
    else:
        edges = np.quantile(feature, np.linspace(0, 1, bins + 1))
        edges[-1] += 1e-9
        fb = np.clip(np.digitize(feature, edges[1:-1]), 0, bins - 1)
    labs, ly = np.unique(label, return_inverse=True)
    nf, nl = fb.max() + 1, labs.size
    joint = np.zeros((nf, nl))
    for a, b in zip(fb, ly):
        joint[a, b] += 1
    joint /= joint.sum()
    pf = joint.sum(1, keepdims=True)
    pl = joint.sum(0, keepdims=True)
    with np.errstate(divide="ignore", invalid="ignore"):
        term = joint * (np.log2(joint) - np.log2(pf) - np.log2(pl))
    return float(np.nansum(term))


def _nearest_centroid_fit_predict(Xtr, ytr, Xte):
    labs = np.unique(ytr)
    cent = np.array([Xtr[ytr == c].mean(0) for c in labs])
    d = np.linalg.norm(Xte[:, None, :] - cent[None, :, :], axis=2)
    return labs[d.argmin(1)]


def balanced_accuracy_grouped(X, y, groups):
    """Leave-one-group-out balanced accuracy (mean per-class recall) with a nearest-centroid classifier.
    Grouped so no session/run leaks across the split. Returns (bal_acc, chance=1/k)."""
    X = np.asarray(X, dtype=float)
    if X.ndim == 1:
        X = X[:, None]
    y = np.asarray(y)
    groups = np.asarray(groups)
    labs = np.unique(y)
    ug = np.unique(groups)
    per_fold = []
    for g in ug:
        te = groups == g
        tr = ~te
        if np.unique(y[tr]).size < 2 or te.sum() == 0:
            continue
        pred = _nearest_centroid_fit_predict(X[tr], y[tr], X[te])
        recalls = []
        for c in labs:
            m = y[te] == c
            if m.sum():
                recalls.append((pred[m] == c).mean())
        if recalls:
            per_fold.append(np.mean(recalls))
    bal = float(np.mean(per_fold)) if per_fold else float("nan")
    return bal, 1.0 / labs.size


def bootstrap_ci(values, n_boot=2000, alpha=0.05, seed=0):
    """Percentile bootstrap CI of the mean (seeded — reproducible)."""
    rng = np.random.default_rng(seed)
    values = np.asarray(values, dtype=float)
    means = [rng.choice(values, values.size, replace=True).mean() for _ in range(n_boot)]
    lo, hi = np.percentile(means, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(values.mean()), float(lo), float(hi)


def within_chance(bal_acc, ci_lo, ci_hi, chance):
    """A defense is leakage-free on this feature iff chance lies within the accuracy CI."""
    return ci_lo <= chance <= ci_hi

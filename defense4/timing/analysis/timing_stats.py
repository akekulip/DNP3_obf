#!/usr/bin/env python3
"""Timing-only statistics: CLRT distributions, leakage, and the transaction-class classifier.

Reads the derived transaction CSVs, writes timing_stats.json. Timing features only — no size
feature is computed or reported here.

What is measured
----------------
CLRT distribution per class and condition, with bootstrap 95% CI on the median.
Jensen-Shannon DISTANCE between distributions (scipy returns distance = sqrt(divergence);
  divergence is reported separately so neither is mistaken for the other).
Mutual information I(transaction class ; CLRT) over predeclared common bins, with a
  permutation null 95% interval, so "near zero" is judged against the null and not against 0.
A READ-vs-SELECT transaction-class classifier on the single feature CLRT, trained on native
  and applied unchanged to defended. This is transaction-class classification, not device
  identification: the testbed has one relay.

Every random draw is seeded, so repeated runs give identical numbers.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from scipy.spatial.distance import jensenshannon
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, mutual_info_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dnp3_timing import FUNC_READ, FUNC_SELECT, read_txn_csv, read_txn_rows  # noqa: E402

# Predeclared common CLRT bins (ms) used for BOTH the JS distance and the MI estimate, so the
# two are computed on the same support and neither can be tuned after seeing the result.
BINS = np.linspace(0.0, 12.0, 61)

SEED_BOOTSTRAP_MEDIAN = 42
SEED_MI_PERMUTATION = 3
SEED_CLASSIFIER_SPLIT = 1
SEED_BA_BOOTSTRAP = 7


def stats(x):
    x = np.asarray(x, dtype=float)
    return dict(n=int(x.size), median=float(np.median(x)), mean=float(np.mean(x)),
                std=float(np.std(x)), p5=float(np.percentile(x, 5)),
                p95=float(np.percentile(x, 95)), p99=float(np.percentile(x, 99)),
                max=float(np.max(x)), n_over_12ms=int(np.sum(x > 12.0)))


def boot_ci(x, fn=np.median, B=2000, seed=SEED_BOOTSTRAP_MEDIAN):
    rng = np.random.default_rng(seed)
    x = np.asarray(x, dtype=float)
    bs = [fn(rng.choice(x, x.size)) for _ in range(B)]
    return [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))]


def _pdf(x):
    h, _ = np.histogram(np.clip(x, BINS[0], BINS[-1]), bins=BINS)
    return h / h.sum() if h.sum() else h


def js_distance(a, b):
    return float(jensenshannon(_pdf(a) + 1e-12, _pdf(b) + 1e-12, base=2))


def mi_common_bins(a, b, B=1000, seed=SEED_MI_PERMUTATION):
    va = np.digitize(np.clip(a, BINS[0], BINS[-1]), BINS)
    vb = np.digitize(np.clip(b, BINS[0], BINS[-1]), BINS)
    labels = np.concatenate([np.zeros(len(a)), np.ones(len(b))])
    values = np.concatenate([va, vb])
    mi = mutual_info_score(labels, values) / np.log(2)
    rng = np.random.default_rng(seed)
    null = [mutual_info_score(rng.permutation(labels), values) / np.log(2) for _ in range(B)]
    return float(mi), [float(np.percentile(null, 2.5)), float(np.percentile(null, 97.5))]


def exclusion_report(path, req_func):
    """Account for every row: kept, cold-start excluded, unpaired. Nothing is silently dropped."""
    rows = [r for r in read_txn_rows(path) if int(r["req_func"]) == req_func]
    cold = [r for r in rows if r["cold"].strip() not in ("0", "")]
    unpaired = [r for r in rows if not r["clrt_ms"].strip()]
    kept = [r for r in rows
            if r["cold"].strip() in ("0", "") and r["clrt_ms"].strip()]
    return dict(total_requests=len(rows), cold_start_excluded=len(cold),
                unpaired_excluded=len(unpaired), analysed=len(kept))


def main():
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    csvdir = root / "derived_csv"
    out_path = root / "timing_stats.json"

    nat = csvdir / "native_txn.csv"
    dread = csvdir / "defended_read_txn.csv"
    dsel = csvdir / "defended_txn.csv"

    nR = np.array(read_txn_csv(nat, FUNC_READ))
    nS = np.array(read_txn_csv(nat, FUNC_SELECT))
    dR = np.array(read_txn_csv(dread, FUNC_READ))
    dS = np.array(read_txn_csv(dsel, FUNC_SELECT))

    mi_nat, ci_nat = mi_common_bins(nR, nS)
    mi_def, ci_def = mi_common_bins(dR, dS)

    res = {
        "feature_set": "timing only (CLRT, request->ACK, request->response). No size feature.",
        "predeclared_CLRT_bins": "linspace(0, 12, 61) ms, common to the JS and MI estimates",
        "seeds": {"bootstrap_median": SEED_BOOTSTRAP_MEDIAN,
                  "mi_permutation": SEED_MI_PERMUTATION,
                  "classifier_split": SEED_CLASSIFIER_SPLIT,
                  "ba_bootstrap": SEED_BA_BOOTSTRAP},
        "row_accounting": {
            "native_READ": exclusion_report(nat, FUNC_READ),
            "native_SELECT": exclusion_report(nat, FUNC_SELECT),
            "defended_READ": exclusion_report(dread, FUNC_READ),
            "defended_SELECT": exclusion_report(dsel, FUNC_SELECT)},
        "clrt_stats": {"native_READ": stats(nR), "native_SELECT": stats(nS),
                       "defended_READ": stats(dR), "defended_SELECT": stats(dS)},
        "bootstrap95_median": {"native_READ": boot_ci(nR), "native_SELECT": boot_ci(nS),
                               "defended_READ": boot_ci(dR), "defended_SELECT": boot_ci(dS)},
        "JS_distance_note": "scipy.jensenshannon returns DISTANCE = sqrt(divergence)",
        "JS_distance": {"native_READ_vs_SELECT": js_distance(nR, nS),
                        "defended_READ_vs_SELECT": js_distance(dR, dS),
                        "native_vs_defended_READ": js_distance(nR, dR),
                        "native_vs_defended_SELECT": js_distance(nS, dS)},
        "JS_divergence": {"native_vs_defended_READ": js_distance(nR, dR) ** 2,
                          "native_vs_defended_SELECT": js_distance(nS, dS) ** 2},
        "MI_class_CLRT_bits_commonbins": {
            "native": mi_nat, "native_perm_null_ci": ci_nat,
            "defended": mi_def, "defended_perm_null_ci": ci_def},
    }

    # READ-vs-SELECT transaction-class classifier on CLRT, trained on native only.
    X = np.concatenate([nR, nS]).reshape(-1, 1)
    y = np.array([0] * len(nR) + [1] * len(nS))
    idx = np.random.default_rng(SEED_CLASSIFIER_SPLIT).permutation(len(X))
    tr, te = idx[:int(.6 * len(idx))], idx[int(.6 * len(idx)):]
    clf = LogisticRegression().fit(X[tr], y[tr])
    nat_ba = balanced_accuracy_score(y[te], clf.predict(X[te]))
    Xd = np.concatenate([dR, dS]).reshape(-1, 1)
    yd = np.array([0] * len(dR) + [1] * len(dS))
    def_ba = balanced_accuracy_score(yd, clf.predict(Xd))

    def ba_ci(Xa, ya, B=1000, seed=SEED_BA_BOOTSTRAP):
        rng = np.random.default_rng(seed)
        vals = [balanced_accuracy_score(ya[s], clf.predict(Xa[s]))
                for s in (rng.integers(0, len(ya), len(ya)) for _ in range(B))]
        return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]

    res["classifier"] = {
        "task": "READ vs SELECT transaction class (NOT device identity)",
        "feature": "CLRT (ms)",
        "split": "transaction-disjoint 60/40, trained on native; NOT session-disjoint "
                 "(one capture session) — stated as a limitation",
        "native_balanced_acc": float(nat_ba), "native_ba_ci": ba_ci(X[te], y[te]),
        "defended_balanced_acc": float(def_ba), "defended_ba_ci": ba_ci(Xd, yd),
        "balanced_acc_chance_baseline": 0.5,
    }

    with open(out_path, "w") as f:
        json.dump(res, f, indent=2)
        f.write("\n")

    s = res["clrt_stats"]
    print("  CLRT native   READ n=%d med=%.3f std=%.3f max=%.3f  >12ms=%d"
          % (s["native_READ"]["n"], s["native_READ"]["median"], s["native_READ"]["std"],
             s["native_READ"]["max"], s["native_READ"]["n_over_12ms"]))
    print("  CLRT native   SELECT n=%d med=%.3f std=%.3f max=%.3f  >12ms=%d"
          % (s["native_SELECT"]["n"], s["native_SELECT"]["median"], s["native_SELECT"]["std"],
             s["native_SELECT"]["max"], s["native_SELECT"]["n_over_12ms"]))
    print("  CLRT defended READ n=%d med=%.3f std=%.3f" %
          (s["defended_READ"]["n"], s["defended_READ"]["median"], s["defended_READ"]["std"]))
    print("  CLRT defended SELECT n=%d med=%.3f std=%.3f" %
          (s["defended_SELECT"]["n"], s["defended_SELECT"]["median"], s["defended_SELECT"]["std"]))
    print("  MI(class;CLRT) native=%.6f (null %.4f-%.4f) -> defended=%.6f (null %.4f-%.4f) bits"
          % (mi_nat, ci_nat[0], ci_nat[1], mi_def, ci_def[0], ci_def[1]))
    print("  classifier BA native=%.4f -> defended=%.4f (chance 0.5)" % (nat_ba, def_ba))
    print("  wrote %s" % out_path.name)


if __name__ == "__main__":
    main()

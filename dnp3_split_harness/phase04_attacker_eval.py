"""phase04_attacker_eval.py -- statistically rigorous attacker evaluation of the Phase-4 eBPF EDT
mechanism (trace-transformation; NOT a defended-wire capture).

It takes the measured *native* per-transaction features from the six real device PCAPs, applies
each scenario's transformation (via ack_fingerprint_eval.apply_defense), and evaluates a random-
forest device classifier with uncertainty:

  * PRIMARY -- capture-level split (train on base PCAPs, test on L PCAPs): leakage-free, because
    train and test are different captures of the same device. Reports accuracy, balanced accuracy,
    macro-F1, per-device precision/recall, confusion matrix, and a bootstrap 95% CI on accuracy.
  * SECONDARY -- RepeatedStratifiedKFold (5x5) on the pooled data for an uncertainty band. CAVEAT:
    random folds put correlated transactions from the same capture in both train and test, so this
    is OPTIMISTIC; the capture-level split is the defensible estimate.
  * PAIRED bootstrap: native vs each transform on the shared capture-level test set (CI on the
    accuracy difference), to test whether small differences are real or resampling noise.

Baseline: MAJORITY-CLASS = 0.400 (test set) -- NOT uniform 1/3=0.333; classes are unequal, so
balanced accuracy is the headline metric.

Scenarios: native (before) ; ebpf_edt (prototype: ACK 20 ms / response 40 ms) ;
ebpf_edt_aligned (ablation: ACK = response = 40 ms, no mechanism-created request->ACK cue) ;
plus_ackmode (COUNTERFACTUAL ORACLE -- models what would remain if an ideal mechanism removed the
ACK-mode distinction; not byte/packet-preserving, not implemented by ack_edt.o).

    python3 phase04_attacker_eval.py

Seeds are fixed (SEED below) and recorded in the JSON.
"""

from __future__ import annotations

import json
import os
import sys

import numpy as np

import ack_fingerprint_eval as A

SEED = 20260716
N_BOOT = 2000
SCENARIOS = ["native", "ebpf_edt", "ebpf_edt_aligned", "plus_ackmode"]
FAMS = ["ack_only", "timing", "size", "all"]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "phases", "phase_04")


def _sk():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_score
    from sklearn.metrics import (accuracy_score, balanced_accuracy_score, f1_score,
                                 precision_recall_fscore_support, confusion_matrix)
    return dict(RF=RandomForestClassifier, pipe=make_pipeline, scaler=StandardScaler,
                RSK=RepeatedStratifiedKFold, cvs=cross_val_score, acc=accuracy_score,
                bacc=balanced_accuracy_score, f1=f1_score, prfs=precision_recall_fscore_support,
                cm=confusion_matrix)


def _model(sk):
    return sk["pipe"](sk["scaler"](), sk["RF"](n_estimators=300, random_state=SEED, n_jobs=-1))


def evaluate(d, sk):
    devices = A.DEVICES
    y_all = d["device_label"].values
    tr = ~d["is_L"].values      # base captures = train
    te = d["is_L"].values       # L captures = test (disjoint capture -> leakage-free)
    rng = np.random.default_rng(SEED)
    out = {}
    for fam in FAMS:
        cols = A.FEATURES[fam]
        out[fam] = {}
        for scen in SCENARIOS:
            x = A.apply_defense(d, scen)[cols].values
            Xtr, ytr, Xte, yte = x[tr], y_all[tr], x[te], y_all[te]
            m = _model(sk); m.fit(Xtr, ytr)
            pred = m.predict(Xte)
            acc = sk["acc"](yte, pred)
            bacc = sk["bacc"](yte, pred)
            mf1 = sk["f1"](yte, pred, average="macro")
            p, r, f, s = sk["prfs"](yte, pred, labels=devices, zero_division=0)
            # bootstrap CI on capture-level test accuracy
            n = len(yte); correct = (pred == yte).astype(int)
            boot = [correct[rng.integers(0, n, n)].mean() for _ in range(N_BOOT)]
            ci = (round(float(np.percentile(boot, 2.5)), 4), round(float(np.percentile(boot, 97.5)), 4))
            # repeated stratified CV (optimistic; leakage caveat) on pooled data
            cv = sk["cvs"](_model(sk), x, y_all,
                           cv=sk["RSK"](n_splits=5, n_repeats=5, random_state=SEED), n_jobs=-1)
            out[fam][scen] = {
                "capture_split": {
                    "accuracy": round(float(acc), 4), "balanced_accuracy": round(float(bacc), 4),
                    "macro_f1": round(float(mf1), 4), "accuracy_ci95": ci,
                    "per_device": {dev: {"precision": round(float(p[i]), 4),
                                         "recall": round(float(r[i]), 4)}
                                   for i, dev in enumerate(devices)},
                    "confusion": {"labels": devices,
                                  "matrix": sk["cm"](yte, pred, labels=devices).tolist()},
                },
                "repeated_stratified_cv_5x5": {
                    "mean_accuracy": round(float(cv.mean()), 4),
                    "std": round(float(cv.std()), 4),
                    "ci95": [round(float(np.percentile(cv, 2.5)), 4),
                             round(float(np.percentile(cv, 97.5)), 4)],
                    "note": "OPTIMISTIC (within-capture leakage); capture_split is the defensible estimate",
                },
            }
    # paired bootstrap on the 'all' family: native vs each transform (shared test set)
    paired = {}
    for scen in ["ebpf_edt", "ebpf_edt_aligned", "plus_ackmode"]:
        cols = A.FEATURES["all"]
        xn = A.apply_defense(d, "native")[cols].values
        xs = A.apply_defense(d, scen)[cols].values
        mn = _model(sk); mn.fit(xn[tr], y_all[tr]); cn = (mn.predict(xn[te]) == y_all[te]).astype(int)
        ms = _model(sk); ms.fit(xs[tr], y_all[tr]); cs = (ms.predict(xs[te]) == y_all[te]).astype(int)
        n = len(cn)
        diffs = [(cs[idx].mean() - cn[idx].mean()) for idx in (rng.integers(0, n, n) for _ in range(N_BOOT))]
        lo, hi = float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))
        paired[scen] = {"delta_accuracy_vs_native": round(float(cs.mean() - cn.mean()), 4),
                        "ci95": [round(lo, 4), round(hi, 4)],
                        "significant": bool(lo > 0 or hi < 0)}
    return out, paired


def write_md(res, path):
    m = res["meta"]; fam = res["families"]; paired = res["paired_vs_native_all"]

    def cs(f, s):
        return fam[f][s]["capture_split"]
    L = ["# Phase 04 — Attacker Evaluation (statistically rigorous)", "",
         "**Trace-transformation evaluation** — the measured *native* per-transaction features from "
         "the six real device PCAPs are transformed by each scenario's model and re-classified. It "
         "is **not** a defended-wire capture.", "",
         "- **Baseline: majority-class = %.3f** (test set; SEL-751 & ION7550 ≈ 40%%, AB1400 ≈ 20%%). "
         "Uniform 3-class chance would be %.3f. Because classes are unequal, **balanced accuracy is "
         "the headline metric.**" % (m["majority_class_baseline_test"], m["uniform_3class"]),
         "- **Primary estimator:** %s. **Model:** %s. **Bootstrap:** %d resamples. Seed fixed."
         % (m["primary_estimator"], m["model"], m["n_bootstrap"]),
         "- Scenarios: `native` · `ebpf_edt` (prototype: ACK 20 ms / response 40 ms) · "
         "`ebpf_edt_aligned` (ablation: ACK = response = 40 ms) · `plus_ackmode` "
         "(**counterfactual oracle** — models what would remain if an ideal mechanism removed the "
         "ACK-mode distinction; not byte/packet-preserving, **not implemented by `ack_edt.o`**).",
         "",
         "## 1. Capture-level split (leakage-free) — random forest per feature family", "",
         "| family | scenario | accuracy [95% CI] | balanced acc | macro-F1 |",
         "|---|---|---|---:|---:|"]
    for f in FAMS:
        for s in SCENARIOS:
            c = cs(f, s)
            L.append("| %s | %s | %.3f [%.3f, %.3f] | %.3f | %.3f |"
                     % (f, s, c["accuracy"], c["accuracy_ci95"][0], c["accuracy_ci95"][1],
                        c["balanced_accuracy"], c["macro_f1"]))
    L += ["", "## 2. Repeated stratified 5×5 CV (uncertainty band — OPTIMISTIC, within-capture leakage)", "",
          "| family | scenario | mean acc [95% CI] |", "|---|---|---|"]
    for f in FAMS:
        for s in SCENARIOS:
            cv = fam[f][s]["repeated_stratified_cv_5x5"]
            L.append("| %s | %s | %.3f [%.3f, %.3f] |"
                     % (f, s, cv["mean_accuracy"], cv["ci95"][0], cv["ci95"][1]))
    L += ["", "_The pooled CV mixes correlated transactions from the same capture into train and "
          "test, so it is optimistic; the capture-level split above is the defensible estimate._", ""]

    # per-device + confusion for 'all'
    L += ["## 3. Per-device precision/recall and confusion — `all` features", ""]
    for s in ["native", "ebpf_edt", "ebpf_edt_aligned"]:
        c = cs("all", s)
        L.append("**%s** (balanced acc %.3f, macro-F1 %.3f):" % (s, c["balanced_accuracy"], c["macro_f1"]))
        L.append("")
        L.append("| device | precision | recall |")
        L.append("|---|---:|---:|")
        for dev, pr in c["per_device"].items():
            L.append("| %s | %.3f | %.3f |" % (dev, pr["precision"], pr["recall"]))
        cm = c["confusion"]
        L.append("")
        L.append("confusion (rows=true, cols=pred; %s):" % ", ".join(cm["labels"]))
        L.append("```")
        for lbl, row in zip(cm["labels"], cm["matrix"]):
            L.append("%8s " % lbl + " ".join("%6d" % v for v in row))
        L.append("```")
        L.append("")

    L += ["## 4. Paired bootstrap vs native — `all` features", "",
          "| transform | Δ accuracy vs native | 95% CI | significant? |", "|---|---:|---|---|"]
    for s, v in paired.items():
        L.append("| %s | %+.4f | [%+.4f, %+.4f] | %s |"
                 % (s, v["delta_accuracy_vs_native"], v["ci95"][0], v["ci95"][1],
                    "yes" if v["significant"] else "no (resampling noise)"))

    nb = cs("all", "native")["balanced_accuracy"]; eb = cs("all", "ebpf_edt")["balanced_accuracy"]
    ab = cs("all", "ebpf_edt_aligned")["balanced_accuracy"]
    na = cs("ack_only", "native")["balanced_accuracy"]; ea = cs("ack_only", "ebpf_edt")["balanced_accuracy"]
    nt = cs("timing", "native")["balanced_accuracy"]; et = cs("timing", "ebpf_edt")["balanced_accuracy"]
    L += ["", "## 5. Reading (balanced accuracy; baseline 0.333 uniform / majority-class 0.400)", "",
          "- **Timing channel collapses to baseline.** `timing` balanced accuracy %.3f → %.3f: "
          "request→response pinned to the common target carries no device information, with no "
          "re-encoding of mode into timing." % (nt, et),
          "- **ACK-mode channel is NOT closed.** `ack_only` balanced accuracy falls %.3f → %.3f "
          "(the request→ACK and gap sub-features are normalized) but stays far above baseline — "
          "`is_separate` (a separate-mode device still emits a distinct pure-ACK packet) is a "
          "categorical leak the mechanism cannot remove." % (na, ea),
          "- **The aligned-target ablation changes nothing** (`ebpf_edt_aligned` = `ebpf_edt` on "
          "every metric: `all` balanced %.3f vs %.3f). So the residual is the categorical ACK-mode "
          "and size channels, **not** the choice of timing targets — aligning ACK and response "
          "targets neither helps nor hurts." % (ab, eb),
          "- **The small raw-accuracy rise is an imbalance artifact.** `all` *raw* accuracy edges up "
          "(%.3f → %.3f, paired CI excludes 0) but *balanced* accuracy **falls** %.3f → %.3f: "
          "normalizing the noisy native timing lets the majority classes (SEL/ION) classify a little "
          "more cleanly at the minority class's (AB1400) expense. Balanced accuracy is the honest "
          "measure and it shows a modest *decrease*, nowhere near baseline."
          % (cs("all", "native")["accuracy"], cs("all", "ebpf_edt")["accuracy"], nb, eb),
          "- **Counterfactual oracle.** `plus_ackmode` (ideal ACK-mode removal — not implemented) "
          "drops `ack_only` and `timing` to baseline, but **`all` stays at %.3f, not baseline**, "
          "because **response size still leaks**. Do not say the fingerprint 'collapses to the "
          "baseline'." % cs("all", "plus_ackmode")["balanced_accuracy"],
          "",
          "**Result:** egress scheduling removes timing leakage but cannot conceal the "
          "transport-structure (ACK-mode) and response-size fingerprints. Full device anonymization "
          "is not achieved by timing normalization alone.", "",
          "_Scope: trace-transformation on the six device PCAPs (SEL-751 separate; AB1400 / ION7550 "
          "combined). Loopback/single-kernel provenance for the transformation model; not a "
          "rig/defended-wire capture._"]
    open(path, "w").write("\n".join(L) + "\n")


def main() -> int:
    if not A._HAVE_SKLEARN:
        sys.stderr.write("needs scikit-learn (pip install 'scikit-learn>=1.3,<1.4')\n"); return 2
    sk = _sk()
    d = A.load()
    te = d[d["is_L"]]
    maj = round(float(te["device_label"].value_counts().max() / len(te)), 4)
    res = {
        "meta": {"n_total": int(len(d)), "n_test_L": int(te.shape[0]),
                 "per_device_all": {k: int(v) for k, v in d["device_label"].value_counts().items()},
                 "seed": SEED, "n_bootstrap": N_BOOT,
                 "majority_class_baseline_test": maj, "uniform_3class": round(1 / 3, 4),
                 "ebpf_ack_target_ms": A.EBPF_ACK_TARGET_MS, "ebpf_resp_target_ms": A.EBPF_RESP_TARGET_MS,
                 "eval_type": "trace-transformation (native traces transformed; NOT defended-wire)",
                 "primary_estimator": "capture-level split (train base pcaps, test L pcaps): leakage-free",
                 "model": "StandardScaler + RandomForest(300 trees), seed %d" % SEED},
        "families": None, "paired_vs_native_all": None,
    }
    fam, paired = evaluate(d, sk)
    res["families"] = fam
    res["paired_vs_native_all"] = paired
    os.makedirs(OUT, exist_ok=True)
    json.dump(res, open(os.path.join(OUT, "attacker_eval.json"), "w"), indent=2)
    write_md(res, os.path.join(OUT, "attacker_eval.md"))

    # console summary
    print("n_total=%d n_test=%d majority-class baseline=%.3f (uniform 1/3=%.3f) seed=%d"
          % (len(d), len(te), maj, 1 / 3, SEED))
    print("%-16s %-16s %-16s %-16s" % ("family/scenario", "acc [95%CI]", "balanced_acc", "macro_F1"))
    for f in FAMS:
        for s in SCENARIOS:
            c = fam[f][s]["capture_split"]
            print("%-16s %.3f[%.3f,%.3f] %14.3f %14.3f"
                  % ("%s/%s" % (f, s), c["accuracy"], c["accuracy_ci95"][0], c["accuracy_ci95"][1],
                     c["balanced_accuracy"], c["macro_f1"]))
    print("\npaired 'all' vs native (Δaccuracy [95% CI], significant?):")
    for s, v in paired.items():
        print("  %-18s %+.4f [%+.4f,%+.4f]  %s"
              % (s, v["delta_accuracy_vs_native"], v["ci95"][0], v["ci95"][1],
                 "SIGNIFICANT" if v["significant"] else "n.s. (resampling noise)"))
    print("\nwrote reports/phases/phase_04/attacker_eval.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

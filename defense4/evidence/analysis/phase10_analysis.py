#!/usr/bin/env python3
"""phase10_analysis.py -- Phase 10 analysis for the faithful two-pipe BOR + RRC defense.

Three strictly separated evidence tiers (do not blur them):

  1. PHYSICAL SILICON  -- the Case-A CLRT result. Read directly from the two joint RRC pcaps
     captured on the Tofino-1 against the physical SEL-751 (native = hold OFF, defended = D4 hold
     ON). Metrics per transaction: request->pure-ACK, pure-ACK->response (the CLRT the D4 deadline
     clamps), request->response. Median/mean/std + P5/P50/P95/P99, READ vs SELECT, native vs
     defended. This is the strong result.

  2. SYNTHETIC / BOOTSTRAPPED  -- the physical-operation-time convolution DEMONSTRATION. No physical
     OPERATE exists (H5 BLOCKED). Native T_physical is modelled as two device classes from the
     Formby operation-time ranges (vendor-1 ~16-38 ms, vendor-2 ~14-33 ms, uniform). Defended =
     T_physical convolved with the bounded RANDOM jitter codebook J ~ U{0,2,4,6,8,10,12} ms. A
     before/after two-class classifier (threshold / logistic / random forest, session-separated)
     measures how much the convolution reduces separability. This demonstrates ONE mechanism; it is
     NOT a multi-device silicon fingerprint-defeat claim.

  3. COMPILER-ONLY  -- ingress-stage cost of the RRC kernel, the additive BOR probe, the one-pipe
     faithful build, and the faithful two-pipe split, taken from the committed bf-p4c COMPILE
     matrices. A compile is not silicon.

Pure analysis. Reads the committed pcaps + compile matrices only. Run with $RESEARCH_PYTHON.
Writes JSON + CSV into this directory. Importable by the figure scripts.
"""
import sys
import json
import csv
from pathlib import Path

import numpy as np
from scipy.spatial.distance import jensenshannon
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (accuracy_score, balanced_accuracy_score,
                             f1_score, confusion_matrix)

HERE = Path(__file__).resolve().parent
NP_DIR = HERE.parent.parent / "size" / "native_parity"       # defense4/size/native_parity
sys.path.insert(0, str(NP_DIR))
from analyze_rrc_pcaps import transactions                    # noqa: E402  (TCP-ACK pairing)

EV = NP_DIR / "evidence"
NATIVE_DIR = EV / "hw_rrc_readsbo_20260812T212234Z" / "captures"   # size-only, D4 hold OFF
JOINT_DIR = EV / "hw_rrc_joint_20260812T223342Z" / "captures"      # joint, D4 hold ON

# --- synthetic model constants (all provenance-tagged SYNTHETIC) ------------------------------
# Formby et al. measured DNP3 operation-time ranges, two device classes (ms).
VENDOR1_RANGE = (16.0, 38.0)
VENDOR2_RANGE = (14.0, 33.0)
# Bounded random jitter codebook J (ms), uniform over buckets -- BOR_RRC_DESIGN.md sec 3 /
# BOR_CONTROL_PLANE.md default --j-set '0,2,4,6,8,10,12'.
J_CODEBOOK = np.array([0, 2, 4, 6, 8, 10, 12], dtype=float)
# DNP3 master timeouts used for the added-latency margin.
MASTER_RESPONSE_TIMEOUT_MS = 2000.0   # protocol default (audit M5: campaign provenance FLAGGED)
POLL_INTERVAL_MS = 400.0              # independently evidenced poll gap (audit)

METRICS = ("req_to_ack_ms", "ack_to_resp_ms", "req_to_resp_ms")


# ============================ tier 1: physical-silicon CLRT ===================================
def pstats(xs):
    """n/min/mean/std/P5/P50/P95/P99/max for a millisecond series."""
    a = np.asarray([x for x in xs if x is not None], dtype=float)
    if a.size == 0:
        return {}
    return {
        "n": int(a.size),
        "min_ms": round(float(a.min()), 4),
        "mean_ms": round(float(a.mean()), 4),
        "std_ms": round(float(a.std(ddof=0)), 4),
        "p5_ms": round(float(np.percentile(a, 5)), 4),
        "p50_ms": round(float(np.median(a)), 4),
        "p95_ms": round(float(np.percentile(a, 95)), 4),
        "p99_ms": round(float(np.percentile(a, 99)), 4),
        "max_ms": round(float(a.max()), 4),
    }


def _series(pcap, klass, field):
    return [t[field] for t in transactions(str(pcap))
            if t["klass"] == klass and t["admitted"]]


def clrt_series():
    """Per-transaction CLRT metrics, keyed [condition][klass][metric] -> list(ms)."""
    out = {}
    for cond, d in (("native", NATIVE_DIR), ("defended", JOINT_DIR)):
        out[cond] = {}
        for klass, pcap in (("READ", d / "read.pcap"), ("SELECT", d / "sbo.pcap")):
            out[cond][klass] = {m: _series(pcap, klass, m) for m in METRICS}
    return out


def clrt_analysis(series):
    """Stats per condition/class/metric + pooled READ+SELECT, native vs defended."""
    res = {"provenance": "physical silicon (Tofino-1 vs physical SEL-751)",
           "native_pcap": str(NATIVE_DIR), "defended_pcap": str(JOINT_DIR),
           "by_condition": {}}
    for cond in ("native", "defended"):
        res["by_condition"][cond] = {"by_class": {}, "pooled": {}}
        for klass in ("READ", "SELECT"):
            res["by_condition"][cond]["by_class"][klass] = {
                m: pstats(series[cond][klass][m]) for m in METRICS}
        for m in METRICS:
            pooled = series[cond]["READ"][m] + series[cond]["SELECT"][m]
            res["by_condition"][cond]["pooled"][m] = pstats(pooled)
    # headline: ACK->response CLRT (the clamped metric)
    def med(cond, klass):
        return pstats(series[cond][klass]["ack_to_resp_ms"]).get("p50_ms")
    res["headline_clrt_ack_to_resp"] = {
        "native": {"READ": med("native", "READ"), "SELECT": med("native", "SELECT"),
                   "diff_ms": round(abs(med("native", "READ") - med("native", "SELECT")), 4)},
        "defended": {"READ": med("defended", "READ"), "SELECT": med("defended", "SELECT"),
                     "diff_ms": round(abs(med("defended", "READ") - med("defended", "SELECT")), 4)},
        "interpretation": ("native READ and SELECT CLRT medians are separable; the D4 hold "
                           "collapses both onto ~20 ms (medians < 0.01 ms apart)."),
    }
    return res


def write_clrt_csv(series, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["condition", "klass", "index"] + list(METRICS))
        for cond in ("native", "defended"):
            for klass in ("READ", "SELECT"):
                cols = [series[cond][klass][m] for m in METRICS]
                n = max((len(c) for c in cols), default=0)
                for i in range(n):
                    w.writerow([cond, klass, i] +
                               [round(cols[j][i], 4) if i < len(cols[j]) and cols[j][i] is not None
                                else "" for j in range(len(METRICS))])


# ==================== tier 2: synthetic operation-time convolution ============================
def _draw_class(rng, rng_lo, rng_hi, n):
    return rng.uniform(rng_lo, rng_hi, n)


def _defend(rng, native, codebook):
    """Convolve native samples with the bounded random jitter codebook J."""
    return native + rng.choice(codebook, size=native.shape[0])


def synth_operation_model(n_per_class=4000, seed=0):
    """Native (T_physical) and defended (T_physical + J) samples for the two device classes."""
    rng = np.random.default_rng(seed)
    v1 = _draw_class(rng, *VENDOR1_RANGE, n_per_class)
    v2 = _draw_class(rng, *VENDOR2_RANGE, n_per_class)
    v1d = _defend(rng, v1, J_CODEBOOK)
    v2d = _defend(rng, v2, J_CODEBOOK)
    return {"v1_native": v1, "v2_native": v2, "v1_defended": v1d, "v2_defended": v2d}


def _js_divergence(a, b, lo, hi, bins=60):
    """Jensen-Shannon divergence (base 2, bits, squared distance) between two 1-D samples."""
    edges = np.linspace(lo, hi, bins + 1)
    pa, _ = np.histogram(a, bins=edges, density=False)
    pb, _ = np.histogram(b, bins=edges, density=False)
    pa = pa / pa.sum()
    pb = pb / pb.sum()
    dist = jensenshannon(pa, pb, base=2)         # distance in [0,1]
    return float(dist ** 2)                       # divergence in bits


def synth_classifier(n_per_class=4000, seed_train=0, seed_test=1, n_boot=1000, seed_boot=7):
    """Two-class (vendor-1 vs vendor-2) before/after classifiers, session-separated.

    Train on an independent draw (seed_train), test on a disjoint draw (seed_test). Reports, for
    the NATIVE and DEFENDED feature: accuracy, balanced accuracy, macro-F1, confusion matrix,
    bootstrap 95% CI on test accuracy, plus the class-separation JS divergence. Chance = 0.5.
    """
    tr = synth_operation_model(n_per_class, seed_train)
    te = synth_operation_model(n_per_class, seed_test)
    rng_boot = np.random.default_rng(seed_boot)

    models = {
        "threshold": DecisionTreeClassifier(max_depth=1, random_state=0),
        "logistic": LogisticRegression(),
        "random_forest": RandomForestClassifier(n_estimators=200, random_state=0),
    }
    out = {"provenance": "synthetic / bootstrapped (offline convolution demonstration, ONE mechanism)",
           "note": ("NOT a multi-device silicon fingerprint-defeat claim. Native T_physical is a "
                    "two-class Formby-range model; J is a bounded RANDOM codebook, not a fixed shift."),
           "chance_level": 0.5, "n_per_class": n_per_class,
           "conditions": {}}

    for cond, keys in (("native", ("v1_native", "v2_native")),
                       ("defended", ("v1_defended", "v2_defended"))):
        Xtr = np.concatenate([tr[keys[0]], tr[keys[1]]]).reshape(-1, 1)
        ytr = np.concatenate([np.zeros(n_per_class), np.ones(n_per_class)]).astype(int)
        Xte = np.concatenate([te[keys[0]], te[keys[1]]]).reshape(-1, 1)
        yte = np.concatenate([np.zeros(n_per_class), np.ones(n_per_class)]).astype(int)
        js = _js_divergence(te[keys[0]], te[keys[1]],
                            lo=min(VENDOR1_RANGE[0], VENDOR2_RANGE[0]),
                            hi=VENDOR1_RANGE[1] + J_CODEBOOK.max())
        cond_res = {"class_separation_js_bits": round(js, 4), "models": {}}
        for name, clf in models.items():
            clf.fit(Xtr, ytr)
            pred = clf.predict(Xte)
            acc = accuracy_score(yte, pred)
            # bootstrap CI on test accuracy
            boot = np.empty(n_boot)
            m = yte.size
            for b in range(n_boot):
                idx = rng_boot.integers(0, m, m)
                boot[b] = accuracy_score(yte[idx], pred[idx])
            cond_res["models"][name] = {
                "accuracy": round(float(acc), 4),
                "balanced_accuracy": round(float(balanced_accuracy_score(yte, pred)), 4),
                "macro_f1": round(float(f1_score(yte, pred, average="macro")), 4),
                "confusion_matrix": confusion_matrix(yte, pred).tolist(),
                "acc_ci95": [round(float(np.percentile(boot, 2.5)), 4),
                             round(float(np.percentile(boot, 97.5)), 4)],
            }
        out["conditions"][cond] = cond_res

    # before/after reduction per model
    out["reduction"] = {}
    for name in models:
        b = out["conditions"]["native"]["models"][name]["accuracy"]
        a = out["conditions"]["defended"]["models"][name]["accuracy"]
        out["reduction"][name] = {
            "native_acc": b, "defended_acc": a,
            "abs_drop": round(b - a, 4),
            "toward_chance_pct": round(100.0 * (b - a) / (b - 0.5), 2) if b > 0.5 else None,
            "near_chance": bool(a <= 0.55),
        }
    out["js_reduction"] = {
        "native_bits": out["conditions"]["native"]["class_separation_js_bits"],
        "defended_bits": out["conditions"]["defended"]["class_separation_js_bits"],
    }
    return out


# ==================== tier 2b: added-latency model (silicon hold + model J) ====================
def added_latency_model(n=200000, seed=3):
    """Added latency distributions: the silicon RRC hold (measured) and the model BOR jitter J."""
    rng = np.random.default_rng(seed)
    # silicon RRC hold: measured joint READ+SELECT request->response (defended), ms.
    rrc = np.asarray(
        _series(JOINT_DIR / "read.pcap", "READ", "req_to_resp_ms") +
        _series(JOINT_DIR / "sbo.pcap", "SELECT", "req_to_resp_ms"), dtype=float)
    # model BOR jitter added to an OPERATE (bounded random codebook), ms.
    j = rng.choice(J_CODEBOOK, size=n)
    return {
        "rrc_hold_silicon": {
            "provenance": "physical silicon (joint READ+SELECT request->response)",
            "stats": pstats(rrc.tolist()),
        },
        "bor_jitter_model": {
            "provenance": "model (bounded random codebook J ~ U{0,2,4,6,8,10,12} ms)",
            "stats": pstats(j.tolist()),
        },
        "master_timeout_margin": {
            "worst_case_added_ms": round(float(pstats(rrc.tolist())["max_ms"] + J_CODEBOOK.max()), 4),
            "master_response_timeout_ms": MASTER_RESPONSE_TIMEOUT_MS,
            "master_response_timeout_provenance": "protocol default; audit M5 flags campaign provenance",
            "margin_vs_response_timeout_ms": round(
                MASTER_RESPONSE_TIMEOUT_MS - (pstats(rrc.tolist())["max_ms"] + J_CODEBOOK.max()), 4),
            "poll_interval_ms": POLL_INTERVAL_MS,
            "poll_interval_provenance": "independently evidenced ~400 ms poll gap",
            "margin_vs_poll_interval_ms": round(
                POLL_INTERVAL_MS - (pstats(rrc.tolist())["max_ms"] + J_CODEBOOK.max()), 4),
        },
    }


# ==================== tier 3: compiler-only resource matrix ====================================
def compiler_resources():
    """Ingress-stage cost from the committed bf-p4c COMPILE matrices (compiler-only)."""
    return {
        "provenance": "compiler-only (bf-p4c 9.13.x table_summary.log; a compile is not silicon)",
        "tf1_ingress_stage_limit": 12,
        "builds": [
            {"name": "RRC kernel (reference)", "ingress_stages": 12, "egress_stages": 3,
             "fits": True, "pipes": 1,
             "source": "evidence/bor_two_pipe/COMPILE_MATRIX.txt (frozen RRC)"},
            {"name": "Additive BOR (naive)", "ingress_stages": 14, "egress_stages": 3,
             "fits": False, "pipes": 1,
             "source": "evidence/bor_stage_recovery (SR0_full_bor, 151 tables)"},
            {"name": "One-pipe faithful", "ingress_stages": 13, "egress_stages": 3,
             "fits": False, "pipes": 1,
             "source": "evidence/bor_two_pipe/COMPILE_MATRIX.txt (RRC+BOR hold + arm-fold + SR1/SR2)"},
            {"name": "Two-pipe faithful pipe0", "ingress_stages": 12, "egress_stages": 3,
             "fits": True, "pipes": 2,
             "source": "evidence/bor_two_pipe_faithful/COMPILE_MATRIX.txt"},
            {"name": "Two-pipe faithful pipe1", "ingress_stages": 10, "egress_stages": 0,
             "fits": True, "pipes": 2,
             "source": "evidence/bor_two_pipe_faithful/COMPILE_MATRIX.txt"},
        ],
        "verdict": ("The additive single-pipe BOR is +2 over the TF1 limit; even the folded one-pipe "
                    "faithful build is +1. The faithful two-pipe split fits: pipe0=12/3, pipe1=10/0."),
    }


# ==================== driver ==================================================================
def build_all():
    series = clrt_series()
    write_clrt_csv(series, HERE / "clrt_series.csv")
    return {
        "clrt_physical_silicon": clrt_analysis(series),
        "synth_operation_summary": {
            "provenance": "synthetic (Formby two-class ranges convolved with random J codebook)",
            "vendor1_range_ms": list(VENDOR1_RANGE), "vendor2_range_ms": list(VENDOR2_RANGE),
            "j_codebook_ms": J_CODEBOOK.tolist(),
        },
        "synth_classifier": synth_classifier(),
        "added_latency": added_latency_model(),
        "compiler_resources": compiler_resources(),
    }


def main():
    out = build_all()
    with open(HERE / "phase10_analysis.json", "w") as f:
        json.dump(out, f, indent=2)
    # concise console summary
    clrt = out["clrt_physical_silicon"]["headline_clrt_ack_to_resp"]
    clf = out["synth_classifier"]
    al = out["added_latency"]
    print("== CLRT ACK->response (physical silicon), medians ms ==")
    print("  native  : READ=%.3f SELECT=%.3f (diff %.3f)" %
          (clrt["native"]["READ"], clrt["native"]["SELECT"], clrt["native"]["diff_ms"]))
    print("  defended: READ=%.3f SELECT=%.3f (diff %.3f)" %
          (clrt["defended"]["READ"], clrt["defended"]["SELECT"], clrt["defended"]["diff_ms"]))
    print("== synthetic two-class classifier (chance 0.5) ==")
    for name in ("threshold", "logistic", "random_forest"):
        r = clf["reduction"][name]
        print("  %-13s native=%.3f defended=%.3f drop=%.3f near_chance=%s" %
              (name, r["native_acc"], r["defended_acc"], r["abs_drop"], r["near_chance"]))
    print("  JS class-separation: native=%.3f defended=%.3f bits" %
          (clf["js_reduction"]["native_bits"], clf["js_reduction"]["defended_bits"]))
    print("== added latency ==")
    print("  RRC hold silicon P50/P95/P99 ms = %.2f/%.2f/%.2f" %
          (al["rrc_hold_silicon"]["stats"]["p50_ms"], al["rrc_hold_silicon"]["stats"]["p95_ms"],
           al["rrc_hold_silicon"]["stats"]["p99_ms"]))
    print("  master-timeout margin (worst case) vs 2 s = %.1f ms; vs 400 ms poll = %.1f ms" %
          (al["master_timeout_margin"]["margin_vs_response_timeout_ms"],
           al["master_timeout_margin"]["margin_vs_poll_interval_ms"]))
    print("wrote", HERE / "phase10_analysis.json", "and clrt_series.csv")


if __name__ == "__main__":
    main()

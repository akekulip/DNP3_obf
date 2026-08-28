#!/usr/bin/env python3
"""make_figures3.py — consolidated 2x2 grid figures.

fig_g1_offsets  the whole offset argument: the tail that must be covered, the coverage/latency
                trade-off, the sweep of D_A against the fail-open horizon, and the split at a
                fixed budget.  (replaces fig_c00 + fig_c08)
fig_g2_leakage  the whole leakage argument: balanced accuracy, mutual information, and the two
                confusion matrices that explain what survives.  (replaces fig_c05 + fig_t02)
"""
from __future__ import annotations
import csv, sys, collections
from pathlib import Path
import numpy as np

ANALYSIS = Path(__file__).resolve().parents[3] / "analysis"
sys.path.insert(0, str(ANALYSIS))
import figstyle as fs                                   # noqa: E402
import matplotlib.pyplot as plt                         # noqa: E402
from matplotlib.ticker import NullFormatter             # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "derived" / "transactions.csv"
SWEEP = ROOT / "sweep" / "sweep_points.csv"
OUT = ROOT / "figures"
CLASSES = ["READ", "SELECT", "OPERATE"]
ARMCOL = {"native": fs.TIMING_OFF, "obfuscated": fs.TIMING_ON}
ARMLAB = {"native": fs.LABEL_OFF, "obfuscated": fs.LABEL_ON}
HATCH = {"native": "///", "obfuscated": "\\\\\\"}
CLSCOL = dict(zip(CLASSES, [fs._BLUE, fs._ORANGE, fs._GREEN]))
D_CHOSEN, H_HORIZON = 24.0, 30.8


def load():
    out = []
    with open(CSV) as f:
        for r in csv.DictReader(f):
            out.append((r["session"], r["arm"], r["txn_class"],
                        float(r["clrt_ms"]), float(r["ack_ms"]), float(r["rt_ms"])))
    return out


def sel(rec, arm=None, cls=None):
    return [r for r in rec if (arm is None or r[1] == arm) and (cls is None or r[2] == cls)]


def tag(ax, t, ha="right"):
    ax.text(0.97 if ha == "right" else 0.03, 0.97, "(%s)" % t, transform=ax.transAxes,
            fontsize=8, va="top", ha=ha)


# ------------------------------------------------------------------ grid 1
def fig_offsets(rec):
    sw = [r for r in csv.DictReader(open(SWEEP)) if r["mode"] == "D4"]
    fig, ax = plt.subplots(2, 2, figsize=(fs.PAGE_WIDTH_IN, 3.95))
    rows = []
    # (a) native tail
    for cls in CLASSES:
        v = np.sort(np.array([r[3] for r in sel(rec, "native", cls)]))
        ax[0][0].step(v, 1.0 - np.arange(v.size) / v.size, where="post",
                      color=CLSCOL[cls], lw=1.0, label=cls, zorder=3)
        for p in (99, 99.9):
            rows.append(["native_clrt_percentile", cls, p, round(float(np.percentile(v, p)), 4)])
    ax[0][0].axvline(D_CHOSEN, color=fs.GREY, lw=0.9, ls=":", zorder=2, label=r"$D=D_A+D_R$")
    ax[0][0].set_xscale("log"); ax[0][0].set_yscale("log")
    ax[0][0].set_xlim(1, 100); ax[0][0].set_ylim(1e-5, 3.0)
    ax[0][0].set_xlabel("Cross-layer response time (ms)")
    ax[0][0].set_ylabel("Fraction exceeding")
    ax[0][0].legend(loc="lower left", fontsize=6.8, handletextpad=0.4, borderpad=0.3,
                    labelspacing=0.2, framealpha=1.0, borderaxespad=0.4)
    # (b) trade-off
    allc = np.array([r[3] for r in sel(rec, "native")])
    grid = np.unique(np.concatenate([np.linspace(4, 100, 400), [D_CHOSEN]]))
    ax[0][1].plot(grid, [100 * np.mean(allc > d) for d in grid], color=fs.SERIES_3, lw=1.2,
                  zorder=3, label="all classes")
    ax[0][1].plot([D_CHOSEN], [100 * float(np.mean(allc > D_CHOSEN))], marker="*", ms=9,
                  mfc=fs.TIMING_ON, mec="black", mew=0.7, ls="none", zorder=5,
                  label="operating point")
    ax[0][1].set_yscale("log"); ax[0][1].set_xlim(0, 100); ax[0][1].set_ylim(5e-4, 200)
    ax[0][1].set_xlabel("Added latency $D$ (ms)")
    ax[0][1].set_ylabel("Not coverable (\\%)" if False else "Not coverable (%)")
    ax[0][1].legend(loc="upper right", fontsize=6.8, handletextpad=0.4, borderpad=0.3,
                    labelspacing=0.2, framealpha=1.0, borderaxespad=0.4)
    for d in (8, 16, 24, 28, 60):
        rows.append(["coverage_vs_deadline", "all", d, round(100 * (1 - float(np.mean(allc > d))), 4)])
    # (c) sweep D_A
    a = sorted([r for r in sw if r["D_R_ms"] == "4"], key=lambda r: float(r["D_A_ms"]))
    da = [float(r["D_A_ms"]) for r in a]
    ax[1][0].plot(da, [float(r["ack_med_ms"]) for r in a], "-o", color=fs.TIMING_ON, ms=3.0,
                  lw=1.1, label="ACK latency", zorder=4)
    ax[1][0].plot(da, [float(r["clrt_med_ms"]) for r in a], "-s", color=fs.TIMING_OFF, ms=3.0,
                  lw=1.1, label="CLRT", zorder=4)
    ax[1][0].axhline(H_HORIZON, color=fs.GREY, lw=0.9, ls=":", zorder=2, label="horizon $H$")
    ax[1][0].set_xlim(0, 40); ax[1][0].set_ylim(0, 52)
    ax[1][0].set_xlabel("$D_A$ (ms), with $D_R=4$ ms")
    ax[1][0].set_ylabel("Interval (ms)")
    ax[1][0].legend(loc="upper left", fontsize=6.8, handletextpad=0.4, borderpad=0.3,
                    labelspacing=0.2, framealpha=1.0, borderaxespad=0.4)
    # (d) fixed budget, vary split
    b = sorted([r for r in sw if r["D_ms"] == "24"], key=lambda r: float(r["D_R_ms"]))
    dr = [float(r["D_R_ms"]) for r in b]
    ax[1][1].plot(dr, [float(r["rt_med_ms"]) for r in b], "-^", color=fs.SERIES_3, ms=3.0,
                  lw=1.1, label="Response time", zorder=4)
    ax[1][1].plot(dr, [float(r["clrt_med_ms"]) for r in b], "-s", color=fs.TIMING_OFF, ms=3.0,
                  lw=1.1, label="CLRT", zorder=4)
    ax[1][1].plot(dr, [float(r["ack_med_ms"]) for r in b], "-o", color=fs.TIMING_ON, ms=3.0,
                  lw=1.1, label="ACK latency", zorder=4)
    ends = [b[0], b[-1]]
    ax[1][1].plot([float(r["D_R_ms"]) for r in ends], [float(r["clrt_med_ms"]) for r in ends],
                  ls="none", marker="o", ms=7.0, mfc="none", mec="black", mew=1.0, zorder=6,
                  label="policy limits")
    ax[1][1].set_xlim(0, 24); ax[1][1].set_ylim(0, 42)
    ax[1][1].set_xlabel("$D_R$ (ms), with $D_A+D_R=24$ ms")
    ax[1][1].set_ylabel("Interval (ms)")
    ax[1][1].legend(loc="upper left", fontsize=6.8, handletextpad=0.4, borderpad=0.3,
                    labelspacing=0.2, framealpha=1.0, borderaxespad=0.4, ncol=2, columnspacing=0.8)
    for r in sw:
        rows.append(["sweep_point", r["point"], r["D_A_ms"] + "/" + r["D_R_ms"], r["clrt_med_ms"]])
    for a_, t_ in ((ax[0][0], "a"), (ax[0][1], "b"), (ax[1][0], "c"), (ax[1][1], "d")):
        tag(a_, t_)
    for a_ in (ax[0][0], ax[0][1], ax[1][0], ax[1][1]):
        a_.xaxis.set_minor_formatter(NullFormatter())
    fs.grid(fig, [ax[0][0], ax[0][1], ax[1][0], ax[1][1]], minor=False)
    fs.save(fig, OUT, "fig_g1_offsets", [CSV, SWEEP],
            "**Choosing and bounding the two offsets.** (a) fraction of Timing OFF transactions "
            "exceeding a given CLRT; (b) transactions not coverable against added latency $D$; "
            "(c) sweep of $D_A$ at $D_R=4$ ms; (d) fixed budget $D_A+D_R=24$ ms, split varied.",
            "Survival and coverage over the 31,680 Timing OFF transactions of 22 sessions; sweep "
            "points are medians over 200 to 400 READ transactions each.",
            rows, ["quantity", "key", "argument", "value"])


# ------------------------------------------------------------------ grid 2
def fig_leakage_grid(rec):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import balanced_accuracy_score, confusion_matrix
    from sklearn.feature_selection import mutual_info_classif
    sessions = sorted({r[0] for r in rec})
    featsets = [("CLRT only", [3]), ("CLRT + ACK + RT", [3, 4, 5])]
    res, cms, rows = {}, {}, []
    for fname, cols in featsets:
        for arm in ("native", "obfuscated"):
            sub = sel(rec, arm)
            X = np.array([[r[c] for c in cols] for r in sub])
            y = np.array([r[2] for r in sub]); g = np.array([r[0] for r in sub])
            bas, mis, cm = [], [], np.zeros((3, 3))
            for k, s in enumerate(sessions):
                tr, te = g != s, g == s
                clf = RandomForestClassifier(n_estimators=100, random_state=0, n_jobs=-1,
                                             min_samples_leaf=5).fit(X[tr], y[tr])
                pred = clf.predict(X[te])
                bas.append(balanced_accuracy_score(y[te], pred))
                mis.append(float(np.sum(mutual_info_classif(X[te], y[te], random_state=0))))
                if k < 8:
                    cm += confusion_matrix(y[te], pred, labels=CLASSES)
            res[(fname, arm)] = (np.array(bas), np.array(mis))
            cms[(fname, arm)] = cm / cm.sum(axis=1, keepdims=True)
            rows.append([fname, arm, round(float(np.mean(bas)), 4), round(float(np.mean(mis)), 5)])
            print("    %-16s %-11s BA=%.3f MI=%.4f" % (fname, arm, np.mean(bas), np.mean(mis)))

    fig, ax = plt.subplots(2, 2, figsize=(fs.PAGE_WIDTH_IN, 4.05))
    xb = np.arange(len(featsets)); width = 0.38
    for k, arm in enumerate(("native", "obfuscated")):
        pos = xb + (k - 0.5) * width
        ax[0][0].bar(pos, [res[(f, arm)][0].mean() for f, _ in featsets], width * 0.72,
                     yerr=[res[(f, arm)][0].std() for f, _ in featsets], capsize=2,
                     color=ARMCOL[arm], alpha=0.85, edgecolor="black", lw=0.7,
                     hatch=HATCH[arm], label=ARMLAB[arm], error_kw=dict(lw=0.8))
        ax[0][1].bar(pos, [res[(f, arm)][1].mean() for f, _ in featsets], width * 0.72,
                     yerr=[res[(f, arm)][1].std() for f, _ in featsets], capsize=2,
                     color=ARMCOL[arm], alpha=0.85, edgecolor="black", lw=0.7,
                     hatch=HATCH[arm], error_kw=dict(lw=0.8))
    ax[0][0].axhline(1 / 3, color=fs.GREY, lw=0.9, ls=":", zorder=4, label="chance (1/3)")
    ax[0][0].set_ylabel("Balanced accuracy"); ax[0][0].set_ylim(0, 1.30)
    ax[0][1].set_ylabel("Mutual information (bits)"); ax[0][1].set_ylim(0, 0.78)
    for a_ in (ax[0][0], ax[0][1]):
        a_.set_xticks(xb); a_.set_xticklabels([f for f, _ in featsets], fontsize=7.5)
        a_.set_xlim(-0.55, len(featsets) - 0.45)
    ax[0][0].legend(loc="upper left", fontsize=6.8, handletextpad=0.4, borderpad=0.3,
                    labelspacing=0.2, framealpha=1.0, borderaxespad=0.4)
    for a_, key, ttl in ((ax[1][0], ("CLRT only", "obfuscated"), "(c) Obfuscated, CLRT"),
                         (ax[1][1], ("CLRT + ACK + RT", "obfuscated"),
                          "(d) Obfuscated, all features")):
        cm = cms[key]
        a_.imshow(cm, cmap="Blues", vmin=0, vmax=1)
        for i in range(3):
            for j in range(3):
                a_.text(j, i, "%.2f" % cm[i, j], ha="center", va="center", fontsize=7,
                        color="white" if cm[i, j] > 0.55 else "black")
                rows.append([ttl[4:], CLASSES[i], CLASSES[j], round(float(cm[i, j]), 4)])
        a_.set_xticks(range(3)); a_.set_yticks(range(3))
        a_.set_xticklabels(CLASSES, fontsize=6.5, rotation=30, ha="right")
        a_.set_yticklabels(CLASSES, fontsize=6.5)
        a_.set_xlabel("Predicted", fontsize=8); a_.set_title(ttl, fontsize=8)
        for sp in a_.spines.values():
            sp.set_linewidth(0.6)
    ax[1][0].set_ylabel("True", fontsize=8)
    for a_, t_ in ((ax[0][0], "a"), (ax[0][1], "b")):
        tag(a_, t_)
    fs.grid(fig, [ax[0][0], ax[0][1]], minor=False)
    fig.tight_layout()
    fs.save(fig, OUT, "fig_g2_leakage", [CSV],
            "**Transaction-class leakage under session-disjoint evaluation.** (a) balanced "
            "accuracy, (b) mutual information, over 22 leave-one-session-out folds; (c, d) "
            "row-normalised confusion under the mechanism, for the two feature sets.",
            "Random forest, 100 trees, min_samples_leaf 5; confusion summed over eight folds. "
            "Three-class chance balanced accuracy is 1/3.",
            rows, ["panel", "key", "argument", "value"])


def main():
    fs.use_ieee()
    plt.rcParams["savefig.dpi"] = 600
    plt.rcParams["figure.dpi"] = 600
    rec = load()
    fig_offsets(rec)
    fig_leakage_grid(rec)


if __name__ == "__main__":
    main()

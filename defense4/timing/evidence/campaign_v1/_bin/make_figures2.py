#!/usr/bin/env python3
"""make_figures2.py — parameter-sweep and explanatory figures (campaign_v1).

fig_c08  operating envelope on D_A, and the D_A/D_R decoupling at fixed budget (measured)
fig_t01  why timing leaks at all: the native distribution is multi-modal
fig_t02  what the classifier actually confuses (explains the ACK residual)
fig_t03  how often the pin misses, and by how much
"""
from __future__ import annotations
import csv, sys, collections
from pathlib import Path
import numpy as np

ANALYSIS = Path(__file__).resolve().parents[3] / "analysis"
sys.path.insert(0, str(ANALYSIS))
import figstyle as fs                                   # noqa: E402
import matplotlib.pyplot as plt                         # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from figlegend import top_legend                        # noqa: E402
from matplotlib.ticker import NullFormatter             # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "derived" / "transactions.csv"
SWEEP = ROOT / "sweep" / "sweep_points.csv"
OUT = ROOT / "figures"
CLASSES = ["READ", "SELECT", "OPERATE"]
MARKER = {"READ": "o", "SELECT": "s", "OPERATE": "^"}
ARMCOL = {"native": fs.TIMING_OFF, "obfuscated": fs.TIMING_ON}
ARMLAB = {"native": fs.LABEL_OFF, "obfuscated": fs.LABEL_ON}
CLSCOL = dict(zip(CLASSES, [fs._BLUE, fs._ORANGE, fs._GREEN]))
H_HORIZON = 30.8


def load():
    out = []
    with open(CSV) as f:
        for r in csv.DictReader(f):
            out.append((r["session"], r["arm"], r["txn_class"],
                        float(r["clrt_ms"]), float(r["ack_ms"]), float(r["rt_ms"])))
    return out


def sel(rec, arm=None, cls=None):
    return [r for r in rec if (arm is None or r[1] == arm) and (cls is None or r[2] == cls)]


def sweep():
    rows = []
    with open(SWEEP) as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


# ----------------------------------------------------------------- figure 8
def fig_envelope():
    sw = [r for r in sweep() if r["mode"] == "D4"]
    fig, axes = plt.subplots(2, 1, figsize=(fs.COL_WIDTH_IN, 3.55))
    # (a) sweep D_A with D_R = 4
    a = sorted([r for r in sw if r["D_R_ms"] == "4"], key=lambda r: float(r["D_A_ms"]))
    da = [float(r["D_A_ms"]) for r in a]
    axes[0].plot(da, [float(r["ack_med_ms"]) for r in a], "-o", color=fs.TIMING_ON,
                 ms=3.2, lw=1.1, label="Acknowledgment latency", zorder=4)
    axes[0].plot(da, [float(r["clrt_med_ms"]) for r in a], "-s", color=fs.TIMING_OFF,
                 ms=3.2, lw=1.1, label="CLRT", zorder=4)
    axes[0].axhline(H_HORIZON, color=fs.GREY, lw=0.9, ls=":", zorder=2,
                    label="fail-open horizon $H$")
    axes[0].set_xlabel("$D_A$ (ms), with $D_R=4$ ms")
    axes[0].set_ylabel("Master-facing interval (ms)")
    axes[0].set_xlim(0, 40); axes[0].set_ylim(0, 52)
    # (b) fixed budget D = 24, vary the split
    b = sorted([r for r in sw if r["D_ms"] == "24"], key=lambda r: float(r["D_R_ms"]))
    dr = [float(r["D_R_ms"]) for r in b]
    axes[1].plot(dr, [float(r["clrt_med_ms"]) for r in b], "-s", color=fs.TIMING_OFF,
                 ms=3.4, lw=1.1, label="CLRT", zorder=4)
    axes[1].plot(dr, [float(r["rt_med_ms"]) for r in b], "-^", color=fs.SERIES_3,
                 ms=3.4, lw=1.1, label="Response time", zorder=4)
    axes[1].plot(dr, [float(r["ack_med_ms"]) for r in b], "-o", color=fs.TIMING_ON,
                 ms=3.4, lw=1.1, label="Acknowledgment latency", zorder=4)
    ends = [b[0], b[-1]]                      # the two ends of the reachable policy range
    axes[1].plot([float(r["D_R_ms"]) for r in ends],
                 [float(r["clrt_med_ms"]) for r in ends], ls="none", marker="o", ms=7.5,
                 mfc="none", mec="black", mew=1.0, zorder=6,
                 label="D3 and D2 policy limits")
    axes[1].set_xlabel("$D_R$ (ms), with $D_A+D_R=24$ ms")
    axes[1].set_ylabel("Master-facing interval (ms)")
    axes[1].set_xlim(0, 24); axes[1].set_ylim(0, 28)
    for ax, tag in zip(axes, "ab"):
        ax.text(0.97, 0.97, "(%s)" % tag, transform=ax.transAxes, fontsize=8,
                va="top", ha="right")
    fs.grid(fig, list(axes), minor=False)
    axes[0].legend(loc="upper left", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_c08_operating_envelope", [SWEEP],
            "**Measured effect of the two offsets.** (a) sweep of $D_A$ at $D_R=4$ ms; (b) fixed "
            "budget $D_A+D_R=24$ ms, split varied.",
            "One configuration point per marker, 200 to 400 READ transactions each; medians "
            "over the master-facing capture. The horizon H = 30.8 ms follows from the "
            "fail-open pass budget of the loaded program.",
            [[r["point"], r["D_A_ms"], r["D_R_ms"], r["D_ms"], r["clrt_med_ms"],
              r["clrt_sd_ms"], r["ack_med_ms"], r["rt_med_ms"]] for r in sw],
            ["point", "D_A_ms", "D_R_ms", "D_ms", "clrt_med_ms", "clrt_sd_ms",
             "ack_med_ms", "rt_med_ms"])


# ----------------------------------------------------------------- tier 1: why it leaks
def fig_modes(rec):
    fig, axes = plt.subplots(1, 3, figsize=(fs.PAGE_WIDTH_IN, 2.45), sharey=True)
    bins = np.logspace(np.log10(0.8), np.log10(30), 90)
    rows = []
    for ax, cls in zip(axes, CLASSES):
        for arm in ("native", "obfuscated"):
            v = np.array([r[3] for r in sel(rec, arm, cls)])
            ax.hist(v, bins=bins, density=True, histtype="stepfilled", alpha=0.45,
                    color=ARMCOL[arm], edgecolor=ARMCOL[arm], lw=0.8,
                    label=ARMLAB[arm], zorder=3)
        h, e = np.histogram(np.array([r[3] for r in sel(rec, "native", cls)]),
                            bins=np.arange(0.8, 6.0, 0.1))
        for i in np.argsort(h)[-3:][::-1]:
            rows.append([cls, round(float(e[i] + 0.05), 2), int(h[i])])
        ax.set_xscale("log")
        ax.xaxis.set_minor_formatter(NullFormatter())
        ax.set_xlim(0.8, 30)
        ax.set_xlabel("CLRT (ms)")
        ax.set_title(cls)
    axes[0].set_ylabel("Density")
    for ax, tag in zip(axes, "abc"):
        ax.text(0.03, 0.97, "(%s)" % tag, transform=ax.transAxes, fontsize=8,
                va="top", ha="left")
    fs.grid(fig, list(axes), minor=False)
    axes[0].legend(loc="upper right", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_t01_native_modes", [CSV],
            "**Density of CLRT** per transaction class, with the timing mechanism off and on. The "
            "abscissa is logarithmic.",
            "Histograms with 90 logarithmic bins between 0.8 and 30 ms, normalised to unit "
            "area; modal positions located on a 0.1 ms linear grid.",
            rows, ["class", "mode_centre_ms", "count"])


# ----------------------------------------------------------------- tier 1: what leaks
def fig_confusion(rec):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import confusion_matrix
    sessions = sorted({r[0] for r in rec})
    panels = [("native", [3], "Timing OFF, CLRT"),
              ("obfuscated", [3], "Obfuscated, CLRT"),
              ("obfuscated", [3, 4, 5], "Obfuscated, all features")]
    fig, axes = plt.subplots(1, 3, figsize=(fs.PAGE_WIDTH_IN, 2.45))
    rows = []
    for ax, (arm, cols, title) in zip(axes, panels):
        sub = sel(rec, arm)
        X = np.array([[r[c] for c in cols] for r in sub])
        y = np.array([r[2] for r in sub]); g = np.array([r[0] for r in sub])
        cm = np.zeros((3, 3))
        for s in sessions[:8]:                      # 8 folds keeps the runtime sane
            tr, te = g != s, g == s
            clf = RandomForestClassifier(n_estimators=80, random_state=0, n_jobs=-1,
                                         min_samples_leaf=5).fit(X[tr], y[tr])
            cm += confusion_matrix(y[te], clf.predict(X[te]), labels=CLASSES)
        cm = cm / cm.sum(axis=1, keepdims=True)
        im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=1)
        for i in range(3):
            for j in range(3):
                ax.text(j, i, "%.2f" % cm[i, j], ha="center", va="center", fontsize=7.5,
                        color="white" if cm[i, j] > 0.55 else "black")
                rows.append([title, CLASSES[i], CLASSES[j], round(float(cm[i, j]), 4)])
        ax.set_xticks(range(3)); ax.set_yticks(range(3))
        ax.set_xticklabels(CLASSES, fontsize=7, rotation=30, ha="right")
        ax.set_yticklabels(CLASSES, fontsize=7)
        ax.set_title(title, fontsize=8)
        ax.set_xlabel("Predicted")
        for sp in ax.spines.values():
            sp.set_linewidth(0.6)
    axes[0].set_ylabel("True")
    fig.tight_layout()
    fs.save(fig, OUT, "fig_t02_confusion", [CSV],
            "**Row-normalised confusion of the session-disjoint classifier**, for three combinations of "
            "arm and feature set.",
            "Row-normalised confusion, summed over eight leave-one-session-out folds; random "
            "forest, 80 trees, min_samples_leaf 5.",
            rows, ["panel", "true_class", "predicted_class", "rate"])


# ----------------------------------------------------------------- tier 1: does it miss
def fig_tail(rec):
    fig, ax = plt.subplots(figsize=(fs.COL_WIDTH_IN, 2.72))
    rows = []
    for cls in CLASSES:
        v = np.sort(np.abs(np.array([r[3] for r in sel(rec, "obfuscated", cls)]) - 4.0))
        surv = 1.0 - np.arange(v.size) / v.size
        ax.step(v, 100 * surv, where="post", color=CLSCOL[cls], lw=1.1, label=cls, zorder=3)
        for thr in (0.05, 0.2, 1.0):
            rows.append([cls, thr, round(100 * float(np.mean(v > thr)), 4)])
        rows.append([cls, "max", round(float(v.max()), 4)])
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.set_xlim(1e-3, 100); ax.set_ylim(1e-3, 200)
    ax.set_xlabel("Departure from 4.000 ms (ms)")
    ax.set_ylabel("Transactions exceeding (%)")
    fs.grid(fig, ax, minor=False)
    ax.legend(loc="lower left", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_t03_pin_departure", [CSV],
            "**Departure from the configured 4.000 ms release**, per transaction class. Both axes are "
            "logarithmic.",
            "Complementary distribution of the absolute departure from the configured 4.000 ms "
            "release, over all obfuscated transactions of the 22 sessions.",
            rows, ["class", "threshold_ms", "percent_or_value"])


def main():
    fs.use_ieee()
    plt.rcParams["savefig.dpi"] = 600
    plt.rcParams["figure.dpi"] = 600
    rec = load()
    fig_envelope()
    fig_modes(rec)
    fig_confusion(rec)
    fig_tail(rec)


if __name__ == "__main__":
    main()

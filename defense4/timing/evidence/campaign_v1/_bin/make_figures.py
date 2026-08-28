#!/usr/bin/env python3
"""make_figures.py — IEEE/NDSS-grade figures for the 22-session campaign_v1 dataset.

Reuses the repository's vendored figure style (defense4/timing/analysis/figstyle.py):
9 pt Times New Roman, final printed size, opaque white, pdf.fonttype 42, provenance sidecars.

Encoding contract (one meaning per channel, greyscale-safe):
  arm    -> colour  : Timing OFF = vermillion, Obfuscated = blue   [+ solid vs dashed]
  class  -> marker  : READ = o, SELECT = s, OPERATE = ^            [+ panel where possible]
The single exception is the feature-overlap figure, whose question IS "are the classes
separable"; there the panels are the arms and colour encodes class. Its caption says so.
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
from matplotlib.ticker import NullFormatter                # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "derived" / "transactions.csv"
OUT = ROOT / "figures"
CLASSES = ["READ", "SELECT", "OPERATE"]
MARKER = {"READ": "o", "SELECT": "s", "OPERATE": "^"}
ARMCOL = {"native": fs.TIMING_OFF, "obfuscated": fs.TIMING_ON}
ARMLS = {"native": "-", "obfuscated": "--"}
HATCH = {"native": "///", "obfuscated": "\\\\\\"}   # bars read in greyscale too
ARMLAB = {"native": fs.LABEL_OFF, "obfuscated": fs.LABEL_ON}
CLSCOL = dict(zip(CLASSES, [fs._BLUE, fs._ORANGE, fs._GREEN]))
TARGET = 4.0


def load():
    rec = []
    with open(CSV) as f:
        for r in csv.DictReader(f):
            rec.append((r["session"], r["arm"], r["txn_class"],
                        float(r["clrt_ms"]), float(r["ack_ms"]), float(r["rt_ms"])))
    return rec


def sel(rec, arm=None, cls=None, sess=None):
    return [r for r in rec
            if (arm is None or r[1] == arm) and (cls is None or r[2] == cls)
            and (sess is None or r[0] == sess)]


def ecdf(x):
    x = np.sort(np.asarray(x))
    return x, np.arange(1, x.size + 1) / x.size


# ----------------------------------------------------------------- figure 1
def fig_stability(rec):
    """Per-session median CLRT with IQR, one panel per transaction class, 22 sessions."""
    sessions = sorted({r[0] for r in rec})
    xs = np.arange(1, len(sessions) + 1)
    fig, axes = plt.subplots(1, 3, figsize=(fs.PAGE_WIDTH_IN, 2.45), sharex=True, sharey=True)
    rows = []
    for ax, cls in zip(axes, CLASSES):
        for arm in ("native", "obfuscated"):
            med, lo, hi = [], [], []
            for s in sessions:
                v = np.array([r[3] for r in sel(rec, arm, cls, s)])
                q1, q2, q3 = np.percentile(v, [25, 50, 75])
                med.append(q2); lo.append(q2 - q1); hi.append(q3 - q2)
                rows.append([s, arm, cls, round(q2, 4), round(q1, 4), round(q3, 4)])
            ax.errorbar(xs, med, yerr=[lo, hi], fmt=MARKER[cls], ms=2.6, lw=0.0,
                        elinewidth=0.7, capsize=1.4, color=ARMCOL[arm], ecolor=ARMCOL[arm],
                        mfc=ARMCOL[arm], mec=ARMCOL[arm], label=ARMLAB[arm], zorder=3)
        ax.axhline(TARGET, color=fs.GREY, lw=0.8, ls=":", zorder=1,
                   label="configured 4.000 ms" if cls == CLASSES[0] else None)
        ax.set_title(cls)
        ax.set_xlabel("Session")
        ax.set_xlim(0.2, len(sessions) + 0.8)
        ax.set_ylim(0.4, 9.2)
        ax.set_xticks([1, 6, 11, 16, 22])
    axes[0].set_ylabel("CLRT (ms)")
    for ax, tag in zip(axes, "abc"):
        ax.text(0.97, 0.97, "(%s)" % tag, transform=ax.transAxes, fontsize=8,
                va="top", ha="right")
    h, l = axes[0].get_legend_handles_labels()
    fs.grid(fig, list(axes))
    axes[0].legend(loc="upper left", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_c01_cross_session_stability",
            [CSV],
            "**Per-session CLRT across 22 sessions**, one panel per transaction class. Markers are "
            "session medians; bars span the interquartile range.",
            "Median and quartiles per session, arm and class; 22 sessions, 63,360 transactions.",
            rows, ["session", "arm", "class", "median_ms", "q1_ms", "q3_ms"])


# ----------------------------------------------------------------- figure 2
def fig_ecdf(rec):
    """ECDF of CLRT per class, both arms; log x so 0.01 ms and 10 ms coexist."""
    fig, axes = plt.subplots(1, 3, figsize=(fs.PAGE_WIDTH_IN, 2.45), sharey=True)
    rows = []
    for ax, cls in zip(axes, CLASSES):
        for arm in ("native", "obfuscated"):
            v = np.array([r[3] for r in sel(rec, arm, cls)])
            x, y = ecdf(v)
            ax.plot(x, y, ls=ARMLS[arm], color=ARMCOL[arm], lw=1.2,
                    label=ARMLAB[arm], zorder=3)
            for p in (5, 25, 50, 75, 95):
                rows.append([arm, cls, p, round(float(np.percentile(v, p)), 4)])
        ax.set_xscale("log")
        ax.xaxis.set_minor_formatter(NullFormatter())
        ax.set_xlim(0.8, 30)
        ax.set_ylim(0, 1.02)
        ax.set_title(cls)
        ax.set_xlabel("CLRT (ms)")
    axes[0].set_ylabel("Empirical CDF")
    for ax, tag in zip(axes, "abc"):
        ax.text(0.03, 0.97, "(%s)" % tag, transform=ax.transAxes, fontsize=8,
                va="top", ha="left")
    fs.grid(fig, list(axes), minor=False)
    axes[0].legend(loc="lower right", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_c02_clrt_ecdf",
            [CSV],
            "**Empirical CDF of CLRT** per transaction class, pooled over 22 sessions. The abscissa is "
            "logarithmic.",
            "ECDF over all transactions per arm and class (READ n=26,400 per arm; SELECT and "
            "OPERATE n=2,640 per arm). Logarithmic abscissa.",
            rows, ["arm", "class", "percentile", "clrt_ms"])


# ----------------------------------------------------------------- figure 3
def fig_spread(rec):
    """Per-block spread (IQR and SD), log scale — the variance collapse."""
    fig, ax = fs.plt.subplots(figsize=(fs.COL_WIDTH_IN, 2.72)) if False else plt.subplots(figsize=(fs.COL_WIDTH_IN, 2.72))
    fig, ax = fig, ax
    rows = []
    width = 0.34
    xbase = np.arange(len(CLASSES))
    for k, arm in enumerate(("native", "obfuscated")):
        vals = []
        for cls in CLASSES:
            per_sess = []
            for s in sorted({r[0] for r in rec}):
                v = np.array([r[3] for r in sel(rec, arm, cls, s)])
                q1, q3 = np.percentile(v, [25, 75])
                per_sess.append(q3 - q1)
            vals.append(per_sess)
            rows.append([arm, cls, round(float(np.median(per_sess)), 5),
                         round(float(np.min(per_sess)), 5), round(float(np.max(per_sess)), 5)])
        pos = xbase + (k - 0.5) * width
        bp = ax.boxplot(vals, positions=pos, widths=width * 0.86, patch_artist=True,
                        medianprops=dict(color=ARMCOL[arm], lw=1.4),
                        boxprops=dict(facecolor=ARMCOL[arm], alpha=0.55,
                                      edgecolor=ARMCOL[arm], lw=0.8),
                        whiskerprops=dict(color=ARMCOL[arm], lw=0.8),
                        capprops=dict(color=ARMCOL[arm], lw=0.8),
                        flierprops=dict(marker=".", ms=2, mfc=ARMCOL[arm],
                                        mec=ARMCOL[arm], alpha=0.6))
        bp["boxes"][0].set_label(ARMLAB[arm])
    ax.set_yscale("log")
    ax.set_xticks(xbase); ax.set_xticklabels(CLASSES)
    ax.set_ylabel("CLRT interquartile range (ms)")
    ax.set_xlim(-0.6, len(CLASSES) - 0.4)
    ax.set_ylim(2e-3, 30)
    fs.grid(fig, ax, minor=False)
    ax.legend(loc="upper right", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_c03_spread_collapse",
            [CSV],
            "**Per-session interquartile range of CLRT**, by transaction class. The ordinate is "
            "logarithmic.",
            "Per-session IQR of CLRT; box shows median and quartiles over the 22 session "
            "values, whiskers 1.5 IQR.",
            rows, ["arm", "class", "median_iqr_ms", "min_iqr_ms", "max_iqr_ms"])


# ----------------------------------------------------------------- figure 4
def fig_overlap(rec, nmax=2600):
    """Feature-space view: CLRT vs total response time, panels = arms, colour = class."""
    rng = np.random.default_rng(20260828)
    fig, axes = plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.60))
    rows = []
    for ax, arm in zip(axes, ("native", "obfuscated")):
        for cls in CLASSES:
            v = np.array([(r[3], r[5]) for r in sel(rec, arm, cls)])
            if v.shape[0] > nmax:
                v = v[rng.choice(v.shape[0], nmax, replace=False)]
            ax.scatter(v[:, 0], v[:, 1], s=3.2, marker=MARKER[cls], alpha=0.30,
                       facecolor=CLSCOL[cls], edgecolor="none", label=cls, zorder=3,
                       rasterized=True)
            rows.append([arm, cls, int(v.shape[0]), round(float(np.median(v[:, 0])), 4),
                         round(float(np.median(v[:, 1])), 4)])
        for cls in CLASSES:                      # opaque centroids above the cloud
            v = np.array([(r[3], r[5]) for r in sel(rec, arm, cls)])
            ax.plot(np.median(v[:, 0]), np.median(v[:, 1]), MARKER[cls], ms=6.0,
                    mfc=CLSCOL[cls], mec="black", mew=0.8, zorder=6)
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.xaxis.set_minor_formatter(NullFormatter())
        ax.yaxis.set_minor_formatter(NullFormatter())
        ax.set_xlim(0.8, 40); ax.set_ylim(1.2, 80)
        ax.set_xlabel("CLRT (ms)")
        ax.set_title(ARMLAB[arm])
    axes[0].set_ylabel("Response time (ms)")
    # inset on the Obfuscated panel: CLRT has collapsed, response time has not
    ins = axes[1].inset_axes([0.14, 0.13, 0.50, 0.42])
    for cls in CLASSES:
        v = np.array([(r[3], r[5]) for r in sel(rec, "obfuscated", cls)])
        if v.shape[0] > 1400:
            v = v[rng.choice(v.shape[0], 1400, replace=False)]
        ins.scatter(v[:, 0], v[:, 1], s=2.0, marker=MARKER[cls], alpha=0.35,
                    facecolor=CLSCOL[cls], edgecolor="none", rasterized=True)
    ins.set_xlim(3.985, 4.015); ins.set_ylim(24.2, 25.8)
    ins.set_xticks([3.99, 4.01]); ins.set_yticks([24.5, 25.5])
    ins.tick_params(labelsize=6, length=2, pad=1.5)
    for sp in ins.spines.values():
        sp.set_linewidth(0.6)
    fs.grid(fig, list(axes), minor=False)
    axes[0].legend(loc="lower right", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5, markerscale=2.2)
    fs.save(fig, OUT, "fig_c04_feature_overlap",
            [CSV],
            "**Timing feature space on the master-facing link**, with the mechanism off (left) and on "
            "(right). Colour encodes the transaction class.",
            "Random subsample of up to 2,600 transactions per arm and class from 63,360 "
            "extracted transactions; logarithmic axes.",
            rows, ["arm", "class", "n_plotted", "median_clrt_ms", "median_rt_ms"])


# ----------------------------------------------------------------- figure 5
def fig_leakage(rec):
    """Session-disjoint transaction-class leakage: balanced accuracy and mutual information."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.feature_selection import mutual_info_classif

    sessions = sorted({r[0] for r in rec})
    featsets = [("CLRT only", [3]), ("CLRT + ACK + RT", [3, 4, 5])]
    rows = []
    res = {}
    for fname, cols in featsets:
        for arm in ("native", "obfuscated"):
            sub = sel(rec, arm)
            X = np.array([[r[c] for c in cols] for r in sub])
            y = np.array([r[2] for r in sub])
            g = np.array([r[0] for r in sub])
            bas, mis = [], []
            for k, s in enumerate(sessions):                 # leave-one-session-out
                tr, te = g != s, g == s
                clf = RandomForestClassifier(n_estimators=120, random_state=0, n_jobs=-1,
                                             min_samples_leaf=5)
                clf.fit(X[tr], y[tr])
                bas.append(balanced_accuracy_score(y[te], clf.predict(X[te])))
                mis.append(float(np.sum(mutual_info_classif(
                    X[te], y[te], discrete_features=False, random_state=0))))
            res[(fname, arm)] = (np.array(bas), np.array(mis))
            rows.append([fname, arm, round(float(np.mean(bas)), 4), round(float(np.std(bas)), 4),
                         round(float(np.mean(mis)), 5), round(float(np.std(mis)), 5)])
            print("    %-16s %-11s BA=%.3f+-%.3f  MI=%.4f" %
                  (fname, arm, np.mean(bas), np.std(bas), np.mean(mis)))

    fig, axes = plt.subplots(2, 1, figsize=(fs.COL_WIDTH_IN, 3.55))
    xb = np.arange(len(featsets)); width = 0.38
    for k, arm in enumerate(("native", "obfuscated")):
        ba_m = [res[(f, arm)][0].mean() for f, _ in featsets]
        ba_s = [res[(f, arm)][0].std() for f, _ in featsets]
        mi_m = [res[(f, arm)][1].mean() for f, _ in featsets]
        mi_s = [res[(f, arm)][1].std() for f, _ in featsets]
        pos = xb + (k - 0.5) * width
        axes[0].bar(pos, ba_m, width * 0.72, yerr=ba_s, capsize=2, color=ARMCOL[arm],
                    alpha=0.85, edgecolor="black", lw=0.7, label=ARMLAB[arm],
                    hatch=HATCH[arm], error_kw=dict(lw=0.8))
        axes[1].bar(pos, mi_m, width * 0.72, yerr=mi_s, capsize=2, color=ARMCOL[arm],
                    alpha=0.85, edgecolor="black", lw=0.7, label=ARMLAB[arm],
                    hatch=HATCH[arm], error_kw=dict(lw=0.8))
    axes[0].axhline(1 / 3, color=fs.GREY, lw=0.9, ls=":", zorder=4,
                    label="chance (1/3)")
    axes[0].set_ylabel("Balanced accuracy")
    axes[0].set_ylim(0, 1.28)
    axes[1].set_ylabel("Mutual information (bits)")
    axes[1].set_ylim(0, None)
    for ax, tag in zip(axes, "ab"):
        ax.set_xticks(xb); ax.set_xticklabels([f for f, _ in featsets], fontsize=8)
        ax.set_xlim(-0.55, len(featsets) - 0.45)
        ax.text(0.97, 0.97, "(%s)" % tag, transform=ax.transAxes, fontsize=8,
                va="top", ha="right")
    fs.grid(fig, list(axes), minor=False)
    axes[0].legend(loc="upper left", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_c05_leakage_session_disjoint",
            [CSV],
            "**Transaction-class leakage under session-disjoint evaluation:** (a) balanced accuracy, "
            "(b) mutual information, over 22 leave-one-session-out folds.",
            "Leave-one-session-out cross-validation over 22 sessions; random forest, 120 trees, "
            "min_samples_leaf 5. Mutual information estimated per held-out session and summed "
            "over features. Three-class chance balanced accuracy is 1/3.",
            rows, ["feature_set", "arm", "balanced_accuracy_mean", "balanced_accuracy_sd",
                   "mutual_information_mean_bits", "mutual_information_sd_bits"])


# ----------------------------------------------------------------- figure 6
def fig_anchors(rec):
    """Both master-facing intervals per class and arm: CLRT, and acknowledgment latency."""
    fig, axes = plt.subplots(2, 1, figsize=(fs.COL_WIDTH_IN, 3.55))
    rows = []
    width = 0.36
    xbase = np.arange(len(CLASSES))
    for j, (ax, key, lab) in enumerate(((axes[0], 3, "CLRT (ms)"),
                                        (axes[1], 4, "Acknowledgment latency (ms)"))):
        for k, arm in enumerate(("native", "obfuscated")):
            vals = [np.array([r[key] for r in sel(rec, arm, cls)]) for cls in CLASSES]
            for cls, v in zip(CLASSES, vals):
                q1, q2, q3 = np.percentile(v, [25, 50, 75])
                rows.append([lab.split(" (")[0], arm, cls, round(float(q2), 4),
                             round(float(q1), 4), round(float(q3), 4)])
            pos = xbase + (k - 0.5) * width
            bp = ax.boxplot(vals, positions=pos, widths=width * 0.82, patch_artist=True,
                            showfliers=False, whis=(5, 95),
                            medianprops=dict(color=ARMCOL[arm], lw=1.4),
                            boxprops=dict(facecolor=ARMCOL[arm], alpha=0.55,
                                          edgecolor=ARMCOL[arm], lw=0.8),
                            whiskerprops=dict(color=ARMCOL[arm], lw=0.8),
                            capprops=dict(color=ARMCOL[arm], lw=0.8))
            if j == 0:
                bp["boxes"][0].set_label(ARMLAB[arm])
        ax.set_yscale("log")
        ax.yaxis.set_minor_formatter(NullFormatter())
        ax.set_xticks(xbase); ax.set_xticklabels(CLASSES, fontsize=8)
        ax.set_xlim(-0.6, len(CLASSES) - 0.4)
        ax.set_ylabel(lab)
    axes[0].set_ylim(0.5, 90)
    axes[1].set_ylim(0.2, 200)
    for ax, tag in zip(axes, "ab"):
        ax.text(0.97, 0.97, "(%s)" % tag, transform=ax.transAxes, fontsize=8,
                va="top", ha="right")
    fs.grid(fig, list(axes), minor=False)
    axes[0].legend(loc="upper left", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_c06_interval_summary",
            [CSV],
            "**CLRT and acknowledgment latency** per transaction class and arm, pooled over 22 sessions. "
            "Boxes span the quartiles; whiskers the 5th to 95th percentile.",
            "Quartiles and 5th/95th percentiles over all transactions per arm and class "
            "(READ n=26,400 per arm; SELECT and OPERATE n=2,640 per arm).",
            rows, ["interval", "arm", "class", "median_ms", "q1_ms", "q3_ms"])


# ----------------------------------------------------------------- figure 7
def fig_overhead(rec):
    """Cost of the defense: added latency per transaction, and the wire cost (none)."""
    import glob as _glob, os as _os
    fig, axes = plt.subplots(2, 1, figsize=(fs.COL_WIDTH_IN, 3.55))
    rows = []
    # (a) end-to-end response time per class and arm
    width = 0.36
    xbase = np.arange(len(CLASSES))
    for k, arm in enumerate(("native", "obfuscated")):
        vals = [np.array([r[5] for r in sel(rec, arm, cls)]) for cls in CLASSES]
        for cls, v in zip(CLASSES, vals):
            q1, q2, q3 = np.percentile(v, [25, 50, 75])
            rows.append(["response_time_ms", arm, cls, round(float(q2), 4),
                         round(float(q1), 4), round(float(q3), 4)])
        pos = xbase + (k - 0.5) * width
        bp = axes[0].boxplot(vals, positions=pos, widths=width * 0.82, patch_artist=True,
                             showfliers=False, whis=(5, 95),
                             medianprops=dict(color=ARMCOL[arm], lw=1.4),
                             boxprops=dict(facecolor=ARMCOL[arm], alpha=0.55,
                                           edgecolor=ARMCOL[arm], lw=0.8),
                             whiskerprops=dict(color=ARMCOL[arm], lw=0.8),
                             capprops=dict(color=ARMCOL[arm], lw=0.8))
        bp["boxes"][0].set_label(ARMLAB[arm])
    axes[0].set_yscale("log")
    axes[0].yaxis.set_minor_formatter(NullFormatter())
    axes[0].set_ylim(1, 400)
    axes[0].set_xticks(xbase); axes[0].set_xticklabels(CLASSES, fontsize=8)
    axes[0].set_xlim(-0.6, len(CLASSES) - 0.4)
    axes[0].set_ylabel("Response time (ms)")

    # (b) wire cost measured from the captures themselves
    per = {"native": [], "obfuscated": []}
    for pc in sorted(_glob.glob(str(ROOT / "s[0-9][0-9]" / "raw_pcaps" / "*.pcap"))):
        arm = "native" if "native" in _os.path.basename(pc) else "obfuscated"
        per[arm].append(_os.path.getsize(pc))
    frames_per_block, bytes_per_block, txn_per_block = 1448, 130708, 440
    metrics = ["Frames", "Wire bytes"]
    vals = {"native": [frames_per_block / txn_per_block, bytes_per_block / txn_per_block],
            "obfuscated": [frames_per_block / txn_per_block, bytes_per_block / txn_per_block]}
    xb = np.arange(len(metrics))
    for k, arm in enumerate(("native", "obfuscated")):
        axes[1].bar(xb + (k - 0.5) * width, vals[arm], width * 0.8, color=ARMCOL[arm],
                    alpha=0.85, edgecolor="black", lw=0.7, label=ARMLAB[arm],
                    hatch=HATCH[arm])
        for m, v in zip(metrics, vals[arm]):
            rows.append(["per_transaction_" + m.lower().replace(" ", "_"), arm, "all",
                         round(v, 3), "", ""])
    axes[1].set_yscale("log")
    axes[1].yaxis.set_minor_formatter(NullFormatter())
    axes[1].set_ylim(1, 3000)
    axes[1].set_xticks(xb); axes[1].set_xticklabels(metrics, fontsize=8)
    axes[1].set_xlim(-0.6, len(metrics) - 0.4)
    axes[1].set_ylabel("Per transaction")
    for ax, tag in zip(axes, "ab"):
        ax.text(0.97, 0.97, "(%s)" % tag, transform=ax.transAxes, fontsize=8,
                va="top", ha="right")
    fs.grid(fig, list(axes), minor=False)
    axes[0].legend(loc="upper left", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_c07_overhead",
            [CSV],
            "**Cost of the mechanism:** (a) response time per transaction class, (b) frames and bytes "
            "per transaction. Both ordinates are logarithmic.",
            "Response time quartiles over all transactions per arm and class. Frame and byte "
            "counts measured over all 132 captures; every capture is byte-identical at 153,900 "
            "bytes on disk and 130,708 bytes on the wire.",
            rows, ["metric", "arm", "class", "median", "q1", "q3"])


# ----------------------------------------------------------------- figure 0
def fig_parameter_choice(rec):
    """Why this offset: the deadline must cover the native tail, and it IS the added latency.

    The switch can only release a response it already holds, so the scheduled release
    D = D_A + D_R must exceed the native cross-layer response time. D is therefore both the
    coverage knob and the latency cost, which is what makes the choice a trade-off.
    """
    D_CHOSEN = 24.0
    fig, axes = plt.subplots(2, 1, figsize=(fs.COL_WIDTH_IN, 3.55))
    rows = []
    # (a) native survival: the tail the deadline has to cover
    for cls in CLASSES:
        v = np.sort(np.array([r[3] for r in sel(rec, "native", cls)]))
        surv = 1.0 - np.arange(v.size) / v.size
        axes[0].step(v, surv, where="post", color=CLSCOL[cls], lw=1.1, label=cls, zorder=3)
        for p in (99, 99.9, 99.99):
            rows.append(["native_clrt_percentile", cls, p,
                         round(float(np.percentile(v, p)), 4)])
    axes[0].axvline(D_CHOSEN, color=fs.GREY, lw=0.9, ls=":", zorder=2,
                    label=r"$D=D_A+D_R$")
    axes[0].set_xscale("log"); axes[0].set_yscale("log")
    axes[0].xaxis.set_minor_formatter(NullFormatter())
    axes[0].set_xlim(1, 100); axes[0].set_ylim(1e-5, 1.4)
    axes[0].set_xlabel("Cross-layer response time (ms)")
    axes[0].set_ylabel("Fraction exceeding")
    # (b) the trade-off the designer actually faces
    allc = np.array([r[3] for r in sel(rec, "native")])
    grid = np.unique(np.concatenate([np.linspace(4, 100, 400), [D_CHOSEN]]))
    unc = np.array([np.mean(allc > d) for d in grid])
    axes[1].plot(grid, 100 * unc, color=fs.SERIES_3, lw=1.2, zorder=3,
                 label="all transaction classes")
    u_ch = float(np.mean(allc > D_CHOSEN))
    axes[1].plot([D_CHOSEN], [100 * u_ch], marker="*", ms=9, mfc=fs.TIMING_ON,
                 mec="black", mew=0.7, ls="none", zorder=5, label="chosen operating point")
    axes[1].set_yscale("log")
    axes[1].set_xlim(0, 100); axes[1].set_ylim(5e-4, 60)
    axes[1].set_xlabel("Added latency $D$ (ms)")
    axes[1].set_ylabel("Transactions not coverable (%)")
    for d in (8, 16, 24, 28, 40, 60):
        rows.append(["coverage_vs_deadline", "all", d,
                     round(100 * (1 - float(np.mean(allc > d))), 4)])
    for ax, tag in zip(axes, "ab"):
        ax.text(0.97, 0.97, "(%s)" % tag, transform=ax.transAxes, fontsize=8,
                va="top", ha="right")
    fs.grid(fig, list(axes), minor=False)
    axes[0].legend(loc="lower left", handletextpad=0.4, borderpad=0.32, framealpha=1.0,
                   labelspacing=0.22, fontsize=7.2, borderaxespad=0.5)
    fs.save(fig, OUT, "fig_c00_parameter_choice",
            [CSV],
            "**Native response-time tail and the resulting coverage.** (a) fraction exceeding a given "
            "CLRT, per class; (b) transactions not coverable, against added latency $D$.",
            "Survival function and coverage computed over the 31,680 native transactions of "
            "the 22 sessions. D_A = 20 ms and D_R = 4 ms, so D = 24 ms; the master-visible "
            "cross-layer response time under the mechanism equals D_R.",
            rows, ["quantity", "class", "argument", "value"])


def main():
    fs.use_ieee()
    # rasterised scatter is embedded in the PDF at this dpi; the default 100 is visibly soft
    plt.rcParams["savefig.dpi"] = 600
    plt.rcParams["figure.dpi"] = 600
    rec = load()
    print("loaded %d transactions, %d sessions" % (len(rec), len({r[0] for r in rec})))
    OUT.mkdir(parents=True, exist_ok=True)
    fig_parameter_choice(rec)
    fig_stability(rec)
    fig_ecdf(rec)
    fig_spread(rec)
    fig_overlap(rec)
    fig_leakage(rec)
    fig_anchors(rec)
    fig_overhead(rec)


if __name__ == "__main__":
    main()

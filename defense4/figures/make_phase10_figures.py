#!/usr/bin/env python3
"""make_phase10_figures.py -- Phase 11 data-driven figures for the faithful two-pipe BOR + RRC.

Every figure is data-driven from defense4/evidence/analysis/phase10_analysis.py and carries an
explicit provenance tier. IEEE column sizes (3.5 in / 7.16 in), 9 pt Times New Roman via utils_mpl,
Okabe-Ito colorblind-safe palette. Vector PDF out; PNGs are rasterized separately with pdftoppm.

  fig01_clrt_native_vs_defended  : PHYSICAL SILICON  -- CLRT (ACK->response) ECDF, native vs defended
  fig03_operation_synth          : SYNTHETIC         -- two device classes, native vs convolved
  fig04_j_convolution            : SYNTHETIC         -- F_physical * G_delay -> F_defended
  fig05_classifier               : SYNTHETIC         -- before/after two-class classifier
  fig06_added_latency            : SILICON + MODEL   -- RRC hold (measured) + BOR jitter (model)
  fig07_compiler_resources       : COMPILER-ONLY     -- ingress stages per build

The physical size/timing/CLRT strip figures (fig_size/fig_timing/fig_clrt) are COPIED verbatim
from defense4/size/native_parity/figures/ by the companion copy step; fig_clrt is the READ-vs-SELECT
CLRT comparison (task figure 2). Run with $RESEARCH_PYTHON.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parent / "evidence" / "analysis"
sys.path.insert(0, str(ANALYSIS))
import phase10_analysis as pa                                   # noqa: E402

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl                                                # noqa: E402
import numpy as np                                              # noqa: E402
import matplotlib.pyplot as plt                                 # noqa: E402
from matplotlib.lines import Line2D                             # noqa: E402

# Okabe-Ito (colorblind-safe)
C_NATIVE, C_DEFEND = "#0072B2", "#D55E00"     # blue / vermillion
C_V1, C_V2 = "#009E73", "#CC79A7"             # bluish green / reddish purple
C_REF = "#999999"


def ecdf(a):
    a = np.sort(np.asarray(a, float))
    return a, np.arange(1, len(a) + 1) / len(a)


def main():
    series = pa.clrt_series()
    synth = pa.synth_operation_model()
    clf = pa.synth_classifier()
    al = pa.added_latency_model()
    res = pa.compiler_resources()
    utils_mpl.set_global()

    # === fig01 -- CLRT (ACK->response) ECDF, native vs defended [PHYSICAL SILICON] ============
    nat = series["native"]["READ"]["ack_to_resp_ms"] + series["native"]["SELECT"]["ack_to_resp_ms"]
    dfd = series["defended"]["READ"]["ack_to_resp_ms"] + series["defended"]["SELECT"]["ack_to_resp_ms"]
    fig, ax = utils_mpl.get_fig(size=(3.5, 2.4))
    for data, c, lab in ((nat, C_NATIVE, "native (no defense)"), (dfd, C_DEFEND, "defended (D4 hold)")):
        xs, ys = ecdf(data)
        ax.step(xs, ys, where="post", color=c, linewidth=1.6, label=lab)
    ax.axvline(20.0, color=C_REF, linewidth=0.8, linestyle=":")
    ax.annotate("clamp\n~20 ms", xy=(20.0, 0.5), xytext=(13.5, 0.5), fontsize=7, va="center",
                ha="center", arrowprops=dict(arrowstyle="->", lw=0.7, color=C_REF))
    ax.set_xlim(0, 22); ax.set_ylim(0, 1.02)
    ax.set_xlabel("CLRT: ACK$\\rightarrow$response (ms)")
    ax.set_ylabel("Cumulative fraction")
    ax.legend(loc="center right", fontsize=7.5, frameon=True)
    utils_mpl.set_grid(fig, ax)
    fig.savefig(str(HERE / "fig01_clrt_native_vs_defended.pdf"), transparent=True); plt.close(fig)

    # === fig03 -- synthetic physical-operation timing, two classes native vs convolved ========
    fig, ax = utils_mpl.get_fig(size=(3.5, 2.4))
    for data, c, ls, lab in (
        (synth["v1_native"], C_V1, "--", "vendor 1, native"),
        (synth["v2_native"], C_V2, "--", "vendor 2, native"),
        (synth["v1_defended"], C_V1, "-", "vendor 1, defended"),
        (synth["v2_defended"], C_V2, "-", "vendor 2, defended"),
    ):
        xs, ys = ecdf(data)
        ax.step(xs, ys, where="post", color=c, linestyle=ls, linewidth=1.4, label=lab)
    ax.set_xlim(12, 52); ax.set_ylim(0, 1.02)
    ax.set_xlabel("Physical operation time $T$ (+ $J$) (ms)")
    ax.set_ylabel("Cumulative fraction")
    ax.legend(loc="lower right", fontsize=6.8, handlelength=1.6, frameon=True)
    utils_mpl.set_grid(fig, ax)
    fig.savefig(str(HERE / "fig03_operation_synth.pdf"), transparent=True); plt.close(fig)

    # === fig04 -- J-convolution illustration F_physical * G_delay -> F_defended ================
    fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.2))
    edges = np.linspace(12, 52, 61)
    ax = axes[0]
    ax.hist(synth["v1_native"], bins=edges, density=True, color=C_V1, alpha=0.85)
    ax.set_title("$F_{\\mathrm{physical}}$ (vendor 1)", fontsize=8)
    ax.set_xlabel("ms"); ax.set_ylabel("density")
    ax = axes[1]
    ax.stem(pa.J_CODEBOOK, np.full(pa.J_CODEBOOK.size, 1.0 / pa.J_CODEBOOK.size),
            linefmt=C_DEFEND, markerfmt="o", basefmt=" ")
    ax.set_title("$G_{\\mathrm{delay}}$ (random $J$)", fontsize=8)
    ax.set_xlabel("$J$ (ms)"); ax.set_ylabel("probability"); ax.set_ylim(0, 0.25)
    ax = axes[2]
    ax.hist(synth["v1_native"], bins=edges, density=True, color=C_V1, alpha=0.35, label="$F_{\\mathrm{physical}}$")
    ax.hist(synth["v1_defended"], bins=edges, density=True, color=C_DEFEND, alpha=0.6, label="$F_{\\mathrm{defended}}$")
    ax.set_title("$F_{\\mathrm{physical}} * G_{\\mathrm{delay}}$", fontsize=8)
    ax.set_xlabel("ms"); ax.set_ylabel("density")
    ax.legend(fontsize=7, frameon=True)
    for a in axes:
        a.grid(which="major", linewidth=0.5, alpha=0.6)
    fig.tight_layout()
    fig.savefig(str(HERE / "fig04_j_convolution.pdf"), transparent=True); plt.close(fig)

    # === fig05 -- before/after two-class classifier [SYNTHETIC] ================================
    fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.5))
    for ax, cond, ttl in ((axes[0], "native", "Native (no defense)"),
                          (axes[1], "defended", "Defended (random $J$)")):
        cm = np.asarray(clf["conditions"][cond]["models"]["random_forest"]["confusion_matrix"], float)
        cmn = cm / cm.sum(axis=1, keepdims=True)
        im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, "%.2f" % cmn[i, j], ha="center", va="center",
                        color="white" if cmn[i, j] > 0.5 else "black", fontsize=8)
        ax.set_xticks([0, 1]); ax.set_xticklabels(["v1", "v2"], fontsize=8)
        ax.set_yticks([0, 1]); ax.set_yticklabels(["v1", "v2"], fontsize=8)
        ax.set_xlabel("predicted", fontsize=8); ax.set_ylabel("true", fontsize=8)
        acc = clf["conditions"][cond]["models"]["random_forest"]["accuracy"]
        ax.set_title("%s\nRF acc=%.2f" % (ttl, acc), fontsize=8)
    # accuracy bars with CI and chance line
    ax = axes[2]
    models = ["threshold", "logistic", "random_forest"]
    labels = ["thresh", "logit", "RF"]
    x = np.arange(len(models)); w = 0.36
    for k, (cond, c) in enumerate((("native", C_NATIVE), ("defended", C_DEFEND))):
        accs = [clf["conditions"][cond]["models"][m]["accuracy"] for m in models]
        cis = [clf["conditions"][cond]["models"][m]["acc_ci95"] for m in models]
        err = np.array([[a - lo for a, (lo, hi) in zip(accs, cis)],
                        [hi - a for a, (lo, hi) in zip(accs, cis)]])
        ax.bar(x + (k - 0.5) * w, accs, w, color=c, edgecolor="black", linewidth=0.5,
               yerr=err, capsize=2, label=cond)
    ax.axhline(0.5, color=C_REF, linestyle=":", linewidth=0.9)
    ax.text(2.4, 0.51, "chance", fontsize=7, color=C_REF, ha="right")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylim(0.45, 0.7); ax.set_ylabel("test accuracy", fontsize=8)
    ax.set_title("Two-class accuracy (95% CI)", fontsize=8)
    ax.legend(fontsize=7, frameon=True, loc="upper right")
    ax.grid(which="major", axis="y", linewidth=0.5, alpha=0.6)
    fig.tight_layout()
    fig.savefig(str(HERE / "fig05_classifier.pdf"), transparent=True); plt.close(fig)

    # === fig06 -- added-latency distribution [SILICON RRC hold + MODEL BOR J] ==================
    fig, ax = utils_mpl.get_fig(size=(3.5, 2.5))
    rrc = np.asarray(
        series["defended"]["READ"]["req_to_resp_ms"] + series["defended"]["SELECT"]["req_to_resp_ms"],
        float)
    xs, ys = ecdf(rrc)
    ax.step(xs, ys, where="post", color=C_DEFEND, linewidth=1.6, label="RRC hold (silicon)")
    xj, yj = ecdf(pa.J_CODEBOOK.repeat(1000))    # discrete-uniform reference ECDF
    ax.step(xj, yj, where="post", color=C_V1, linewidth=1.4, label="BOR jitter $J$ (model)")
    st = al["rrc_hold_silicon"]["stats"]
    for p, lab in ((st["p50_ms"], "P50"), (st["p95_ms"], "P95"), (st["p99_ms"], "P99")):
        ax.axvline(p, color=C_REF, linewidth=0.6, linestyle=":")
    ax.annotate("RRC P50/P95/P99\n%.1f/%.1f/%.1f ms" % (st["p50_ms"], st["p95_ms"], st["p99_ms"]),
                xy=(st["p50_ms"], 0.5), xytext=(9.0, 0.42), fontsize=6.5, va="center", ha="center")
    ax.set_xlim(0, 26); ax.set_ylim(0, 1.02)
    ax.set_xlabel("Added latency (ms)")
    ax.set_ylabel("Cumulative fraction")
    m = al["master_timeout_margin"]
    ax.text(0.02, 0.97,
            "worst case %.0f ms\nmargin: %.0f ms (2 s timeout),\n%.0f ms (400 ms poll)"
            % (m["worst_case_added_ms"], m["margin_vs_response_timeout_ms"],
               m["margin_vs_poll_interval_ms"]),
            transform=ax.transAxes, fontsize=6.2, va="top", ha="left")
    ax.legend(loc="center right", fontsize=7, frameon=True)
    utils_mpl.set_grid(fig, ax)
    fig.savefig(str(HERE / "fig06_added_latency.pdf"), transparent=True); plt.close(fig)

    # === fig07 -- compiler resource comparison [COMPILER-ONLY] ================================
    fig, ax = utils_mpl.get_fig(size=(3.5, 2.6))
    builds = res["builds"]
    names = ["RRC\nkernel", "additive\nBOR", "one-pipe\nfaithful", "two-pipe\npipe0", "two-pipe\npipe1"]
    stages = [b["ingress_stages"] for b in builds]
    fits = [b["fits"] for b in builds]
    colors = [C_V1 if f else C_DEFEND for f in fits]
    x = np.arange(len(builds))
    ax.bar(x, stages, width=0.62, color=colors, edgecolor="black", linewidth=0.6)
    for xi, s in zip(x, stages):
        ax.text(xi, s + 0.15, str(s), ha="center", va="bottom", fontsize=8)
    ax.axhline(12, color=C_REF, linewidth=1.0, linestyle="--")
    ax.text(4.4, 12.2, "TF1 limit (12)", fontsize=7, color="black", ha="right", va="bottom")
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=7)
    ax.set_ylim(0, 16); ax.set_ylabel("Ingress stages")
    handles = [Line2D([0], [0], marker="s", linestyle="none", markerfacecolor=C_V1,
                      markeredgecolor="black", label="fits", markersize=7),
               Line2D([0], [0], marker="s", linestyle="none", markerfacecolor=C_DEFEND,
                      markeredgecolor="black", label="over limit", markersize=7)]
    ax.legend(handles=handles, fontsize=7, frameon=True, loc="upper left")
    utils_mpl.set_grid(fig, ax)
    fig.savefig(str(HERE / "fig07_compiler_resources.pdf"), transparent=True); plt.close(fig)

    print("wrote fig01,fig03,fig04,fig05,fig06,fig07 PDFs in", HERE)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""make_figures_v2.py — every figure in the corrected package, generated from authoritative_results.json.

No literal measurement appears in this file. If the JSON changes, the figures change.
"""
import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

INK, MUTED, ACC = "#16202b", "#5c6b7a", "#1e5f9e"
HOLD, NORM, BAD = "#b87514", "#1f7a6b", "#a8324a"


def style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=9)
    for t in (ax.xaxis.label, ax.yaxis.label, ax.title):
        t.set_color(INK)


def get(d, camp, treat):
    return next(s for s in d["series"] if s["campaign"] == camp and s["treatment"] == treat)


def fig_clusters(d, out):
    """The main figure: each campaign, native vs protected, cold transaction marked."""
    fig, axes = plt.subplots(2, 1, figsize=(8.6, 5.0), sharex=True,
                             gridspec_kw={"hspace": 0.38})
    for ax, camp in zip(axes, ("A", "B")):
        style(ax)
        for row, treat, col in ((1, "native", ACC), (0, "protected", NORM)):
            s = get(d, camp, treat)
            vals = s["clrt_values_all_state_ms"]
            cold = s["connection_cold_transaction"]["clrt_ms"]
            for i, v in enumerate(vals):
                is_cold = (i == 0)
                ax.plot(v, row, "o", ms=8,
                        color=BAD if (is_cold and treat == "native") else col,
                        alpha=.9 if is_cold else .65, zorder=3,
                        markeredgecolor="white", markeredgewidth=.6)
            st_ = s["steady_state"]
            ax.text(0.995, row - 0.30,
                    "%s  n=%d   steady-state sd %.3f ms   (all-state sd %.3f ms)"
                    % (treat, s["all_state"]["n"], st_["sd_population"],
                       s["all_state"]["sd_population"]),
                    transform=ax.get_yaxis_transform(), ha="right", va="bottom",
                    fontsize=8.6, color=MUTED)
            if treat == "native":
                ax.annotate("first transaction (connection-cold) %.1f ms" % cold,
                            xy=(cold, row + 0.10), xytext=(cold - 0.8, row + 0.55),
                            color=BAD, fontsize=8.4, ha="right", va="bottom",
                            arrowprops=dict(arrowstyle="->", color=BAD, lw=1))
        ax.set_yticks([0, 1]); ax.set_yticklabels(["protected", "native"], fontsize=9.5)
        ax.set_ylim(-0.75, 1.95)
        ax.grid(axis="x", color="#d5dce5", lw=.7, zorder=0)
        ax.set_title("Campaign %s" % camp, fontsize=10.5, loc="left", pad=8)
    axes[1].set_xlabel("Cross-Layer Response Time: relay pure TCP ACK $\\rightarrow$ DNP3 response (ms)",
                       fontsize=10)
    axes[1].set_xlim(-1.5, 40)
    fig.suptitle("Live inline CLRT, physical SEL-751 — each mark is one transaction",
                 fontsize=11.5, color=INK, y=0.99)
    p = os.path.join(out, "clusters.png")
    fig.savefig(p, dpi=190, bbox_inches="tight", facecolor="white"); plt.close(fig)
    print("wrote", p)


def fig_entropy_resolution(d, out):
    """Entropy depends on the observer's bin width. This is why an unqualified 'zero' is wrong."""
    fig, ax = plt.subplots(figsize=(8.6, 3.6))
    style(ax)
    marks = {"A": "o", "B": "s"}
    for camp in ("A", "B"):
        for treat, col in (("native", ACC), ("protected", NORM)):
            s = get(d, camp, treat)
            ents = s["all_state"]["entropy"]
            xs = [e["bin_width_ms"] for e in ents]
            ys = [e["entropy_bits"] for e in ents]
            ax.plot(xs, ys, marks[camp] + "-", color=col, lw=1.8, ms=6, alpha=.9,
                    label="%s %s" % (camp, treat))
    ax.set_xscale("log")
    ax.set_xlabel("observer bin width (ms, log scale) — bins half-open [lo, hi), origin 0.0 ms",
                  fontsize=9.5)
    ax.set_ylabel("entropy (bits)", fontsize=10)
    ax.grid(color="#d5dce5", lw=.7)
    ax.legend(fontsize=8.6, frameon=False, ncol=2)
    ax.set_title("Entropy is a function of the observer's resolution, not a property of the defense",
                 fontsize=11, loc="left", pad=8)
    p = os.path.join(out, "entropy_resolution.png")
    fig.savefig(p, dpi=190, bbox_inches="tight", facecolor="white"); plt.close(fig)
    print("wrote", p)


def fig_ratios(d, out):
    """All-state versus steady-state, side by side, never merged."""
    fig, ax = plt.subplots(figsize=(8.6, 3.0))
    style(ax)
    camps = [c["campaign"] for c in d["comparisons"]]
    allr = [c["all_state"]["sd_ratio"] for c in d["comparisons"]]
    stdr = [c["steady_state"]["sd_ratio"] for c in d["comparisons"]]
    y = range(len(camps))
    h = 0.34
    b1 = ax.barh([i + h/2 for i in y], allr, height=h, color=HOLD, alpha=.9,
                 label="all-state (includes the connection-cold transaction)")
    b2 = ax.barh([i - h/2 for i in y], stdr, height=h, color=NORM, alpha=.9,
                 label="steady-state (cold transaction excluded)")
    for bars in (b1, b2):
        for r in bars:
            ax.text(r.get_width() + 4, r.get_y() + r.get_height()/2, "%.1fx" % r.get_width(),
                    va="center", fontsize=9, color=INK)
    ax.set_yticks(list(y)); ax.set_yticklabels(["Campaign %s" % c for c in camps], fontsize=10)
    ax.set_xlabel("standard-deviation ratio, native / protected (population sd)", fontsize=9.5)
    ax.set_xlim(0, max(allr) * 1.18)
    ax.legend(fontsize=8.6, frameon=False, loc="lower right")
    ax.set_title("Both variants are reported; neither is 'the' result", fontsize=11, loc="left", pad=8)
    p = os.path.join(out, "ratios.png")
    fig.savefig(p, dpi=190, bbox_inches="tight", facecolor="white"); plt.close(fig)
    print("wrote", p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=os.path.join(os.path.dirname(__file__), "..",
                                                   "authoritative_results.json"))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    d = json.load(open(a.json))
    os.makedirs(a.out, exist_ok=True)
    fig_clusters(d, a.out)
    fig_entropy_resolution(d, a.out)
    fig_ratios(d, a.out)


if __name__ == "__main__":
    main()

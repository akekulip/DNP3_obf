#!/usr/bin/env python3
"""make_figures.py — data figures for the inline-live report, from the MEASURED samples.

Nothing here is illustrative: every value is a CLRT measured on the physical SEL-751 through the
inline Tofino on 2026-07-25.  Regenerate with:

    $RESEARCH_PYTHON make_figures.py --out ../assets
"""
import argparse
import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --- measured CLRT, ms -------------------------------------------------------
# native: run 1 (n=10, exact values) plus the 37.22 ms outlier seen in run 2.
NATIVE = [1.06, 1.08, 1.10, 1.20, 2.09, 2.16, 2.22, 3.36, 4.02, 22.66, 37.22]
# protected: run 1 at G = 25 ms (n=11, exact values).
PROTECTED = [25.00, 25.00, 25.02, 25.05, 25.05, 25.06, 25.06, 25.07, 25.07, 25.08, 25.08]

INK, MUTED, ACC = "#16202b", "#5c6b7a", "#1e5f9e"
HOLD, NORM, BAD = "#b87514", "#1f7a6b", "#a8324a"


def style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.xaxis.label.set_color(INK)
    ax.yaxis.label.set_color(INK)
    ax.title.set_color(INK)


def bins_of(vals):
    h = {}
    for v in vals:
        k = int(math.floor(v))
        h[k] = h.get(k, 0) + 1
    return h


def entropy(h):
    n = sum(h.values())
    if not n:
        return 0.0
    e = 0.0
    for c in h.values():
        p = c / n
        if p > 0:
            e -= p * math.log2(p)
    return e


def fig_clustering(out):
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(8.4, 4.4), sharex=True,
                                 gridspec_kw={"hspace": 0.32})
    for ax, vals, lab, col in ((a1, NATIVE, "native", ACC), (a2, PROTECTED, "protected  G=25 ms", NORM)):
        style(ax)
        seen = {}
        for v in vals:
            k = round(v, 1)
            seen[k] = seen.get(k, 0) + 1
            ax.plot(v, seen[k], "o", ms=7, color=BAD if (lab == "native" and v > 20) else col,
                    alpha=.85, zorder=3)
        h = bins_of(vals)
        ax.set_title("%s   —   %d occupied 1 ms bins,  entropy %.3f bits"
                     % (lab, len(h), entropy(h)), fontsize=10.5, loc="left", pad=6)
        ax.set_ylim(0, max(max(seen.values()) + 1, 4))
        ax.set_yticks([])
        ax.grid(axis="x", color="#d5dce5", lw=.7, zorder=0)
    a2.set_xlim(-1, 40)
    a2.set_xlabel("CLRT: relay pure-ACK $\\rightarrow$ DNP3 response (ms)", fontsize=10)
    a1.annotate("tail: 22.7 and 37.2 ms\n(above G — these would escape)",
                xy=(30, 1), xytext=(24, 2.6), color=BAD, fontsize=8.6,
                arrowprops=dict(arrowstyle="->", color=BAD, lw=1))
    fig.suptitle("Measured CLRT on the live SEL-751 — the distribution collapses to one value",
                 fontsize=11.5, color=INK, y=.99)
    p = os.path.join(out, "clustering.png")
    fig.savefig(p, dpi=190, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote %s" % p)


def fig_entropy_vs_g(out):
    gs = list(range(1, 51))
    ent, esc = [], []
    for g in gs:
        got = [v if v > g else g for v in NATIVE]
        ent.append(entropy(bins_of(got)))
        esc.append(sum(1 for v in NATIVE if v > g))
    fig, ax = plt.subplots(figsize=(8.4, 3.5))
    style(ax)
    ax.plot(gs, ent, lw=2.2, color=ACC, label="observer entropy (bits)")
    ax.set_xlabel("guard interval G (ms)", fontsize=10)
    ax.set_ylabel("entropy (bits)", fontsize=10)
    ax.set_xlim(1, 50)
    ax.set_ylim(-0.05, max(ent) + .2)
    ax2 = ax.twinx()
    style(ax2)
    ax2.step(gs, esc, where="post", lw=1.6, color=BAD, alpha=.85,
             label="transactions escaping unprotected")
    ax2.set_ylabel("escaped transactions", fontsize=10, color=BAD)
    ax2.tick_params(colors=BAD)
    for g, lbl, col in ((25, "G = 25 ms\nas first run", HOLD), (38, "first G with\nzero escapes", NORM)):
        ax.axvline(g, color=col, ls="--", lw=1.3, alpha=.9)
        ax.annotate(lbl, xy=(g, max(ent) * .72), xytext=(g + 1, max(ent) * .72),
                    color=col, fontsize=8.6, va="center")
    ax.set_title("Entropy reaches zero only once G clears every native sample",
                 fontsize=11.5, loc="left", pad=8)
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, fontsize=8.8, frameon=False, loc="upper right")
    p = os.path.join(out, "entropy_vs_g.png")
    fig.savefig(p, dpi=190, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote %s" % p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../assets")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    fig_clustering(a.out)
    fig_entropy_vs_g(a.out)


if __name__ == "__main__":
    main()

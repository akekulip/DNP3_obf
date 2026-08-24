#!/usr/bin/env python3
"""Schematic: the four-queue hold-and-release mechanism, IEEE double column.

The relay's acknowledgment and response are held in low-priority queues while high-priority blocker
tokens recirculate; the traffic manager releases the originals on their deadlines. Strict priority
7>6>5>4 guarantees the acknowledgment is never released after the response, and the blocker tokens
never leave toward the master. Drawn with matplotlib so it is reproducible.

  $RESEARCH_PYTHON fig_mechanism.py <out_basename>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


def box(ax, x, y, w, h, text, fc, ec="0.3", fs=7, hatch=None, tc="black"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.01,rounding_size=0.02",
                                linewidth=0.8, edgecolor=ec, facecolor=fc, hatch=hatch))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, zorder=5)


def arrow(ax, x0, y0, x1, y1, color="0.3", style="-|>", lw=1.0, ls="-"):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle=style, mutation_scale=8,
                                 linewidth=lw, color=color, linestyle=ls, zorder=4))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "defense4/timing/figures/fig_mechanism"
    utils_mpl.set_global()
    fig, ax = utils_mpl.get_fig(size=(7.16, 2.7))
    ax.set_xlim(0, 10); ax.set_ylim(0, 5.2); ax.axis("off")

    ACKc, RESPc, BLKc = "#cfe0f3", "#f6d0d0", "#e8e8e8"
    # endpoints
    box(ax, 0.1, 2.1, 1.05, 1.0, "SEL-751\nrelay", "#eeeeee", fs=7)
    box(ax, 8.85, 2.1, 1.05, 1.0, "DNP3\nmaster", "#eeeeee", fs=7)
    # switch container
    ax.add_patch(FancyBboxPatch((1.7, 0.25), 6.6, 4.7, boxstyle="round,pad=0.02,rounding_size=0.05",
                                linewidth=1.0, edgecolor="0.45", facecolor="none"))
    ax.text(5.0, 4.72, "Tofino switch: four-queue traffic manager (strict priority 7 > 6 > 5 > 4)",
            ha="center", va="center", fontsize=7.5, weight="bold")
    # four queues
    qx, qw, qh = 3.4, 3.2, 0.72
    ys = [3.75, 2.85, 1.55, 0.65]
    box(ax, qx, ys[0], qw, qh, "Q_ACK_BLOCK  (qid7)  blocker tokens", BLKc, hatch="////", fs=7)
    box(ax, qx, ys[1], qw, qh, "Q_ACK_HOLD  (qid6)  the real ACK", ACKc, fs=7)
    box(ax, qx, ys[2], qw, qh, "Q_RESP_BLOCK  (qid5)  blocker tokens", BLKc, hatch="////", fs=7)
    box(ax, qx, ys[3], qw, qh, "Q_RESP_HOLD  (qid4)  the real RESPONSE", RESPc, fs=7)
    # pktgen source of blockers
    box(ax, 1.95, 2.15, 1.05, 0.9, "pktgen\n(0x88C1)", "#fff3cf", fs=6.5)
    arrow(ax, 3.0, 2.75, qx, ys[0] + qh / 2, color="#b58900")     # to ACK_BLOCK
    arrow(ax, 3.0, 2.45, qx, ys[2] + qh / 2, color="#b58900")     # to RESP_BLOCK
    # relay ACK/RESP into the hold queues
    arrow(ax, 1.15, 2.75, qx, ys[1] + qh / 2, color="#1f5fa8")    # ACK -> Q_ACK_HOLD
    arrow(ax, 1.15, 2.45, qx, ys[3] + qh / 2, color="#c02020")    # RESP -> Q_RESP_HOLD
    ax.text(2.05, 3.05, "ACK", fontsize=6.5, color="#1f5fa8")
    ax.text(2.02, 2.15, "RESP", fontsize=6.5, color="#c02020")
    # recirculation loop on blockers
    for y in (ys[0], ys[2]):
        arrow(ax, qx + qw, y + qh / 2, qx + qw + 0.35, y + qh / 2, color="#b58900")
        arrow(ax, qx + qw + 0.35, y + qh / 2, qx + qw + 0.35, y - 0.2, color="#b58900")
        arrow(ax, qx + qw + 0.35, y - 0.2, qx - 0.35, y - 0.2, color="#b58900")
        arrow(ax, qx - 0.35, y - 0.2, qx - 0.35, y + qh / 2, color="#b58900")
        arrow(ax, qx - 0.35, y + qh / 2, qx, y + qh / 2, color="#b58900")
    ax.text(qx + qw + 0.45, ys[2] + qh + 0.02, "blockers\nrecirculate\ntil deadline", fontsize=6, color="#b58900")
    # TM releases the originals to the master
    arrow(ax, qx + qw, ys[1] + qh / 2, 8.85, 2.75, color="#1f5fa8", lw=1.2)
    arrow(ax, qx + qw, ys[3] + qh / 2, 8.85, 2.45, color="#c02020", lw=1.2)
    ax.text(7.15, 3.0, "release ACK\nat T_A", fontsize=6, color="#1f5fa8")
    ax.text(7.1, 1.35, "release RESP\nat T_RESP", fontsize=6, color="#c02020")
    ax.text(5.0, 0.05, "blocker tokens never leave toward the master; the original packets are released unmodified",
            ha="center", fontsize=6.2, color="0.35")
    fig.savefig(out + ".pdf", transparent=True)
    fig.savefig(out + ".png", dpi=300, transparent=False)
    print("wrote", out)


if __name__ == "__main__":
    main()

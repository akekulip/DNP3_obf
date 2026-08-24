#!/usr/bin/env python3
"""Schematic: testbed and adversary placement, IEEE single column.

  $RESEARCH_PYTHON fig_topology.py <out_basename>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


def box(ax, x, y, w, h, text, fc, fs=7.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.04",
                                linewidth=0.9, edgecolor="0.3", facecolor=fc))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "defense4/timing/figures/fig_topology"
    utils_mpl.set_global()
    fig, ax = utils_mpl.get_fig(size=(3.5, 1.7))
    ax.set_xlim(0, 10); ax.set_ylim(0, 4.2); ax.axis("off")
    box(ax, 0.2, 1.5, 2.1, 1.2, "DNP3 master\n192.168.10.1", "#eeeeee")
    box(ax, 3.9, 1.5, 2.2, 1.2, "Tofino switch\ndefense4_caseA", "#dfeaf7")
    box(ax, 7.7, 1.5, 2.1, 1.2, "SEL-751 relay\n(READ-only)", "#eeeeee")
    ax.add_patch(FancyArrowPatch((2.3, 2.1), (3.9, 2.1), arrowstyle="<|-|>", mutation_scale=9, lw=1.1, color="0.3"))
    ax.add_patch(FancyArrowPatch((6.1, 2.1), (7.7, 2.1), arrowstyle="<|-|>", mutation_scale=9, lw=1.1, color="0.3"))
    ax.text(3.1, 2.35, "dp9", fontsize=6, color="0.4"); ax.text(6.7, 2.35, "dp64", fontsize=6, color="0.4")
    # adversary on the master-facing segment
    box(ax, 1.15, 3.1, 2.2, 0.85, "passive observer\nmeasures CLRT", "#fdeae0", fs=6.8)
    ax.add_patch(FancyArrowPatch((2.25, 3.1), (2.25, 2.7), arrowstyle="-|>", mutation_scale=8, lw=0.9, color="#c0522a", linestyle=(0, (3, 2))))
    ax.text(2.4, 2.85, "tap", fontsize=6, color="#c0522a")
    ax.text(3.0, 0.9, "master-facing segment (only the shaped timing is visible here)",
            ha="center", fontsize=6, color="0.4")
    fig.savefig(out + ".pdf", transparent=True)
    fig.savefig(out + ".png", dpi=300, transparent=False)
    print("wrote", out)


if __name__ == "__main__":
    main()

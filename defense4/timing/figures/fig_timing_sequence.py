#!/usr/bin/env python3
"""Per-mode timing-sequence figure (data-grounded), IEEE single column.

For each mode, a timeline from the READ (t=0) shows where the acknowledgment is released (open marker)
and where the response is released (filled marker), from the MEASURED median read-to-ACK and
read-to-RESP over both campaigns. The coloured span between them is the CLRT, the interval a passive
observer measures. It makes each mode's behaviour visible: OFF native and narrow; D2/D4 pin the
response so the CLRT is a fixed 10 ms; D3 releases both together (CLRT ~0); D1 pins the response but
releases the acknowledgment on an event, so its CLRT is wide.

  $RESEARCH_PYTHON fig_timing_sequence.py <out_basename> <medians.json>
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl
import matplotlib.pyplot as plt

MODES = ["OFF", "D1", "D2", "D3", "D4"]
COLORS = {"OFF": "#7f7f7f", "D1": "#1f77b4", "D2": "#d62728", "D3": "#2ca02c", "D4": "#9467bd"}
DESC = {"OFF": "native", "D1": "event ACK, held RESP", "D2": "held RESP (D_A=0)",
        "D3": "ACK+RESP together (D_R=0)", "D4": "held ACK + RESP"}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "defense4/timing/figures/fig_timing_sequence"
    med = json.load(open(sys.argv[2] if len(sys.argv) > 2 else "/tmp/timing_medians.json"))

    utils_mpl.set_global()
    fig, ax = utils_mpl.get_fig(size=(3.5, 2.7))
    ymap = {m: len(MODES) - 1 - i for i, m in enumerate(MODES)}  # OFF on top
    for m in MODES:
        y = ymap[m]
        a = med[m]["r2a"]; r = med[m]["r2r"]; c = med[m]["clrt"]
        col = COLORS[m]
        ax.plot([0, 16], [y, y], "-", color="0.85", lw=0.7, zorder=1)          # baseline
        ax.plot([a, r], [y, y], "-", color=col, lw=3.2, alpha=0.85, zorder=2,   # the CLRT span
                solid_capstyle="butt")
        ax.plot([a], [y], marker="^", color=col, ms=6, zorder=3, markeredgecolor="white", markeredgewidth=0.5)  # ACK release
        ax.plot([r], [y], marker="o", color=col, ms=6, zorder=3, markeredgecolor="white", markeredgewidth=0.5)  # RESP release
        ax.annotate("%.1f ms" % c, (r, y), xytext=(4, 3), textcoords="offset points",
                    fontsize=6.5, color=col, weight="bold")
    ax.axvline(0, color="0.4", lw=0.8, ls=":")
    ax.annotate("READ", (0, len(MODES) - 0.35), xytext=(2, 0), textcoords="offset points", fontsize=6.5, color="0.4")
    ax.set_yticks([ymap[m] for m in MODES])
    ax.set_yticklabels(["%s\n%s" % (m, DESC[m]) for m in MODES], fontsize=6.5)
    ax.set_ylim(-0.6, len(MODES) + 0.35)
    ax.set_xlim(-0.5, 18.0)
    ax.set_xlabel("time since READ (ms)")
    # legend: markers, placed above the plot so it never covers a marker
    ax.plot([], [], "^", color="0.3", ms=6, label="ACK out")
    ax.plot([], [], "o", color="0.3", ms=6, label="RESP out")
    ax.plot([], [], "-", color="0.3", lw=3, label="CLRT")
    ax.legend(fontsize=6, loc="upper center", ncol=3, framealpha=0.9,
              bbox_to_anchor=(0.5, 1.02), columnspacing=1.2, handletextpad=0.4)
    utils_mpl.set_grid(fig, ax)
    fig.savefig(out + ".pdf", transparent=True)
    fig.savefig(out + ".png", dpi=300, transparent=False)
    print("wrote", out + ".pdf/.png")


if __name__ == "__main__":
    main()

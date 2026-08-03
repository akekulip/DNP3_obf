"""Figure 14 (single column) — the MEASURED hold-continuity floor (silicon, 2026-08-03).

A step plot, the plainest AXES encoding of the result: measured hold duration
(linear, ms) against reservoir size K, one curve per requested deadline D
(96 trials, 3 reps per point, evidence/ksweep_hold/20260803T175912Z). Below the
floor every curve sits at ~0 ms (the ACK escapes after ~1 us, invisible on a
linear axis); at K = 44 each curve jumps to its OWN requested D and stays there
— the y ticks sit exactly at 0/2/8/16 so the plateaus name themselves. The
green band is the measured floor, identical for all three D. Escape
microseconds, release bias and the loop-RTT mechanism live in RESULTS.md.
"""
import json
import os
import sys
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import Patch

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[2] / "control"))
import utils_mpl
import d3_style as ds
import parameter_policy as pp

ds.setup_only()

EV = Path(__file__).parents[2] / "evidence/ksweep_hold/20260803T175912Z/summary.json"
summary = json.load(open(EV))["summary"]
D_REAL = {d: pp.quantize_d(float(d))["realized_ns"] for d in (2, 8, 16)}

fig, ax = ds.setup(size=(3.5, 2.6))

ax.axvspan(40, 44, color=ds.PASS, alpha=0.18, zorder=1)

MARK = {2: ("o", ds.ARM["d2"]), 8: ("s", ds.ARM["d8"]), 16: ("^", ds.ARM["d16"])}
for d in (2, 8, 16):
    pts = sorted((s["k"], [(D_REAL[d] + x) / 1e6 for x in s["deltas_ns"] if x is not None])
                 for s in summary if s["d_ms"] == d)
    ks = [k for k, _ in pts]
    means = [sum(v) / len(v) for _, v in pts]
    m, c = MARK[d]
    ax.plot(ks, means, "-", color=c, lw=1.2, zorder=3)
    for k, vals in pts:                          # all three reps, overlapping
        ax.plot([k] * len(vals), vals, m, color=c, ms=3.6, mec="black", mew=0.4,
                ls="none", zorder=4)
    ax.plot([], [], m + "-", color=c, ms=3.6, mec="black", mew=0.4,
            label=r"$D$ = %d ms" % d)

ax.set_xlim(0, 68)
ax.set_ylim(-0.9, 17.5)
ax.set_xticks([0, 8, 16, 24, 32, 40, 48, 56, 64])
ax.set_yticks([0, 2, 8, 16])
ax.set_xlabel("reservoir size $K$ (tokens)", fontweight="bold")
ax.set_ylabel("measured hold (ms)", fontweight="bold")

handles, labels = ax.get_legend_handles_labels()
handles.append(Patch(facecolor=ds.PASS, alpha=0.18, edgecolor="none"))
labels.append("measured floor $K$ = 44")
ax.legend(handles, labels, fontsize=6.6, ncol=2, loc="lower center",
          bbox_to_anchor=(0.5, 1.005), framealpha=1.0, handlelength=1.4,
          borderpad=0.35, labelspacing=0.3, columnspacing=1.0)
ax.set_title("the hold jumps from zero to the full $D$ at $K$ = 44",
             fontsize=8.0, pad=30)
utils_mpl.set_grid(fig, ax)
ax.set_axisbelow(True)

out = Path(__file__).parents[1] / "out"
sub = "report" if os.environ.get("D3_FIG_W") else ""   # REPORT.pdf widths
dest = out / sub / "fig14_ksweep_hold.pdf"
dest.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(dest, transparent=True)
fig.savefig(dest.with_suffix(".png"), dpi=300)
n = sum(len([x for x in s["deltas_ns"] if x is not None]) for s in summary)
print("fig14 step plot: %d trials -> %s (from %s)" % (n, dest, EV.parent.name))

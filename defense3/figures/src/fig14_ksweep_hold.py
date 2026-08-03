"""Figure 14 (single column) — the MEASURED hold-continuity floor (silicon, 2026-08-03).

Achieved ACK hold vs. reservoir size K, three deadlines D, 3 reps per point
(96 trials, evidence/ksweep_hold/20260803T175912Z). Deliberately minimal: three
per-D point series and the measured floor band, legend outside the axes. Below
the floor the hold collapses to ~K/rate microseconds (the TM drains the tokens
once and Q_HOLD is served before the first token returns from its ~1.1 us
loop); at K >= 44 it lands on the deadline plateau at every D. The drain-limit
model and the falsified ~16 prior estimate are discussed in the RESULTS.md, not
drawn — they made the panel too busy.
"""
import json
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

fig, ax = ds.setup(size=(3.5, 2.8))

# the one non-data element: the measured floor band (40, 44]
ax.axvspan(40, 44, color=ds.PASS, alpha=0.15, zorder=1)

MARK = {2: ("o", ds.ARM["d2"]), 8: ("s", ds.ARM["d8"]), 16: ("^", ds.ARM["d16"])}
for d in (2, 8, 16):
    xs, ys = [], []
    for s in summary:
        if s["d_ms"] != d:
            continue
        for delta in s["deltas_ns"]:
            if delta is None:
                continue
            xs.append(s["k"])
            ys.append((D_REAL[d] + delta) / 1e6)
    m, c = MARK[d]
    ax.plot(xs, ys, m, color=c, ms=3.4, mec="black", mew=0.4, ls="none",
            zorder=4, label=r"$D$ = %d ms" % d)

ax.set_yscale("log")
ax.set_xlim(0, 68)
ax.set_ylim(3.2e-4, 40)
ax.set_xticks([0, 8, 16, 24, 32, 40, 48, 56, 64])
ax.set_xlabel("reservoir size $K$ (tokens)", fontweight="bold")
ax.set_ylabel("achieved ACK hold (ms)", fontweight="bold")

# legend OUTSIDE the plot area, in a band between the axes and the title
handles, labels = ax.get_legend_handles_labels()
handles.append(Patch(facecolor=ds.PASS, alpha=0.15, edgecolor="none"))
labels.append("measured floor $K$ = 44")
ax.legend(handles, labels, fontsize=6.6, ncol=2, loc="lower center",
          bbox_to_anchor=(0.5, 1.005), framealpha=1.0, handlelength=1.2,
          borderpad=0.35, labelspacing=0.3, columnspacing=1.0)
ax.set_title("the continuity floor is $K$ = 44, at every $D$", fontsize=8.0, pad=32)
utils_mpl.set_grid(fig, ax)
ax.set_axisbelow(True)

out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig14_ksweep_hold.pdf", transparent=True)
fig.savefig(out / "fig14_ksweep_hold.png", dpi=300)
n = sum(len([x for x in s["deltas_ns"] if x is not None]) for s in summary)
print("fig14: %d trials plotted; floors: D2=44 D8=44 D16=44 (from %s)" % (n, EV.parent.name))

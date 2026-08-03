"""Figure 14 (single column) — the MEASURED hold-continuity floor (silicon, 2026-08-03).

Achieved ACK hold vs. reservoir size K, three deadlines D, 3 reps per point
(96 trials, evidence/ksweep_hold/20260803T175912Z). Below the floor the hold is
not "shorter" — it collapses to the queue-drain limit max(K/rate, transit): the
TM drains the K tokens once at line rate and Q_HOLD is served before the first
token returns from its ~1.1 us recirculation loop. At K >= 44 the hold lands on
the deadline plateau at every D (release bias = K/rate, confirmed separately).
The prior fig13 estimate of the floor (~16, from the Part-12 loop RTT) is drawn
for contrast — measurement moved it to 44.
"""
import json
import sys
from pathlib import Path

import numpy as np
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

RATE = pp.RATE_DP8_PPS
TRANSIT_NS = 495.0                      # measured small-K pipe transit (K=1..8 holds)
D_REAL = {d: pp.quantize_d(float(d))["realized_ns"] for d in (2, 8, 16)}

fig, ax = ds.setup(size=(3.5, 2.6))

# the queue-drain limit the EARLY points ride: max(K/rate, transit)
kk = np.linspace(1, 68, 300)
ax.plot(kk, np.maximum(kk / RATE * 1e9, TRANSIT_NS) / 1e6, color="0.45", ls="--",
        lw=0.9, zorder=2, label="queue-drain limit (model)")

# measured floor band (40, 44] and the falsified prior estimate
ax.axvspan(40, 44, color=ds.PASS, alpha=0.15, zorder=1)
ax.axvline(16, color="0.45", ls=":", lw=0.9, zorder=2)

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

handles, labels = ax.get_legend_handles_labels()
handles += [Patch(facecolor=ds.PASS, alpha=0.15, edgecolor="none"),
            plt.Line2D([], [], color="0.45", ls=":", lw=0.9)]
labels += ["measured floor (40, 44]", "prior estimate $\\approx$ 16"]
order = [1, 2, 3, 0, 4, 5]
ax.legend([handles[i] for i in order], [labels[i] for i in order], fontsize=6.2,
          loc="center right", framealpha=1.0, handlelength=1.5, borderpad=0.35,
          labelspacing=0.3)
ax.set_title("the continuity floor is $K$ = 44, at every $D$", fontsize=8.0, pad=3)
utils_mpl.set_grid(fig, ax)
ax.set_axisbelow(True)

out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig14_ksweep_hold.pdf", transparent=True)
fig.savefig(out / "fig14_ksweep_hold.png", dpi=300)
n = sum(len([x for x in s["deltas_ns"] if x is not None]) for s in summary)
print("fig14: %d trials plotted; floors: D2=44 D8=44 D16=44 (from %s)" % (n, EV.parent.name))

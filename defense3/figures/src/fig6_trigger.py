"""Figure 6 (single column) — the trigger chain against the deadline it has to beat.
The reservoir must be complete before the relay's own ACK can possibly arrive; the
measured margin is a factor of ~330, which is why there is no race."""
import sys, os
from pathlib import Path
import numpy as np, matplotlib.pyplot as plt
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl
import d3_style as ds
ds.setup_only()
_W = float(os.environ.get("D3_FIG_W", "3.5"))
_SUB = "report" if os.environ.get("D3_FIG_W") else "."

# measured: 100 clean trials, 4 ns total spread (REPORT §6.4); relay ACK from 480 txns
segs = [("mirror to the generator\nand back", 0, 688, "0.80"),
        ("generator reacts", 688, 699, "0.55"),
        ("64 tokens admitted", 699, 1215, ds.BLOCKER)]
fig, ax = utils_mpl.get_fig(size=(_W, 2.2500*_W/3.5))
for name, x0, x1, col in segs:
    ax.barh(0.12, x1 - x0, left=x0, height=0.34, color=col, ec="black", lw=0.7,
            label=f"{name}  ({x1-x0} ns)")
ax.axvline(1215, color="black", lw=0.9)
ax.text(1330, -0.08, "reservoir complete,\n1 215 ns", fontsize=6.4, va="top",
        ha="left")
ax.axvline(400000, color=ds.ACK, lw=1.3)
ax.text(350000, 0.36, "earliest possible\nrelay ACK,\n400 000 ns", fontsize=6.4,
        va="bottom", ha="right", color=ds.ACK)
ax.annotate("", xy=(400000, -0.56), xytext=(1215, -0.56),
            arrowprops=dict(arrowstyle="<->", lw=0.9, color="0.25"))
ax.text(22000, -0.63, r"margin $\approx 330\times$", fontsize=7.0, ha="center", va="top")
ax.set_xscale("log"); ax.set_xlim(400, 1.1e6)
ax.set_yticks([]); ax.set_ylim(-0.92, 1.02)
ax.set_xlabel("nanoseconds after the READ arrives (log scale)", fontweight="bold",
              labelpad=1.5)
ax.legend(fontsize=6.2, loc="upper left", framealpha=0.97, handlelength=1.0,
          borderpad=0.3, labelspacing=0.22)
utils_mpl.set_grid(fig, ax)
out = Path(__file__).parents[1] / "out" / _SUB
out.mkdir(parents=True, exist_ok=True)
fig.savefig(out / "fig6_trigger.pdf", transparent=True)
fig.savefig(out / "fig6_trigger.png", dpi=300)
print("fig6 ok  margin = %.0fx" % (400000/1215))

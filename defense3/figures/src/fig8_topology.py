"""Figure 8 (single column) — where the switch sits, what each link carries, and where
the eavesdropper is assumed to stand. Every port number is the one actually used in the
physical campaign."""
import sys, os
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl
import d3_style as ds
ds.setup_only()
_W = float(os.environ.get("D3_FIG_W", "3.5"))
_SUB = "report" if os.environ.get("D3_FIG_W") else "."

fig, ax = utils_mpl.get_fig(size=(_W, 2.5000*_W/3.5))
ax.set_xlim(0, 10.4); ax.set_ylim(0, 7.4); ax.axis("off")
for sp in ax.spines.values(): sp.set_visible(False)
ax.grid(False)

def node(x, y, w, h, fc, t1, t2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="square,pad=0.08", fc=fc,
                                ec="black", lw=0.9, zorder=3))
    ax.text(x + w/2, y + h*0.63, t1, fontsize=7.0, ha="center", va="center",
            fontweight="bold", zorder=4)
    ax.text(x + w/2, y + h*0.24, t2, fontsize=6.0, ha="center", va="center",
            color="0.2", zorder=4)

node(0.10, 4.05, 2.55, 1.45, "0.93", "DNP3 master", "a Linux host\n192.168.10.1")
node(3.55, 3.55, 3.30, 2.45, "#EAF1F8", "Tofino-1 switch", "Defense 3 runs here\n(2 pipes, 32 ports)")
node(7.75, 4.05, 2.55, 1.45, "0.93", "SEL-751 relay", "the outstation\n192.168.10.7")

def link(x1, x2, y, port, speed, port_at="x2"):
    ax.add_patch(FancyArrowPatch((x1, y), (x2, y), arrowstyle="<|-|>", mutation_scale=6,
                 lw=1.1, color="black", zorder=2, shrinkA=0, shrinkB=0))
    px, ha = (x2 - 0.16, "right") if port_at == "x2" else (x1 + 0.16, "left")
    ax.text(px, y + 0.18, port, fontsize=6.3, ha=ha, va="bottom", fontweight="bold",
            zorder=5)
    ax.text((x1 + x2)/2, y - 0.20, speed, fontsize=5.7, ha="center", va="top",
            color="0.3", zorder=5)
link(2.65, 3.55, 4.78, "port 9",  "25 Gb/s", port_at="x2")   # switch end, master side
link(6.85, 7.75, 4.78, "port 64", "1 Gb/s",  port_at="x1")   # switch end, relay side

# the internal loopback that does the actual holding
ax.add_patch(Rectangle((3.55, 2.05), 3.30, 1.15, fc="#EFF1F3", ec=ds.BLOCKER, lw=0.8, zorder=3))
ax.text(5.20, 2.93, "internal loopback, port 8, 25 Gb/s", fontsize=6.0, ha="center", va="center",
        zorder=4, color="0.25")
ax.text(5.20, 2.40, "$Q_{BLOCK}$ / $Q_{HOLD}$\nthe hold happens here", fontsize=5.9,
        ha="center", va="center", zorder=4)
ax.add_patch(FancyArrowPatch((4.55, 3.55), (4.55, 3.20), arrowstyle="-|>",
             mutation_scale=6, lw=0.9, color=ds.ACK, zorder=4))
ax.add_patch(FancyArrowPatch((5.85, 3.20), (5.85, 3.55), arrowstyle="-|>",
             mutation_scale=6, lw=0.9, color=ds.ACK, zorder=4))

# the observer
ax.add_patch(FancyBboxPatch((1.35, 0.35), 4.05, 1.05, boxstyle="round,pad=0.07",
                            fc="white", ec=ds.FAIL, lw=1.0, ls="--", zorder=3))
ax.text(3.38, 1.08, "the passive eavesdropper", fontsize=6.7, ha="center", va="center",
        fontweight="bold", color=ds.FAIL, zorder=4)
ax.text(3.38, 0.66, "it sees only what leaves port 9", fontsize=5.9, ha="center",
        va="center", color="0.25", zorder=4)
ax.add_patch(FancyArrowPatch((3.40, 1.40), (3.14, 4.58), arrowstyle="-|>",
             mutation_scale=6, lw=0.9, color=ds.FAIL, ls="--", zorder=2))
ax.text(5.85, 0.88, "we capture at exactly this\npoint, so every number in\nthis report "
        "is what the\nattacker would get", fontsize=5.9, ha="left", va="center",
        color="0.25")
ax.text(0.10, 6.60, "The relay is untouched. No packet byte is modified. Only the "
        "TIMING\nof the ACK leaving port 9 is changed.", fontsize=6.3, ha="left",
        va="center", color="0.15")
fig.subplots_adjust(left=0.005, right=0.995, top=0.995, bottom=0.005)
out = Path(__file__).parents[1] / "out" / _SUB
out.mkdir(parents=True, exist_ok=True)
fig.savefig(out / "fig8_topology.pdf", transparent=True)
fig.savefig(out / "fig8_topology.png", dpi=300)
print("fig8 ok")

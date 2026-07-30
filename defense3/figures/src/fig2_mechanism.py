"""Figure 2 (double column) — how a switch with no timers delays a packet, and where
every nanosecond of the hold goes. (b) shows the components AFTER the deadline, at
nanosecond scale, because D itself is three orders of magnitude larger."""
import sys
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Rectangle, FancyBboxPatch
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl, paper_palettes as pp
utils_mpl.set_global(); C = pp.get("alessandretti-nature")
BLK, HLD, TOK, ACC = C[1], C[0], C[3], C[2]

fig = plt.figure(figsize=(7.16, 2.45))
gs = fig.add_gridspec(1, 2, width_ratios=[1.28, 1.0], wspace=0.20)

# ================= (a) the construction =================
ax = fig.add_subplot(gs[0]); ax.set_xlim(0, 10.4); ax.set_ylim(0, 7.1); ax.axis("off")
def arr(x1, y1, x2, y2, c="black", ls="-", lw=0.9):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=7,
                 color=c, ls=ls, lw=lw, zorder=5, shrinkA=0, shrinkB=0))
ax.add_patch(Rectangle((2.35, 1.30), 5.05, 4.30, fc="0.965", ec="0.62", lw=0.7, zorder=1))
ax.text(7.35, 5.72, "traffic manager,\ninternal loopback", fontsize=6.6,
        ha="right", va="center", color="0.35")
# Q_BLOCK
ax.add_patch(FancyBboxPatch((2.60, 3.62), 4.55, 1.20, boxstyle="round,pad=0.05",
                            fc=BLK, ec="black", lw=0.8, zorder=2))
ax.text(2.78, 4.60, r"$\mathbf{Q_{BLOCK}}$  strict priority 7", fontsize=7.3,
        ha="left", va="center", zorder=4)
for i in range(8):
    ax.add_patch(Rectangle((2.82 + i*0.44, 3.80), 0.30, 0.42, fc=TOK, ec="black",
                           lw=0.5, zorder=3))
ax.text(6.42, 4.42, r"$\times K{=}64$", fontsize=6.9, ha="left", va="center", zorder=4)
# Q_HOLD
ax.add_patch(FancyBboxPatch((2.60, 1.55), 4.55, 1.20, boxstyle="round,pad=0.05",
                            fc=HLD, ec="black", lw=0.8, zorder=2))
ax.text(2.78, 2.53, r"$\mathbf{Q_{HOLD}}$  priority 0", fontsize=7.3, ha="left",
        va="center", zorder=4)
for x, w, fc, t in ((2.85, 0.60, "white", "ACK"), (3.55, 0.78, "0.86", "RESP")):
    ax.add_patch(Rectangle((x, 1.74), w, 0.42, fc=fc, ec="black", lw=0.6, zorder=3))
    ax.text(x + w/2, 1.95, t, fontsize=6.2, ha="center", va="center", zorder=4)
# the recirculation loop, routed clear of both boxes
arr(7.15, 4.22, 8.20, 4.22, TOK); arr(8.20, 4.22, 8.20, 3.30, TOK)
arr(8.20, 3.30, 1.95, 3.30, TOK); arr(1.95, 3.30, 1.95, 4.22, TOK)
arr(1.95, 4.22, 2.60, 4.22, TOK)
ax.text(5.05, 3.10, "each token reads the clock and re-circulates until $t_{ACK}+D$",
        fontsize=6.7, ha="center", va="top", color=TOK)
# in / out
arr(0.55, 1.95, 2.60, 1.95); ax.text(1.55, 2.16, "from relay", fontsize=6.7, ha="center")
arr(7.15, 1.95, 9.95, 1.95, ACC, lw=1.35)
ax.text(8.55, 2.18, "to master, in order", fontsize=6.7, ha="center", color=ACC)
# the trigger
ax.add_patch(FancyBboxPatch((0.95, 6.02), 3.45, 0.74, boxstyle="round,pad=0.05",
                            fc="white", ec="black", lw=0.8, zorder=3))
ax.text(2.62, 6.39, "READ arrives: arms the transaction,\nmirrors a tagged copy to the generator",
        fontsize=6.4, ha="center", va="center", zorder=4)
arr(1.62, 6.05, 1.62, 4.55, TOK, ls=":"); arr(1.62, 4.55, 1.95, 4.55, TOK, ls=":")
ax.text(0.05, 0.60, "Strict priority means $Q_{HOLD}$ is never served while $Q_{BLOCK}$\n"
        "holds anything at all — so the crowd of tokens IS the delay.",
        fontsize=6.8, color="0.25", va="top")
ax.set_title("(a) delaying a packet in a chip with no timers", fontsize=9, pad=1)

# ================= (b) after the deadline, at ns scale =================
ax = fig.add_subplot(gs[1])
detect, drain, tail = 6.0, 1693.0, 26.0          # ns, measured on the physical relay
left = 0.0
for name, val, col in (("detection", detect, "0.55"),
                       ("drain of the $K$ tokens", drain, TOK),
                       ("release tail", tail, ACC)):
    ax.barh(0, val, left=left, height=0.40, color=col, ec="black", lw=0.7,
            label=f"{name}  ({val:.0f} ns)")
    left += val
ax.set_yticks([]); ax.set_ylim(-0.62, 0.95)
ax.set_xlim(0, 1860)
ax.set_xlabel("nanoseconds after the deadline $t_{ACK}+D$", fontweight="bold")
ax.legend(fontsize=6.8, loc="upper right", framealpha=0.96, handlelength=1.1,
          borderpad=0.35, labelspacing=0.3)
ax.annotate("", xy=(1725, -0.36), xytext=(0, -0.36),
            arrowprops=dict(arrowstyle="<->", lw=0.8, color="0.2"))
ax.text(862, -0.44, "release bias  1 725 ns measured,  model $K/\\mathrm{rate}$ = 1 711 ns",
        fontsize=6.9, ha="center", va="top")
ax.annotate("6 ns", xy=(6, 0.20), xytext=(150, 0.55), fontsize=6.8,
            arrowprops=dict(arrowstyle="-", lw=0.6, color="0.35"))
ax.set_title(r"(b) the hold is $D$ + this;  $D$ = 1 999 691 ns", fontsize=9, pad=2)
utils_mpl.set_grid(fig, ax)
fig.subplots_adjust(left=0.005, right=0.985, top=0.90, bottom=0.19)
out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig2_mechanism.pdf", transparent=True)
fig.savefig(out / "fig2_mechanism.png", dpi=300)
print("fig2 ok: D + %.0f = %.3f us total; model bias 1711 ns vs measured %.0f ns"
      % (detect + drain + tail, (1999691 + detect + drain + tail)/1000.0,
         detect + drain + tail))

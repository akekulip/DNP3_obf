"""Figure 4 (single column) — the same exchange under no defense and under each of the
three possible defenses, drawn on one time axis so the reader can SEE which interval
carries the secret in each case. ACK and RESPONSE are drawn in two lanes per row because
under Defenses 1 and 3 they leave within microseconds of each other and would overlap."""
import sys, os
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl
import d3_style as ds
ds.setup_only()
_W = float(os.environ.get("D3_FIG_W", "3.5"))
_SUB = "report" if os.environ.get("D3_FIG_W") else "."
ACKC, RSPC, SECRET = ds.ACK, ds.RESPONSE, ds.RESPONSE   # the span rides on response timing

a, c, D, G, d = 0.45, 2.85, 4.0, 6.9, 0.03      # ms; a and c are the measured medians
rows = [
    ("no defense",  a,           a + c,          [(a, a + c, "$c$ = CLRT, the secret")]),
    ("Defense 1\nhold ACK until\nthe response", a + c, a + c + d,
     [(0, a + c, "$a+c$ — the secret is HERE")]),
    ("Defense 2\nhold response\nto $t_{ACK}+G$", a, a + G,
     [(a, a + G, "$G$, a constant")]),
    ("Defense 3\nhold ACK to\n$t_{ACK}+D$",     a + D, a + D + d,
     [(0, a + D, "$a+D$, no $c$ in it")]),
]
LANE = 0.155
fig, ax = utils_mpl.get_fig(size=(_W, 3.0500*_W/3.5))
for i, (name, tack, trsp, spans) in enumerate(rows):
    y = (len(rows) - 1 - i) * 1.06
    for dy in (+LANE, -LANE):
        ax.plot([0, 11.4], [y + dy, y + dy], color="0.86", lw=0.7, zorder=1)
    ax.plot([0, 0], [y - LANE, y + LANE], color="black", lw=1.3, zorder=3)
    ax.plot([tack], [y + LANE], marker="o", ms=4.2, color=ACKC, mec="black", mew=0.5,
            zorder=4, clip_on=False)
    ax.plot([trsp], [y - LANE], marker="s", ms=4.2, color=RSPC, mec="black", mew=0.5,
            zorder=4, clip_on=False)
    if abs(trsp - tack) < 0.6:                    # they are simultaneous: say so
        ax.plot([tack, trsp], [y + LANE, y - LANE], color="0.45", lw=0.6, ls=":",
                zorder=3)
    for x0, x1, lab in spans:
        ax.add_patch(FancyArrowPatch((x0, y + LANE + 0.20), (x1, y + LANE + 0.20),
                     arrowstyle="<->", mutation_scale=5, lw=0.9, color=SECRET, zorder=5))
        ax.text((x0 + x1)/2, y + LANE + 0.35, lab, fontsize=6.3, ha="center",
                va="bottom", color=SECRET)
    ax.text(-0.40, y, name, fontsize=6.6, ha="right", va="center")
ax.text(0, 3*1.06 + LANE + 0.62, "READ leaves\nthe master", fontsize=6.2, ha="center",
        va="bottom", color="0.3")
ax.plot([], [], marker="o", ms=4.2, color=ACKC, mec="black", mew=0.5, ls="none",
        label="ACK reaches the master")
ax.plot([], [], marker="s", ms=4.2, color=RSPC, mec="black", mew=0.5, ls="none",
        label="RESPONSE reaches the master")
ax.legend(fontsize=6.3, loc="lower right", bbox_to_anchor=(0.992, 0.012),
          framealpha=0.98, handlelength=0.8, borderpad=0.3, labelspacing=0.2)
ax.set_xlim(-3.7, 12.0); ax.set_ylim(-0.92, 4.52)
ax.set_yticks([])
ax.set_xlabel("time after the READ leaves the master (ms)", fontweight="bold",
              labelpad=1.5)
ax.set_xticks([0, 2, 4, 6, 8, 10])
utils_mpl.set_grid(fig, ax)
out = Path(__file__).parents[1] / "out" / _SUB
out.mkdir(parents=True, exist_ok=True)
fig.savefig(out / "fig4_timelines.pdf", transparent=True)
fig.savefig(out / "fig4_timelines.png", dpi=300)
print("fig4 ok  a=%.2f c=%.2f D=%.1f G=%.1f" % (a, c, D, G))

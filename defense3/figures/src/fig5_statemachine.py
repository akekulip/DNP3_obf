"""Figure 5 (single column) — the transaction state machine. One register byte carries
three states. The encoding is chosen so that (i) the live states are told apart by a
single hardware test on the top bit, and (ii) a blocker token can still recognise its own
generation after the state changes, which is what keeps the reservoir alive."""
import sys, os
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl
import d3_style as ds
ds.setup_only()
_W = float(os.environ.get("D3_FIG_W", "3.5"))
_SUB = "report" if os.environ.get("D3_FIG_W") else "."

fig, ax = utils_mpl.get_fig(size=(_W, 3.4500*_W/3.5))
ax.set_xlim(0, 10.95); ax.set_ylim(0, 10.75); ax.axis("off")
for sp in ax.spines.values(): sp.set_visible(False)
ax.grid(False)

BX0, BX1 = 0.30, 7.05                      # live-state boxes
def box(y0, h, fc, lines):
    ax.add_patch(FancyBboxPatch((BX0, y0), BX1 - BX0, h, boxstyle="round,pad=0.08",
                                fc=fc, ec="black", lw=0.9, zorder=2))
    for dy, txt, kw in lines:
        ax.text((BX0 + BX1)/2, y0 + dy, txt, ha="center", va="center", zorder=3, **kw)

BOLD = dict(fontsize=7.2, fontweight="bold")
MONO = dict(fontsize=7.6, family="monospace", color=ds.STATE)
SMAL = dict(fontsize=5.9, color="0.15")
TOKS = dict(fontsize=5.9, color="#555", fontweight="bold")

box(9.35, 1.30, "0.93", [(0.92, "IDLE — no transaction", BOLD),
                         (0.34, "0x00", MONO)])
box(5.30, 2.15, "#EAF1F8", [(1.78, "LIVE — nothing pending yet", BOLD),
                       (1.19, "0xC0 . . 0xCF", MONO),
                       (0.72, "top bit SET; low nibble = the DNP3 sequence", SMAL),
                       (0.30, "a token sees difference 0x00  →  still mine", TOKS)])
box(1.10, 2.15, "#FDF0E3", [(1.78, "LIVE — a response is queued behind the ACK", BOLD),
                       (1.19, "0x10 . . 0x1F", MONO),
                       (0.72, "top bit CLEAR, and never 0x00", SMAL),
                       (0.30, "a token sees difference 0xB0  →  STILL mine", TOKS)])

def varr(x, y0, y1, col="black"):
    ax.add_patch(FancyArrowPatch((x, y0), (x, y1), arrowstyle="-|>", mutation_scale=7,
                 lw=0.95, color=col, zorder=4, shrinkA=0, shrinkB=0))
def poly(pts, col):
    for p, q in zip(pts, pts[1:-1]):
        ax.plot([p[0], q[0]], [p[1], q[1]], color=col, lw=0.95, zorder=4)
    ax.add_patch(FancyArrowPatch(pts[-2], pts[-1], arrowstyle="-|>", mutation_scale=7,
                 lw=0.95, color=col, zorder=4, shrinkA=0, shrinkB=0))

varr(1.55, 9.35, 7.45)
ax.text(1.75, 8.35, "a READ arrives:\nwrite the identity", fontsize=6.2, ha="left",
        va="center")
varr(1.55, 5.30, 3.25, ds.RESPONSE)
ax.text(1.75, 4.24, "the first response is admitted:\nadd 0x50  (one-shot)", fontsize=6.2,
        ha="left", va="center", color=ds.RESPONSE)
poly([(7.05, 6.38), (8.55, 6.38), (8.55, 10.05), (7.05, 10.05)], ds.ACK)
ax.text(9.14, 8.10, "ACK released,\nnothing pending", fontsize=6.1,
        ha="center", va="center", rotation=90, color=ds.ACK)
poly([(7.05, 2.17), (9.85, 2.17), (9.85, 9.65), (7.05, 9.65)], ds.RESPONSE)
ax.text(10.32, 5.90, "the queued response\nleaves", fontsize=6.1,
        ha="center", va="center", rotation=90, color=ds.RESPONSE)
ax.text(0.30, 0.05, "Three disjoint domains in ONE byte. The live states differ only in "
        "the top bit,\nso the switch separates them with a single signed comparison "
        "against zero.", fontsize=6.1, ha="left", va="bottom", color="0.2")
fig.subplots_adjust(left=0.005, right=0.995, top=0.995, bottom=0.005)
out = Path(__file__).parents[1] / "out" / _SUB
out.mkdir(parents=True, exist_ok=True)
fig.savefig(out / "fig5_statemachine.pdf", transparent=True)
fig.savefig(out / "fig5_statemachine.png", dpi=300)
print("fig5 ok")

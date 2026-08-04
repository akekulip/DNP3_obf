"""Figure 10 — the mechanism, in three stages, read left to right.

Deliberately MECHANISM ONLY. No repair callouts, no section cross-references, no register
names or sequence-number handling: those are the subject of their own sections and putting
them here made the one figure that should explain the idea the hardest one to read. Every
arrow points left-to-right, and time advances in the same direction.

What it has to convey, and nothing else:
  1. a READ arms the transaction and fills Q_BLOCK with K tokens;
  2. the relay's ACK and RESPONSE land in Q_HOLD, which strict priority keeps unserved
     while Q_BLOCK holds anything at all -- so the crowd of tokens IS the delay;
  3. at the deadline the tokens terminate, Q_BLOCK empties, and Q_HOLD drains in order.

Colours keep their project meaning: blue = ACK, orange = RESPONSE, grey = internal
blocker tokens, near-black = host packets.
"""
import os
import sys

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import d3_style as ds

ds.setup_only()
W = float(os.environ.get("D3_FIG_W", 7.16))
fig, ax = plt.subplots(figsize=(W, 3.05))
ax.set_xlim(0, 100)
ax.set_ylim(0, 100)
ax.axis("off")

STAGE = [(2.0, 30.0), (35.0, 30.0), (68.0, 30.0)]      # (x0, width) per stage
TITLES = ["1.  the READ arms the hold",
          "2.  the reply waits in the queue",
          "3.  the deadline releases it"]
BLOCK_FC, HOLD_FC = "#EFF1F3", "#EAF1F8"


def stage_panel(x0, w, title):
    ax.add_patch(Rectangle((x0, 12), w, 76, facecolor="#FAFAFA",
                           edgecolor="#DDDDDD", lw=0.7, zorder=0))
    ax.text(x0 + w / 2, 84.5, title, fontsize=7.8, ha="center", va="center",
            weight="bold", color="#333333", zorder=4)


def queue(x0, w, y, h, label, fc, sub=None):
    ax.add_patch(FancyBboxPatch((x0, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.0",
                                facecolor=fc, edgecolor="black", lw=0.9, zorder=2))
    ax.text(x0 + 1.6, y + h - 2.6, label, fontsize=7.0, ha="left", va="center",
            weight="bold", zorder=4)
    if sub:
        ax.text(x0 + w - 1.6, y + h - 2.6, sub, fontsize=6.2, ha="right", va="center",
                color="#555555", zorder=4)


def arrow(x1, y1, x2, y2, color=ds.NATIVE, lw=1.4, style="-", ms=11):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=ms,
                                 color=color, lw=lw, linestyle=style, zorder=5,
                                 shrinkA=0, shrinkB=0))


def tokens(x0, n, y, color=ds.BLOCKER):
    for i in range(n):
        ax.add_patch(Rectangle((x0 + i * 2.25, y), 1.7, 3.4, facecolor=color,
                               edgecolor="black", lw=0.4, zorder=3))


def pkt(x, y, w, label, ec, fc):
    ax.add_patch(Rectangle((x, y), w, 4.6, facecolor=fc, edgecolor=ec, lw=1.0, zorder=3))
    ax.text(x + w / 2, y + 2.3, label, fontsize=6.4, ha="center", va="center",
            color=ec, weight="bold", zorder=4)


for (x0, w), t in zip(STAGE, TITLES):
    stage_panel(x0, w, t)

# ---------------- stage 1: the READ arms the hold ------------------------------------
x0, w = STAGE[0]
ax.text(x0 + 2.0, 74.5, "MASTER", fontsize=6.8, ha="left", va="center", weight="bold")
arrow(x0 + 11.0, 74.5, x0 + 26.0, 74.5)
ax.text(x0 + 18.5, 77.6, "READ", fontsize=6.6, ha="center", color=ds.NATIVE)
queue(x0 + 2.5, w - 5.0, 47.0, 15.0, r"$\mathbf{Q_{BLOCK}}$  priority 7",
      BLOCK_FC, sub="$K$ tokens")
tokens(x0 + 4.5, 10, 50.5)
ax.text(x0 + w / 2, 45.8, "the switch fills it with $K$ tokens\nthat recirculate,"
        " so it never empties", fontsize=6.4, ha="center", va="top", color="#444444")
queue(x0 + 2.5, w - 5.0, 24.0, 13.0, r"$\mathbf{Q_{HOLD}}$  priority 0", HOLD_FC,
      sub="empty")

# ---------------- stage 2: the reply waits -------------------------------------------
x0, w = STAGE[1]
arrow(x0 - 2.6, 74.5, x0 + 12.0, 74.5, color=ds.ACK)
ax.text(x0 + 4.5, 77.6, "ACK", fontsize=6.6, ha="center", color=ds.ACK)
arrow(x0 + 14.5, 74.5, x0 + 27.5, 74.5, color=ds.RESPONSE)
ax.text(x0 + 21.0, 77.6, "RESPONSE", fontsize=6.6, ha="center", color=ds.RESPONSE)
ax.text(x0 + w / 2, 68.0, "from the relay", fontsize=6.2, ha="center", color="#666666")
queue(x0 + 2.5, w - 5.0, 47.0, 15.0, r"$\mathbf{Q_{BLOCK}}$  priority 7",
      BLOCK_FC, sub="still full")
tokens(x0 + 4.5, 10, 50.5)
ax.text(x0 + w / 2, 45.8, "strict priority: while $Q_{BLOCK}$ holds anything,\n"
        "$Q_{HOLD}$ is never served", fontsize=6.4, ha="center", va="top",
        color="#444444")
queue(x0 + 2.5, w - 5.0, 24.0, 13.0, r"$\mathbf{Q_{HOLD}}$  priority 0", HOLD_FC,
      sub="waiting")
pkt(x0 + 4.5, 26.2, 8.0, "ACK", ds.ACK, "white")
pkt(x0 + 13.5, 26.2, 10.5, "RESPONSE", ds.RESPONSE, "#FDF0E3")

# ---------------- stage 3: release ----------------------------------------------------
x0, w = STAGE[2]
queue(x0 + 2.5, w - 5.0, 47.0, 15.0, r"$\mathbf{Q_{BLOCK}}$  priority 7",
      BLOCK_FC, sub="empty")
ax.text(x0 + (w - 5.0) / 2 + 2.5, 52.2, "tokens terminate at  $t_{ACK} + D$",
        fontsize=6.4, ha="center", va="center", color="#444444")
ax.text(x0 + w / 2, 45.8, "$Q_{BLOCK}$ is empty, so $Q_{HOLD}$ is served\n"
        "and drains in order", fontsize=6.4, ha="center", va="top", color="#444444")
queue(x0 + 2.5, w - 5.0, 24.0, 13.0, r"$\mathbf{Q_{HOLD}}$  priority 0", HOLD_FC,
      sub="draining")
pkt(x0 + 4.5, 26.2, 8.0, "ACK", ds.ACK, "white")
pkt(x0 + 13.5, 26.2, 10.5, "RESPONSE", ds.RESPONSE, "#FDF0E3")
# the release, on its own line BELOW the queue so nothing is drawn over the box or its
# labels: one straight left-to-right arrow, order stated above it
ax.text(x0 + 11.0, 20.2, "ACK first, then RESPONSE", fontsize=6.4, ha="center",
        va="center", color="#444444")
arrow(x0 + 3.5, 16.0, x0 + 19.0, 16.0)
ax.text(x0 + 20.4, 16.0, "MASTER", fontsize=6.8, ha="left", va="center", weight="bold")

# ---------------- stage-to-stage progression -----------------------------------------
for x in (STAGE[0][0] + STAGE[0][1] + 0.6, STAGE[1][0] + STAGE[1][1] + 0.6):
    ax.add_patch(FancyArrowPatch((x, 50.0), (x + 1.8, 50.0), arrowstyle="-|>",
                                 mutation_scale=16, color="#888888", lw=2.2,
                                 zorder=6, shrinkA=0, shrinkB=0))

# ---------------- legend, one line, outside the stages -------------------------------
y = 6.0
items = [(ds.NATIVE, "host packet"), (ds.ACK, "ACK"), (ds.RESPONSE, "RESPONSE")]
x = 20.0
for c, lab in items:
    ax.add_patch(FancyArrowPatch((x, y), (x + 5.0, y), arrowstyle="-|>",
                                 mutation_scale=9, color=c, lw=1.3, shrinkA=0, shrinkB=0))
    ax.text(x + 6.0, y, lab, fontsize=6.4, va="center")
    x += 18.0
ax.add_patch(Rectangle((x, y - 1.5), 3.0, 3.0, facecolor=ds.BLOCKER, edgecolor="black",
                       lw=0.4))
ax.text(x + 4.0, y, "blocker token", fontsize=6.4, va="center")

fig.tight_layout(pad=0.3)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out")
sub = "report" if os.environ.get("D3_FIG_W") else ""
dest = os.path.join(out, sub, "fig10_lifecycle.pdf")
os.makedirs(os.path.dirname(dest), exist_ok=True)
fig.savefig(dest, transparent=True)
fig.savefig(dest.replace(".pdf", ".png"), dpi=300, transparent=True)
print("wrote", dest)

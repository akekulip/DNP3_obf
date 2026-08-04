"""Figure 10 — the end-to-end Defense 3 packet lifecycle.

One figure a reviewer can read in under a minute: parser/classification and state, the Traffic
Manager queues, and release/observation, in three horizontal zones. Solid arrows are host
packets, dashed arrows are internal clones/tokens, dotted arrows are state-register accesses.
Only the load-bearing registers are shown: reg_tag, reg_failopen, deadline, session/TCP.
"""
import os
import sys

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import d3_style as ds

ds.setup_only()
W = float(os.environ.get("D3_FIG_W", 7.16))
fig, ax = plt.subplots(figsize=(W, 4.6))
ax.set_xlim(0, 100)
ax.set_ylim(0, 100)
ax.axis("off")

# ---- three horizontal zones -----------------------------------------------------------
zones = [("Release & observation", 2, 30, "#F3F6FA"),
         ("Traffic Manager queues", 32, 66, "#F7F3EE"),
         ("Classification & state", 68, 98, "#F1F6F1")]
for name, y0, y1, col in zones:
    ax.add_patch(Rectangle((1, y0), 98, y1 - y0, facecolor=col, edgecolor="#DDDDDD", lw=0.6, zorder=0))
    ax.text(2.2, y1 - 2.4, name, fontsize=7.5, style="italic", color="#666666", va="top")


def box(x, y, w, h, text, fc="white", ec=ds.NATIVE, tc="black", fs=7.6, lw=1.0, bold=False):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                 boxstyle="round,pad=0.3,rounding_size=1.2", facecolor=fc,
                 edgecolor=ec, linewidth=lw, zorder=3))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, color=tc,
            zorder=4, weight="bold" if bold else "normal")


def arrow(x1, y1, x2, y2, color=ds.NATIVE, style="-", lw=1.3, label=None, lx=None, ly=None, ls=8):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=11,
                 color=color, lw=lw, linestyle=style, zorder=2,
                 shrinkA=2, shrinkB=2))
    if label:
        ax.text(lx if lx is not None else (x1 + x2) / 2,
                ly if ly is not None else (y1 + y2) / 2, label, fontsize=ls,
                color=color, ha="center", va="center",
                bbox=dict(boxstyle="round,pad=0.1", fc="white", ec="none", alpha=0.85))


def callout(x, y, text, color=ds.PASS):
    ax.text(x, y, text, fontsize=7.0, color="white", ha="center", va="center", zorder=6,
            weight="bold", bbox=dict(boxstyle="round,pad=0.25", fc=color, ec="black", lw=0.4))


# ================= ZONE: classification & state (top) =================
box(12, 90, 15, 7, "MASTER", fc="#EDEDED", bold=True)
box(40, 90, 20, 8, "Parser +\nclassify", ec=ds.NATIVE)
arrow(19.5, 90, 30, 90, label="READ", ly=93, ls=7.5)

# three outputs of classification
box(72, 94, 20, 6.5, "arm reg_tag  (E1)", ec=ds.STATE, tc=ds.STATE, fs=7.2)
box(72, 85.5, 20, 6.5, "learn session /\nTCP trackers", ec=ds.STATE, tc=ds.STATE, fs=7.2)
box(72, 77, 20, 6.5, "trigger K=64 tokens", ec=ds.BLOCKER, tc="#555", fs=7.2)
for yy in (94, 85.5, 77):
    arrow(50, 90, 62, yy, color="#999999", lw=0.9)

# ================= ZONE: TM queues (middle) =================
box(72, 58, 20, 7, "Q_BLOCK  (prio 7)", ec=ds.BLOCKER, fc="#EFF1F3", fs=7.4, bold=True)
# recirculate: a self-loop that leaves the right edge and re-enters it
ax.add_patch(FancyArrowPatch((82.3, 60.2), (82.3, 55.8), connectionstyle="arc3,rad=-1.7",
             arrowstyle="-|>", mutation_scale=9, color=ds.BLOCKER, lw=1.0,
             linestyle="--", zorder=2, shrinkA=0, shrinkB=0))
ax.text(87.2, 58, "recirculate\nuntil deadline", fontsize=6.8, color="#555", va="center")
arrow(72, 73.5, 72, 62.0, color=ds.BLOCKER, style="--", lw=1.1)   # tokens into Q_BLOCK

box(40, 45, 22, 7, "Q_HOLD  (prio 0)", ec=ds.ACK, fc="#EAF1F8", fs=7.4, bold=True)
# relay ACK into Q_HOLD — the head must land ON the box edge, not under the box
box(12, 52, 15, 6.5, "RELAY ACK", fc="#EAF1F8", ec=ds.ACK, tc=ds.ACK, bold=True, fs=7.2)
arrow(19.9, 51, 28.6, 48.4, color=ds.ACK, label="ACK", lx=24, ly=51.5, ls=7.2)
# relay RESPONSE -> mark -> Q_HOLD, behind the ACK
box(12, 40, 15, 6.5, "RELAY\nRESPONSE", fc="#FDF0E3", ec=ds.RESPONSE, tc=ds.RESPONSE, bold=True, fs=7.0)
arrow(19.9, 41.5, 28.6, 43.8, color=ds.RESPONSE, lw=1.2, label="mark 0xCn→0x1n",
      lx=24.5, ly=39.8, ls=6.8)

# state accesses (dotted) from queues to registers
box(88, 45, 18, 6.5, "reg_tag / deadline", ec=ds.STATE, tc=ds.STATE, fs=7.0)
arrow(51, 45, 79, 45, color=ds.STATE, style=":", lw=0.9)

# ================= ZONE: release & observation (bottom) =================
box(40, 20, 24, 7, "deadline reached →\nblockers terminate", ec=ds.NATIVE, fs=7.2)
arrow(40, 41.1, 40, 24.0, color=ds.NATIVE, lw=1.1)
box(74, 20, 18, 6.5, "reg_failopen note", ec=ds.STATE, tc=ds.STATE, fs=7.0)
arrow(52, 20, 65, 20, color=ds.STATE, style=":", lw=0.9)

box(12, 10, 15, 6.5, "MASTER", fc="#EDEDED", bold=True)
# ACK then RESPONSE released, in order — both leave the deadline box edge and
# land on the MASTER box edge, each label sitting on its own arrow
arrow(27.7, 21.5, 17.3, 13.8, color=ds.ACK, label="ACK", lx=24, ly=18.9, ls=7.2)
arrow(31, 16.2, 20.0, 10.6, color=ds.RESPONSE, label="then RESPONSE",
      lx=26.5, ly=14.0, ls=7.0)

# legend for arrow semantics
lx = 62
ax.add_patch(FancyArrowPatch((lx, 8), (lx + 5, 8), arrowstyle="-|>", mutation_scale=9, color=ds.NATIVE, lw=1.2))
ax.text(lx + 6, 8, "host packet", fontsize=6.6, va="center")
ax.add_patch(FancyArrowPatch((lx, 5), (lx + 5, 5), arrowstyle="-|>", mutation_scale=9, color=ds.BLOCKER, lw=1.1, linestyle="--"))
ax.text(lx + 6, 5, "internal token/clone", fontsize=6.6, va="center")
ax.add_patch(FancyArrowPatch((lx + 30, 8), (lx + 35, 8), arrowstyle="-|>", mutation_scale=9, color=ds.STATE, lw=1.0, linestyle=":"))
ax.text(lx + 36, 8, "state access", fontsize=6.6, va="center")

fig.tight_layout(pad=0.3)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out")
dest = os.path.join(out, "fig10_lifecycle.pdf")
fig.savefig(dest, transparent=True)
fig.savefig(dest.replace(".pdf", ".png"), dpi=300, transparent=True)
print("wrote", dest)

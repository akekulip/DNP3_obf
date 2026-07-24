#!/usr/bin/env python3
"""Render the 4 report diagrams as PNGs (matplotlib; no browser needed)."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = "/home/philip/Projects/DNP3/research/physical_sel751/clrt_300poll_20260723T152242/diagrams"
os.makedirs(OUT, exist_ok=True)
TEAL = "#0e7c86"; INK = "#1c2321"; SOFT = "#4c5854"; PANEL = "#eef3f3"; GATE = "#b0432c"; GOLD = "#9a7b1f"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})


def box(ax, x, y, w, h, text, fc=PANEL, ec=TEAL, fs=9.5, tc=INK):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                                fc=fc, ec=ec, lw=1.4))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, zorder=5)


def arrow(ax, x1, y1, x2, y2, style="-|>", color=INK, lw=1.5, ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=14,
                                 color=color, lw=lw, linestyle=ls, shrinkA=2, shrinkB=2))


# ---------- Diagram 1: CLRT sequence ----------
fig, ax = plt.subplots(figsize=(7.2, 3.9)); ax.axis("off"); ax.set_xlim(0, 10); ax.set_ylim(0, 10)
mx, rx = 2.0, 8.0
box(ax, mx - 1.4, 8.7, 2.8, 0.9, "Master (link addr 1)", fc="#dcecee")
box(ax, rx - 1.4, 8.7, 2.8, 0.9, "SEL-751 (link addr 0)", fc="#dcecee")
for x in (mx, rx):
    ax.plot([x, x], [1.0, 8.6], color=SOFT, lw=1, ls=(0, (4, 3)))
def msg(y, text, r2l=False, dashed=False, color=INK, tcol=SOFT):
    x1, x2 = (rx, mx) if r2l else (mx, rx)
    arrow(ax, x1, y, x2, y, color=color, ls="--" if dashed else "-")
    ax.text((mx + rx) / 2, y + 0.28, text, ha="center", va="bottom", fontsize=9, color=tcol)
msg(7.4, "DNP3 READ, Class-0   (t = 0)")
msg(5.8, "pure TCP ACK   (+0.9 ms)", r2l=True, dashed=True, color=TEAL, tcol=TEAL)
ax.text(rx + 0.15, 4.9, "relay assembles\nthe response", ha="left", va="center", fontsize=8, color=SOFT, style="italic")
msg(3.6, "DNP3 RESPONSE, 69 pts   (+6.1 ms after ACK)", r2l=True, color=GATE, tcol=GATE)
ax.annotate("", xy=(5.0, 5.8), xytext=(5.0, 3.6), arrowprops=dict(arrowstyle="<->", color=GOLD, lw=1.4))
ax.text(5.2, 4.7, "CLRT\n= 6.1 ms", ha="left", va="center", fontsize=8.5, color=GOLD, fontweight="bold")
ax.set_title("DNP3 Case-A transaction: separate ACK, then response (CLRT is the gap)", fontsize=10.5, color=INK)
fig.tight_layout(); fig.savefig(f"{OUT}/diag_clrt_sequence.png", dpi=150, bbox_inches="tight"); plt.close(fig)

# ---------- Diagram 2: testbed topology ----------
fig, ax = plt.subplots(figsize=(7.4, 4.2)); ax.axis("off"); ax.set_xlim(0, 12); ax.set_ylim(0, 10)
box(ax, 1.0, 5.4, 2.2, 1.0, "Vision\nDNP3 master\n10.10.54.19", fc="#dcecee", fs=8.5)
box(ax, 3.7, 5.4, 2.0, 1.0, "Hulk\ntraffic host\n10.10.54.158", fs=8.5)
box(ax, 6.1, 5.4, 2.0, 1.0, "gambit\ndev/analysis\n10.10.54.133", fs=8.5)
box(ax, 8.5, 5.4, 2.4, 1.0, "Tofino-1\nprog. switch\nmgmt 10.10.54.81", ec=TEAL, fs=8.5)
box(ax, 2.5, 2.9, 8.0, 0.9, "unmanaged TP-Link switch  (lab net 10.10.54.0/24)", fc="#efece3", ec="#c7c1b2", fs=9)
for cx in (2.1, 4.7, 7.1, 9.7):
    ax.plot([cx, cx], [5.4, 3.8], color=SOFT, lw=1.2)
box(ax, 1.0, 0.6, 3.0, 1.0, "SEL-751 relay\n192.168.10.7  (Case A)", fc="#dcefe3", ec="#2c8a58", fs=8.5)
arrow(ax, 2.1, 5.4, 2.1, 1.6, style="<|-|>", color="#2c8a58", lw=1.8)
ax.text(2.35, 3.5, "direct link\nVision eno1 (+.1)\n↔ relay :20000", ha="left", va="center", fontsize=7.6, color="#2c8a58")
arrow(ax, 3.0, 5.9, 8.5, 5.9, style="-", color=TEAL, lw=1.2, ls="--")
ax.text(6.0, 6.15, "25G data links to Tofino (dp8/dp9)", ha="center", fontsize=7.6, color=TEAL)
ax.set_title("Testbed topology (physical-relay phase; Tofino not yet inline)", fontsize=10.5, color=INK)
fig.tight_layout(); fig.savefig(f"{OUT}/diag_topology.png", dpi=150, bbox_inches="tight"); plt.close(fig)

# ---------- Diagram 3: size pipeline ----------
fig, ax = plt.subplots(figsize=(8.2, 2.5)); ax.axis("off"); ax.set_xlim(0, 12); ax.set_ylim(0, 3)
steps = ["frame in\n60–120 B", "classify by\nsize class", "map to one\n128 B state", "prepend\npad header", "one real\nqueue", "frame out\n= 128 B"]
w = 1.7; gap = 0.28; x = 0.2
for i, s in enumerate(steps):
    fc = "#dcefe3" if i == len(steps) - 1 else PANEL
    box(ax, x, 0.9, w, 1.2, s, fc=fc, fs=8.3)
    if i < len(steps) - 1:
        arrow(ax, x + w, 1.5, x + w + gap, 1.5, color=INK)
    x += w + gap
ax.set_title("Thread A — Level-1 size normalization pipeline on Tofino (every frame → 128 B)", fontsize=10, color=INK)
fig.tight_layout(); fig.savefig(f"{OUT}/diag_size_pipeline.png", dpi=150, bbox_inches="tight"); plt.close(fig)

# ---------- Diagram 4: accept-then-hang-up ----------
fig, ax = plt.subplots(figsize=(7.2, 3.9)); ax.axis("off"); ax.set_xlim(0, 10); ax.set_ylim(0, 10)
mx, rx = 2.0, 8.0
box(ax, mx - 1.6, 8.7, 3.2, 0.9, "Vision (192.168.10.100)", fc="#dcecee", fs=8.5)
box(ax, rx - 1.6, 8.7, 3.2, 0.9, "SEL-751 (192.168.10.7)", fc="#dcecee", fs=8.5)
for x in (mx, rx):
    ax.plot([x, x], [1.2, 8.6], color=SOFT, lw=1, ls=(0, (4, 3)))
def msg2(y, text, r2l=False, color=INK):
    x1, x2 = (rx, mx) if r2l else (mx, rx)
    arrow(ax, x1, y, x2, y, color=color)
    ax.text((mx + rx) / 2, y + 0.26, text, ha="center", va="bottom", fontsize=8.6, color=color if color != INK else SOFT)
msg2(7.5, "TCP SYN")
msg2(6.3, "SYN-ACK", r2l=True)
msg2(5.1, "ACK  (handshake complete)")
msg2(3.6, "FIN  (relay closes it, ~1.9 ms, 0 DNP3 bytes)", r2l=True, color=GATE)
ax.text(5.0, 1.9, "opendnp3 immediately reconnects → 55 sessions/second", ha="center", fontsize=8.2,
        color=GATE, style="italic")
ax.set_title("Challenge 3 — accept-then-hang-up (the DNPIP1 master-IP allowlist)", fontsize=10.2, color=INK)
fig.tight_layout(); fig.savefig(f"{OUT}/diag_accept_hangup.png", dpi=150, bbox_inches="tight"); plt.close(fig)

print("wrote 4 diagrams to", OUT)
for f in sorted(os.listdir(OUT)):
    print("  ", f, os.path.getsize(os.path.join(OUT, f)), "bytes")

"""Figure 12 — the repairs did not change the normal-path timing.

READ->ACK median vs D for the three physical campaigns run against the same relay on
successive builds. The three lines lie almost on top of each other and on the theoretical
READ->ACK_out = a + D, so the repairs changed correctness without moving the healthy-path
timing an eavesdropper would see.
"""
import json
import os
import statistics as st
import sys

import numpy as np
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import d3_style as ds

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
CAMPS = [
    ("session 1", "evidence/physical/dsweep_blocks.jsonl", ds.NATIVE, "--", "o"),
    ("session 2", "evidence/physical_repaired/20260730T194855Z/dsweep_blocks.jsonl", ds.ACK, "-", "s"),
    ("session 3", "evidence/physical_repaired/r1r2r3_20260730T203353Z/dsweep_blocks.jsonl", ds.PASS, "-", "^"),
]


def medians(path):
    byD = {}
    for ln in open(os.path.join(ROOT, path)):
        r = json.loads(ln); d = r.get("d_ms")
        for row in (r.get("block", {}).get("rows") or []):
            v = row.get("read_to_ack_ms")
            if v is not None:
                byD.setdefault(d, []).append(v)
    return {d: st.median(v) for d, v in sorted(byD.items()) if d and d >= 1}


fig, ax = ds.setup(size=(3.5, 2.5))

# theoretical a + D (a = native ACK latency ~ 0.5 ms, from the campaigns' intercept)
a = 0.5
Dline = np.linspace(0.8, 17, 50)
ax.plot(Dline, a + Dline, color="#BBBBBB", lw=1.0, linestyle=(0, (1, 1)), zorder=1,
        label=r"theory: $a + D$")

for name, path, col, ls, mk in CAMPS:
    m = medians(path)
    xs = sorted(m); ys = [m[x] for x in xs]
    ax.plot(xs, ys, color=col, linestyle=ls, marker=mk, ms=4.5, lw=1.4,
            markeredgecolor="black", markeredgewidth=0.4, label=name, zorder=3,
            markerfacecolor=("none" if name == "session 1" else col))

ax.set_xlabel("configured D (ms)")
ax.set_ylabel("READ→ACK median (ms)")
ax.set_title("normal-path timing is unchanged across builds", fontsize=9)
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xticks([1, 2, 4, 8, 16]); ax.set_xticklabels(["1", "2", "4", "8", "16"])
ax.set_yticks([1, 2, 4, 8, 16]); ax.set_yticklabels(["1", "2", "4", "8", "16"])
ax.legend(loc="upper left", fontsize=7, framealpha=0.9)
ax.text(0.97, 0.05, "3 campaigns overlap: non-regression", transform=ax.transAxes,
        ha="right", va="bottom", fontsize=7, style="italic", color="#555")

ds.grid(fig, ax)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out")
sub = "report" if os.environ.get("D3_FIG_W") else ""
dest = os.path.join(out, sub, "fig12_nonregression.pdf")
os.makedirs(os.path.dirname(dest), exist_ok=True)
fig.savefig(dest, transparent=True)
fig.savefig(dest.replace(".pdf", ".png"), dpi=300, transparent=True)
print("wrote", dest)

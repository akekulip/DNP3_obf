"""Figure 3 (single column) — what a passive observer actually gets. The CLRT was the
flattering feature: READ->ACK, which the defense CREATES, beats it at every D, and the
total READ->RESPONSE is the least separable because the defense conserves it."""
import json, sys, os
from pathlib import Path
import numpy as np, matplotlib.pyplot as plt
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl
import d3_style as ds
ds.setup_only()
_W = float(os.environ.get("D3_FIG_W", "3.5"))
_SUB = "report" if os.environ.get("D3_FIG_W") else "."

F = ("read_to_ack_ms", "clrt_ms", "read_to_resp_ms")
rows = {}
for line in open(Path(__file__).parents[2] / "evidence/physical/dsweep_blocks.jsonl"):
    b = json.loads(line)
    for r in b.get("block", {}).get("rows", []):
        if all(r.get(f) is not None for f in F):
            rows.setdefault(b["arm"], []).append(r)
def sepr(p, n):
    w = sum(1.0 if a > b else (0.5 if a == b else 0.0) for a in p for b in n)
    a = w / (len(p) * len(n)); return max(a, 1 - a)

ARMS = [("d1", 1), ("d2", 2), ("d4", 4), ("d8", 8), ("d16", 16)]
S = {f: [sepr([r[f] for r in rows[a]], [r[f] for r in rows["native"]])
         for a, _ in ARMS] for f in F}
floors = {f: 0.0 for f in F}
nat = rows["native"]; h = len(nat)//2
for f in F: floors[f] = sepr([r[f] for r in nat[:h]], [r[f] for r in nat[h:]])

fig, ax = utils_mpl.get_fig(size=(_W, 2.6000*_W/3.5))
y = np.arange(len(ARMS)); w = 0.26
names = {"read_to_ack_ms": r"READ$\rightarrow$ACK  (created by the defense)",
         "clrt_ms": "CLRT  (the feature being hidden)",
         "read_to_resp_ms": r"READ$\rightarrow$RESPONSE  (the total)"}
cols = {"read_to_ack_ms": ds.ACK, "clrt_ms": ds.RESPONSE,
        "read_to_resp_ms": ds.NATIVE}
for i, f in enumerate(F):
    ax.barh(y + (1-i)*w, np.array(S[f]) - 0.50, w, left=0.50, color=cols[f],
            ec="black", lw=0.6, label=names[f])  # 0.50 is chance, so bars start there
ax.axvline(np.mean(list(floors.values())), color="0.35", ls=":", lw=1.0)
ax.text(0.524, -0.58, "0.517 = drift floor (native scored against itself)",
        fontsize=5.8, color="0.3", va="center", ha="left")
ax.axvline(0.50, color="0.55", lw=0.8)
ax.set_yticks(y); ax.set_yticklabels([str(d) for _, d in ARMS])
ax.set_ylabel(r"$D$ (ms)", fontweight="bold")
ax.set_xlabel("separability from native (AUROC folded at 0.5)", fontweight="bold")
ax.set_xlim(0.44, 1.02)
ax.set_xticks([0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
ax.set_ylim(len(ARMS) + 1.15, -0.85)             # D = 1 on top; bottom band for legend
ax.legend(fontsize=6.4, loc="lower center", framealpha=0.97, handlelength=1.0,
          borderpad=0.3, labelspacing=0.22)
utils_mpl.set_grid(fig, ax)
out = Path(__file__).parents[1] / "out" / _SUB
out.mkdir(parents=True, exist_ok=True)
fig.savefig(out / "fig3_observer.pdf", transparent=True)
fig.savefig(out / "fig3_observer.png", dpi=300)
print("fig3 floors:", {k: round(v, 3) for k, v in floors.items()})
for f in F: print("  %-18s %s" % (f, [round(v, 3) for v in S[f]]))

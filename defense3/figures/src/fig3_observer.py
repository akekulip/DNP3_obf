"""Figure 3 (single column) — what a passive observer actually gets. The CLRT was the
flattering feature: READ->ACK, which the defense CREATES, beats it at every D, and the
total READ->RESPONSE is the least separable because the defense conserves it."""
import json, sys, os
from pathlib import Path
import numpy as np, matplotlib.pyplot as plt
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl, paper_palettes as pp
utils_mpl.set_global(); C = pp.get("alessandretti-nature")
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

fig, ax = utils_mpl.get_fig(size=(_W, 2.4500*_W/3.5))
x = np.arange(len(ARMS)); w = 0.26
names = {"read_to_ack_ms": r"READ$\rightarrow$ACK  (created by the defense)",
         "clrt_ms": "CLRT  (the feature being hidden)",
         "read_to_resp_ms": r"READ$\rightarrow$RESPONSE  (the total)"}
cols = {"read_to_ack_ms": C[3], "clrt_ms": C[1], "read_to_resp_ms": C[0]}
for i, f in enumerate(F):
    ax.bar(x + (i-1)*w, np.array(S[f]) - 0.50, w, bottom=0.50, color=cols[f],
           ec="black", lw=0.6, label=names[f])   # 0.50 is chance, so bars start there
ax.axhline(np.mean(list(floors.values())), color="0.35", ls=":", lw=1.0)
ax.text(-0.46, 0.4405, "0.517 = drift floor (native scored against itself)",
        fontsize=6.0, color="0.3", va="bottom", ha="left")
ax.axhline(0.50, color="0.55", lw=0.8)
ax.set_xticks(x); ax.set_xticklabels([str(d) for _, d in ARMS])
ax.set_xlabel(r"$D$ (ms)", fontweight="bold")
ax.set_ylabel("separability from native", fontweight="bold")
ax.set_ylim(0.4335, 1.205)
ax.set_yticks([0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
ax.legend(fontsize=6.4, loc="upper center", bbox_to_anchor=(0.5, 1.02), ncol=1,
          framealpha=0.97, handlelength=1.0, borderpad=0.3, labelspacing=0.22)
utils_mpl.set_grid(fig, ax)
out = Path(__file__).parents[1] / "out" / _SUB
out.mkdir(parents=True, exist_ok=True)
fig.savefig(out / "fig3_observer.pdf", transparent=True)
fig.savefig(out / "fig3_observer.png", dpi=300)
print("fig3 floors:", {k: round(v, 3) for k, v in floors.items()})
for f in F: print("  %-18s %s" % (f, [round(v, 3) for v in S[f]]))

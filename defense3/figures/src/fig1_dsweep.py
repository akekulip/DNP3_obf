"""Figure 1 (double column) — the central result: concealment and detectability rise
TOGETHER. Left: the observed CLRT distribution collapsing as D grows. Right: the
concealed fraction against the separability an adversary achieves, on the same x axis."""
import json, sys, statistics as st
from pathlib import Path
import numpy as np, matplotlib.pyplot as plt
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl, paper_palettes as pp

ARMS = [("native", None), ("d1", 1), ("d2", 2), ("d4", 4), ("d8", 8), ("d16", 16)]
rows = {}
for line in open(Path(__file__).parents[2] / "evidence/physical/dsweep_blocks.jsonl"):
    b = json.loads(line)
    for r in b.get("block", {}).get("rows", []):
        if r.get("clrt_ms") is not None and r.get("read_to_ack_ms") is not None:
            rows.setdefault(b["arm"], []).append(r)

def auroc(p, n):
    w = sum(1.0 if a > b else (0.5 if a == b else 0.0) for a in p for b in n)
    return w / (len(p) * len(n))
def septy(p, n):
    a = auroc(p, n); return max(a, 1 - a)

nat = [r["clrt_ms"] for r in rows["native"]]
utils_mpl.set_global()
pp.apply("alessandretti-nature")
C = pp.get("alessandretti-nature")

fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.7))

# ---- (a) the CLRT distribution per arm, log scale, with the release-tail floor ----
ax = axes[0]
data = [[r["clrt_ms"] for r in rows[a]] for a, _ in ARMS]
labels = ["native"] + ["%d" % d for _, d in ARMS[1:]]
bp = ax.boxplot(data, tick_labels=labels, widths=0.6, showfliers=True,
                patch_artist=True, medianprops=dict(color="black", lw=1.1),
                flierprops=dict(marker=".", ms=2.5, mfc="0.4", mec="none"))
for i, box in enumerate(bp["boxes"]):
    box.set_facecolor(C[0] if i == 0 else C[1]); box.set_alpha(0.55 if i else 0.8)
    box.set_edgecolor("black"); box.set_linewidth(0.7)
ax.set_yscale("log")
ax.axhline(0.032, color=C[3], ls="--", lw=1.0, zorder=0)
ax.text(6.35, 0.032, " release\n tail", color=C[3], fontsize=7.5, va="center", ha="left")
ax.set_xlabel(r"$D$ (ms) — the chosen ACK hold", fontweight="bold")
ax.set_ylabel("observed CLRT (ms)", fontweight="bold")
ax.set_ylim(0.02, 40)
ax.set_title("(a) the fingerprint collapses", fontsize=9, pad=3)

# ---- (b) concealment vs detectability ----
ax = axes[1]
D = [d for _, d in ARMS[1:]]
conceal = [100.0 * sum(1 for r in rows[a] if r["clrt_ms"] < 0.1) / len(rows[a])
           for a, _ in ARMS[1:]]
sepc = [100.0 * septy([r["clrt_ms"] for r in rows[a]], nat) for a, _ in ARMS[1:]]
sepa = [100.0 * septy([r["read_to_ack_ms"] for r in rows[a]],
                      [r["read_to_ack_ms"] for r in rows["native"]]) for a, _ in ARMS[1:]]
ax.plot(D, conceal, "o-", color=C[2], ms=4, label="CLRT concealed (%)")
ax.plot(D, sepc, "s--", color=C[1], ms=4, label="detectable from CLRT")
ax.plot(D, sepa, "^-", color=C[3], ms=4, label=r"detectable from READ$\rightarrow$ACK")
ax.axhline(53.0, color="0.45", ls=":", lw=1.0)
ax.text(1.15, 56.5, "drift floor", color="0.35", fontsize=7.5)
ax.set_xscale("log"); ax.set_xticks(D); ax.set_xticklabels([str(d) for d in D])
ax.set_xlabel(r"$D$ (ms)", fontweight="bold")
ax.set_ylabel("percent", fontweight="bold")
ax.set_ylim(-4, 104)
ax.legend(fontsize=7.2, loc="lower right", framealpha=0.95)
ax.set_title("(b) but the defense becomes obvious", fontsize=9, pad=3)

for a in axes: utils_mpl.set_grid(fig, a)
fig.tight_layout(pad=0.4)
out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig1_dsweep.pdf", transparent=True)
fig.savefig(out / "fig1_dsweep.png", dpi=300)
print("fig1: CLRT median native=%.3f d16=%.3f | conceal %s | sepCLRT %s | sepACK %s"
      % (st.median(nat), st.median([r["clrt_ms"] for r in rows["d16"]]),
         [round(x) for x in conceal], [round(x) for x in sepc], [round(x) for x in sepa]))

"""Figure 1 (double column) — the central result: concealment and detectability rise
TOGETHER. Left: the observed CLRT distribution collapsing as D grows. Right: the
concealed fraction against the separability an adversary achieves, on the same x axis."""
import json, sys, statistics as st
from pathlib import Path
import numpy as np, matplotlib.pyplot as plt
from scipy.stats import rankdata
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl
import d3_style as ds

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

def _auroc_arr(p, n):
    # same statistic as auroc(), via ranks (ties weighted 0.5), vectorised
    r = rankdata(np.concatenate([p, n]))
    u = r[:p.size].sum() - p.size * (p.size + 1) / 2.0
    return u / (p.size * n.size)

def septy_ci(p, n, nboot=1000, seed=0):
    """95% bootstrap percentile CI of the separability max(AUROC, 1-AUROC)."""
    rng = np.random.default_rng(seed)
    p = np.asarray(p, float); n = np.asarray(n, float)
    vals = np.empty(nboot)
    for i in range(nboot):
        a = _auroc_arr(rng.choice(p, p.size), rng.choice(n, n.size))
        vals[i] = max(a, 1.0 - a)
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))

def wilson(k, n, z=1.96):
    """95% Wilson score interval for a proportion k/n."""
    p = k / n; den = 1 + z * z / n
    ctr = (p + z * z / (2 * n)) / den
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return ctr - half, ctr + half

nat = [r["clrt_ms"] for r in rows["native"]]
ds.setup_only()

fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.55),
                         gridspec_kw=dict(width_ratios=[1.30, 1.0, 1.0]))

# ---- (a) the CLRT distribution per arm, log scale, with the release-tail floor ----
ax = axes[0]
data = [[r["clrt_ms"] for r in rows[a]] for a, _ in ARMS]
labels = ["native"] + ["%d" % d for _, d in ARMS[1:]]
bp = ax.boxplot(data, tick_labels=labels, widths=0.6, showfliers=True,
                patch_artist=True, medianprops=dict(color="black", lw=1.1),
                flierprops=dict(marker=".", ms=2.5, mfc="0.4", mec="none"))
for i, box in enumerate(bp["boxes"]):
    box.set_facecolor(ds.ARM[ARMS[i][0]]); box.set_alpha(0.75 if i else 0.35)
    box.set_edgecolor("black"); box.set_linewidth(0.7)
ax.set_yscale("log")
ax.axhline(0.1, color=ds.ACK, ls="--", lw=1.0, zorder=0)
ax.text(0.62, 0.112, "collapse threshold  0.1 ms  (panel b counts below this)",
        color=ds.ACK, fontsize=6.4, va="bottom", ha="left")
ax.axhline(0.032, color="0.45", ls="--", lw=1.0, zorder=0)
ax.text(0.62, 0.0148, "external floor  0.032 ms  (median; NOT a constant)",
        color="0.35", fontsize=6.4, va="bottom", ha="left")
ax.set_xlabel(r"$D$ (ms) — the chosen ACK hold", fontweight="bold")
ax.set_ylabel("observed CLRT (ms)", fontweight="bold")
ax.set_ylim(0.0125, 40)
ax.set_title("(a) the CLRT distribution compresses", fontsize=8.4, pad=3)

# ---- (b) and (c) — DELIBERATELY SEPARATE AXES ----
# A thresholded sample proportion and a ranking statistic are not the same kind of
# quantity and must not share a percentage axis; plotting them together invites an
# arithmetic comparison that is not defined. Split per the 2026-07-30 audit.
D = [d for _, d in ARMS[1:]]
conceal = [100.0 * sum(1 for r in rows[a] if r["clrt_ms"] < 0.1) / len(rows[a])
           for a, _ in ARMS[1:]]
sepc = [septy([r["clrt_ms"] for r in rows[a]], nat) for a, _ in ARMS[1:]]
natk = [r["read_to_ack_ms"] for r in rows["native"]]
sepa = [septy([r["read_to_ack_ms"] for r in rows[a]], natk) for a, _ in ARMS[1:]]

# 95% CIs, from the same per-transaction rows (Wilson for the proportion,
# bootstrap percentile for the ranking statistic)
wils = [wilson(sum(1 for r in rows[a] if r["clrt_ms"] < 0.1), len(rows[a]))
        for a, _ in ARMS[1:]]
ci_c = [septy_ci([r["clrt_ms"] for r in rows[a]], nat) for a, _ in ARMS[1:]]
ci_a = [septy_ci([r["read_to_ack_ms"] for r in rows[a]], natk) for a, _ in ARMS[1:]]

ax = axes[1]
yerr_b = [[c - 100 * lo for c, (lo, hi) in zip(conceal, wils)],
          [100 * hi - c for c, (lo, hi) in zip(conceal, wils)]]
ax.errorbar(D, conceal, yerr=yerr_b, fmt="o-", color=ds.ACK, ms=4, lw=1.2,
            capsize=2, elinewidth=0.8)
ax.set_xscale("log"); ax.set_xticks(D); ax.set_xticklabels([str(d) for d in D])
ax.set_xlabel(r"$D$ (ms)", fontweight="bold")
ax.set_ylabel("percent of transactions", fontweight="bold")
ax.set_ylim(-4, 104)
ax.set_title("(b) CLRT collapsed below 0.1 ms\n(a thresholded proportion)",
             fontsize=7.6, pad=3)

ax = axes[2]
ax.errorbar(D, sepa, yerr=[[s - lo for s, (lo, hi) in zip(sepa, ci_a)],
                           [hi - s for s, (lo, hi) in zip(sepa, ci_a)]],
            fmt="^-", color=ds.ACK, ms=4, lw=1.2, capsize=2, elinewidth=0.8,
            label=r"from READ$\rightarrow$ACK")
ax.errorbar(D, sepc, yerr=[[s - lo for s, (lo, hi) in zip(sepc, ci_c)],
                           [hi - s for s, (lo, hi) in zip(sepc, ci_c)]],
            fmt="s--", color=ds.RESPONSE, ms=4, lw=1.2, capsize=2, elinewidth=0.8,
            label="from CLRT")
ax.axhline(0.53, color="0.45", ls=":", lw=1.0)
ax.text(1.0, 0.545, "drift floor\n0.53", fontsize=5.6, color="0.35", va="bottom",
        ha="left")
ax.set_xscale("log"); ax.set_xticks(D); ax.set_xticklabels([str(d) for d in D])
ax.set_xlabel(r"$D$ (ms)", fontweight="bold")
ax.set_ylabel("separability from native", fontweight="bold")
ax.set_ylim(0.47, 1.06)
ax.legend(fontsize=6.8, loc="lower right", framealpha=0.95, handlelength=1.2)
ax.set_title("(c) detectability of the defense\n(AUROC, a ranking statistic)",
             fontsize=7.6, pad=3)

for a in axes: utils_mpl.set_grid(fig, a)
fig.tight_layout(pad=0.4)
out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig1_dsweep.pdf", transparent=True)
fig.savefig(out / "fig1_dsweep.png", dpi=300)
print("fig1: CLRT median native=%.3f d16=%.3f | collapsed %s | sepCLRT %s | sepACK %s"
      % (st.median(nat), st.median([r["clrt_ms"] for r in rows["d16"]]),
         [round(x) for x in conceal], [round(x, 3) for x in sepc],
         [round(x, 3) for x in sepa]))
print("fig1 95%% CIs: conceal %s | sepCLRT %s | sepACK %s"
      % ([(round(float(100*lo), 1), round(float(100*hi), 1)) for lo, hi in wils],
         [(round(lo, 3), round(hi, 3)) for lo, hi in ci_c],
         [(round(lo, 3), round(hi, 3)) for lo, hi in ci_a]))

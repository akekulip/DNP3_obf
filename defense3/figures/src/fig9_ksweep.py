"""Figure 9 (double column) — the fail-open reconciliation. (a) On the unrepaired build the
budget-zero terminations are 1 TMO and K-1 STALE at EVERY reservoir size, including K=1:
one native token clears reg_tag and the rest read foreign. That resolves the apparent
single-token/aggregate contradiction — the first token clobbers, it is not an emergent
effect of size. (b) R2 turns the same event into K budget terminations and 0 stale, and
preserves reg_tag."""
import sys
from pathlib import Path
import numpy as np, matplotlib.pyplot as plt
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl, paper_palettes as pp
utils_mpl.set_global(); C = pp.get("alessandretti-nature")
TMOC, STLC = C[3], C[1]                       # red = budget (TMO), orange = stale

# measured, pure-defect build, 12 fail-open trials per K (evidence/ksweep)
K = np.array([1, 2, 4, 8, 16, 32, 64])
TMO = np.ones_like(K)                          # 1 at every K
STALE = K - 1                                  # K-1 at every K

fig = plt.figure(figsize=(7.16, 2.6))
gs = fig.add_gridspec(1, 2, width_ratios=[1.32, 1.0], wspace=0.28)

# ---------------- (a) the K-sweep ----------------
ax = fig.add_subplot(gs[0])
ax.plot(K, TMO, "o-", color=TMOC, ms=5, lw=1.4, label=r"budget-expiry (TMO): 1 at every $K$")
ax.plot(K, STALE, "s--", color=STLC, ms=5, lw=1.4,
        label="stale ($K{-}1$): reads foreign after the tag is cleared")
ax.plot(K, K, ":", color="0.55", lw=1.0, label="$K$ (tokens admitted)")
ax.set_xscale("log", base=2); ax.set_yscale("log", base=2)
ax.set_xticks(K); ax.set_xticklabels([str(k) for k in K])
ax.set_yticks([1, 2, 4, 8, 16, 32, 64]); ax.set_yticklabels([1, 2, 4, 8, 16, 32, 64])
ax.set_xlabel("reservoir size $K$ (tokens)", fontweight="bold")
ax.set_ylabel("terminations per fail-open", fontweight="bold")
ax.set_title("(a) the defect is present at every $K$, including $K=1$", fontsize=8.6, pad=3)
ax.annotate("$K=1$: one token clears\n" + r"$\mathtt{reg\_tag}$", xy=(1, 1), xytext=(1.7, 7.0),
            fontsize=6.6, color=TMOC,
            arrowprops=dict(arrowstyle="-|>", lw=0.8, color=TMOC))
ax.legend(fontsize=6.4, loc="upper left", framealpha=0.97, handlelength=1.6,
          borderpad=0.35, labelspacing=0.28)
utils_mpl.set_grid(fig, ax)

# ---------------- (b) R2 before/after at K=64 ----------------
ax = fig.add_subplot(gs[1])
groups = ["unrepaired", "with R2"]
x = np.arange(2); w = 0.38
tmo_b = [1, 64]; stale_b = [63, 0]
ax.bar(x - w/2, tmo_b, w, color=TMOC, ec="black", lw=0.6, label="budget-expiry (TMO)")
ax.bar(x + w/2, stale_b, w, color=STLC, ec="black", lw=0.6, label="stale")
for xi, (tb, sb) in enumerate(zip(tmo_b, stale_b)):
    ax.text(xi - w/2, tb + 1.5, str(tb), ha="center", fontsize=7, color=TMOC, fontweight="bold")
    ax.text(xi + w/2, sb + 1.5, str(sb), ha="center", fontsize=7, color=STLC, fontweight="bold")
ax.text(0, -9, r"$\mathtt{reg\_tag}\to 0$", ha="center", fontsize=6.6, color="0.25")
ax.text(1, -9, r"$\mathtt{reg\_tag}$ kept", ha="center", fontsize=6.6, color="0.25")
ax.set_xticks(x); ax.set_xticklabels(groups)
ax.set_ylim(-13, 74)
ax.set_ylabel("terminations ($K=64$)", fontweight="bold")
ax.set_title("(b) R2: 64 budget, 0 stale, tag preserved", fontsize=8.6, pad=3)
ax.legend(fontsize=6.6, loc="upper center", framealpha=0.97, handlelength=1.0,
          borderpad=0.3, ncol=1)
utils_mpl.set_grid(fig, ax)

fig.subplots_adjust(left=0.075, right=0.988, top=0.9, bottom=0.16)
out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig9_ksweep.pdf", transparent=True)
fig.savefig(out / "fig9_ksweep.png", dpi=300)
print("fig9 ok  TMO=%s STALE=%s" % (list(TMO), list(STALE)))

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
import utils_mpl
import d3_style as ds
ds.setup_only()
plt.rcParams["hatch.linewidth"] = 0.5
TMOC, STLC = ds.PASS, ds.FAIL     # green = budget (the intended terminator), red = stale (the defect)
STL_HATCH = "//"                  # redundant encoding: stale differs by pattern, not hue alone

# measured, pure-defect build, 12 fail-open trials per K (evidence/ksweep)
K = np.array([1, 2, 4, 8, 16, 32, 64])
TMO = np.ones_like(K)                          # 1 at every K
STALE = K - 1                                  # K-1 at every K

fig = plt.figure(figsize=(7.16, 2.6))
gs = fig.add_gridspec(1, 2, width_ratios=[1.32, 1.0], wspace=0.28)

# ---------------- (a) the K-sweep, as a stacked accounting ----------------
# Every fail-open's terminations sum to exactly K, so show each K as one 100% stack:
# the single budget-expiry (green) plus the K-1 stale (red) account for every token.
ax = fig.add_subplot(gs[0])
x = np.arange(len(K))
share_tmo = 100.0 * TMO / K
share_stl = 100.0 * STALE / K
ax.bar(x, share_tmo, 0.62, color=TMOC, ec="black", lw=0.6,
       label=r"budget-expiry (TMO): exactly 1 at every $K$")
ax.bar(x, share_stl, 0.62, bottom=share_tmo, color=STLC, ec="black", lw=0.6,
       hatch=STL_HATCH, label="stale ($K{-}1$): reads foreign after the tag is cleared")
_num = dict(facecolor=STLC, edgecolor="none", pad=0.6)   # keeps the count legible over the hatch
for xi, (k, s) in enumerate(zip(K, STALE)):
    if s:                                  # the stale count, inside its segment
        ax.text(xi, share_tmo[xi] + share_stl[xi]/2, str(s), ha="center",
                va="center", fontsize=6.6, color="white", fontweight="bold", bbox=_num)
ax.set_xticks(x); ax.set_xticklabels([str(k) for k in K])
ax.set_ylim(0, 138); ax.set_yticks([0, 25, 50, 75, 100])
ax.set_xlabel("reservoir size $K$ (tokens)", fontweight="bold")
ax.set_ylabel("share of the $K$ terminations (%)", fontweight="bold")
ax.set_title("(a) the defect is present at every $K$, including $K=1$", fontsize=8.6, pad=3)
ax.legend(fontsize=6.4, loc="upper right", framealpha=1.0, handlelength=1.4,
          borderpad=0.35, labelspacing=0.28)
utils_mpl.set_grid(fig, ax)
ax.xaxis.grid(False)                       # bar chart: only horizontal gridlines
ax.set_axisbelow(True)                     # grid under the bars, never over them

# ---------------- (b) R2 before/after at K=64, same stacked accounting ----------------
ax = fig.add_subplot(gs[1])
groups = ["unrepaired\n" + r"($\mathtt{reg\_tag}\to 0$)",
          "with R2\n" + r"($\mathtt{reg\_tag}$ kept)"]
x = np.arange(2); w = 0.5
tmo_b = [1, 64]; stale_b = [63, 0]
ax.bar(x, tmo_b, w, color=TMOC, ec="black", lw=0.6)
ax.bar(x, stale_b, w, bottom=tmo_b, color=STLC, ec="black", lw=0.6, hatch=STL_HATCH)
ax.text(0, 1 + 63/2, "63", ha="center", va="center", fontsize=7,
        color="white", fontweight="bold", bbox=_num)
ax.text(1, 32, "64", ha="center", va="center", fontsize=7,
        color="white", fontweight="bold")
ax.annotate("TMO = 1", xy=(0.25, 1), xytext=(0.52, 10), fontsize=6.4, color="0.2",
            arrowprops=dict(arrowstyle="-|>", lw=0.7, color="0.2"))
ax.set_xticks(x); ax.set_xticklabels(groups)
ax.set_ylim(0, 70); ax.set_yticks([0, 16, 32, 48, 64])
ax.set_ylabel("terminations ($K=64$)", fontweight="bold")
ax.set_title("(b) R2: 64 budget, 0 stale, tag preserved", fontsize=8.6, pad=3)
utils_mpl.set_grid(fig, ax)
ax.xaxis.grid(False)
ax.set_axisbelow(True)

fig.subplots_adjust(left=0.075, right=0.988, top=0.9, bottom=0.21)
out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig9_ksweep.pdf", transparent=True)
fig.savefig(out / "fig9_ksweep.png", dpi=300)
print("fig9 ok  TMO=%s STALE=%s" % (list(TMO), list(STALE)))

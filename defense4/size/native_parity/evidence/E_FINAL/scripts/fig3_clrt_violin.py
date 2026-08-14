"""FIG-3: CLRT distribution by group (violin + box) --
native READ, native SELECT, defended READ, defended SELECT.

Data: csv/native_txn.csv, csv/defended_read_txn.csv, csv/defended_txn.csv
(cold==0). Native groups are broad; defended groups are pinned to ~4 ms.

AUDIT CORRECTION: the violins/boxes are built from the FULL sample, but the
y-view is capped at 14 ms. A visible "y-axis truncated at 14 ms" label marks
that native SELECT extends past the top (max ~18 ms), so the cap is a view
limit, not the data range. Overflow counts per group are annotated.
"""
import numpy as np
import _figstyle as S

S.utils_mpl.set_global()

YMAX = 14.0

groups = [
    ("native\nREAD", S.clrt("native_txn.csv", 1), S.C_READ),
    ("native\nSELECT", S.clrt("native_txn.csv", 3), S.C_SELECT),
    ("defended\nREAD", S.clrt("defended_read_txn.csv", 1), S.C_DEF_READ),
    ("defended\nSELECT", S.clrt("defended_txn.csv", 3), S.C_DEF_SELECT),
]
data = [np.asarray(g[1]) for g in groups]
labels = [g[0] for g in groups]
colors = [g[2] for g in groups]
pos = np.arange(1, len(groups) + 1)

fig, ax = S.utils_mpl.get_fig(size=(3.5, 2.6))
vp = ax.violinplot(data, positions=pos, widths=0.8, showextrema=False)
for body, c in zip(vp["bodies"], colors):
    body.set_facecolor(c)
    body.set_edgecolor("k")
    body.set_alpha(0.5)
    body.set_linewidth(0.8)
bp = ax.boxplot(data, positions=pos, widths=0.18, showfliers=False,
                patch_artist=True, medianprops=dict(color="k", lw=1.2),
                boxprops=dict(facecolor="white", lw=0.8),
                whiskerprops=dict(lw=0.8), capprops=dict(lw=0.8))
# per-group overflow markers above the cap (audit correction)
for p, d in zip(pos, data):
    n_over = int(np.sum(d > YMAX))
    if n_over:
        ax.annotate(f"+{n_over}>14ms", xy=(p, YMAX), ha="center", va="bottom",
                    fontsize=6.0, color="0.25")
ax.set_xticks(pos)
ax.set_xticklabels(labels, fontsize=8.0)
ax.set_ylabel("CLRT (ms)")
S.utils_mpl.set_y_axis(ax, bnd=[0, YMAX])
# visible truncation label (audit correction)
ax.annotate("y-axis truncated at 14 ms", xy=(0.5, 0.965),
            xycoords="axes fraction", ha="center", va="top", fontsize=6.5,
            color="0.25",
            bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="0.5",
                      lw=0.7, alpha=0.9))
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-3_clrt_violin")

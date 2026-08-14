"""FIG-3: CLRT distribution by group (violin + box) --
native READ, native SELECT, defended READ, defended SELECT.

Data: csv/native_txn.csv, csv/defended_read_txn.csv, csv/defended_txn.csv
(cold==0). Native groups are broad; defended groups are pinned to ~4 ms.
"""
import numpy as np
import _figstyle as S

S.utils_mpl.set_global()

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
ax.set_xticks(pos)
ax.set_xticklabels(labels, fontsize=8.0)
ax.set_ylabel("CLRT (ms)")
S.utils_mpl.set_y_axis(ax, bnd=[0, 14])
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-3_clrt_violin")

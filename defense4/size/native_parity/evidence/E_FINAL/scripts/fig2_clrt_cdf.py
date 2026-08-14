"""FIG-2: Empirical CDFs of native vs defended CLRT (READ + SELECT).

Data: csv/native_txn.csv, csv/defended_read_txn.csv, csv/defended_txn.csv
(cold==0). Native curves rise gradually; defended curves are near-vertical at
the ~4 ms policy target.
"""
import numpy as np
import _figstyle as S

S.utils_mpl.set_global()


def ecdf(x):
    x = np.sort(np.asarray(x))
    y = np.arange(1, x.size + 1) / x.size
    return x, y


series = [
    ("native READ", S.clrt("native_txn.csv", 1), S.C_READ, "-"),
    ("native SELECT", S.clrt("native_txn.csv", 3), S.C_SELECT, "-"),
    ("defended READ", S.clrt("defended_read_txn.csv", 1), S.C_DEF_READ, "--"),
    ("defended SELECT", S.clrt("defended_txn.csv", 3), S.C_DEF_SELECT, "--"),
]

fig, ax = S.utils_mpl.get_fig(size=(3.5, 2.6))
for label, data, color, ls in series:
    x, y = ecdf(data)
    ax.step(x, y, where="post", color=color, ls=ls, lw=1.4,
            label=f"{label} (n={len(data)})")
ax.set_xlabel("CLRT (ms)")
ax.set_ylabel("Empirical CDF")
S.utils_mpl.set_x_axis(ax, bnd=[0, 12])
S.utils_mpl.set_y_axis(ax, bnd=[0, 1])
ax.legend(loc="lower right", fontsize=7.0)
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-2_clrt_cdf")

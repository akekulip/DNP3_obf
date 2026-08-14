"""FIG-2: Empirical CDFs of native vs defended CLRT (READ + SELECT).

Data: csv/native_txn.csv, csv/defended_read_txn.csv, csv/defended_txn.csv
(cold==0). Native curves rise gradually; defended curves are near-vertical at
the ~4 ms policy target.

AUDIT CORRECTION: the ECDF is computed over the FULL sample (no data dropped),
but the x-view is truncated at 12 ms for readability. A visible
"tail truncated at 12 ms" note marks that native SELECT/READ extend past the
right edge (native SELECT max ~18 ms), so the flattening at the edge is a
view limit, not the end of the data.
"""
import numpy as np
import _figstyle as S

S.utils_mpl.set_global()

XMAX = 12.0


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
n_beyond = 0
for label, data, color, ls in series:
    x, y = ecdf(data)
    n_beyond += int(np.sum(x > XMAX))
    ax.step(x, y, where="post", color=color, ls=ls, lw=1.4,
            label=f"{label} (n={len(data)})")
ax.set_xlabel("CLRT (ms)")
ax.set_ylabel("Empirical CDF")
S.utils_mpl.set_x_axis(ax, bnd=[0, XMAX])
S.utils_mpl.set_y_axis(ax, bnd=[0, 1])
ax.legend(loc="lower right", fontsize=7.0)
# visible truncation note (audit correction)
ax.annotate(f"tail truncated at 12 ms\n({n_beyond} native obs beyond)",
            xy=(0.965, 0.44), xycoords="axes fraction", ha="right", va="top",
            fontsize=6.5, color="0.25",
            bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="0.5",
                      lw=0.7, alpha=0.9))
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-2_clrt_cdf")

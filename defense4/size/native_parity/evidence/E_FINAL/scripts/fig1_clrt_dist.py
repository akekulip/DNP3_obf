"""FIG-1: Native vs defended CLRT distributions (histogram + KDE), READ | SELECT.

Data: csv/native_txn.csv (native, req_func 1/3), csv/defended_read_txn.csv
(defended READ), csv/defended_txn.csv (defended SELECT). cold==0 rows only.
Story: native CLRT is wide; defended collapses to a ~4 ms policy spike.
"""
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde
import _figstyle as S

S.utils_mpl.set_global()

nat_read = np.array(S.clrt("native_txn.csv", req_func=1))
nat_sel = np.array(S.clrt("native_txn.csv", req_func=3))
def_read = np.array(S.clrt("defended_read_txn.csv", req_func=1))
def_sel = np.array(S.clrt("defended_txn.csv", req_func=3))

XMAX = 12.0
bins = np.linspace(0, XMAX, 49)


def panel(ax, nat, dfn, title):
    ax.hist(np.clip(nat, 0, XMAX), bins=bins, density=True, color=S.C_NATIVE,
            alpha=0.45, label=f"native (n={nat.size})")
    ax.hist(np.clip(dfn, 0, XMAX), bins=bins, density=True, color=S.C_DEFENDED,
            alpha=0.55, label=f"defended (n={dfn.size})")
    # KDE overlay for the (wide) native distribution
    grid = np.linspace(0, XMAX, 400)
    if np.ptp(nat) > 0:
        ax.plot(grid, gaussian_kde(nat)(grid), color=S.C_NATIVE, lw=1.4)
    # defended is a near-delta spike (std ~0.02 ms); mark its median
    ax.axvline(np.median(dfn), color=S.C_DEFENDED, lw=1.4, ls="--")
    ax.set_title(title)
    ax.set_xlabel("ACK->response latency, CLRT (ms)")
    S.utils_mpl.set_x_axis(ax, bnd=[0, XMAX])
    ax.legend(loc="upper right")


fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.16, 2.7))
panel(a1, nat_read, def_read, "READ (func 1)")
panel(a2, nat_sel, def_sel, "SELECT (func 3)")
a1.set_ylabel("Probability density")
for ax in (a1, a2):
    S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-1_clrt_distribution")

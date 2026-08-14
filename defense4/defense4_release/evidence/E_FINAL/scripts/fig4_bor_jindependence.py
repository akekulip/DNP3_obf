"""FIG-4: BOR OPERATE timing is independent of the configured jitter value J.

Data: csv/sbo_j2.csv, sbo_j6.csv, sbo_j12.csv (Jpolicy, txn, A_ms, R_ms,
echo_ack_ms). For each metric -- A (ACK @ T0+A), R (echo @ T0+R), and
echo-ACK = R-A -- the plotted point is the MEDIAN with a bootstrap 95 %
confidence interval.

AUDIT CORRECTIONS:
  * MEDIAN + bootstrap-95% CI (percentile, 10 000 resamples), NOT mean +/- SD.
    The first transaction of each capture is a cold-start outlier that inflates
    the SD; the median with a bootstrap CI is robust to it.
  * J is the CONFIGURED codebook value written into the switch, NOT a quantity
    observed on the master-facing capture. The axis and caption say so
    explicitly: flat medians => the master-facing observables do not reveal the
    configured J.
"""
import numpy as np
import _figstyle as S

S.utils_mpl.set_global()

RNG = np.random.default_rng(20260813)
N_BOOT = 10000
CI = (2.5, 97.5)

J = [2, 6, 12]
files = {2: "sbo_j2.csv", 6: "sbo_j6.csv", 12: "sbo_j12.csv"}
d = {j: S.sbo(files[j]) for j in J}


def boot_median_ci(x):
    x = np.asarray(x, float)
    med = float(np.median(x))
    idx = RNG.integers(0, x.size, size=(N_BOOT, x.size))
    boot = np.median(x[idx], axis=1)
    lo, hi = np.percentile(boot, CI)
    return med, med - lo, hi - med


metrics = [
    ("A (ACK @ T0+A)", "A", S.C_NATIVE, "o"),
    ("R (echo @ T0+R)", "R", S.C_DEFENDED, "s"),
    ("echo-ACK = R-A", "echo", S.C_BASELINE, "^"),
]

fig, ax = S.utils_mpl.get_fig(size=(3.5, 2.6))
for label, key, color, mk in metrics:
    med, elo, ehi = zip(*(boot_median_ci(d[j][key]) for j in J))
    ax.errorbar(J, med, yerr=[elo, ehi], color=color, marker=mk, ms=5, lw=1.4,
                capsize=3, label=label)
ax.set_xlabel("Configured jitter codebook value J (ms)")
ax.set_ylabel("Master-facing time (ms)\nmedian, bootstrap 95% CI")
ax.set_xticks(J)
S.utils_mpl.set_x_axis(ax, bnd=[0, 14])
S.utils_mpl.set_y_axis(ax, bnd=[0, 28])
ax.legend(loc="center right", fontsize=7.5)
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-4_bor_j_independence")

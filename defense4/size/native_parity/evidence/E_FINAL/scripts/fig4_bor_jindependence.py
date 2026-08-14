"""FIG-4: BOR OPERATE timing is J-independent.

Data: csv/sbo_j2.csv, sbo_j6.csv, sbo_j12.csv (Jpolicy, txn, A_ms, R_ms,
echo_ack_ms). Plots mean +/- std of A (ACK), R (echo), and echo-ACK = R-A
against the internal jitter policy J in {2,6,12} ms. Flat lines => the
master-facing observables do not leak J.
"""
import numpy as np
import _figstyle as S

S.utils_mpl.set_global()

J = [2, 6, 12]
files = {2: "sbo_j2.csv", 6: "sbo_j6.csv", 12: "sbo_j12.csv"}
d = {j: S.sbo(files[j]) for j in J}

metrics = [
    ("A (ACK @ T0+A)", "A", S.C_NATIVE, "o"),
    ("R (echo @ T0+R)", "R", S.C_DEFENDED, "s"),
    ("echo-ACK = R-A", "echo", S.C_BASELINE, "^"),
]

fig, ax = S.utils_mpl.get_fig(size=(3.5, 2.6))
for label, key, color, mk in metrics:
    mean = [np.mean(d[j][key]) for j in J]
    std = [np.std(d[j][key]) for j in J]
    ax.errorbar(J, mean, yerr=std, color=color, marker=mk, ms=5, lw=1.4,
                capsize=3, label=label)
ax.set_xlabel("Internal jitter policy J (ms)")
ax.set_ylabel("Master-facing time (ms)")
ax.set_xticks(J)
S.utils_mpl.set_x_axis(ax, bnd=[0, 14])
S.utils_mpl.set_y_axis(ax, bnd=[0, 28])
ax.legend(loc="center right", fontsize=7.5)
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-4_bor_j_independence")

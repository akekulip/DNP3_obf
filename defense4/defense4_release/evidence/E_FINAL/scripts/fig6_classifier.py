"""FIG-6: READ-vs-SELECT classifier balanced accuracy, native vs defended.

Data: verdict_stats.json ["classifier"] -- native_balanced_acc with
native_ba_ci, defended_balanced_acc with defended_ba_ci, and
balanced_acc_chance_baseline (0.5). Native leaks (BA > chance); defended
collapses to chance.

AUDIT CORRECTION: the 0.546 "majority-class" line is REMOVED. That figure was
ordinary accuracy under class imbalance, NOT a balanced-accuracy baseline, so
it does not belong on a balanced-accuracy axis. The only reference line shown is
the balanced-accuracy chance baseline = 0.500. All values + CIs are read from
the JSON.
"""
import numpy as np
import _figstyle as S

S.utils_mpl.set_global()

c = S.load_json("verdict_stats.json")["classifier"]
labels = ["native", "defended"]
ba = [c["native_balanced_acc"], c["defended_balanced_acc"]]
ci = [c["native_ba_ci"], c["defended_ba_ci"]]
colors = [S.C_NATIVE, S.C_DEFENDED]
chance = c["balanced_acc_chance_baseline"]

# asymmetric error bars from CI
yerr = np.array([[ba[i] - ci[i][0], ci[i][1] - ba[i]] for i in range(2)]).T

fig, ax = S.utils_mpl.get_fig(size=(3.5, 2.5))
x = np.arange(2)
ax.bar(x, ba, width=0.55, color=colors, edgecolor="k", lw=0.8, zorder=2)
ax.errorbar(x, ba, yerr=yerr, fmt="none", ecolor="k", capsize=4, lw=1.2,
            zorder=3)
ax.axhline(chance, color=S.C_CHANCE, ls="--", lw=1.2,
           label=f"balanced-accuracy chance = {chance:.3f}")
for xi, b, cc in zip(x, ba, ci):
    ax.text(xi, cc[1] + 0.006, f"{b:.3f}", ha="center", va="bottom",
            fontsize=8.5)
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.set_ylabel("Balanced accuracy (READ vs SELECT)")
S.utils_mpl.set_y_axis(ax, bnd=[0.45, 0.68])
ax.legend(loc="upper right", fontsize=7.0)
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-6_classifier_ba")

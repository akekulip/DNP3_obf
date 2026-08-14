"""FIG-6: READ-vs-SELECT classifier balanced accuracy, native vs defended.

Data: verdict_stats.json ["classifier_READ_vs_SELECT"] -- native_balanced_acc
with native_ba_ci, defended_balanced_acc with defended_ba_ci, chance (0.5) and
majority_baseline. Native leaks (BA > chance); defended collapses to chance.
All values + CIs read from the JSON.
"""
import numpy as np
import matplotlib.pyplot as plt
import _figstyle as S

S.utils_mpl.set_global()

c = S.load_json("verdict_stats.json")["classifier_READ_vs_SELECT"]
labels = ["native", "defended"]
ba = [c["native_balanced_acc"], c["defended_balanced_acc"]]
ci = [c["native_ba_ci"], c["defended_ba_ci"]]
colors = [S.C_NATIVE, S.C_DEFENDED]
chance = c["chance_balanced_acc"]
majority = c["majority_baseline"]

# asymmetric error bars from CI
yerr = np.array([[ba[i] - ci[i][0], ci[i][1] - ba[i]] for i in range(2)]).T

fig, ax = S.utils_mpl.get_fig(size=(3.5, 2.5))
x = np.arange(2)
ax.bar(x, ba, width=0.55, color=colors, edgecolor="k", lw=0.8, zorder=2)
ax.errorbar(x, ba, yerr=yerr, fmt="none", ecolor="k", capsize=4, lw=1.2,
            zorder=3)
ax.axhline(chance, color=S.C_CHANCE, ls="--", lw=1.2,
           label=f"chance = {chance:.3f}")
ax.axhline(majority, color=S.C_BASELINE, ls=":", lw=1.4,
           label=f"majority baseline = {majority:.3f}")
for xi, b in zip(x, ba):
    ax.text(xi, b + 0.012, f"{b:.3f}", ha="center", va="bottom", fontsize=8.5)
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.set_ylabel("Balanced accuracy")
S.utils_mpl.set_y_axis(ax, bnd=[0.45, 0.68])
ax.legend(loc="upper right", fontsize=7.0)
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-6_classifier_ba")

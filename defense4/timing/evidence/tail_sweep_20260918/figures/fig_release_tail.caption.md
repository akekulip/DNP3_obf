### fig_release_tail

The release tail $\varepsilon$ against the budget $D$ for READ, SELECT and OPERATE, over three installs of each setting; whiskers span them, and in the shaded region the reservoir spends its pass budget and releases early. OPERATE is timed from the request, so its $\varepsilon$ is the acknowledgment's arrival beyond $T_0 + D_A$. Lower right, each configured quantity that could set a master-visible OPERATE interval, against the interval it would set: CLRT$_{\mathrm{new}}$ is obeyed, $A$ and $R-A$ are ignored.

**Statistics.** (a) tail = median(request-to-acknowledgment | Obfuscated) - median(same | Timing OFF blocks of the same pass) - configured hold; point is the mean over three passes, whiskers the min and max. (b) per-setting medians of the interval each quantity is supposed to govern

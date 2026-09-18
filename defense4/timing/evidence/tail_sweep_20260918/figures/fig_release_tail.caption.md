### fig_release_tail

(a) The release tail $\varepsilon$, the interval between a packet's scheduled instant and its actual one, against the budget $D$ the operator sets, over three independent installs of each policy. It falls on one of two branches, near 25~$\mu$s or growing with the hold to 0.96~ms; the shaded region is where the reservoir spends its pass budget and releases early. (b) Every configured quantity that could set a master-visible OPERATE interval, measured against what was asked for. The configured CLRT$_{\mathrm{new}}$ is obeyed on the identity; the control-lane offset $A$ and the difference $R-A$ are ignored.

**Statistics.** (a) tail = median(request-to-acknowledgment | Obfuscated) - median(same | Timing OFF blocks of the same pass) - configured hold; point is the mean over three passes, whiskers the min and max. (b) per-setting medians of the interval each quantity is supposed to govern

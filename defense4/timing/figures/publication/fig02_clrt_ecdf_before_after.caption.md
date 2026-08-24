### fig02_clrt_ecdf_before_after

Empirical CDF of CLRT for READ and for the SELECT phase of SBO, with the in-network timing mechanism disabled (solid) and enabled (dashed). With the timing mode off the two transaction types separate clearly and the SELECT distribution carries a tail to 18.18 ms, shown in full; with it on, both collapse onto 4.001 ms, and the inset resolves the two Timing ON curves, which coincide at full scale. Both arms ran the same unified switch binary with the size-shaping datapath active; the Timing OFF arm is not an unmodified device baseline, and the comparison isolates the timing-mode change.

**Statistics.** Empirical CDFs of per-transaction CLRT; every observation appears, nothing is smoothed or truncated. Cold-start transactions excluded as in Figure 1. Size shaping was enabled in both arms, verified from the response segmentation on the wire.

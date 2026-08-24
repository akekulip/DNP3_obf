### fig_T1_clrt_before_after

Command-to-link response time (CLRT) before and after in-network timing normalization, measured master-facing against the physical SEL-751. Left: READ (function 1). Right: the SELECT phase of select-before-operate (function 3); these are SELECT observations, not complete SBO transactions. Native CLRT spans roughly 1 to 18 ms and differs between the two transaction types; after normalization both collapse onto a 4.001 ms policy value with a standard deviation of about 0.02 ms. Axes show the full native range, so no tail is clipped; the inset resolves the defended distribution, which is narrower than the line width at full scale.

**Statistics.** Empirical CDFs of per-transaction CLRT = T_response - T_ack. Cold-start transactions (the first of each TCP connection) are excluded and counted in timing_stats.json under row_accounting. No smoothing, no binning, no resampling: every observation appears.

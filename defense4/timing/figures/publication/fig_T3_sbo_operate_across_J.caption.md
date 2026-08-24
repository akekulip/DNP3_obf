### fig_T3_sbo_operate_across_J

OPERATE timing under three configured hold values. Left: the master-visible request-to-ACK delay A and request-to-echo delay R, both flat in J. Right: the echo-to-ACK interval R-A, which stays at about 4.00 ms across J = 2, 6 and 12 ms, so an observer who subtracts the two observable timestamps learns nothing about the configured hold. Markers are medians of 30 OPERATE transactions per condition; bars are bootstrap 95 percent confidence intervals on the median and are smaller than the markers on the right-hand panel. J is the configured codebook value; it was not observed on the relay-facing wire.

**Statistics.** Median over the 30 OPERATE transactions of each J condition, with a percentile bootstrap 95 percent confidence interval on the median (10,000 resamples, seed 20260824). A and R are master-visible and include a path and capture offset of roughly 1 ms relative to the configured 20 ms and 24 ms deadlines; that offset cancels in R-A.

# Figure and table captions (descriptive only; findings are stated in REPORT.md)

All data come from campaign `rc01_hw_c72_eval_20261027_01`: 64 blocks, 16 per D in {5, 10, 15, 20} ms. Each block
ran the four arms on the SEL-751 relay through the c72 switch program. A block-arm is one cold connection with 65
READ (33 mixed, 32 integrity), 64 SELECT and 64 OPERATE. Timestamps come from the master NIC (receiver captures).
CLRT is the time from the relay's first ACK of a request to the complete response, as Formby et al. define it.
Request sizes are native in every arm. B denotes bytes of TCP payload.

Encoding in every figure:
- **Classes:** READ / SELECT / OPERATE are near-black / red / amber, with solid / dashed / dotted lines, plain /
  hatched / dotted fills and plus / X / hexagon markers.
- **Arms:** no obfuscation / Timing+Size / Timing / Size are navy / purple / blue / light blue, with circle /
  diamond / square / triangle markers and plain / cross-hatched / back-slash / horizontal-line fills.
- **Markers:** hollow markers (white fill, arm-coloured edge) show a secondary statistic.
- **Reference lines:** chance is the grey horizontal line; zero is the thin black horizontal line.
- **Boxes:** the box spans the interquartile range, the line is the median, the cross is the mean, and the whiskers
  run from the 5th to the 95th percentile. The median and mean are drawn white on dark boxes.

## Figures

**F1 CLRT histograms.**
- Layout: rows are D; columns are (a) no obfuscation, (b) Timing, (c) Size, (d) Timing+Size.
- Bins: 0.25 ms from 0 to 30 ms. The separate bin at "≥30" collects every value of 30 ms or more.
- Lines: the mean per-block fraction per class over the 16 blocks (1,040 READ, 1,024 SELECT and 1,024 OPERATE
  exchanges per arm and D). T1 gives each cell's standard deviation of CLRT.

**F1b CLRT histograms, Timing and Timing+Size, zoom.** Shows D ± 3 ms with 0.2 ms bins. Lines are as in F1.
Values of CLRT outside the window are not drawn: 0–7 per D, arm and class (`figure_notes.json`,
`F3b_F1b_values_outside_D_plus_minus_3ms`).

**F1c CLRT histograms, no obfuscation and Size, zoom.** Shows 0–10 ms with 0.1 ms bins. Lines are as in F1.
Values of CLRT above 10 ms are not drawn; F1 shows them.

**F2 Response-size histograms.**
- Layout: rows are D; columns are the four arms.
- Bars: the mean per-block fraction of responses at each payload size per class, with classes side by side.
- Labels: the number above a bar group is the exact payload size.
- The fraction is identical in every block, with standard deviation 0 across blocks
  (`figures/figure_notes.json`).

**F2b Request sizes.** Request payload per request type (READ mixed, READ integrity, SELECT, OPERATE). It is
identical in every arm and at every D.

**F3 CLRT spread.** One box plot per class and D for each arm, pooling all exchanges of the 16 blocks. Boxes are as
in the encoding above.

**F3b CLRT minus D, Timing and Timing+Size.**
- Layout: rows are D.
- Plots the distribution of CLRT − D per class, with 0.1 ms bins, from −3 to 3 ms. Values of CLRT − D outside that
  range are not drawn and are counted in `figure_notes.json` (0–7 per D, arm and class).
- Lines are as in F1.

**F4 Formby signatures.**
- Plots the mean Formby Eq. 1 signature of K = 64 windows per class, for (a) no obfuscation and (b) Timing+Size.
- Bins: 199 equal bins on [0, H), with H = 1.05 × the largest training CLRT (values in `figure_notes.json`).
- Overflow: the overflow bin is drawn as one marker per class at "≥H", with the READ, SELECT and OPERATE markers
  shown in the legend.
- Error bars on the overflow markers: ±1 standard deviation across windows.

**F5 Formby classifiers (CLRT, size, joint).**
- Layout: rows are the classifier and attacker; columns are D. The x-axis is the window size K.
- Classifiers:
  - multinomial naive Bayes, retrained per arm;
  - multinomial naive Bayes trained before deployment on the no-obfuscation arm (training blocks 1–8, test blocks
    9–16);
  - FF-ANN (one hidden layer, Formby's random 75/25 split);
  - GMM (full covariance, three components, window mean and variance of each feature).
- Filled markers:
  - For naive Bayes and GMM, the mean balanced accuracy over the 8 test blocks, with a 95% block-bootstrap interval
    (10,000 resamples).
  - For FF-ANN, the pooled value on its random test split, which has no block interval.
- Hollow markers: the minimum per-class recall, drawn beneath the filled marker where the two coincide.
- Grey line: chance balanced accuracy (1/3).
- Some intervals are narrower than the markers.

**F5d Confusion matrices.**
- Plots naive Bayes on CLRT at K = 64, retrained, for no obfuscation and Timing+Size at each D.
- Shading: the row-normalized fraction. Numbers: window counts.

**F6 Latency.** Columns are classes; rows are:
- Top: request-to-response time per arm and D, with boxes as in F3.
- Middle: the added p50 (filled) and p95 (hollow, drawn just right of p50) request-to-response time relative to the
  same block's no-obfuscation arm. Markers are the mean over blocks of the per-block difference, with 95%
  block-bootstrap intervals (2,000 resamples). The black line marks zero.
- Bottom: request-to-ACK time, with boxes as in F3.

Outliers beyond the whiskers are not drawn. The largest request-to-response time, 236 ms, belongs to the first READ
of a connection; T1 lists each cell's maximum.

**F7 Block stability.**
- Rows are D; the x-axis is the block repetition at that D.
- Markers: the per-block median CLRT, with whiskers at the 25th–75th percentile, for (a) no obfuscation and Size.
  Lines join consecutive blocks of one arm.
- For (b) Timing and Timing+Size, the per-block median CLRT − D with the same whiskers.
- Classes are pooled.

**F8 CLRT CDFs.**
- Layout: rows are D; columns are the four arms.
- Lines: the mean per-block empirical CDF per class over the 16 blocks.
- A curve that ends below 1 at 30 ms has mass beyond the axis.

**F8b CLRT CDFs, Timing and Timing+Size, zoom.** Shows D ± 3 ms. Lines are as in F8.

**F8c CLRT CDFs, no obfuscation and Size, zoom.** Shows 0–10 ms. Lines are as in F8. A curve that ends
below 1 at 10 ms has CLRT mass beyond the axis.

**F9 Window mean and variance.**
- Plots K = 8 windows of CLRT per class, for no obfuscation and Timing+Size at each D.
- Points: one window each. Ellipses: two standard deviations of each class, computed on the mean and the base-10
  logarithm of the variance.
- Axes: the window mean against the window variance, with variance on a logarithmic axis. Each row has its own
  variance scale.
- The mean axis covers the 1st to 99th percentile of window means and every ellipse, with a small margin. The few
  windows outside it (at most 6 per panel) are counted in `figure_notes.json` (`F9_windows_outside_x_range`).

**F10 Overhead per D and arm.**
- (a) Padding per response.
- (b) Change in request+response payload per transaction relative to no obfuscation.
- (c) Added p50 (filled) and p95 (hollow, drawn just right of p50) request-to-response time relative to no
  obfuscation.
- (d) Transactions per second per connection.
- (e) Total retransmitted TCP segments over the 16 blocks.
- (a)–(c) are measured relative to no obfuscation, so that arm has no marker there. The black line marks zero.
- In (a)–(d), markers are the mean over blocks with 95% block-bootstrap intervals (2,000 resamples). Some intervals
  are narrower than the markers.

## Tables

- **T1:** n, mean, standard deviation, median, quartiles, 5th/95th percentiles, minimum and maximum of CLRT,
  response size, request-to-response time and request-to-ACK time, per D, arm and class. Piggybacked exchanges are
  excluded.
- **T2:** classifier metrics:
  - pooled balanced accuracy;
  - block-mean balanced accuracy with its 95% interval;
  - Formby's mean and minimum per-class (one-vs-rest) accuracy, precision and recall.

  Chance is 1/3 for balanced accuracy and recall, but 5/9 for the mean one-vs-rest accuracy. Precision is 0 for a
  class that is never predicted. Cells that could not be computed are listed with the reason.
- **T3:** delivery: exchanges, OK outcomes, application-layer checks, CROB status decoded from captured bytes,
  retransmitted segments, kernel capture drops and piggybacked ACKs.
- **T4:** overhead per D and arm.
- **T4b:** switch resources of the c72 build (`results/analysis/stage_cut/final_resources.json`).

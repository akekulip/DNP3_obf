# Figure and table captions

All data come from campaign `rc01_hw_c72_eval_20261027_01`: 64 blocks, 16 per D in {5, 10, 15, 20} ms. Each block
ran the four arms on the SEL-751 relay through the c72 switch program. A block-arm is one cold connection with 65
READ (33 mixed, 32 integrity), 64 SELECT and 64 OPERATE. Timestamps come from the master NIC (receiver captures).
CLRT is the time from the relay's first ACK of a request to the complete response, as Formby et al. define it.
B denotes bytes of TCP payload. Every number in a caption is recorded by the generator in
`final/figures/figure_notes.json` or appears in tables T1-T4.

The figures follow the P4USE (IEEE TDSC 2026) style: one message per figure and at most two panels. `main/` holds
fig01-fig08. The distribution figures use D = 5 ms, the reference setting of the matrix and the D where the
classifier criterion was falsified. `supplementary/` repeats them for every D and adds the remaining detail.

Encoding in every figure:
- **Arms:** No obfuscation is blue with circles and solid lines; Timing+Size is orange with diamonds and dashed lines;
  Timing is grey with squares and dotted lines; Size is gold with triangles and dash-dot lines.
- **Classes:** READ is green and solid, SELECT purple and dashed, OPERATE crimson and dotted. Where markers appear,
  READ is a plus, SELECT an X and OPERATE a hexagon.
- **Reference lines:** the red dashed vertical line labelled D marks the hold D; the grey dashed horizontal line is
  chance (1/3); the black horizontal line is zero.
- **Spread:** error bars are 95% block-bootstrap intervals. Classifier intervals use the 8 test blocks and 10,000
  resamples; latency, rate and request-to-ACK intervals use the 16 blocks and 2,000 resamples. FF-ANN uses Formby's
  random 75/25 window split and has no block interval. Histograms and CDFs plot the mean per-block value over the
  16 blocks, without bands; T1 gives each cell's standard deviation.
- **Text in plots:** bars carry their value as a data label. Apart from these, legends and the D marker, no text
  appears inside a plot area.

## Main figures

**Fig. 1 (`fig01_clrt_histogram_D5`). CLRT histograms at D = 5 ms, (a) no obfuscation and (b) Timing+Size.** One
line per class gives the mean per-block fraction of exchanges per bin. Both panels use 0.25 ms bins: (a) from 0 to 10 ms
plus one bin for 10 ms or more, and (b) over D ± 3 ms, which leaves out 4 of 3,088 exchanges. With no
obfuscation the class medians span 0.46 ms, with SELECT lowest; under Timing+Size they lie within 0.007 ms of each
other.

**Fig. 2 (`fig02_median_spread_vs_D`). Spread of the per-class median CLRT against D.** The line is the spread
(largest minus smallest class median) over all 16 blocks, the value the timing verdict uses; the small points are
the 16 per-block spreads. With no obfuscation the class medians lie 0.40-0.58 ms apart, and with Timing or
Timing+Size they lie within 0.004-0.036 ms at every D. Single blocks scatter more: per block the timed arms reach
0.56 ms (block medians 0.11-0.22 ms), against 0.13-2.02 ms with no obfuscation.

**Fig. 3 (`fig03_response_size`). Response payload per class, native and padded.** Native sizes appear in the no-
obfuscation and Timing arms, padded sizes in the Size and Timing+Size arms; each class has exactly one size in every
block. The padded arms map READ mixed from 91 to 141 B, READ integrity from 134 to 158 B, and SELECT and OPERATE
from 49 to 60 B, so READ stays larger than SELECT/OPERATE in every arm.

**Fig. 4 (`fig04_classifier_vs_D`). Balanced accuracy on CLRT at K = 64 against D, (a) naive Bayes and (b) FF-ANN,
both retrained per arm.** Whiskers in (a) are 95% block-bootstrap intervals of balanced accuracy over the 8 test
blocks. FF-ANN in (b) follows Formby's random 75/25 split with 12 test windows, so it moves in steps of 1/12 and has
no interval. At K = 64, naive Bayes scores 0.625-0.750 with no obfuscation and 0.250-0.458 under Timing+Size; the
paired interval for the drop excludes zero at every D except D = 5 ms for Timing+Size. With CLRT and response size
together (S08, joint feature), naive Bayes still scores 0.667-0.875 under Timing+Size, against 1.0 with no
obfuscation; REPORT.md discusses this residual.

**Fig. 5 (`fig05_confusion_D5`). Naive Bayes confusion matrices on CLRT at D = 5 ms and K = 64.** Cells give window
counts over the 8 test blocks; shading gives the row-normalized fraction. With no obfuscation the classifier labels
15 of 24 test windows correctly, and under Timing+Size it labels 9 of 24, where chance is 8.

**Fig. 6 (`fig06_added_latency_vs_D`). Added request-to-response time against D, (a) median and (b) 95th
percentile.** Each point is the mean over blocks of the arm's value minus the same block's no-obfuscation value,
with a 95% block-bootstrap interval over the 16 blocks. The median rises by 4.74-4.92 ms at D = 5 ms and by
19.64-19.78 ms at D = 20 ms in the two timed arms, while Size alone adds at most 0.11 ms.

**Fig. 7 (`fig07_rate_vs_D`). Exchanges per second per connection against D (`txn_per_s` in T4).** An exchange is
one request and its response, and each connection carries 193. The master pauses about 26.7 ms after each READ
response and about 1 ms after each SELECT or OPERATE response. Whiskers are 95% block-bootstrap intervals over the
16 blocks, and the axis starts at zero. With no obfuscation a connection completes about 62 exchanges per second;
the timed arms complete 47-48 at D = 5 ms and 28 at D = 20 ms.

**Fig. 8 (`fig08_first_request_retransmissions`). Connections whose first request the master's TCP stack
retransmitted, per arm.** Each arm has 64 fresh connections over the four D values. The counts are 3 with no
obfuscation, 6 with Timing, 3 with Size and 4 with Timing+Size; no other request was retransmitted. Timed against
untimed is 10/128 against 6/128, Fisher two-sided p = 0.44.

## Supplementary figures

- **S01 (`S01_clrt_histogram_D{5,10,15,20}`):** Fig. 1 at each D. **S02 (`..._timing_size`):** the same for Timing
  and Size. Timed panels leave out 0-7 exchanges per class outside D ± 3 ms (`figure_notes.json`).
- **S03 (`S03_clrt_cdf_D{d}`):** the mean per-block empirical CDF per class, no obfuscation (0-10 ms) and Timing+Size
  (D ± 3 ms). A no-obfuscation curve that ends below 1 has CLRT mass above 10 ms.
- **S04 (`S04_formby_signature_D{d}`):** the mean Formby Eq. 1 signature of K = 64 windows per class. Bins are 199
  equal bins on [0, H) with H = 1.05 × the largest training CLRT; the marker at "≥H" is the overflow bin, with ±1
  standard deviation across windows.
- **S05 (`S05_mean_variance_D{d}`):** K = 8 window mean against window variance (logarithmic), one point per window,
  with a two-standard-deviation ellipse per class (Formby Fig. 6a). The mean axis covers the 1st-99th percentile and
  every ellipse; at most 6 windows per panel fall outside it.
- **S06 (`S06_confusion_D{d}`):** Fig. 5 at each D.
- **S07 (`S07_block_stability_D{d}`):** the per-block median CLRT (untimed arms) and median CLRT − D (timed arms),
  classes pooled, against block repetition, with whiskers at the 25th and 75th percentiles.
- **S08 (`S08_classifier_{clrt,size,joint}_nb`):** balanced accuracy at K = 64 against D for all four arms, naive
  Bayes retrained per arm and trained before deployment on the no-obfuscation arm. **S09 (`..._ann_gmm`):** the same
  for FF-ANN and GMM (full covariance, three components, window mean and variance).
- **S10 (`S10_classifier_vs_K_{clrt,size,joint}`):** naive Bayes balanced accuracy against window size K at D = 5
  and 20 ms.
- **S11 (`S11_request_sizes`):** request payload per request type: READ mixed 25 B, READ integrity 27 B, SELECT and
  OPERATE 45 B, the same in every arm and at every D.
- **S12 (`S12_request_to_ack_vs_D`):** the mean over blocks of the per-block median request-to-ACK time. It is about
  3.4 ms in the untimed arms and 5.8-6.1 ms in the timed arms, where the switch holds the ACK until the response is
  ready.

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

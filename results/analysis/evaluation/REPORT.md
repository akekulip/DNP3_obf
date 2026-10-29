# c72 evaluation on the SEL-751: timing and size distributions, Formby classifiers, overhead

Campaign `rc01_hw_c72_eval_20261027_01`, run 2026-10-27 19:55 to 2026-10-28 ~03:10. Every number below comes from
`final/REPORT_NUMBERS.md`, `final/figures/*.csv|json` or `final/rows/rows.csv`, which `scripts/analysis/run_evaluation.sh`
generated from the retained captures. The design was registered before any traffic in `DESIGN.json`. The run log is
`RUN_LOG.md` and the figure captions are in `CAPTIONS.md`.

## What was run

The run has 64 blocks: 16 at each of D = 5, 10, 15 and 20 ms, with D cycling block by block. Each block ran all four
arms, in a Latin-square order: no obfuscation, timing, size, and timing plus size. Each arm-block was one cold connection
to the relay carrying 65 READ, 64 SELECT and 64 OPERATE. The run therefore covers 256 connections and 49,408 exchanges.

All 64 blocks completed and restoration was verified after each one. The extractor reported no problems. Every
trial was captured with zero kernel and interface drops. The pre-registered sufficiency gate passed in every
D/arm/class cell: at least 8 training and 8 test blocks, at least 8 test windows at K = 64, and at least 64 at K = 8.
Training used blocks 1-8 of each D and testing used blocks 9-16.

## Delivery

All 49,408 exchanges completed with outcome OK and passed the application check. All 32,768 SELECT and OPERATE
responses decode, from the captured bytes, to CROB status SUCCESS on both points 1 and 3 (65,536 point statuses). No
ACK was piggybacked. 16 TCP segments were retransmitted (T3), each one on the first request of a fresh connection
(below).

## Pre-registered verdicts

**Size: not falsified.** In the size and timing+size arms every response equals its class image: READ mixed
141 octets, READ integrity 158, SELECT and OPERATE 60. No native size appears (Fig. 3). The transform does not make READ
and SBO responses equal, so a size-only classifier separates READ from SELECT/OPERATE in every arm, at balanced
accuracy 0.667 for K = 64 (T2). That separation is the design limit of the current transform. Neither SELECT nor
OPERATE is distinguishable by size, natively or padded.

**Timing, criterion 1 (class-median spread): not falsified at any D.** In the timed arms the per-class CLRT medians
lie within 0.004-0.036 ms of each other. In the no-obfuscation arm at the same D they are 0.40-0.58 ms apart.

**Timing, criterion 2 (retrained naive Bayes on CLRT lower than no obfuscation): supported in 21 of 24 cells.** At
D = 10, 15 and 20 ms, every timed cell's paired block-bootstrap interval for (no-obfuscation BA minus arm BA) lies
above zero for K = 8, 32 and 64. At D = 5 ms the interval includes zero for timing+size at K = 32 and K = 64 and for
timing at K = 32. Those three cells count as falsified, as registered.

## Distributions

- **No obfuscation.** The SEL-751 CLRT is broad: the median is about 2.2-2.8 ms per class, the p95 about 7-9 ms, and
  the tail reaches 90 ms. The classes differ mainly in shape. SELECT has a lower median than OPERATE by 0.40-0.58 ms;
  two-sample KS D = 0.17-0.23 (Fig. 1, Fig. 2, S03, T1).
- **Timing and timing+size.** Every class concentrates at D. Median CLRT is within 0.035 ms of D, with a standard
  deviation of 0.86-1.70 ms. The per-class CDFs overlap at every D (S01, S03).
- **Size only.** CLRT is indistinguishable from no obfuscation at the level of these summaries (T1).

## Formby classifiers (T2, Fig. 4, Fig. 5, S08-S10)

At K = 64, naive Bayes on CLRT scores the following balanced accuracy, as a block mean with 95% interval:

| Arm | D = 5 ms | D = 10 ms | D = 15 ms | D = 20 ms |
|---|---|---|---|---|
| No obfuscation | 0.625 [0.500, 0.750] | 0.708 [0.583, 0.833] | 0.750 [0.583, 0.917] | 0.750 [0.583, 0.875] |
| Timing | 0.375 [0.250, 0.500] | 0.375 [0.167, 0.542] | 0.375 [0.250, 0.500] | 0.417 [0.250, 0.625] |
| Timing+size | 0.375 [0.167, 0.583] | 0.458 [0.333, 0.583] | 0.458 [0.375, 0.583] | 0.250 [0.125, 0.417] |

Chance is 0.333. The pre-deployment attacker, trained on no obfuscation, falls to 0.29-0.46 on the timed arms. The
FF-ANN scores every timed cell below no obfuscation. The GMM sits near chance in every arm. With no obfuscation the
GMM already scores 0.333-0.375 at K = 64, so the GMM shows no reduction to measure.

The size feature pushes a pre-deployment attacker to exactly 0.333 on the padded arms. That number is an artefact of
fitting H on native sizes: every padded size lands in the overflow bin. It does not mean padding hides size (see the
size verdict).

### Exploratory, not pre-registered: residual SELECT/OPERATE information under timing+size

The joint feature (CLRT and size) was registered, but this breakdown was not. Size removes READ, so the joint naive
Bayes reduces to a SELECT-versus-OPERATE test on CLRT. Under timing+size it labels SELECT/OPERATE test windows
correctly 45 of 64 times at K = 64 (70%; one-sided binomial p = 0.0008), against 64 of 64 with no obfuscation and 35
of 64 under timing alone. The pooled SELECT and OPERATE CLRT distributions in the timed arms differ only slightly:
medians within 0.024 ms, means within 0.12 ms, KS D = 0.03-0.07. Per D and timed arm (eight tests) the smallest KS
p is 0.022, so none survives a Bonferroni correction over the eight.

The timing hold therefore removes most, but not all, of the SELECT/OPERATE CLRT difference. Under timing+size, a
residual mostly in the upper tail stays detectable with 64-transaction windows. The mechanism has not been determined.
This should be stated as a limitation and not explained away.

## Overhead (T4, Fig. 6-8)

- **Latency.** Relative to the same block's no-obfuscation arm, the median request-to-response time rises by about
  D: 4.7-4.9 ms at D = 5 up to 19.6-19.8 ms at D = 20. The p95 rises by a similar amount (Fig. 6). Size alone adds at
  most 0.11 ms to the median. Its interval excludes zero only at D = 5 ms (0.08 ms, [0.002, 0.170]), and its p95
  intervals include zero at every D. The largest request-to-response time stays far
  below the master's 3,000 ms budget.
- **Bytes.** Padding adds 37.2 octets on average per READ response (50 for mixed, 24 for integrity) and 11 per
  SELECT/OPERATE response. Payload per transaction (request plus response) rises 18.2%.
- **Polling rate.** The master is sequential: it waits for each response, then pauses 26.6-26.8 ms after a READ and
  0.8-1.0 ms after a SELECT or OPERATE (per-arm medians). The hold therefore lowers the exchanges (request-response
  pairs) per second per connection from about 62 to 47, 38, 32 and 28 at D = 5, 10, 15 and 20 ms. Size alone runs
  0.3-1.0 exchanges per second below no obfuscation.
- **Switch resources** of the c72 build are in `T4b_switch_resources.json`. The arms change only runtime flags.

## Data event: first-request retransmissions

In 16 of 256 fresh connections the master's TCP stack retransmitted the first READ request, 206-216 ms after the
original. By arm: no obfuscation 3/64, size 3/64, timing 6/64, timing+size 4/64. Timed versus untimed is 10/128
against 6/128, Fisher two-sided p = 0.44. No other request in the campaign was retransmitted.

In every case the relay's first ACK of the request came 2.1-8.7 ms after the retransmitted copy, so the original
first request most likely never reached the relay's processing. The Tofino port counters show a one-frame deficit
between the master port (9) and the relay port (64) in all 16 cases. The same deficit appears in 54 of the 240
connections without a retransmission, so the Tofino counters do not identify where the frame was lost. Outside loss
injection, the same pattern appears in two c69 connections (smoke t0, persistence-RST c2) and in one of the 20 c72
qualification connections (reconnect c1). It therefore predates this build and occurs without obfuscation. It
conflicts with the paper's RO3 wording, "no request is retransmitted", and is recorded as a pre-existing first-
request loss. The mechanism has not been determined: the captures are master-NIC only and no switch-side trace was
taken.

**Update 2026-10-29 (diagnostic-build evidence, `results/analysis/diag_mirror_d3/SUMMARY.md`).** A relay-leg mirror on
the `c72_diag_mirror` build located the loss. In 3 of 40 mirror-on fresh connections the first request reached the
switch (dev9 RX counted it), and no copy of it ever left toward the relay; only the retransmission did. In 4 more
connections the switch did not forward the master's final handshake ACK, which TCP does not notice. That fits the
one-frame deficit seen above in connections without a retransmission. The pipeline mechanism is still open.

## Limits of this evidence

- Captures were taken at the master NIC. They do not show when the switch emitted a packet, its departure timing, or
  packet boundaries at the switch.
- Requests keep their native size: 25 octets for READ mixed, 27 for READ integrity, 45 for SELECT/OPERATE. Request
  size therefore identifies the operation class in every arm (S11).
- The claims cover transaction-class leakage on one SEL-751 with one master, not device identification.
- The cyclic Latin square balances arm position but not carry-over from the previous arm.
- The FF-ANN follows Formby's random 75/25 window split, which shares blocks between training and testing. No
  block-level interval exists for it.
- The paper's historical RO2, a single 61-octet response size, describes the earlier software-outstation testbed and
  was not evaluated.

## Files

- `final/rows/rows.csv` (SHA-256 in `final/rows/rows_manifest.json`) with input hashes bound to each block's
  `artifact_manifest.json`.
- `final/formby/formby_results.json` and `final/SHA256SUMS`.
- `final/figures/`: 8 main figures (`main/`, fig01-fig08) and 39 supplementary figures (`supplementary/`, S01-S12),
  each as PDF and SVG, in the P4USE (IEEE TDSC 2026) style; T1-T4 as CSV and Markdown; `verdicts.json`,
  `sufficiency.json` and `figure_notes.json`.
- Tooling: `scripts/analysis/{eval_rows,eval_watchdog,formby_eval,eval_tables,eval_figures,eval_report}.py`, the
  figure modules `fig_style.py`, `figs_main.py` and `figs_supp.py`, and `run_evaluation.sh`, with tests in
  `tests/analysis/`.

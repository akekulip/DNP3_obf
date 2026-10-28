# c72 classifier analysis v2 (corrected): summary

Schema `c72-formby-eval-v2`, produced on 2026-10-28 by `scripts/analysis/formby_eval_v2.py` and
`formby_v2_models.py`. The input is `results/analysis/evaluation/final/rows/rows.csv` (SHA-256 `29b02822…3c75`,
49,408 rows). Every number below comes from `formby_results_v2.json` or `T2v2_classifier_metrics.csv`.

The task is operation classification (READ, SELECT or OPERATE) on one SEL-751, not device identification. This is
a corrected analysis of data that v1 and the audit have already examined, so it is not a new, untouched test set.
v1 (`final/formby/`) is unchanged.

## What changed from v1

- **One split for every classifier.** NB, GMM and FF-ANN all train on repetitions 1-8 and test on 9-16, per D. In
  v1, NB and GMM already used this split, but the FF-ANN used Formby's random 75/25 split of windows, so its test
  windows came from blocks that also supplied training windows.
- **FF-ANN model selection.** The hidden size (32 or 100) comes from a 5-fold GroupKFold over the 8 training
  blocks. H is refitted inside every inner fold, then on all training windows for the final fit.
- **Observers.** Retrained (trained on the arm) and pre-deployment (trained on off at the same D), for all three
  classifiers.
- **Exploratory features** (`exploratory=True`): `ack` (request to ACK) and `rt` (request to complete response).
  Request to first response byte equals `rt` here: `resp_segments` = 1 for all 49,408 rows.
- **Ties.** Scores within 1e-9 of the row maximum count as tied. A tie goes to READ, then SELECT, then OPERATE.
  Near-ties are counted per cell.
- **Retained per fit:** window membership, per-window predictions and scores (in `formby_fits_v2.json`, bound by
  SHA-256), parameter summaries, convergence with warnings captured inside each fit, and the environment.
- **Uncertainty.** A 95% percentile bootstrap over the 8 test blocks (10,000 resamples, seed 20261027), for each
  balanced accuracy (BA) and for the paired change Δ = off − arm over matched repetitions. A positive Δ means the
  arm lowered BA.

## Reproducibility

- Two runs with 8 threads produced byte-identical files:

  | File | SHA-256 |
  |---|---|
  | `formby_results_v2.json` | `d97354600f66…` |
  | `formby_fits_v2.json` | `9df28c2c6ce0…` |
  | `T2v2_classifier_metrics.csv` | `05e451dc2900…` |

- Environment: Python 3.12.13, NumPy 2.3.5, SciPy 1.16.3, scikit-learn 1.9.0, OpenBLAS (recorded in the JSON).
- v2 reproduces 171 of v1's 288 NB confusion matrices exactly. Every one of the 117 that differ contains a near-tie.
  That is consistent with the declared tie rule causing the differences, but it is a co-occurrence (117 of
  117 under Python 3.12.13 and scikit-learn 1.9.0), not a demonstration.
  - 19 of those 117 change BA. No K=64 retrained CLRT or joint cell changed.
  - The cell the audit flagged (D=5, Timing, K=8, CLRT) has one exactly tied window and gives 0.317708, the audit's
    value.

## Sample sizes

Every cell has 8 training and 8 test blocks. Windows per cell, the same in training and test:

| K | Windows | Per class |
|---:|---:|---:|
| 8 | 192 | 64 |
| 32 | 48 | 16 |
| 64 | 24 | 8 |

At K=64 a per-block BA can only be 0, 1/3, 2/3 or 1.

## K=64, retrained NB

Each cell shows BA [95% CI]; Δ [95% CI]. Chance is 0.333.

**CLRT (preregistered, primary).** These values are identical to v1.

| Arm | D = 5 ms | D = 10 ms | D = 15 ms | D = 20 ms |
|---|---|---|---|---|
| Off | 0.625 [0.500, 0.750] | 0.708 [0.583, 0.833] | 0.750 [0.583, 0.917] | 0.750 [0.583, 0.875] |
| Timing | 0.375 [0.250, 0.500]; Δ +0.250 [+0.125, +0.417] | 0.375 [0.167, 0.542]; Δ +0.333 [+0.083, +0.542] | 0.375 [0.250, 0.500]; Δ +0.375 [+0.167, +0.584] | 0.417 [0.250, 0.625]; Δ +0.333 [+0.042, +0.625] |
| Size | 0.833 [0.708, 0.958]; Δ −0.208 [−0.375, +0.000] | 0.625 [0.417, 0.833]; Δ +0.083 [−0.167, +0.417] | 0.667 [0.667, 0.667]; Δ +0.083 [−0.083, +0.250] | 0.833 [0.708, 0.958]; Δ −0.083 [−0.250, +0.125] |
| Timing+Size | 0.375 [0.167, 0.583]; Δ +0.250 [−0.083, +0.542] | 0.458 [0.333, 0.583]; Δ +0.250 [+0.167, +0.333] | 0.458 [0.375, 0.583]; Δ +0.292 [+0.125, +0.458] | 0.250 [0.125, 0.417]; Δ +0.500 [+0.292, +0.750] |

Δ excludes zero in 7 of the 8 timed cells. The exception is Timing+Size at D=5.

**Size (preregistered).** Every arm at every D gives 0.667 [0.667, 0.667], with Δ 0. Padding maps each native size
class to one padded size, and SELECT and OPERATE share one size before and after padding.

**Joint CLRT and size (preregistered).**

| Arm | D = 5 ms | D = 10 ms | D = 15 ms | D = 20 ms |
|---|---|---|---|---|
| Off | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| Timing | 0.750 [0.583, 0.917]; Δ +0.250 [+0.083, +0.417] | 0.708 [0.542, 0.875]; Δ +0.292 [+0.125, +0.458] | 0.542 [0.417, 0.625]; Δ +0.458 [+0.375, +0.583] | 0.792 [0.625, 0.958]; Δ +0.208 [+0.042, +0.375] |
| Size | 1.000 [1.000, 1.000]; Δ +0.000 | 1.000 [1.000, 1.000]; Δ +0.000 | 0.958 [0.875, 1.000]; Δ +0.042 [+0.000, +0.125] | 1.000 [1.000, 1.000]; Δ +0.000 |
| Timing+Size | 0.667 [0.500, 0.833]; Δ +0.333 [+0.167, +0.500] | 0.833 [0.708, 0.958]; Δ +0.167 [+0.042, +0.292] | 0.833 [0.708, 0.958]; Δ +0.167 [+0.042, +0.292] | 0.875 [0.750, 1.000]; Δ +0.125 [+0.000, +0.250] |

**Request to ACK (EXPLORATORY).**

| Arm | D = 5 ms | D = 10 ms | D = 15 ms | D = 20 ms |
|---|---|---|---|---|
| Off | 0.833 [0.708, 0.958] | 0.833 [0.708, 0.958] | 0.667 [0.500, 0.833] | 0.833 [0.667, 0.958] |
| Timing | 0.792 [0.625, 0.958]; Δ +0.042 [−0.083, +0.167] | 0.958 [0.875, 1.000]; Δ −0.125 [−0.292, +0.042] | 0.958 [0.875, 1.000]; Δ −0.292 [−0.458, −0.125] | 0.875 [0.750, 0.958]; Δ −0.042 [−0.208, +0.125] |
| Size | 0.875 [0.750, 0.958]; Δ −0.042 [−0.208, +0.125] | 0.708 [0.542, 0.875]; Δ +0.125 [−0.083, +0.333] | 0.667 [0.542, 0.792]; Δ +0.000 [−0.167, +0.167] | 0.875 [0.750, 1.000]; Δ −0.042 [−0.250, +0.167] |
| Timing+Size | 0.750 [0.583, 0.875]; Δ +0.083 [−0.125, +0.292] | 0.917 [0.792, 1.000]; Δ −0.083 [−0.208, +0.000] | 0.917 [0.792, 1.000]; Δ −0.250 [−0.458, −0.083] | 0.833 [0.708, 0.958]; Δ +0.000 [−0.250, +0.250] |

**Request to complete response (EXPLORATORY).**

| Arm | D = 5 ms | D = 10 ms | D = 15 ms | D = 20 ms |
|---|---|---|---|---|
| Off | 0.875 [0.708, 1.000] | 0.833 [0.708, 0.958] | 0.917 [0.792, 1.000] | 1.000 [1.000, 1.000] |
| Timing | 0.792 [0.625, 0.958]; Δ +0.083 [−0.208, +0.333] | 0.917 [0.792, 1.000]; Δ −0.083 [−0.208, +0.083] | 1.000 [1.000, 1.000]; Δ −0.083 [−0.208, +0.000] | 0.917 [0.792, 1.000]; Δ +0.083 [+0.000, +0.208] |
| Size | 0.917 [0.792, 1.000]; Δ −0.042 [−0.167, +0.083] | 0.708 [0.542, 0.875]; Δ +0.125 [−0.042, +0.292] | 0.917 [0.792, 1.000]; Δ +0.000 [−0.167, +0.167] | 0.917 [0.792, 1.000]; Δ +0.083 [+0.000, +0.208] |
| Timing+Size | 0.917 [0.792, 1.000]; Δ −0.042 [−0.250, +0.167] | 1.000 [1.000, 1.000]; Δ −0.167 [−0.292, −0.042] | 1.000 [1.000, 1.000]; Δ −0.083 [−0.208, +0.000] | 0.958 [0.875, 1.000]; Δ +0.042 [+0.000, +0.125] |

Neither exploratory feature shows a reduction. In none of the 16 timed cells does the paired Δ interval lie above
zero. Five cells sit slightly below off (Δ +0.042 to +0.083, every interval reaching zero or below); three lie
above off with intervals below zero: ack at D=15 (Timing 0.958, Timing+Size 0.917, against 0.667) and rt at D=10
under Timing+Size (1.000 against 0.833). These values
match the audit's section 3 table. The two features were chosen post-hoc and bound the CLRT result; they are not a
preregistered test.

## Other observers and classifiers

**Pre-deployment NB, K=64, Timing+Size.** CLRT gives 0.375, 0.375, 0.500 and 0.333 at D = 5, 10, 15 and 20 ms;
joint gives the same values. Scores near 1/3 are often overflow artefacts: H was fitted on native traffic. Read each
one together with its `near_ties` count, which is in the CSV.

**FF-ANN, K=64, retrained.** The v2 grouped split (24 windows from 8 held-out blocks) against v1's random split
(12 windows). Each cell shows v2 / v1.

| Arm | CLRT D5 | CLRT D10 | CLRT D15 | CLRT D20 | Joint D5 | Joint D10 | Joint D15 | Joint D20 |
|---|---|---|---|---|---|---|---|---|
| Off | 0.583 / 0.583 | 0.667 / 0.667 | 0.708 / 0.750 | 0.750 / 0.750 | 1.000 / 1.000 | 1.000 / 0.917 | 1.000 / 1.000 | 1.000 / 0.917 |
| Timing | 0.417 / 0.250 | 0.417 / 0.417 | 0.333 / 0.333 | 0.458 / 0.583 | 0.750 / 0.583 | 0.542 / 0.583 | 0.583 / 0.667 | 0.792 / 0.917 |
| Size | 0.833 / 0.833 | 0.542 / 0.583 | 0.708 / 0.750 | 0.667 / 0.750 | 1.000 / 1.000 | 0.958 / 0.917 | 0.958 / 1.000 | 0.958 / 1.000 |
| Timing+Size | 0.375 / 0.250 | 0.458 / 0.583 | 0.458 / 0.333 | 0.292 / 0.500 | 0.708 / 0.583 | 0.792 / 0.750 | 0.917 / 0.583 | 0.875 / 0.917 |

One K=64 CLRT fit (D=10, Timing) did not converge.

**GMM.** The off arm on CLRT at K=64 scores 0.333-0.375, already at chance, so there is no reduction to measure.

## Convergence of the final fits

- **NB:** 240 of 240 (closed form).
- **GMM:** 192 of 240. The 48 others are all size fits. scikit-learn reports `converged_` = True for them, but the
  k-means initialisation warned that it found only 2 distinct clusters for 3 components. Both flags are kept in the
  JSON.
- **FF-ANN:** 208 of 240 final fits and 2,172 of 2,400 inner-CV fits converged.
  - At K=8, the final fits that converged were CLRT 5/16, rt 7/16, ack 13/16, joint 15/16 and size 16/16.
  - At K=64, CLRT and ack were each 15/16, and the rest 16/16.

## Near-ties

Only NB produced near-ties: 7,089 windows in 139 of its 480 cells.
- **Size: 6,336 windows.** SELECT and OPERATE have identical histograms, so every SBO window ties. Those BAs are the
  same under any tie order.
- **The other features: 753 windows,** almost all in pre-deployment cells.

## SELECT/OPERATE recomputation (joint, K=64, retrained NB; exploratory)

This is the share of SELECT/OPERATE windows labelled correctly; a READ prediction counts as wrong. The per-D
intervals resample that D's 8 blocks, and the pooled interval resamples within each D.

| Arm | D=5 | D=10 | D=15 | D=20 | Pooled [95% CI] | Binomial p (windows independent) |
|---|---|---|---|---|---|---|
| Off | 16/16 | 16/16 | 16/16 | 16/16 | 64/64 = 1.000 [1.000, 1.000] | 5.4e-20 |
| Timing | 10/16 | 9/16 | 5/16 | 11/16 | 35/64 = 0.547 [0.422, 0.656] | 0.27 |
| Size | 16/16 | 16/16 | 15/16 | 16/16 | 63/64 = 0.984 [0.953, 1.000] | 3.5e-18 |
| Timing+Size | 8/16 [0.250, 0.750] | 12/16 [0.562, 0.938] | 12/16 [0.562, 0.938] | 13/16 [0.625, 1.000] | 45/64 = 0.703 [0.609, 0.797] | 0.00078 |

v1 reported 45/64 with p = 0.0008, treating windows as independent. With clustering by block, the pooled interval
still excludes 0.5, so a residual SELECT/OPERATE difference remains under Timing+Size. Per D it is detectable at
D = 10, 15 and 20 ms, but not at D = 5 ms. With 8 blocks per D, these percentile intervals are coarse and probably
too narrow.

## Limits

- The data was examined before, and the ack and rt features were chosen post-hoc.
- Each cell has 8 test blocks. A percentile bootstrap over 8 clusters understates the uncertainty.
- An interval that reaches chance does not show the classes are indistinguishable.
- These are operation labels on one relay. Device fingerprinting has not been evaluated.

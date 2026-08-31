# WORKING_NOTES.md — final timing-paper repository

Last updated 2026-08-26 (end of the manuscript rewrite session).

## Task

Complete the timing-only IEEE manuscript in Dr. Lin's structure from the verified timing
evidence, on one branch, with every claim bounded by `defense4/timing/CLAIMS_AND_LIMITATIONS.md`.
The experiment is finished; no hardware, size, or push actions.

## Status — campaign_v1 corrections applied; branch not pushed

The scientific correction pass of 2026-08-31 is complete on
`paper/campaign-v1-ndss-corrections-20260828`, working from tip `5a49393`. Nothing is pushed.

- **Evidence.** All 22 `DATASET.sha256` manifests verify (268 entries). The regenerated canonical
  table is compared against the frozen `derived/transactions.csv` row by row on identity,
  ordering and all three intervals, tolerance 1e-6 ms. The 19-point hardware sweep is now part of
  the reproduction: 42 manifest entries verified, 5,860 transactions, 0 problems.
- **Corrections that changed a published number.** Read-lane coverage is 29 of 29,040 (99.900 %),
  replacing the pooled "30 of 31,680" that put request-anchored OPERATE in an ACK-anchored
  denominator. The sweep's `rt_med_ms` was a sum of two medians and is now the real median, with
  the published quantity retained as `sum_of_interval_medians_ms`. The sweep's `clrt_sd_ms` was
  published with the population convention, which is now recorded rather than silently changed.
- **Withdrawn.** The jackknife interval on the MI estimate (its interval excluded its own point
  estimate in *both* arms) and the bootstrap over the 22 dependent fold scores. MI is reported
  against a permutation null with an empirical p-value; classifier spread is descriptive.
- **Figures.** Four NDSS figures; the budget figure is rebuilt on the measured sweep and no
  longer pools the two anchors. Each ships PDF, 600-dpi PNG, data CSV, caption, method note,
  limitations note and a full provenance sidecar. Style gates fail the build, not warn.
- **Manuscript.** Contribution list is three verb-led items with no firstness claim; the DNP3
  framing/CRC explanation is corrected; the evaluation is reordered as an argument; OPERATE no
  longer claims codebook insensitivity. Build PASS, `lin_check --compare` shows no regression.
- **Authority.** `campaign_v1` is the single active authority; the retired `final_read_sbo`
  claims, figures and reports are labelled historical at the top of each file.
- **Verification.** `reproduce.sh` runs green end to end from a fresh output directory: 112
  tests pass and the publication gate reports 0 problems. NDSS preflight passes in draft mode and
  correctly fails `--submission` on the unassigned HotCRP paper number.

## Next action

Review the five commits, then decide whether to push. The HotCRP paper number in
`paper/rewrite/ndss/submission.tex` is still empty and must not be invented.

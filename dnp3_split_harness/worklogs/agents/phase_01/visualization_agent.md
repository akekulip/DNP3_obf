# Phase 01 — Visualization Agent worklog

**Role:** Phase 01 Visualization Agent (DNP3 trace-characterization study).
**Producing script:** `phase01_figures.py` (committed at repo root of `dnp3_split_harness/`).
**Run directory:** `runs/20260716T024101Z_phase_01_real_trace_characterization/`
**Source table:** `tables/ack_trace_characterization.csv` (22,988 rows total).
**git_commit at generation:** `c69e07e569183f2d21846c1c909aef28fdb2aa25`
**Generation command:** `python3 phase01_figures.py --run-dir runs/20260716T024101Z_phase_01_real_trace_characterization`
**Environment:** Python 3.8.10, matplotlib 3.7.5 (Agg backend), numpy 1.24.4, standard `csv` (no pandas).
**Outputs:** each figure written as PNG (200 dpi), PDF (vector), SVG (vector) plus a
`<figname>.metadata.json` sidecar — all in `<run-dir>/figures/`.

## Dataset facts (drive the n values and degeneracy notes)

- Analysis uses **device-specific rows only** (`is_reference == False`): **11,494** rows.
  - SEL751 = 4,298 · AB1400 = 2,398 · ION7550 = 4,798.
- Classification composition (device-specific):
  - **SEL751: 100% SEPARATE_ACK_RESPONSE** (4,298).
  - **AB1400: 100% COMBINED_ACK_RESPONSE** (2,398).
  - **ION7550: 4,797 COMBINED + 1 SEPARATE** (essentially all combined).
  - No `OTHER_OR_AMBIGUOUS` rows exist in this run (that class renders as 0%).
- Separate-ACK population (pure-ACK metrics populated): **4,299** rows =
  SEL751 (4,298) + ION7550 (**1** — degenerate single sample).
- TCP anomalies (device-specific): retransmission_count>0 = **93**, duplicate_ack_count>0 = **93**,
  out_of_order==True = **0**, reset==True = **4**, missing_response==True = **0**.

## Figures

| # | figname (basename) | n | Statistical transformation | Notes |
|---|--------------------|---|----------------------------|-------|
| 1 | `fig01_req_to_resp_cdf` | 11,494 | empirical CDF, 3 device lines on one axes | clean |
| 2 | `fig02_req_to_pure_ack_cdf` | 4,299 | empirical CDF, separate-ACK devices only | **ION7550 line degenerate (n=1)** — see below |
| 3 | `fig03_pure_ack_to_resp_cdf` | 4,299 | empirical CDF, separate-ACK devices only | **ION7550 line degenerate (n=1)** |
| 4 | `fig04_req_to_resp_violin` | 11,494 | violin (KDE), median marked, per device | clean; long upper tails (max ≈171 ms SEL751) compress the bodies |
| 5 | `fig05_ack_to_resp_violin` | 4,299 | violin (KDE) of `pure_ack_to_resp_ms`, separate-ACK only | **ION7550 (n=1) cannot form a violin → drawn as a single red diamond marker + in-title note**; SEL751 violin fine (n=4,298) |
| 6 | `fig06_req_to_resp_hist` | 11,494 | per-device histograms (shared 40 bins), median line | small-multiples, one panel per device |
| 7 | `fig07_request_size_dist` | 11,494 | normalized value distribution of `req_tcp_len` (grouped bars) | only 2 discrete request sizes observed (22 B / 35 B) |
| 8 | `fig08_response_size_dist` | 11,494 | normalized value distribution of `resp_tcp_len` (grouped bars) | discrete sizes {37,54,61} B |
| 9 | `fig09_ack_mode_fraction` | 11,494 | per-device class fractions (stacked bar, hatched) | SEL751=100% Separate, AB1400=100% Combined, ION7550≈100% Combined; ION7550's 1 Separate txn = 0.02% (segment too thin to see, not annotated) |
| 10 | `fig10_base_vs_L_cdf` | 11,494 | empirical CDF of `req_to_resp_ms`, base vs L per device | 3-panel small-multiple; every device has both base and L captures |
| 11 | `fig11_correlation_heatmap` | 11,494 | Pearson correlation, pairwise-complete deletion | **2 cells blank (NaN):** `packet_count`×`pure_ack_to_resp_ms` — within the 4,299 separate-ACK rows `packet_count` is constant (=3), so correlation is undefined. `pure_ack_to_resp_ms` pairs use n≥4,299 (SEPARATE rows only). |
| 12 | `fig12_combined_ack_timeline` | 1 | single-transaction event timeline | representative COMBINED txn (median `req_to_resp_ms`): ION7550, req 22 B → piggybacked ACK+response 61 B at 16.04 ms |
| 13 | `fig13_separate_ack_timeline` | 1 | single-transaction event timeline | representative SEPARATE txn (median `req_to_resp_ms`): SEL751, req 22 B → pure ACK at 4.45 ms → response 54 B at 16.13 ms |
| 14 | `fig14_tcp_anomaly_summary` | 11,494 | per-anomaly transaction counts (bar) | **Out-of-order = 0 and Missing response = 0** (bars present but zero, labeled); Retransmission=93, Duplicate ACK=93, Reset=4 |
| 15 | `fig15_timing_vs_respsize_scatter` | 11,494 | scatter `req_to_resp_ms` vs `resp_tcp_len`, colored/marked by device | deterministic x-jitter (±0.35 B, seed 0) applied because response sizes are discrete |

### Filters recorded in each sidecar
- Figs 1,4,6,7,8,9,10,11,14,15: `is_reference==False` (fig 10 additionally split base vs L; fig 11 pairwise-complete).
- Figs 2,3,5: `is_reference==False; SEPARATE_ACK_RESPONSE only (non-blank metric)`.
- Fig 12: `COMBINED_ACK_RESPONSE; representative (median req_to_resp_ms)`.
- Fig 13: `SEPARATE_ACK_RESPONSE; representative (median req_to_resp_ms)`.

## Degenerate / caveated figures (not silently skipped)

1. **fig02 / fig03 (separate-ACK CDFs):** ION7550 contributes exactly **1** separate-ACK
   transaction. Its "line" is a single point (req_to_pure_ack ≈ 43.3 ms, pure_ack_to_resp ≈ 28.8 ms)
   and carries no distributional meaning. SEL751 (n=4,298) is the meaningful curve. Both are drawn;
   the ION7550 legend entry states n=1.
2. **fig05 (ACK-to-response violin, separate-ACK):** ION7550 (n=1, zero variance) cannot be a
   violin — matplotlib's KDE would be singular. It is rendered as a single red diamond marker and
   the title carries the explicit note. SEL751 violin (n=4,298) is valid.
3. **fig09 (ACK-mode fraction):** each device is ~degenerate in composition (one dominant class per
   device). This is the real finding (device-specific ACK behavior), not a plotting artifact.
   ION7550's lone Separate transaction (0.02%) is present but visually invisible.
4. **fig11 (correlation heatmap):** `packet_count`×`pure_ack_to_resp_ms` correlation is undefined
   (blank) because `packet_count` has zero variance on the separate-ACK subset where
   `pure_ack_to_resp_ms` is defined. Left blank rather than fabricated. Also note the near-perfect
   `packet_count`↔`transaction_ip_bytes` (r=1.00) and `req_to_resp_ms`↔`pure_ack_to_resp_ms` (r=0.99)
   are genuine structural couplings in the data.
5. **fig14 (TCP anomalies):** Out-of-order and Missing-response bars are exactly **0** in this run —
   drawn and labeled as zero rather than omitted.
6. **Discrete-value distributions (fig07/fig08/fig15):** request and response TCP lengths take only
   a handful of discrete byte values; histograms/scatter reflect that (jitter added to the scatter).

## Verification
- Script runs clean end-to-end (exit 0); it self-checks that figures/ contains exactly 15 PNG,
  15 PDF, 15 SVG, and 15 sidecars before returning success.
- Confirmed on disk: **45 image files + 15 metadata sidecars = 60 files** in
  `runs/20260716T024101Z_phase_01_real_trace_characterization/figures/`.
- Spot-checked rendered PNGs for figs 2, 4, 5, 9, 11, 12, 13, 14 (including all degenerate cases).
- No other `.py`, timing/ACK/split code, or run tables/manifest were modified.

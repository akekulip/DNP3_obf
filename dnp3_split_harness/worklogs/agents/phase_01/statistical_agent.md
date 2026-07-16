# Phase 01 — Statistical Analysis Agent Worklog

Run: `runs/20260716T024101Z_phase_01_real_trace_characterization/`
Source of truth for recomputation: `tables/ack_trace_characterization.csv` (22,988 data rows).
Verifier stack: Python 3.8.10, numpy 1.24.4, scipy 1.10.1, pandas 2.0.3 (scipy used only as an
independent cross-check for KS / Wasserstein; the pipeline itself is numpy-only).

**Verdict: all recomputed statistics match `device_summary.csv` and `capture_comparison.csv`
within rounding. No incorrect statistic found. Degenerate cells are present but correctly
handled (not over-interpreted).**

## Population / grouping confirmed
- Each capture in the raw CSV carries a 50/50 `is_reference` split (device-specific vs a shared
  reference outstation `10.0.0.2` that appears in every capture). The summary pipeline excludes
  `is_reference == True`. Non-reference counts reproduce the summary `n` exactly:
  SEL751 base=299 / L=3999, AB1400 base=399 / L=1999, ION7550 base=799 / L=3999.
- `capture_kind`: `*L.pcap` -> `L`, else `base`. Confirmed against `phase01_characterize.py:47`.
- Reference exclusion documented in `reports/data_quality_report.md` (shared outstation 10.0.0.2,
  11,494 reference txns). This is why raw rows = 2x summary n.

## 1. Descriptive spot checks (recomputed from raw column vs device_summary.csv)

| cell | stat | recomputed | reported | match |
|---|---|---|---|---|
| SEL751 / base / req_to_resp_ms | n | 299 | 299 | OK |
| SEL751 / base / req_to_resp_ms | mean | 18.572227 | 18.572227 | OK |
| SEL751 / base / req_to_resp_ms | median | 16.98494 | 16.98494 | OK |
| SEL751 / base / req_to_resp_ms | std | 11.551085 | 11.551085 | OK |
| SEL751 / base / req_to_resp_ms | p95 | 21.54541 | 21.54541 | OK |
| AB1400 / L / req_to_first_rev_ms | n | 1999 | 1999 | OK |
| AB1400 / L / req_to_first_rev_ms | mean | 16.272381 | 16.272381 | OK |
| AB1400 / L / req_to_first_rev_ms | median | 16.247034 | 16.247034 | OK |
| AB1400 / L / req_to_first_rev_ms | std | 1.097127 | 1.097127 | OK |
| AB1400 / L / req_to_first_rev_ms | p95 | 17.344594 | 17.344594 | OK |
| ION7550 / base / transaction_ip_bytes | n | 799 | 799 | OK |
| ION7550 / base / transaction_ip_bytes | mean | 185.493116 | 185.493116 | OK |
| ION7550 / base / transaction_ip_bytes | median | 180.0 | 180.0 | OK |
| ION7550 / base / transaction_ip_bytes | std | 5.499996 | 5.499996 | OK |
| ION7550 / base / transaction_ip_bytes | p95 | 191.0 | 191.0 | OK |

Percentile convention (numpy linear interpolation), std ddof=0, and round-to-6 all reproduce.

## 2. Bootstrap CIs — containment + determinism

Re-ran `phase01_stats.bootstrap_ci(..., seed=12345, n_boot=2000)` on the raw column values.

| cell | n | point | reported mean CI | lo<=point<=hi | re-run == CSV | deterministic (2 runs) |
|---|---|---|---|---|---|---|
| SEL751/base/req_to_resp_ms | 299 | 18.572227 | [17.453167, 20.028548] | yes | yes | yes |
| AB1400/L/req_to_first_rev_ms | 1999 | 16.272381 | [16.229745, 16.322868] | yes | yes | yes |
| ION7550/base/transaction_ip_bytes | 799 | 185.493116 | [185.107635, 185.892365] | yes | yes | yes |
| SEL751/base/pure_ack_to_resp_ms | 299 | 14.56385 | [13.444625, 15.980052] | yes | yes | yes |

Seeded `np.random.default_rng(12345)` gives byte-identical intervals across re-runs; CIs bracket
the point estimate and are plausibly tight for the n (widest is SEL751 base req_to_resp_ms, whose
heavy right tail / std=11.55 justifies the ~+/-1.3 ms half-width at n=299).

## 3. SEL-751 base-vs-L KS / Wasserstein / effect-size cross-check

Recomputed with my own numpy (via `phase01_stats`) AND scipy independently:

| metric | quantity | reported | scipy | phase01_stats |
|---|---|---|---|---|
| req_to_resp_ms | KS | 0.236445 | 0.236445 | 0.236445 |
| req_to_resp_ms | W1 | 1.280254 | 1.280254 | 1.280254 |
| req_to_resp_ms | Cliff's delta | 0.217671 | — | 0.217671 |
| req_to_resp_ms | Cohen's d | 0.186558 | — | 0.186558 |
| pure_ack_to_resp_ms | KS | 0.217883 | 0.217883 | 0.217883 |
| pure_ack_to_resp_ms | W1 | 1.241002 | 1.241002 | 1.241002 |
| pure_ack_to_resp_ms | Cliff's delta | 0.205399 | — | 0.205399 |
| pure_ack_to_resp_ms | Cohen's d | 0.178020 | — | 0.178020 |

Not just "same ballpark" — exact to 6 dp against scipy `ks_2samp` and `wasserstein_distance`.
Effect-size signs are sane: median(base) > median(L) for both metrics (16.985 > 16.104;
12.898 > 12.178), so positive Cliff's delta / Cohen's d (base slightly slower) is the correct
direction. Magnitudes are "small" (Cohen's d ~0.18-0.19, Cliff's delta ~0.21) — consistent with
the modest median gap; no exaggeration.

## 4. Separate-only metrics computed over SEPARATE transactions only

`req_to_pure_ack_ms` and `pure_ack_to_resp_ms` are `None`/blank on COMBINED rows; `_clean()` drops
them, so n naturally equals the separate count (no explicit filter, but result is equivalent).
For every (device, capture) the reported n equals the SEPARATE_ACK_RESPONSE count and equals the
non-null count — COMBINED rows do not dilute:

| device/capture | separate | combined | reported n | match |
|---|---|---|---|---|
| SEL751 base | 299 | 0 | 299 | OK |
| SEL751 L | 3999 | 0 | 3999 | OK |
| AB1400 base | 0 | 399 | 0 | OK |
| AB1400 L | 0 | 1999 | 0 | OK |
| ION7550 base | 0 | 799 | 0 | OK |
| ION7550 L | 1 | 3998 | 1 | OK |

## 5. Degenerate / small-n statistics — present but correctly handled

- **ION7550 L, separate metrics (n=1):** `req_to_pure_ack_ms` = 43.304 ms, `pure_ack_to_resp_ms`
  = 28.754 ms come from a SINGLE separate transaction (0.02% of L). `device_summary` collapses the
  bootstrap CI to the point (lo=hi=value) via the `arr.size==1` branch — honest, not a fabricated
  interval. `capture_comparison.csv` / `statistical_comparison.md` correctly print `n/a` for KS,
  W1, Cliff's delta, Cohen's d on these cells (n_a=0). NOT over-interpreted anywhere; the observed
  profile records `separate: 1, separate_pct: 0.0208` faithfully.
- **AB1400 separate metrics (n=0, 100% combined):** all `n/a`. Correct.
- **packet_count std=0 cells** (AB1400 base/L, ION7550 base, SEL751 base/L): genuinely constant
  columns (all rows identical), so std=0 / cv=0 / KS=0 / W1=0 is exact, not spurious.
- **CV on near-zero mean:** no risk — smallest metric mean is ~3.9 ms (SEL751 req_to_first_rev),
  well away from zero; no CV is inflated by a tiny denominator.

### Consistency note (checked, not a defect)
`device_summary` reports ION7550 **L** packet_count std = 0.015811 (mean 2.00025) — one 3-packet
outlier among 3998 two-packet rows — which is fully consistent with the comparison table's
KS=0.00025 (=1/3999) and Cohen's d=-0.017 for that cell. Only the truly-constant packet_count
cells show std=0. No internal inconsistency between the two tables.

## Bottom line
- Recomputed descriptives: MATCH (exact to 6 dp).
- Bootstrap CIs: contain the point, deterministic under seed=12345, reproduce the CSV.
- SEL-751 base-vs-L KS/W1: exact vs scipy; effect sizes correct sign and modest magnitude.
- Separate-only n: verified over separate transactions only.
- Degenerate cells (n=1 ION7550 separate; constant packet_count) are handled honestly and not
  over-interpreted; the report footnote already disclaims temporal stability and avoids
  p-value-only claims.

# TEMPORAL_DEPENDENCE_ANALYSIS.md — serial dependence & bootstrap validity (Tasks 2–3)

Working from committed `per_poll.csv` (read-only). Script: `temporal_analysis.py`. Ljung–Box computed
manually via the χ² distribution (statsmodels not installed). Autocorrelations in
`autocorr_{request_to_pure_ACK,ACK_to_response_CLRT,request_to_response}.csv`; plots in `plots/`.

## Autocorrelation (lags 1–10) and Ljung–Box (95% band = ±1.96/√300 = ±0.113)
| series | ACF lag1 | lags outside band | Ljung–Box h=10 (Q, p) | Ljung–Box h=5 (p) |
|---|---|---|---|---|
| request→pure-ACK | −0.032 | {3, 7} | Q=49.1, **p=4.0e-7** | p=0.018 |
| **ACK→response (CLRT)** | **0.351** | **{1,2,3,4,5,6,7,8,9,10}** | Q=199.3, **p≈0** | **p≈0** |
| request→response | 0.290 | {1,2,3,4,5,7,8,10} | Q=153.6, **p≈0** | p≈8e-16 |

**The CLRT series is strongly, persistently positively autocorrelated** — lag-1 ACF 0.35 and *every*
lag 1–10 exceeds the 95% band; Ljung–Box overwhelmingly rejects independence. request→response is
similar. request→pure-ACK shows weaker but still significant dependence.

## Linear trend vs poll number
No meaningful drift in any series: slopes ~1e-4–6e-4 ms/poll, **all p ≥ 0.69, r² ≈ 0.0005**. The
dependence is **short-range serial correlation / clustering, not a trend** over the run.

## Segment summaries (first 50 / middle 200 / final 50), CLRT ms
| segment | median | p95 |
|---|---|---|
| first 50 | 2.723 | 10.301 |
| middle 200 | 1.824 | 6.641 |
| final 50 | 2.152 | 7.523 |
The central location is broadly stable; the **first 50 polls have a noticeably heavier tail** (p95 10.3
vs ~6.6–7.5 ms). Rolling median/p95 (window 25, `plots/clrt_rolling.png`) confirm a stable median with a
mildly elevated early-run p95.

## Clustered high-latency observations
Above the p90 threshold (CLRT 5.99 ms), the 30 high observations fall into **7 maximal clusters**
(≥2 consecutive), i.e. slow responses arrive in short bursts rather than uniformly — the mechanism
behind the positive autocorrelation. (Per-series cluster lists are in `temporal_results.json`.)

## Bootstrap validity (Task 3)
- **The committed bootstrap is an IID bootstrap** — `analyze_clrt.py` resamples individual observations
  with replacement (`RNG.integers(0, n, size=(B, n))`), which **assumes independence**.
- Because the CLRT is autocorrelated, the IID bootstrap **understates** interval width (correlated data
  carry less information than the same number of independent draws). It is **not** acceptable as the sole
  interval here.
- **Moving-block bootstrap (MBB)** added (overlapping blocks, wrap-around, 10 000 resamples, seed
  20260723). Point estimates are unchanged (median 1.899, mean 2.983 ms); only the intervals widen:

| CLRT statistic | IID CI95 | MBB L=7 | MBB L=15 | MBB L=30 |
|---|---|---|---|---|
| mean | [2.732, 3.251] | **[2.593, 3.402]** | [2.473, 3.552] | [2.360, 3.647] |
| median | [1.825, 1.926] | **[1.791, 2.056]** | [1.782, 2.187] | [1.779, 2.294] |

The MBB interval **widens monotonically with block length** (as expected under persistent dependence);
the median interval roughly **doubles-to-triples** vs IID.

## Selected primary interval
**Primary = moving-block bootstrap, block length L = round(n^{1/3}) = 7** (a standard rule), reported
alongside the L=15 and L=30 sensitivity. Rationale: the CLRT is significantly autocorrelated, so a
block bootstrap that preserves short-range dependence gives an honest interval; the IID interval is
retained and shown for transparency but is anti-conservative. Because the ACF remains significant out to
lag 10, even L=7 may modestly *under*-cover — the true CLRT-mean 95% interval is **at least** the MBB-L7
width `[2.59, 3.40] ms` and plausibly as wide as the L=30 `[2.36, 3.65] ms`.

## Bottom line
Latency samples **do show temporal dependence** (strong for CLRT and request→response, weaker but
present for request→pure-ACK). The **IID bootstrap intervals in the original report are not valid as
stated**; the moving-block intervals above supersede them for uncertainty statements. Point estimates
(medians/means/percentiles) are unaffected.

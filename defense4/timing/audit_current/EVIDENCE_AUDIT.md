# Evidence audit — timing study, current state (2026-09-02)

What was reproduced, what the numbers are, and what the readback failure means. Grounded only in
files present in this checkout on 2026-09-02. Nothing here edits frozen evidence.

## 1. Frozen `final_read_sbo` reproduces

`defense4/timing/reproduce.sh` rebuilt every derived CSV, statistic, and the five historical
figures from the six raw captures into a scratch tree and compared them against the frozen CSVs.

Result: **every measured value reproduces within one last printed digit** (0.001 ms).

| CSV | rows | last-digit diffs | max |Δ| |
|---|---|---|---|
| native_txn | 1489 | 124 | 0.001 ms |
| defended_read_txn | 600 | 42 | 0.001 ms |
| defended_txn | 500 | 40 | 0.001 ms |
| sbo_j2 / j6 / j12 | 30 each | 5 / 6 / 6 | 0.001 ms |

The last-digit diffs are rounding in the final printed place, not value disagreement.

Frozen headline values (`audit/verdict_stats.json`), all confirmed:

* MI(class; CLRT), common bins: native `0.42436`, defended `0.00184` bits.
* balanced accuracy: native `0.5921`, defended `0.5000` (chance 0.5).
* medians: native READ `1.272`, native SELECT `2.107`, defended READ/SELECT `4.001` ms.

## 2. The "24 ms at 99.9%" statement is not supported by either dataset

The deadline-coverage function `C(h) = |{X ≤ h}| / n` was computed directly from raw-derived
CSVs (spec §4).

**Retained `final_read_sbo` read-lane** (n = 1487; the two cold-start rows, 23.531 and 45.794 ms,
carry `cold=1` and are excluded):

| h | coverage | over |
|---|---|---|
| 12 ms | 99.126% | 13 |
| 18 ms | 99.933% | 1 |
| 20 ms | 100.000% | 0 |
| 24 ms | 100.000% | 0 |

max = 18.178 ms, p99 = 11.098 ms, p99.9 = 14.800 ms.

**`campaign_v1` native read-lane** (n = 29,040):

| h | coverage |
|---|---|
| 12 ms | 98.185% |
| 18 ms | 99.714% |
| 20 ms | 99.738% |
| 24 ms | 99.900% |

Neither dataset yields "24 ms at 99.9%". In `final_read_sbo`, 24 ms is 100% of the retained
sample and 12 ms is 99.126% (not 99.9%). In `campaign_v1`, 24 ms is 99.900%. The correct
description of 24 ms is: **a conservative configured response-release horizon that covers the
retained sample; it is not the protected CLRT, not a measured physical operation time, and not a
population-level 99.9% guarantee.**

## 3. Shift versus replacement — the read lane replaces, it does not translate

Computed on `campaign_v1` by `repro/replacement_stats.py` (session-level bootstrap, seed
20260902, Brown-Forsythe for skew-robust spread). A pure shift `X' = X + c` preserves variance;
replacement removes the native `X` term and collapses the spread to scheduling jitter.

| read lane | native SD | protected SD | variance ratio (prot/nat) | 95% CI (session bootstrap) | IQR ratio | MAD ratio | Brown-Forsythe p |
|---|---|---|---|---|---|---|---|
| READ | 2.609 ms | 0.628 ms | 0.0579 | [0.019, 0.101] | 0.0021 | 0.0031 | < 1e-300 |
| SELECT | 2.267 ms | 0.024 ms | 0.000114 | [1.4e-5, 3.4e-4] | 0.0022 | 0.0028 | 1.9e-301 |

The counterfactual is the proof. A native distribution shifted so its median lands on the
protected median keeps the native SD **exactly** (2.609 and 2.267 ms). The protected SD is 1–4
orders of magnitude smaller. A shift cannot produce that collapse; a common-anchor replacement
can. Combined with the recovered implementation equations (§QUEUE_AND_ANCHOR_AUDIT), this is the
evidence that the master-visible post-ACK interval is replaced, not translated.

Bounded conclusion: *the implementation replaced the master-visible post-ACK interval with a
configured ≈4 ms interval for transactions whose native response arrived before the configured
release horizon.* Physical operation time was not measured and is not replaced by this evidence.

## 4. True latency cost is not the CLRT change

The CLRT median moves from ≈2 ms to 4 ms, but that is not the end-to-end cost. The true
master-facing overheads (protected minus native, per interval) are in
`repro/stats.json:added_response_latency_ms`: request-to-response rises by ≈21–23 ms per class,
because the read path holds the acknowledgment ≈20 ms (`D_A`) before releasing the response 4 ms
later. The manuscript reports the ≈21–23 ms overhead, not the 2 ms CLRT delta, as the cost.

## 5. The frozen readback FAIL is explained; provenance stays PARTIAL

`evidence/final_read_sbo/readbacks/hw_config_readback.txt` ends `RESULT: FAIL (n_fail=1 n_warn=0)`
while all four visible assertion lines are `[ok]`. Verified findings:

* The file is 26 lines: 4 `[ok]` assertions plus a later register readback, then the `RESULT:`
  line. It lacks the `==== configure-all readback ====` header every genuine transcript carries.
* The checker (`Checks.render()` in `defense4_rrc_bor_unified12_setup.py`) prints every held row,
  including any `[FAIL]` row. A run with `n_fail=1` must have held a failing row, but no `[FAIL]`
  row appears in this file.
* No archived transcript in the repository records a run with `n_fail=1`; every genuine
  configure-all transcript reports `n_fail=0`.

Conclusion: the file is a hand-assembled excerpt combining a configure-all readback with a later
register readback, and its `RESULT:` line does not belong to the rows above it. **The failed
assertion was not captured into any surviving file and cannot be identified.** Frozen
configuration provenance is therefore **PARTIAL**: the timing-relevant parameters (A, R, the J
codebook, TCP-timestamp policy, tick quantization) appear as passing rows matched to a
zero-failure configure-all run, and `shape_enable=0` is established from the wire (single 49-byte
payloads; identical 1,448-frame / 130,708-byte captures in both arms), but the unidentified
failure is not explained away. The frozen file was not edited.

## 6. Manifests

All 22 `campaign_v1` `DATASET.sha256` manifests verify (268 entries); the 42-entry sweep manifest
verifies; the regenerated canonical table agrees with the frozen table row by row (63,360 rows,
tolerance 1e-6 ms). `final_read_sbo/MANIFEST.sha256` verifies against its raw captures.

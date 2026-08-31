> **Historical.** A dated record of work that preceded the campaign_v1 correction of
> 2026-08-28. Where it names evidence, figures or claims as current, read it as describing
> the `final_read_sbo` state of that date. The active evidence authority is
> `defense4/timing/evidence/campaign_v1/`, the active claim authority is
> `defense4/timing/CLAIMS_AND_LIMITATIONS.md`, and the active figures are
> `paper/rewrite/figures/ndss/`. Kept for provenance.

# Reproduction and test report — 2026-08-26

Run in the single checkout `/home/philip/Projects/DNP3` on branch
`paper/final-timing-rewrite-20260826`, before any manuscript prose was written and again after
the figure relabel. Raw captures were never written to; every output went to a scratch directory
or to `build/` first and was compared with the frozen data before anything was copied.

## Environments

| interpreter | numpy | scipy | scikit-learn | matplotlib | used for |
|---|---|---|---|---|---|
| Python 3.8.10 (`/usr/bin/python3`) | 1.24.4 | 1.10.1 | 1.3.2 | 3.7.5 | tests; the committed figures (`TIMING_PYTHON=/usr/bin/python3 ./reproduce.sh`) |
| Python 3.12.13 (`~/.local/bin/python3.12`) | as installed | | | | tests |
| Python 3.13.12 (`uv run`, `.venv` pinned by `pyproject.toml`) | 2.5.2 | 1.18.1 | 1.9.0 | 3.11.1 | full `reproduce.sh` into a scratch directory |

No path outside the repository is used; `~/.venvs/research` is not on the reproduction path.

## Evidence integrity

`evidence/final_read_sbo/MANIFEST.sha256`: 24 of 24 files OK before and after every run (the two
`CAPTURE_MANIFEST` entries were regenerated and re-hashed once, for the D_A/D_R correction; the
six raw captures and the derived CSVs are unchanged). Exact experiment source
`implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` hashes to
`7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861`, the recorded value. The
loaded-binary hash `33fa3a77…` is a recorded value; no binary is kept, so it cannot be re-derived
(PARTIAL, as before). All four 2026-08-24 bundles and the new 2026-08-26 bundle verify as
"complete history".

## Tests

`tests/test_timing.py`: `RESULT: PASS (102 checks, 0 failed)` under Python 3.8.10 and under
Python 3.12.13. Coverage: request/ACK/response pairing; TCP direction and endpoints; DNP3
function-code validation (READ 1, SELECT 3, OPERATE 4); monotonic timestamps; positive CLRT;
cold-start exclusion; missing-ACK and missing-response handling; duplicate prevention;
deterministic sample counts; no silent clipping; no hard-coded measured results in the plotting
code (AST check).

## Reproduction from the raw captures

`./reproduce.sh` regenerated the transaction CSVs, the SBO CSVs, `timing_stats.json` and the five
figures. Comparison with the frozen CSVs (`analysis/compare_frozen.py`): every value agrees within
0.001 ms (one unit in the last printed digit) over 1489 + 600 + 500 rows and 30 + 30 + 30 OPERATE
rows; schema and row counts identical.

| condition | class | n | median | std | max | > 12 ms |
|---|---|---|---|---|---|---|
| Timing OFF | READ | 999 | 1.272 ms | 1.354 ms | 12.275 ms | 2 |
| Timing OFF | SELECT | 488 | 2.107 ms | 2.530 ms | 18.178 ms | 11 |
| Obfuscated | READ | 599 | 4.001 ms | 0.022 ms | 4.098 ms | 0 |
| Obfuscated | SELECT | 499 | 4.001 ms | 0.021 ms | 4.124 ms | 0 |

Mutual information I(class; CLRT): 0.424356 bits (null 0.0155–0.0330) → 0.002085 bits (null
0.0000–0.0033). Classifier balanced accuracy 0.5921 → 0.5000. OPERATE echo − ACK medians 4.001 /
4.002 / 4.003 ms at J = 2 / 6 / 12 ms, n = 30 each; A ≈ 21.03 ms, R ≈ 25.03 ms master-visible.
Every value in the brief's expected-results table is met; the two "verify from data" maxima are
4.098 ms and 4.124 ms. The frozen `verdict_stats.json` value 0.001837 bits for the Obfuscated MI
differs from the regenerated 0.002085 bits for the documented bin-edge reason
(`EVIDENCE_AUDIT.md` §11); the conclusion (inside the permutation null) is unchanged, and the
paper quotes it as "below 0.003 bits".

## Figures

Regenerated with the legend label `Obfuscated` under Python 3.8.10 / matplotlib 3.7.5. The
figure data CSVs are byte-identical to the previous ones except for the arm key in
`fig05_timing_leakage_summary_data.csv` (`timing_on` → `obfuscated`); the plotted numbers are
unchanged. Publication copies and manuscript copies are byte-identical; hashes in
`paper/rewrite/FIGURE_PROVENANCE.md` and `FINAL_FIGURES.md`.

# 2026-09-29 analysis audit slice

Scope: offline verification only. No paper, immutable evidence, result tree, or hardware files were edited.

## C3 replacement values

- Fixed-budget D_R values: `[2.0, 4.0, 8.0, 12.0, 16.0, 20.0, 24.0, 26.0]`.
- Correct READ CLRT medians from MANUSCRIPT_VALUES: `[1.9995, 4.0, 8.0055, 12.0005, 16.001, 20.0, 24.002, 26.001]` ms.
- Correct request-to-response medians: `[28.106, 28.106, 28.107, 28.108, 28.108, 28.108, 28.106, 28.108]` ms.
- The broad 'within 6 us' statement is only safe for the READ fixed-budget series. SELECT at configured 8 ms is 8.012 ms in `sweep_timing.json`.

## Grid audit

- Status: `passed`.
- Checked `240000` exchanges, `10813` raw input hashes, `720` model artifacts, `1008` scored attacks, and `6300000` prediction signatures.
- Training rounds: `0-39`; held-out rounds: `40-99`.
- Scope limit: the audit verifies retained hashes and prediction ledgers; it does not refit models or prove pickle serialization is independently recoverable beyond hash identity.

## Findings

- `C3-stale-values` (ledger-corrected): Keep paper/manuscript frozen; the engineering ledger now has the corrected values.
- `J-not-observed` (supported-limitation): Do not say per-transaction J or codebook entries were readback-verified in campaign_v2.
- `byte-equality-scope` (supported-limitation): State captured volume equality unless payload bytes are separately hashed/compared.
- `grid-model-artifacts` (verified-with-scope): Describe grid audit as retained-artifact and prediction-ledger verification, not independent model retraining.

## Quick paper-only probes

- Abstract still contains the device-identification wording, while campaign v2 supports transaction-class classification on one device.
- Headline chance wording is present; the fixed attack reaches chance balanced accuracy, but the degenerate confusion should stay qualified.
- Abstract and conclusion do not contain the term master-facing; the introduction contains it elsewhere, but the latency bullet should still be checked before any paper edit.

## Provenance notes

- Campaign counts and frozen table comparison come from `defense4/timing/evidence/campaign_v2/repro/audit_20260925/validation_report.json`.
- Sweep before/after values come from `defense4/timing/evidence/campaign_v2/repro/audit_20260925/result_comparison.json`.
- The independent grid audit result is `defense4/timing/audit_current/verification_20260929/analysis/grid_audit/audit_grid_result.json`.
- The structured findings are `defense4/timing/audit_current/verification_20260929/analysis/campaign_and_grid_findings.json`.

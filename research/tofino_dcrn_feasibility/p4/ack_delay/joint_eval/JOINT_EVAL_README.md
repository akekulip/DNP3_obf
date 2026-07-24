# Joint size+timing evaluation tooling (Phase 7)

Analysis skeleton for the joint evaluation. The evaluation **methodology** is fully specified in the repo
(`ACK_DELAY_EXPERIMENT_PLAN.md`, `research_design.md`); the joint **defense** it must score does not exist
yet (single-program infeasible → platform split, and Phase-5 mechanism undecided). This directory provides
the reproducible scoring code + schema so that, once defended hardware runs exist, they can be scored
without new tooling — and it is verified now on synthetic fixtures so the scoring is trustworthy.

## Contents
- `leakage_metrics.py` — MI (bits), grouped balanced accuracy vs chance, bootstrap CI, within-chance test.
  numpy only (no sklearn in the research venv).
- `eval_schema.json` — the 6 evaluation configurations (baseline / txncore / defense1 / defense2 / size /
  combined), feature families, metrics, and the honesty scoring rules (grouped CV, joint two-number split,
  chance baseline, no-mode-hiding, no-manufactured-results).
- `tests/test_leakage_metrics.py` — synthetic leaky-vs-normalized fixtures proving the metrics behave:
  **3/3 PASS** (leaky → MI>1 bit, accuracy≫chance, chance NOT in CI; normalized → MI≈0, accuracy≈chance,
  chance IN CI).

## Status (honest)
- Analysis code: **offline-verified on synthetic fixtures.** No real defended hardware runs exist yet
  (dp8 blocked → no silicon defense evaluation). Nothing here is a hardware result.
- To run on real data: build per-run feature tables `(feature, label, group)` from captured evidence,
  one row per transaction, `group` = independent session/run; call `mutual_information` and
  `balanced_accuracy_grouped`; compare the accuracy CI to `1/k`. The schema fixes the configs/metrics.

## What this does NOT do
- It does not manufacture or assume any hardware/defended result.
- It does not build the joint defense (Phase-5 mechanism + platform split are human-gated).
- It does not decide the CLRT ground truth (C1) or the G_i set (C2) — those feed the feature values.

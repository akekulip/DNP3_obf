# History map

What in this repository is historical, where it is, and how to get it back if it moves. Written
2026-10-23 at HEAD `4a0b0fc56`. "Historical" means no current claim, build or run depends on it; it does
not mean it may be deleted. Raw evidence is never removed.

`STAGE` = `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments`.

## Historical areas that stay where they are

| path | what it is | why it stays in place |
|---|---|---|
| `defense4/timing/evidence/campaign_v2/` | timing-only campaign (22 grouped runs, 132 captures, 63,360 exchanges, size carve off) on the request-anchored build; the earlier timing-only paper's evidence | still reproducible through `defense4/timing/reproduce.sh`; `campaign_v2/repro/leakage_campaign.py` is imported by active code; the campaign_v2 figure families in `paper/rewrite/figures/{ndss,clrt,tail,model}` are generated from it |
| `defense4/timing/evidence/campaign_v1/` | the acknowledgment-anchored build's campaign, which `campaign_v2` corrects | `--historical` path of `reproduce.sh`; never-modify raw captures |
| `defense4/timing/evidence/final_read_sbo/`, `tail_sweep_20260918/` | earlier READ/SBO record; the 2026-09-18 tail sweep of the acknowledgment-anchored build | never-modify raw captures; cited by `CLAIMS_AND_LIMITATIONS.md` |
| `defense4/timing/implementation/` | the exact P4 and harness that ran for campaign_v1/v2 | never modify (CLAUDE.md) |
| `defense4/timing/anchor_fix/` | request-anchoring fix and before/after (`FINDINGS.md`) | cited by the manuscript and the claim documents |
| `defense4/timing/audit_current/` | audits of 2026-09-15 to 2026-10-05: duplicates, OPERATE retransmission, epsilon, master RTO, the 2026-09-29 verification ledger, framework_20261005 | cited by `CLAUDE.md` claim boundaries; its `tools/` generate the CLRT and model figures |
| `defense4/timing/latency_search/` | matched 5/10/15/20 ms delay grid (2026-09-26/27) and attacker analyses; 21,192 tracked files incl. 1,195 `*.pid` runtime files in `evidence/` | evidence; code references `active_harness` |
| `defense4/timing/stage_reduction/` | seven-ingress-stage timing-only candidate and its 2026-09-25 smoke test | evidence; `hardware/20260925/run_block.py` references `active_harness` |
| `defense4/timing/response_ready/` | READ response-ready candidate (never deployed) | evidence-heavy (424 of 449 files) |
| `defense4/timing/framework/` except `size/` | 2026-10-06 framework track: contract, BMv2 model, results | `framework/run_tests.sh` and `framework/control/*` import `active_control`, `active_harness`, `active_probe`; `framework/size` is active |
| `defense4/timing/active_{harness,control,probe}/`, `defense4/timing/tests/` | campaign-era harness, admission control, RTO probe, timing tests | referenced by framework, latency_search and stage_reduction code; moving them breaks `sys.path` resolution |
| `relay_rto_20260915/` | relay RTO capture of 2026-09-15 | referenced by `paper/rewrite/figures/clrt/*.provenance.json` and `audit_current/tools/clrt_distribution_and_variance.py` |
| `STAGE/{dup_hold_01, n_crc_residue, t_sealed_lifetime, combined_nt_diag_01, retx_passthrough_01}` | earlier stage experiments | the active candidate's P4 lineage: `seg61_02/generate.py`, `combined_nt_01/generate.py`, `hw/sealed_profile.py` and every `read_complete_01/hw/config/rc01_m12p_*.json` pin files inside them |
| `STAGE/{realrelay_01, realrelay_native_01, seg61_e_crc_01, t_outcome_elide, t_split_outcomes_01, e_window_fold_classify}` | earlier stage experiments | each is named by an evidence record or a sibling's code (table below), and each resolves siblings or its parent through `HERE.parent` / `HERE.parents[1]`, so a move breaks its own generator |

## Proposed moves

Scheme: one root directory `history/` that mirrors the original path. A single root keeps the `.ignore`
rule to one line and makes restoration a prefix strip. A `STAGE/_history/` scheme was rejected because
it would need a second rule for root-level items and would still change every moved item's depth.

The script was `.scratch_repo/moves.sh`; it re-ran the reference check and was executed on 2026-10-23 for the three items marked yes (now under `history/`).

| item | references found | moves.sh |
|---|---|---|
| `STAGE/next_stage_analysis_01/` | none | yes |
| `STAGE/e_stage_review.md` | none | yes |
| `tools/history_rewrite/` | none | yes |
| `STAGE/e_window_fold_classify/` | `next_stage_analysis_01/{REPORT.md, evidence/placement_extract.json}`; generator reads `HERE.parents[1]/evidence/incremental_55` | no |
| `STAGE/t_split_outcomes_01/` | `next_stage_analysis_01` (2 files); generator reads sibling `combined_nt_diag_01` | no |
| `STAGE/t_outcome_elide/` | `integration/evidence/rearm_01/STAGE_REDUCTION.md` (untracked); tests read siblings `t_sealed_lifetime`, `n_crc_residue`, `combined_nt_01` | no |
| `STAGE/realrelay_01/` | `realrelay_native_01` code (3 files); `rearm_01/STATUS.md` | no |
| `STAGE/realrelay_native_01/` | `WORKING_NOTES.md`; `rearm_01/STATUS.md` | no |
| `STAGE/seg61_e_crc_01/` | `case4_architecture/HANDOVER.md`; `seg61_02/evidence/MECHANISM_REPORT.md`; code reads siblings `seg61_02`, `read_reencode_01`, `seg61_01` | no |
| `STAGE/{dup_hold_01, n_crc_residue, t_sealed_lifetime, combined_nt_diag_01, retx_passthrough_01}` | 90 to 921 files each, including active code and current hardware configs | no |
| `defense4/timing/active_harness/` | 22 files incl. `framework/run_tests.sh`, `latency_search/{remote,run_block}.py` | no |
| `defense4/timing/active_control/` | 15 files incl. `framework/control/{bfrt_device,profiles}.py` | no |
| `defense4/timing/active_probe/` | 8 files incl. `framework/run_tests.sh` | no |
| `defense4/timing/tests/` | `FINAL_TIMING_ALLOWLIST.txt`, `PROVENANCE.md`; resolves `../analysis` by depth | no |
| `defense4/timing/tools/` | `HOW_MUCH_DELAY_IS_SAFE.md` documents `render_md_pdf.sh` | no |
| `relay_rto_20260915/` | `paper/` provenance (4 files), 3 code files | no |

Tracked runtime clutter, listed but not proposed for removal: four force-added `.pyc` files under
`defense4/timing/framework/size/endpoint_gate/context_evidence_0{2,3}/sources/__pycache__/`, and 1,195
`*.pid` files, almost all under `defense4/timing/latency_search/evidence/` (delay_grid 800, focused 200,
blocks 130, randomized 63). Both sit inside evidence bundles and may be covered by their hashes.

### Restoring a moved item

```sh
git mv history/<original path> <original path>          # undo a move that is still in the tree
git checkout 4a0b0fc56 -- <original path>                # restore the pre-move copy from the baseline
git show 4a0b0fc56:<original path>/<file>                # read one file as it was
```

## Superseded authorizations and authority statements

These were in the root documents and are kept here with their dates. The current boundary is in
`CLAUDE.md` under "Current authorization".

| date | statement | superseded by |
|---|---|---|
| 2026-08-26 to 2026-10-18 | `campaign_v2` is the approved publication evidence and the active corpus | 2026-10-19: the manuscript evidence is `eval_m11_09_20261018_02` on m11_09 (Philip) |
| 2026-09-29 | "Current authorization: offline audit and corrections only." The 2026-09-26 focused study and the 2026-09-27 matched delay grid were authorized and ran under frozen protocols; no testbed contact, pipeline load, configuration change or traffic without new authorization | 2026-10-06 Case 4 scope; 2026-10-22 directive (hardware through the existing gated machinery) |
| 2026-09-29 | Paper freeze pending Dr. Lin's acceptance: no change to `paper/rewrite/`; paper findings go to `audit_current/verification_20260929/` | 2026-10-19 manuscript rebuild on Dr. Lin's draft |
| 2026-09-29 | "No testbed operations are authorized" (README) | as above |
| until 2026-10-19 | Timing-only claim boundary: no size, segmentation, padding or splitting claim | 2026-10-19: response-size claims scoped to the measured normalization are allowed in the rebuilt manuscript; the boundary still governs the campaign_v2 record |
| 2026-10-06 | "Work on main, no new branch or push"; separate candidate code, BMv2, offline tests and padding/carving authorized; new live runs need their own recorded authorization | still in force in substance; folded into the 2026-10-22 boundary |

## Documents removed from the tree

Each is a `git show <commit>:<path>` away.

| removed | at | what it was |
|---|---|---|
| `REMOVAL_REPORT.md`, `VERIFICATION_REPORT.md`, `REPOSITORY_AUDIT.md` | `f6dd821` | the 2026-08-26 reduction of the full repository |
| `CLEANUP_PLAN.md` | `f573eec` · also `dc721cdf` | disposition of every candidate in that reduction |
| `REMOVAL_MANIFEST.csv` | `6e2eff2` | the per-path record of it |
| the six root review and correction reports of 2026-09-15 and 2026-09-16 | `48373e39` | the reviews this repository answered |
| twenty superseded notes under `defense4/timing/`, `audit_current/` and `paper/rewrite/` | `dc721cdf` | branch maps, rerun plans, session logs, pre-rewrite reconciliations, an applied patch proposal, a duplicate writing guide and a duplicate definitions table |
| superseded campaign set under `defense4/timing/history/` | removed 2026-09-15 | recoverable from git history; only `CLAIMS_AND_LIMITATIONS_final_read_sbo.md` remains |
| `figures/timing/fig01…fig05` | removed 2026-09-07 | byte-identical duplicates of `defense4/timing/figures/publication/` |

`WORKING_NOTES.md` was once listed here as removed. It is tracked again and holds the live session log.

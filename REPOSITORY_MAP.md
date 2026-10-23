# Repository map

Each top-level area is one of four kinds: **active** (current code and its gates), **paper** (the
manuscript and what it cites), **evidence** (records of what ran; never edited) or **historical** (no current
claim or run depends on it; kept for provenance). File counts are tracked files at `4a0b0fc56`
(54,432 in total); "of which evidence" counts paths containing `/evidence/`.

`ARCH` = `defense4/timing/case4_architecture`; `STAGE` = `ARCH/integration/core/response_only_rearm/stage_experiments`.

| path | kind | tracked files (of which evidence) | what it is |
|---|---|---|---|
| `ARCH/` | active + evidence | 28,854 (27,468) | the Case 4 implementation: P4 generators, model drivers, hardware supervisor, endpoints, ownership; map in `ARCH/ACTIVE_CODE_MAP.md` |
| `STAGE/` (inside `ARCH`) | active + evidence | 17,451 (16,762) | candidate builds and their records; `m12_fullsize` (generator), `ctl_timing_01` (builds, model gate), `read_complete_01` (current run), `seg61_02` (manuscript evaluation) |
| `STAGE/seg61_02/evaluation/`, `analysis/paper_evidence.py`, `evidence/evaluation_campaigns/eval_m11_09_20261018_02_paper` | paper evidence | | the manuscript's claim matrix, figure and table generator, and evaluation data |
| `paper/` | paper | 253 | `paper/rewrite/`: the manuscript, rebuilt on Dr. Lin's draft; build `pipeline/build.sh` |
| `defense4/timing/framework/size/` | active | 365 (7) | software endpoints and size reference used by `ARCH` |
| `defense4/timing/framework/` (rest) | historical | 680 (121) | 2026-10-06 framework track (BMv2, contract, results) |
| `defense4/timing/evidence/` | evidence (historical) | 1,237 (1,237) | `campaign_v2` (timing-only paper record), `campaign_v1`, `final_read_sbo`, `tail_sweep_20260918` |
| `defense4/timing/latency_search/` | historical + evidence | 21,192 (18,782) | 2026-09-26/27 matched delay grid and attacker analyses |
| `defense4/timing/audit_current/` | historical | 1,031 | claim, retransmission, epsilon and RTO audits; the 2026-09-29 verification ledger; CLRT and model figure tools |
| `defense4/timing/anchor_fix/` | historical | 133 | request-anchoring fix and before/after findings |
| `defense4/timing/stage_reduction/` | historical + evidence | 80 (26) | seven-stage timing-only candidate, 2026-09-25 smoke test |
| `defense4/timing/response_ready/` | historical + evidence | 449 (424) | READ response-ready candidate, never deployed |
| `defense4/timing/implementation/` | evidence | 12 | exact source that ran for campaign_v1/v2; never modify |
| `defense4/timing/{analysis,figures,active_*,tests,tools}/` | historical | 15 / 90 / 15 / 1 / 1 | campaign-era analysis, figure families, harness, admission control, RTO probe |
| `defense4/timing/` top-level files | reference | 12 | `README.md`, `CLAIMS_AND_LIMITATIONS.md`, `NOTATION_MAPPING.md` (sole definition of `D_R`), `TIMING_MODEL.md`, `PROVENANCE.md`, `reproduce.sh` (campaign_v2) and others |
| `relay_rto_20260915/` | evidence | 14 | relay RTO captures; cited by paper figure provenance |
| `history/` | historical | 6 | items moved out of the active tree on 2026-10-23 (original paths mirrored; see HISTORY_MAP.md): `tools/history_rewrite/`, `STAGE/next_stage_analysis_01/`, `STAGE/e_stage_review.md` |
| root | docs | 9 | `README.md`, `CLAUDE.md`, this map, `WORKING_NOTES.md` (live session log), `FINAL_TIMING_ALLOWLIST.txt`, `BRANCH_PRUNE_20260915.txt`, `DNP3_Implementation_Directive_492013014.md` (deleted in the working tree, not yet committed), `.gitignore`, `.gitattributes`; new and untracked: `HISTORY_MAP.md`, `.ignore` |

Rules that follow from the kinds: evidence is never edited or removed; historical items move only through
`HISTORY_MAP.md` after a reference check; the manuscript changes only under the paper rules in `CLAUDE.md`.

Root files `main.tex`, `paper structure.pdf` and the directive markdown files are untracked inputs from Philip
and Dr. Lin, not part of the tree.

A repository manifest does not say what is loaded on the switch. Inspect the live state before any hardware
operation.

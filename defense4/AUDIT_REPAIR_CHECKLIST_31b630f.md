# Audit-repair checklist — 31b630f → branch `defense4-size-transport-kernel-repair`

Self-contained PI tracker for the overnight software/compile-only repair of the independent audit of
`31b630f`. Relative paths only. `31b630f` is immutable (branched from, never amended). No hardware, no
switch/relay, no history rewrite, no `main` merge. Author/committer `akekulip`, no AI attribution.
Status vocabulary: TODO / IN-PROGRESS / DONE / PARTIAL / FAIL / UNKNOWN. Re-read this + `dir.md` before
each synthesis/commit checkpoint. `dir.md` (the private directive) is NOT committed.

## Preflight (DONE)
- Branch `defense4-size-transport-kernel-repair` from `31b630f`; server `ls-remote` of the source branch = `31b630f`; local clean; 53 paths inventoried; author/committer `akekulip`; not merged to `main`.
- Baselines rerun (current, pre-repair): timing 29/29; transport suite reports gate PASS (**false-green — B1**); observer 9/9 (logic-only — M1). These are the state to correct.

## Workstreams (task · owner · reviewer · evidence path · status · limitation)

| ID | Task (audit ref) | Owner role | Reviewer | Evidence path | Status |
|---|---|---|---|---|---|
| A | Transport oracle: fix tuple-reuse new-epoch translation (**B1**), template_id conflict, SYN-learned SACK, wall-clock retirement, real mutation harness | TCP formalist | red-team | `size/offline/` + mutation results | **DONE — PASS**: 84/84 (`test_transport_oracle.py` 46 + `test_transport_repairs.py` 38) + **12/12 mutants killed**; per-packet epoch discriminator fails closed on tuple reuse; manifests in `size/gate_results/` |
| B | P4: fix cover bytes (**B2** golden `05 64 09 44 32 00 01 00 50 C7 C0 C1 02 00 D8 2E`), fail-closed eligibility (**B4**), ledger match-or-downgrade (**B3**), target-policy-or-relabel (**B5**), conformance corpus, bf-p4c or UNKNOWN | P4 architect | red-team | `size/p4/` + `evidence/cover_kernel_repair/` | **DONE — FUNCTIONAL-PASS + COMPILE-PASS** (not silicon): golden bytes (2 CRC impls), fail-closed eligibility, honest depth-1 downgrade = fixed +16 B enlargement (NOT normalization), 49-vector ref↔emulator conformance, bf-p4c 0 errors / egress 12/12; source sha256 `8074374…`; `REPAIR_DECISION.md` |
| C | Real OpenDNP3 TCP full-stack; reclassify `test_full_transaction.cpp` (**M2**); SIGSTKFLT root cause | OpenDNP3 expert | red-team | `size/evidence/cover_frame_gate/` | **PARTIAL (2026-08-12)**: M2 reclassified (app-context+link, not TCP); real single-process `DNP3Manager` TCP loopback READ/SBO built + captured (`real_channel/`, incl. 7-seg transport reassembly, SYN/FIN/RST); full-stack cover-injection BLOCKED-BY-SANDBOX (SIGSTKFLT = sandbox kill of loopback relays, native stack clean — `real_channel/evidence/sigstkflt_root_cause.txt`) |
| D | Observer scorer evidence-driven (**M1**): emit+parse JSON vectors, real 50000+idx decoys, repeated reads, confusion/precision/recall/FPR | privacy expert | red-team | `size/evidence/observer_scoring/` + vectors | **DONE — PASS**: rewritten evidence-driven, real 50000+idx decoys, Gate D 4/4; O_config_known recovers counts; **O_parse_profile FPR=1.0 on a quiescent plant** (a demonstrated limit) |
| E | Timing: differential-ε-as-absolute (**M3**), band tolerance (**M4**), confidence-aware selector, 2000 ms provenance→UNKNOWN (**M5**) | timing/stats | red-team | `timing/analysis/` | **DONE**: 38/38 byte-identical; `L_master` direct from paired timestamps (ε_R UNKNOWN for analysis-only); band tolerance conditional; "no candidate ≥99% at 95%"; 2000 ms→UNKNOWN |
| F | Decoy docs (**M6**): remove both "no native device emits two G12V1 headers"; SBO duplicate = APDU replay; availability tradeoff; scorecard fix | PI/docs | red-team | `size/evidence/decoy_gate/README.md` | **DONE**: both universal claims removed (→ relative to the tested baseline); SBO "retransmission" → APDU duplicate; availability tradeoff noted |
| G | Reproducibility (**hygiene**): deprecate 5 v1 scripts with absolute `dnp3_split_harness` paths (`canonical_response.py`, `p4_egress_emulator.py`, `size_transform.py`, `joint_transform_oracle.py`, `sbo_oracle.py`) + stale `p4/baseline.err`; run manifests; `git diff --check` | repro reviewer | PI | `size/offline/`, `size/p4/baseline.err` | **DONE**: `DEPRECATED_v1.md` (paths sanitized to `~/`); build trees gitignored; build logs unstaged; no abs paths / secrets in deliverables |

## Claims to WITHDRAW/DOWNGRADE now (audit) — enforced across docs on integration
transport "gate PASS"/"mutation-checked"; P4 "integration gate demonstrated"; P4 cover "CRC-valid"; P4
"runs the offline oracle"; P4 "common-target normalization"; cover harness "full transport/TCP" or "proves
no close"; observer READ temporal residual "demonstrated"; observer SBO "parsed from evidence"; "two G12V1
headers impossible for all native devices"; `(2,12)` "tested/confirmed ≥99%"; 2000 ms "protocol default
tied to this campaign"; "loading the current kernel is the smallest justified physical experiment."

## Integration gates (run in order after workstreams; PI accepts only on evidence)
reference correctness → mutation kills → packet-vector conformance (ref vs P4/emulator) → serialization/checksum
(2 independent impls) → endpoint bounded pass + full-stack class recorded → compile (or COMPILE-UNKNOWN) →
doc claim-scan (no prohibited/universal overclaim) → reproducibility (isolated regen + manifests) → red-team →
PI synthesis. **OVERALL is not PASS unless all P0 (A,B) gates pass; otherwise precise FAIL/PARTIAL/UNKNOWN, no physical recommendation.**

## Required outputs (this branch)
this checklist · transport invariant/state-machine doc *(folded into `size/offline/transport_oracle.py`
module docstring + `gate_results/` manifests)* · P4↔reference conformance matrix *(`size/offline/test_cover_conformance.py`
+ `conformance_corpus.py`, 49 vectors)* · evidence manifests *(`size/gate_results/`, `size/evidence/cover_kernel_repair/`)* ·
corrected `SIZE_CANDIDATE_DECISION.md` + `DESIGN_DECISION_v2.1.md` (physical load **WITHDRAWN** — done) ·
`OVERNIGHT_PI_REPORT.md` (done) · specialist findings folded into `REPAIR_DECISION.md` + the report.

## Final disposition (2026-08-12) — **OVERALL: PARTIAL**
Both P0 gates pass for their bounded claims; every audit false-green is eliminated; all results re-verified
by the main session. PARTIAL (not PASS) because the P4 gate passes only as an honestly **downgraded** fixed
+16 B first-response enlargement (not normalization), the full-stack gate is PARTIAL (sandbox-blocked), and
**nothing is on silicon**. Physical-load recommendation **withdrawn**; **no physical action taken or
recommended**. Full disposition + per-gate table: `OVERNIGHT_PI_REPORT.md`.

| Gate | Disposition |
|---|---|
| P0 Transport | PASS (84/84 + 12/12 mutants) |
| P0 P4 semantics | FUNCTIONAL-PASS (49-vector conformance, golden bytes, fail-closed) |
| P4 compile | COMPILE-PASS (bf-p4c 0 errors, egress 12/12; NOT silicon) |
| OpenDNP3 full-stack | PARTIAL (real TCP loopback; cover-injection sandbox-blocked) |
| Observer | PASS (evidence-driven; O_parse_profile FPR=1.0 limit recorded) |
| Timing | PASS (38/38; honest verdicts) |
| Physical action | NONE |

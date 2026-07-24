# Spec / Roadmap Reconciliation — 2026-07-24 (overnight run, offline)

Read-only reconciliation of the normative documents for all six phases, produced during the bounded
autonomous run (`OVERNIGHT_RUN_20260723-2255.md`). Purpose: extract per-phase requirements and flag
contradictions / materially-incomplete specs BEFORE writing code, so no phase is advanced by inventing a
new architecture. Sources: `END_TO_END_IMPLEMENTATION_PLAN.md`, `END_TO_END_MISSION_CHARTER.md`,
`p4/ack_delay/{dcrn_defense1.p4, dcrn_defense2.p4, CASE_A_TERMINOLOGY.md, ACK_DELAY_*.md,
DEFENSE1_TELEMETRY_REVIEW.md, phase_status.json}`, `shadow/{dnp3_shadow.p4, SHADOW_*, GATE1_*}`,
`txncore/{TXNCORE_PHASE2_REPORT.md, COMPILE_FIT_RESULT.md}`, `inline_dnp3_size_normalization/research_design.md`,
`queue_microbench/{QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md, size_pattern_builder/*}`.

## Per-phase implementability verdict (the gate on tonight's work)

| Phase | Verdict | Why | Offline-safe work this run |
|---|---|---|---|
| 1 shadow classifier | **COMPLETE / implemented** | P4 compiles 4/12; dir-1 silicon-validated; only blocker is dp8 link + B1 run | GATE-1 test infra (done) |
| 2 transaction core | **MATERIALLY-INCOMPLETE** | generation *carried* fits 12/12; *enforcement* (recirc read) does NOT fit → needs a human-gated compact redesign (`COMPILE_FIT_RESULT.md`) | requirements matrix + gate consolidation for the CARRIED variant; logic already validated |
| 3 Defense 1 (frozen) | **COMPLETE (mechanism)**; harden-fold incomplete | frozen file 12/12, replay-PASS; folding Phase-2 enforcement inherits the Phase-2 blocker | Defense-1 reference model + behavior tests; resource record |
| 4 Defense 2 | **MATERIALLY-INCOMPLETE** | mechanism fits 10/12 but (a) G_i target set undecided (see C2), (b) recirc-drain/qid calibration unproven (measured ~107 ms constant, hardware-only) | reference-model behavior tests only; NO G_i pick, NO calibration (hardware-gated) |
| 5 size regeneration | **MATERIALLY-INCOMPLETE** | two mutually-exclusive mechanisms (C3), pattern `P` uncomputed, physical 134 B uncovered (C5), byte-preservation invariant change unresolved | size INVENTORY from evidence only (no mechanism); document blocking decisions |
| 6 joint evaluation | methodology COMPLETE; mechanism blocked | eval method well-specified; the joint defense doesn't exist (depends on Phase-5 platform split) | analysis/schema tooling verified on synthetic fixtures; NO hardware results |

**Rule honored:** where a phase needs an undocumented architecture/calibration decision (2 enforcement, 4
calibration+G_i, 5 mechanism), it is NOT invented here — it is documented as human-gated (red-line).

## Contradictions flagged (must be resolved by a human before the dependent phase proceeds)

- **C1 — native CLRT ground truth (~7× disagreement).** Physical relay median **1.899 ms** (charter/plan)
  vs historical trace corpus median **12.9 ms** (`CASE_A_TERMINOLOGY.md`) vs microbench **12.2 ms**. Every
  guard/deadline bound inherits whichever source is chosen. Unreconciled.
- **C2 — Defense-2 G_i target set (four regimes).** Design doc **60 ms**; charter/plan **8/12/16/20 ms**;
  experiment plan **{25,30,35,40}–50 ms**; measured hardware **~107 ms** constant. Undecided.
- **C3 — size mechanism (two mutually-exclusive designs).** `research_design.md`: in-switch per-flow TCP
  seq-space translator on the Tofino. `queue_microbench` §0.5.7: two-edge outer encapsulation, seq space
  untouched, translator "alternative feasibility study only." Plan sides with the second.
- **C4 — single-ASIC vs platform-split.** `research_design.md` claims size normalization "buildable
  entirely on Tofino-1"; plan §5/§10 declares single-program joint infeasible → SmartNIC/second edge.
- **C5 — max response size to cover.** Builder corpus max **120 B** (128 B state "covers it"); physical
  relay response **134 B wire / 115 B DNP3** → 128 B < 134 B does NOT cover the physical frame.
- **C6 — refmodel (port-based) vs silicon (physical-direction) classification.** Reconciled operationally
  (B1 bidirectional required; refmodel is the looser oracle), but the two oracles disagree unless physical
  direction matches port direction.
- **C7 — "Case B" terminology.** Resolved to option (b) (Case A/B = device patterns; Defense 2 ≠ Case B),
  but `dcrn_defense2.p4` / `ACK_DELAY_STATE_MACHINE.md` / `ACK_DELAY_DEFENSE2_DESIGN.md` prose still use the
  deprecated "Case B = Defense 2".

## Key extracted specs (condensed — full citations in the run log)

- **Byte-preservation invariant** (Phases 1–4): no DNP3/TCP/IP field edit, no seq/ack rewrite, no CRC
  recompute, no Checksum extern; recirc bridge pushed on hold-enter, popped in egress before Vision.
  **Phase 5 deliberately abandons this** (append-only pad-up) — a governing-spec change, unresolved.
- **No-controller-fast-path** invariant across all defenses (control plane only installs tables/policy).
- **Defense-1 registers** (×65536): `reg_armed`, `reg_expected_ack`(32b), `flow_has_held_ack`,
  `reg_resp_seen`, `reg_ack_gone`; `ACK_MAX_PASS=2^16`, `RESP_MAX_PASS=2^17`, `GUARD_PASSES=4`,
  `QID_HOLD=5`. Event-governed release; zero-inversion crux. 12/12 stages.
- **Defense-2 registers**: adds `reg_deadline`(32b), `reg_ack_seen`, `reg_txn`, `reg_held_count`;
  `check_deadline` SALU runtime-operand; `bounded_target` 256-entry table (G_i per bucket); tick =
  `global_tstamp[47:16]` ≈ 65.536 µs; egress refreshes `bridge.tstamp_tick` each pass. 10/12 stages.
- **Fail-open everywhere**: `drop()` is L2-malformed only; MAX_PASS is a fail-open alarm that must stay ~0.

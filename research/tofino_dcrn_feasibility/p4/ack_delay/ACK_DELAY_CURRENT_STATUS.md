# ACK-Delay Current Status

Section-25 `ACK_DELAY_CURRENT_STATUS.md` + Section-26 reporting. Date 2026-07-20. Branch
`research/ack-timing-phased`.

## PRECISE STATUS (PI-directed 2026-07-20) — Case A is NOT complete
**Correct statement:** *the Case-A ACK-delay state machine is modeled, tested, and locally compiled.
Hardware semantics and wire behavior remain gated.* Do NOT describe Case A itself as complete.

| Item | Status |
|---|---|
| Case-A policy model | **PASS** |
| Case-A randomized invariant (zero-inversion) | **PASS under modeled assumptions** |
| Local `bf-p4c 9.13.1` compilation | **PASS** |
| Tofino resource fit | **PASS, but tight at 11/12 stages** |
| On-switch placement (9.13.2) | **NOT YET PROVEN** |
| Recirculation hold duration | **NOT YET PROVEN** |
| Register-visibility assumption | **NOT YET PROVEN** |
| Shared-FIFO ordering assumption | **NOT YET PROVEN** |
| Wire-level ACK-delay behavior | **NOT YET PROVEN** |

## GATE STATUS (PI-corrected numbering — Gate 2 must pass before claiming Case-A enforcement)
- Gate 0: Repository audit — **PASS**
- Gate 1: Policy / reference model — **PASS**
- Gate 2: Controlled recirculation hold (deadline/event-governed release, pacing, MAX_PASS fail-open
  only, timestamp refresh, register-visibility + FIFO probes) — **IN_PROGRESS** (design done; unproven
  on hardware). A local compile can pass before Gate 2, but Gate 2 must pass before claiming Case-A
  enforcement.
- Gate 3: Local P4 compile-fit — **PASS** (11/12 stages, tight)
- Gate 4: On-switch compile + transparent forwarding — **NOT STARTED**
- Gate 5: Case-A wire microbenchmark (fixed guard) — **NOT STARTED**

## OPERATION REVIEW (this turn)
- GATE 0 repository/evidence audit done: current `dcrn.p4` = request-relative both-hold (§22-forbidden
  for the primary experiment); switch runs the co-resident program (DCRN not loaded → no window).
- §5.A original-PCAP analysis done from the real captures (not memory): SEL751 = SEPARATE (native CLRT
  median 12.9 ms), AB1400 + ION7550 = COMBINED (no CLRT). Saved with SHA-256 provenance in
  `p4/ack_delay/evidence/`.
- Convened 5 expert agents as PI (principal-investigator, p4-dataplane-engineer, power-systems-expert,
  research-scientist, sdn-networks-expert). Synthesised into `ACK_DELAY_POLICY.md`,
  `ACK_DELAY_STATE_MACHINE.md`, `ACK_DELAY_EXPERIMENT_PLAN.md`, this file.
- Nothing measured on hardware this turn; no code compiled.

## COMPLETED
- Native CLRT + separate/combined ground truth (§5.A), device-verified.
- Policy spec, P4 state machine, experiment plan, attacker-eval design — all as planning docs.
- Build-order disagreement among experts RESOLVED (see below).

## MEASURED (device-confirmed, this session)
- SEL751 native CLRT median 12.9 ms (p10–p90 11.6–15.9, tail to 166 ms); req→ACK 3.7 ms; req→resp 17.0 ms.
- AB1400/ION7550: 0 pure ACKs → COMBINED → no CLRT; req→resp ~16 ms; ION7550 has native retransmits.
- (From prior phases) recirc hold currently uncontrolled 38–100 ms — MAX_PASS-governed, not deadline.

## BLOCKED
- **Case B (deadline-governed)** — blocked on the recirc **clock fix** (bridge back egress
  `global_tstamp`; ig_prsr_md doesn't refresh on recirc) AND the **pacing fix** (dp68 qid5
  `pg_id`/`pg_queue` mapping). Both need a switch window (the C1–C4 probe).
- **All hardware efficacy** — blocked on switch authorization (no window; co-resident program owns the
  chip) AND on the de-degeneracy fix (only one separate-ACK device → need ≥3 SEL751 config profiles).
- **Physical-device validation (T4)** — needs real SEL751/AB1400/ION7550 hardware (separate line).

## UNRESOLVED (hardware unknowns — ranked)
1. `global_tstamp` refresh on recirc (Case B only; Case A immune).
2. dp68 qid5 pacing actually applied (correct queue mapping).
3. Monotone register visibility + same-queue FIFO (the Case-A zero-inversion invariants).
4. Minimum reliable ordering guard δ (Case-A E1).
5. Multi-segment ordering (needs a controlled larger-response sweep).
6. Master effective RTO on the rig (bound Case-A ACK-hold and Case-B G below it).

## KEY PI DECISION — build order (expert disagreement, resolved)
- p4-dataplane-engineer: **Case A first** — its ACK release is EVENT-governed (response arrival flips
  `reg_ack_gone`; ordering is structural via a shared FIFO queue + monotone register visibility), so it
  is IMMUNE to the unresolved recirc-clock bug and can be hardware-proven before the clock fix.
- principal-investigator + sdn-networks-expert: Case B is scientifically the stronger defense (Case A
  *relocates* the CLRT signal into req→ACK) and transport-safer, so they leaned Case B first.
- **PI resolution:** **Case A first** — it aligns with Dr. Lin's mandate AND is the only one buildable
  without the clock fix, so it de-risks the fastest. Fix the clock/pacing in parallel (for Case B and
  Case A's bounded-guard E2). Carry Case A's honest limitation throughout: it relocates the signal, so
  the attacker eval MUST include a `req→ACK`/joint classifier, not CLRT alone. Lead the paper with the
  Case A (cheap, relocates) vs Case B (costly, normalises) tradeoff.

## SCIENTIFIC INTERPRETATION (honest scope, up front)
On this corpus CLRT is not a cross-device discriminator — **ACK mode is** (anonymity-set-of-one:
SEL751 is the only separate-ACK device). The CLRT policies collapse the *within-separate CLRT
sub-channel* only; the separate-vs-combined ACK mode and response size remain and still fully separate
the three devices. Realistic verdict for the efficacy experiments (E2/E4) = **PASS_WITH_LIMITATION**
(CLRT collapses; ACK-mode + size residuals survive — out of this phase's byte-preserving, no-synthesis
scope). Novel core (sdn-confirmed, survives review): first byte-preserving, non-cooperative, in-ASIC
control of the CLRT channel — hold a REAL pure ACK on the datapath and release it, order-guaranteed,
ahead of a not-yet-arrived response (cite PCQ NSDI'20 for the hold primitive, NetWarden USENIX'20 as
the synthesis/slowpath contrast, Formby NDSS'16 as the target).

## DEVELOPMENT GATES (§23) — status
- GATE 0 repository audit — **DONE.**
- GATE 1 policy specification (2 state machines, metrics, bypass, acceptance, Python reference model +
  tests) — **DONE.** Spec docs written; **Python reference model `refmodel/ack_state_machine.py` +
  `tests/test_ack_state_machine.py` (12 tests) PASS** — the Case-A zero-inversion invariant holds
  across a randomized sweep (jitter, non-same-cycle register visibility vis_delay 1–8, guard variation,
  response-before/after-ACK arrival); combined-bypass, fail-open, Case-B deadline-governed release
  (not MAX_PASS), and device-independent target selection all validated in simulation.
- GATE 2 hold primitive (clock + pacing fix, deadline release, MAX_PASS fail-open only) —
  **BLOCKED** on a switch window (C1–C4 probe); design done.
- GATE 3 local P4 compile (Case-A variant, resource report, ≤12 stages) — **DONE (clean fit).**
  `dcrn_ackA.p4` (32.5 KB, event-governed Case-A state machine) compiles on **bf-p4c 9.13.1: 0 errors,
  11/12 ingress stages** (vs DCRN's 9; the ACK/response event machine adds 2 — **1 stage headroom**),
  critical path 7, 46 tables, 58 SRAM, 0 TCAM, real `tofino.bin` + `context.json` produced. All 7
  registers present (reg_gen/armed/req_tick/ack_seen/resp_seen/ack_gone + global watermark);
  zero-inversion implemented as designed (response released only on a pass reading `reg_ack_gone==1`;
  ACK sets `ack_gone` on its own PORT_VISION-directing pass; both to qid 0 = shared FIFO; QID_HOLD on
  recirc paths only). Evidence: `p4/ack_delay/build_ackA_9.13.1/` + `evidence/ackA_9.13.1/` (+ SHA256SUMS).
  Six placement fit fixes (all MAU register-co-scheduling, none language-level). **Two functional
  reductions flagged (both safe in the single-outstanding/single-flow initial scope):** (a) the recirc
  watermark keeps its ARMING gate but defers its release-time decrement (occupancy ≤2 ≪ HELD_MAX=256 →
  cap never trips; restore precise occupancy via an egress-side global counter for multi-flow scale);
  (b) recirc gen-staleness enforcement deferred (bridge carries `gen`; flag-clear discipline covers
  freshness while one transaction is outstanding). **Remaining semantic-fit risk:** 9.13.1→9.13.2
  placement parity at 11/12 (1 stage slack) — the top local-to-switch item; and the `-g` build does NOT
  exercise the two correctness unknowns (monotone recirc register visibility; ACK+response on one FIFO
  queue) — both remain switch-run items.
- GATE 4 on-switch transparent forwarding — **BLOCKED** (no window).
- GATE 5 Case-A microbench (event-governed, ACK-before-response, fixed guard) — **BLOCKED** (after G3/G4).
- GATE 6 Case-B microbench — **BLOCKED** (after the clock fix).
- GATE 7 common-bounded policies — **BLOCKED.**
- GATE 8 device-derived live replay (SEL751/AB1400/ION7550, wire ACK-mode classified) — **BLOCKED.**
- GATE 9 Vision↔Hulk campaign — **BLOCKED.**
- GATE 10 physical-device campaign — **BLOCKED** (needs hardware).

## CURRENT STATUS: **IN_PROGRESS** (planning complete; first action / GATE 0–1 delivered)

## NEXT GATE
The off-switch Case-A work is **complete and clean** — reference model + tests (GATE 1) and local
`bf-p4c 9.13.1` compile at 11/12 stages (GATE 3) both pass. Everything further needs either a switch
window or the Case-B clock-fix design:
- **Off-switch (no window needed):** author the **Case-B compile-time variant** (`dcrn_ackB.p4`) once
  the clock fix is settled (bridge back egress `global_tstamp`) and local-compile it; and gate the
  `run_master.py` `unsolClassMask` change behind `--suppress-startup-unsolicited` (§6).
- **Needs a gated switch window (GATE 4 → GATE 2 probe):** transparent-forwarding + rollback, then the
  C1–C4 clock/pacing probe, then the Case-A microbenchmark E1 (event-governed, fixed guard,
  zero-inversion on the wire). **Do NOT request a switch window without recording current program/port/TM
  config, a rollback plan, and explicit GO.**

Three decisions are Philip's (not blocking the reference-model/compile work): (1) confirm **Case A
first** (I recommend yes); (2) whether to capture **≥3 SEL751 config profiles** to de-degenerate the
classifier, and/or acquire a second separate-ACK device (materially strengthens the claim); (3)
authorize the eventual switch window for the C1–C4 probe when the off-switch work is ready.

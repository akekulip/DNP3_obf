# PI Framing contribution (agent a45eec9d, 2026-07-18) — raw, for synthesis

Landing zone (PI verdict): **B (on-switch recirculation-hold) and D (hybrid switch-decides/edge-holds) are live; A (native TM) ruled out; E (infeasible→DPU/FPGA) is fallback; C (re-expressed scheduled/TAS release) is a semantics-changing alternative worth one eval.** Most-defensible-today = D; most-novel-if-authorized = B.

## Research questions (RQ1–RQ7)
- RQ1 native realizability of absolute per-flow release deadline t0+D, D∈[32–42]ms (expected: NO — the pivot).
- RQ2 realize (on-switch recirc-hold) / re-express (scheduled/TAS/PIFO dequeue) / split (switch decides, edge holds) — cost each.
- RQ3 dual-case: SEPARATE case must hold BOTH a pure ACK and its response, emit ordered per-flow FIFO + bounded guard-delta.
- RQ4 precision: deadline jitter vs software residual (FIXED ~0.056ms rig / ~0.19ms loopback, device-correlated); can HW realize BOUNDED without a new device-correlated signal.
- RQ5 safety+budget: fail-open (never drop, never overshoot master effective TCP RTO, clean revert); RTO margin with recirc/pass jitter added to D. ~211ms is a Linux FLOOR, re-measure on Vision master.
- RQ6 Phase-07 P4-readiness split: likely-feasible (classify direction; pure-ACK vs payload; flow map; delay existing packet; limited per-flow metadata) vs difficult (absolute-deadline scheduling; accurate per-flow timers).
- RQ7 claim boundary: switch cannot touch ACK-mode or size in-phase → timing primitive is NECESSARY-BUT-NOT-SUFFICIENT.

## Verdict rubric A–E (evidence gates)
- A native on-switch: ruled out (TM bounds rate; lone frame at idle queue departs immediately).
- B recirc-hold w/ constraints X {32-bit sliced timestamp global_tstamp[47:16] so compare fits SALU predicate; loopback port shaped to bound passes ~10^3 not 10^5; ≤~1 concurrent held frame at DNP3 rates; four fail-open guards}. Affordable/plausible/UNBUILT — costs are inference. Needs compiled-P4 + resource report + HW capture.
- C scheduled/time-gated (TAS 802.1Qbv / PIFO): NOT an exposed Tofino-1 primitive (P4-TAS is Tofino-2/controller-assisted); CHANGES target semantics per-flow-absolute→cyclic → must re-run attacker eval for phase-within-cycle residual.
- D hybrid: switch classifies/arms/tags at line rate; hold runs on already-rig-proven eBPF EDT/fq at outstation NIC (PASS_MEASURED) or DPU w/ real timer. Most defensible today.
- E infeasible on Tofino-1 → hold to DPU/SmartNIC/FPGA, switch keeps Stage-1 only. Triggered if deadline compare can't fit SALU/gateway width even sliced, or recirc load unbounded for dual-case FIFO, or fail-open not guaranteeable on-chip.

## Contribution positioning
Claim: byte-preserving in-network normalizer that removes device-processing-time fingerprint from a DNP3 outstation's response timing vs passive on-path observer, calibrated on measured multi-profile traces, bounded by master effective TCP RTO, with honest platform-feasibility verdict on the absolute-hold primitive.
Position against: (1) DNP3/ICS device fingerprinting via response-time (Formby CLRT) = the threat; (2) WFP timing defenses (constant-rate/adaptive padding — Tamaraw/DynaFlow/BLANKET) — DCRN differentiator = strict byte-preservation (no pad/cover/proxy); (3) programmable schedulers (PIFO/SP-PIFO, Loom, P4-TAS, EDT/fq pacing, Sonata telemetry).
Novelty boundary: NOVEL = dual-case absolute-deadline release normalizer, byte-preserving, RTO-calibrated, rig-validated in SW + the negative/boundary result that absolute-hold is NOT native to wire-speed TM. NOT novel = in-network timing normalization concept, P4 shaping/scheduling, DNP3 fingerprinting. Caps: single-device-per-profile → device-CONFIGURATION not device-FAMILY; timing-axis only; on-switch hold unbuilt/inference.

## Report skeleton (13 sections)
1 abstract/one-para verdict · 2 problem+threat model · 3 what DCRN is/proved · 4 the mechanism gap (SW EDT/fq vs Tofino TM-shapes-rate) = spine · 5 on-switch feasibility [p4 agent] · 6 dual-case wrinkle · 7 alternative realizations · 8 SDN arch + SOTA [sdn agent] · 9 verdict rubric applied · 10 risk/residual ledger · 11 P4-readiness table · 12 claim-to-evidence matrix + novelty boundary · 13 future experiment plan + gate (next step = COMPILE-ONLY Stage-1 probe; hold stays unbuilt pending explicit PI auth).

## Risk ledger
size fingerprint (High to anonymity; scope out — dominant residual, padding dead end) · ACK-mode (Med; separate primitive socket-coalescing) · recirc-load ceiling (Low DNP3 / High if generalized; concurrency argument; doesn't generalize) · RTO margin (Med; RTO-cap guard below measured Vision floor) · fail-open (High; a spurious retransmit is loudest tell + trips Zeek dnp3 IDS; 4 guards must be HW-demonstrated) · guard-delta residual (Med; operate BOUNDED) · reproduction caveats (Med; config-not-family; Tofino numbers inference until compiled P4; plan forbids stating stage/SRAM/SALU/queue counts without it).

## Delegation map (further specialists, beyond p4+sdn already run)
- p4-dataplane-engineer + tofino-p4: COMPILE-ONLY Stage-1 classify PoC + resource-fit probe for deadline compare (hold NOT built).
- research-scientist + statistical-analysis: attacker-eval equivalence for any re-expressed (C) release — detect phase-within-cycle residual, grouped-CV.
- literature-reviewer + arxiv/semantic-scholar: SOTA map (Formby + P4 scheduling + WFP timing defenses).
- ieee-journal-reviewer: adversarial pre-synthesis review (necessary-but-not-sufficient survives; no Tofino number without compiled-P4).
- power-systems-expert: DNP3-correctness lens (RTO-binding, fail-open no-retransmit/IDS, arm only on payload-bearing READ, no-delay-on-protection allowlist).
- systems-paper-writing + Zotero build: final authoring.

## Open questions ONLY Philip decides
1. Headline verdict = D (hybrid, defensible today) vs B (on-switch recirc, novel but needs compile probe to succeed) — VENUE-FIT call (P4/systems venue favors B; security/grid venue favors D+boundary result).
2. Authorize even the COMPILE-ONLY Stage-1 P4 probe? (plan's final gate: no auto P4; classify-only/no-hold/compile-only still touches P4 → explicit go/no-go).
3. External-validity ceiling: device-family claim needs additional physical devices (separate data line) — Philip green-light only.

# Defense 4 — governing directive (SUPERSEDED — kept as record)

> **⛔ SUPERSEDED 2026-08-04 by [`DEFENSE4_CHECKPOINT_2026-08-04.md`](DEFENSE4_CHECKPOINT_2026-08-04.md).**
> Two of this directive's locked rules are now REVERSED and one topology retired:
> - **Rule 2 "NO decoy CROBs … outer encapsulation only" is REVERSED.** Size is now normalized by
>   **master-inserted real-plus-decoy CROBs (K = R + D)** — the decoy-CROB line is REVIVED (with an
>   explicit inertness/authorization safety gate), and the outer-encapsulation size plane is retired.
> - **The two-edge / external-loop tunnel topology is retired** in favour of a **single Tofino-1 at the
>   outstation** (master → observed WAN → switch → relay).
> - **The READ/SBO six-slot template, filler positions, second decoder, and MB-8 are retired.**
> The rest (integrated size-AND-timing intent, the timing substrate = D1/D2/D3 engine, no controller
> fast path, the safety posture, exact matching / fail-open) carries forward. This file is preserved as
> the record of the prior direction; read the checkpoint for the controlling architecture.

**2026-08-04, Philip's correction directive. This file OVERRIDES any conflicting statement in the
draft deliverables. The other `DEFENSE4_*.md` remain DRAFTS until their contradictions with this
directive are resolved by the regeneration step (after MB-1). Where the adversarial review pushed the
scope too far (demoting size to "future work"), this directive is the authority.**

## 1. Locked structure — Defense 4 is FOUR coordinated work packages

Defense 4 is the **integrated size-and-timing system**, not a timing defense. It remains:

1. **Timing substrate** — one configurable engine reproducing Defense 1, Defense 2, Defense 3, plus the
   combined scheduled (grid) mode. *The timing grid is the Defense 4 timing substrate, NOT Defense 4 by
   itself.*
2. **Size substrate** — finite outer-size states, byte-preserving encapsulation/decapsulation, explicit
   overflow fail-open, **no arbitrary splitting in v1**.
3. **READ/SBO transaction template** — full packet roles, directions, counts, slot timing, and outer
   filler for unused positions.
4. **Integrated Defense 4** — a real READ and an emulator full SBO pass through the **same**
   implementation and produce the **same declared shape within a bounded envelope**.

**A failed size compile forces a smaller size profile, another pass on the same Tofino, or a narrower
workload envelope. It MUST NOT silently turn Defense 4 into a timing-only defense.** Timing-only is a
fallback *result*, reported as such, never renamed "Defense 4."

## 2. Locked rules

- Defense 4 remains the integrated size-and-timing system.
- The timing grid is the timing substrate, not Defense 4 by itself.
- ~~**NO decoy CROBs and NO modified DNP3 objects.** Size concealment comes from **outer encapsulation
  only**.~~ **⛔ REVERSED by the 2026-08-04 checkpoint.** Size is now normalized by **master-inserted
  real-plus-decoy CROBs (K = R + D)**: the authorized master pads to a fixed K-object list (R real +
  D inert decoys); the relay has explicitly configured **inert** decoy points; the **Tofino never
  fabricates/inserts/modifies a CROB**. Decoy inertness must be proven and authorization obtained before
  any physical control test (§7 of the checkpoint). The `DECOY_CROB_PADDING.md` research record is now
  IN scope again as the basis for this plane. Outer encapsulation is retired.
- **pktgen provides the internal slot clock. Traffic Manager queues enforce holding and release.**
- **Public sizes are observer-visible Ethernet frame lengths at ONE precisely defined measurement
  boundary** (the protected-link tap point; see the topology in the spec).
- The transaction template must include **every** visible unit: every DNP3 packet, pure TCP ACK,
  piggybacked ACK, optional CONFIRM, filler position, direction, and count.
- The existing documents remain drafts until their contradictions are resolved.

## 3. Comparison and contribution calibration (corrects the adversarial review)

- **Ditto (NDSS'22) is the main comparison** — it already provides programmable-switch padding,
  buffering, fixed patterns, and chaff. But **"Ditto subsumes Defense 4" is TOO STRONG.**
- **The Defense 4 contribution** is: the **DNP3 transaction-aware mechanism**, **event/deadline
  configurability**, **ACK-before-response gating**, **SBO causality and timeout safety**, **exact
  matching**, and **bounded fail-open behaviour**. None of these is in Ditto (an oblivious link shaper).
- **NetShaper (USENIX Sec'24)** is a relevant privacy-oriented middlebox baseline, **not** a direct
  Tofino or DNP3 substitute.

## 4. First offline evidence wave (NO switch, NO relay actuation)

1. **Stripped Defense 2 core** — build in a NEW `defense4/` directory; leave frozen D1/D2/D3 evidence
   untouched. Compile it and report the **ACTUAL** stages, critical path, SRAM, Map RAM, PHV, and
   stateful ALU use. **Do NOT retain the estimated "7–8 stages" unless the compiler proves it.**
2. **Emulator full SBO** — run the existing `run_multicrob_sweep.py` for N ∈ {1,2,4,8,16}. Capture
   SELECT, SELECT RESPONSE, OPERATE, OPERATE RESPONSE, and all associated TCP ACK behaviour. Simulated
   outstation only — no SEL-751.
3. **Comparable READ traces** with different response sizes (same emulator stack, for comparability).
4. **Part 12 release-tail recalculation** from raw timestamps — settle the unit. Current evidence
   indicates ~**1.72 µs**, not 1.72 ms.
5. **Reproduce the Defense 3 / E0 timing analysis.** Treat the synthetic-population test as a
   **falsifier**, not evidence of cross-device anonymity.

## 5. The decisive combined compile — MB-1

MB-1 MUST include: configurable D1/D2/D3 release predicates; READ, SELECT, OPERATE phase state;
SELECT-to-OPERATE linkage; generation-safe matching and cleanup; slot bitmap and slot-clock state;
**`size_profile` selection; per-slot size lookup; outer-header fields; real/filler tagging inside the
trusted representation**; fail-open logic.

Detailed telemetry and the **physical padding action** may be excluded from this ingress feasibility
skeleton, but **the complete size-control surface cannot be excluded.**

### Decision after MB-1

| result | action |
|---|---|
| **≤12 ingress stages** | proceed with the single-pass bounded Defense 4 design |
| **>12 stages** | evaluate a same-Tofino two-pass or ingress/egress redistribution design |
| **still infeasible** | report integrated Defense 4 as NO-GO under that profile; keep the timing substrate as a **separate** result; **do NOT rename timing-only work as Defense 4** |
| **oversized READ traffic** | narrow the supported envelope and fail open outside it; **do NOT claim cellization until implemented** |

## 6. After the results

Regenerate ONE consistent architecture specification, evidence ledger, feasibility report, and
implementation plan. Only then freeze the public slot pattern and begin the offline transaction oracle.

## 7. Hardware sequencing (later, gated on authorization)

The first hardware experiment is the **four-level priority microbenchmark**: 100/100 causality trials +
BF-RT configuration readback, **synthetic packets only**. The SEL-751 remains **strictly READ-only**;
all SELECT and OPERATE experiments remain on the emulator.

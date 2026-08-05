# Defense 4 — implementation + verification plan

Gates run in order. Each gate is committed before the next. No hardware is touched before the hardware
phase, which requires Philip's explicit authorization.

## Required timing-core properties (must all be retained)

Tofino-1 data-plane release; no controller fast-path dependency; exact flow + transaction matching;
canonical **bidirectional** flow identity; collision detection + fail-open; internal generation per
transaction; expected TCP ACK number; expected relay sequence state; pure-ACK validation; matching DNP3
RESPONSE validation; one-shot ACK + RESPONSE admission; queue-resident ACK + RESPONSE holding; **two
isolated blocker roles**; stale-generation rejection; FIN/RST cleanup; missing-ACK + missing-RESPONSE
cleanup; bounded blocker budgets; bounded transaction watchdog; duplicate/retransmission idempotence; **no
external blocker-token escape**; lightweight correctness counters only. Initially **one active protected
transaction per scheduler domain**; a concurrent eligible transaction fails open without overwriting.

## Gate 1 — Specification  (this commit)

Complete + commit: mode truth table, deadline equations, queue/priority contract, transaction state
machine, ACK-bearing-RESPONSE handling, failure/cleanup table, source-to-mechanism provenance, exact
claim boundary. → `README.md`, `ARCHITECTURE.md`, `TIMING_SPEC.md`, `EVIDENCE_BASELINE.md`, this file,
`RISK_REGISTER.md`.

## Gate 2 — Minimal P4 compile  (offline, no switch load)

Implement `timing/p4/defense4_timing.p4`. Remove old **size fields, slot bitmaps, outer headers, decoder
logic, filler roles, detailed research telemetry, unrelated CROB state**. Compile with **BF-SDE 9.13.1**
(9.13.2 only on an authorized dev env). **Do not load the switch.**

Report (from the compile logs, into `timing/evidence/`): ingress + egress stages; critical path; logical
tables; SRAM; Map RAM; TCAM; PHV containers + bits; stateful + statistics ALUs; parser/deparser changes;
pktgen application use; queue requirements.

**Required result:** zero compile errors; **no safety property removed to force a fit**. If the core
exceeds **12 ingress stages**, identify the exact dependency or PHV cause and test **bounded
ingress→egress redistribution** or a **same-Tofino two-pass** construction — do **not** pivot to another
platform.

## Gate 3 — Static + synthetic validation  (offline, no switch load)

Create tests for: `OFF`; `D1_EVENT`; `D2_RESPONSE_DEADLINE`; `D3_ACK_DEADLINE`; `D4_DUAL_DEADLINE`;
ACK-bearing RESPONSE (PROPOSED — safe fail-open/bypass); ACK-before-RESPONSE and RESPONSE-before-ACK
arrival; deadlines just before / at / just after expiry; duplicate ACK; duplicate RESPONSE; stale
generation; FIN + RST; missing ACK; missing RESPONSE; budget expiry; late ACK; late RESPONSE; concurrent
READ; collision fail-open; token isolation; cleanup + subsequent-transaction reuse; **asymmetric blocker
expiry** (ACK blocker expires while the RESPONSE blocker is still active, and the reverse); and
**timestamp-wrap safety** (deadlines + watchdogs immediately before, across, and immediately after a
32-bit timestamp wrap, per `TIMING_SPEC.md` §8). Prepare the hardware runner + analyzers but **do not load
the switch**.

Claim boundary for Gates 2–3: they provide **offline compiler-fit evidence and model-level functional
evidence only** — not silicon logical correctness (`TIMING_SPEC.md` §12).

After Gates 1–3: write `READY_FOR_HARDWARE_REVIEW.md`, commit, push, verify remote sync, and **stop for
review**.

## Hardware phase — only after Philip's explicit authorization

1. Snapshot current switch state + establish the exact restore target.
2. Compile with the deployment compiler.
3. Load the new timing core.
4. Verify all four queue priorities by **BF-RT `max_priority` readback**.
5. Verify dual-reservoir readiness + continuity with synthetic packets.
6. Test every mode with synthetic traffic.
7. Test the Hulk emulator.
8. Test **READ traffic only** against the physical SEL-751.
9. Run randomized native + protected timing campaigns.
10. Restore the exact prior switch state in every exit path.
11. Preserve PCAPs, counters, timestamps, commands, logs, compiler evidence, hashes.

**No SELECT or OPERATE to the physical relay.**

## Priority 2 — size (after the timing PASS checkpoint)

Do not begin size implementation merely because timing compiles — timing needs its own committed PASS
checkpoint. Then create `defense4/size/` and evaluate separately: current pad-only fixed-size evidence;
fixed-K real-plus-inert-decoy CROBs as a possible control-traffic mechanism; splitting + reassembly for
oversize packets; packet-count / burst / idle-gap leakage. Any size transform must integrate as
`classify -> size transform -> ACK/RESPONSE timing queues -> output` **without changing release
semantics**. Do not claim splitting, reassembly, chaff, or full fixed-size normalization until
implemented and measured.

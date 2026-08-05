# DNP3 Defense 4 — timing core (Priority 1)

**Single entry point and authority for Defense 4. Read this first. There are no competing authority
documents and no dated checkpoint files in this tree.**

Defense 4 is an in-network traffic-analysis defense for DNP3-over-TCP, implemented on **one Intel
Tofino-1 at the outstation edge**:

```
DNP3 master  →  observed WAN  →  one Tofino-1 (outstation edge)  →  relay / outstation
```

There is **no second switch, decoder, external-loop tunnel, slot grid, or endpoint modification**, and
the design is **Tofino-1 data-plane only** (no SmartNIC/DPU, no eBPF, no host pacing, no controller
release fast-path).

## Priority order (scope reset 2026-08-05)

1. **Priority 1 — the unified Defense 4 timing engine.** One P4 program that reproduces the proven
   Defense 1/2/3 mechanisms as selectable modes plus a combined dual-deadline mode, using four logical
   queues on one internal loopback scheduler domain. **This is the current active work.**
2. **Priority 2 — size obfuscation.** Deferred. It does **not** resume until the timing core passes its
   own committed PASS checkpoint. The fixed-K real-plus-inert-decoy CROB work is **deferred size work,
   not the timing core**, and is not active. (It remains recoverable from git history, commits
   `92cb620`…`0155e0`.)

**Complete Defense 4 is NOT demonstrated.** Nothing here is validated on silicon. Hardware changes
(loading a P4 program, TM/port config, contacting the relay, physical SELECT/OPERATE) require Philip's
explicit authorization.

## Structure

| path | purpose |
|---|---|
| `README.md` | this file — the single authority |
| `ARCHITECTURE.md` | topology, queues, reservoir + loopback contract |
| `TIMING_SPEC.md` | mode truth table, deadline equations, transaction state machine, provenance, claim boundary |
| `EVIDENCE_BASELINE.md` | the frozen D1/D2/D3/Part-11/Part-12/four-queue sources this design reuses |
| `IMPLEMENTATION_PLAN.md` | Gate 1 (spec) → Gate 2 (compile) → Gate 3 (synthetic validation) → hardware (gated) |
| `RISK_REGISTER.md` | risks + kill criteria |
| `timing/p4/defense4_timing.p4` | the unified timing core (one program, selectable modes) |
| `timing/control/defense4_timing_setup.py` | control-plane setup + BF-RT readback (queues, reservoirs, params) |
| `timing/run/` , `timing/tests/` | runners + static/synthetic tests |
| `timing/evidence/` | compile logs, synthetic-test results, hashes |

There is deliberately **no `size/` directory** during Priority 1.

## Gates (see `IMPLEMENTATION_PLAN.md`)

- **Gate 1 — Specification:** mode truth table, deadline equations, queue/priority contract, transaction
  state machine, ACK-bearing-RESPONSE handling, failure/cleanup table, source-to-mechanism provenance,
  claim boundary.
- **Gate 2 — Minimal P4 compile** (BF-SDE 9.13.1, offline, no switch load): resource report; ≤12 ingress
  or a documented bounded ingress→egress / two-pass remedy; zero errors; no safety property removed to fit.
- **Gate 3 — Static + synthetic validation:** every mode, ACK-bearing RESPONSE, ordering, deadline
  boundaries, duplicates, stale generation, FIN/RST, missing ACK/RESPONSE, budget expiry, late
  ACK/RESPONSE, concurrent READ, collision fail-open, token isolation, cleanup + reuse.

After Gate 3, `READY_FOR_HARDWARE_REVIEW.md` is written and pushed; work stops for review. The hardware
phase runs only on Philip's explicit authorization.

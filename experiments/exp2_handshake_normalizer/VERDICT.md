# Experiment 2B — verdict

## Primary verdict: COMPILE_PASS (model functional test not yet executed)

The standalone Tofino-1 TCP handshake normalizer **compiles cleanly** with bf-p4c 9.13.1 to a
loadable binary (`0 errors`, exit 0; `tofino.bin` + `context.json` produced). The mechanism the
Experiment 2A design specified — fixed-width `data_offset`-keyed option parse, canonical MSS,
option-region shrink to `data_offset` 6, TTL/IP-ID scrub, full IPv4+TCP checksum recompute,
fail-open everywhere, single-count telemetry — is **expressible on the target and stateless** (no
registers/meters declared, no stateful ALU allocated).

This is **not** `COMPILE_PASS_MODEL_PASS`: the tofino-model + PTF functional run was **not performed
in this turn**, so no functional/behavioral PASS is claimed. It is **not** `COMPILE_FAIL`: compile
succeeded. It is **not** `BLOCKED_ENVIRONMENT`: the compiler and the model stack are both present and
working; the model run is a deliberate, budget-bounded next step, not an environment block. The
honest state is **compile gate PASSED, functional gate PENDING** — the harness, fixtures, and exact
run procedure are committed (`MODEL_TESTS.md`, `tests/ptf/test.py`).

## What was actually established

1. **The ICE was a coding-shape problem, not a feasibility wall.** Early drafts hit a bf-p4c 9.13.1
   Internal Compiler Error (a hard, message-less crash in the final lowering pass). Bisection traced
   it to three ordinary faults that bf-p4c reports cleanly in isolation but crashes on at full
   nesting: a non-mutually-exclusive shared `Counter`; arithmetic on deparsed fields; and deep
   nested gateways carrying wide-field predicates. Each was fixed with a standard idiom (single
   indexed count; `data_offset`→length const table; 1-bit precomputed flags + range-match MSS
   clamp). Full diagnosis in `COMPILE_RESULTS.md`; the crashing source is in git history for a bug
   report. **The same mechanism then compiles.**

2. **It is stateless and small.** 29 logical tables, 5 SRAM, 1 TCAM (the range clamp), 2 MapRAM, 0
   registers, ~162-cycle ingress latency (`RESOURCE_REPORT.md`). This directly closes the
   Experiment 2A review's residual "is the `data_offset`-keyed parser fit a real compile risk"
   question: it is not.

3. **Two adversarial reviews pass at the compile gate** (`REVIEW_2B.md`), leaving two documented
   caveats: checksum correctness is asserted-by-construction until the model observes it, and
   "fail open" means "TCP options untouched," while the L3 scrub is unconditional.

## What this does NOT establish (unchanged by this experiment)

- **Functional correctness** — pending the model run (the next gate).
- **Endpoint safety** — whether real device stacks honor the negotiation fallback within the DNP3
  timing budget is Experiment 3, on ordinary TCP + isolated OpenDNP3 first, then read-only SEL-751.
- **The repository verdict.** `DECISION_MEMO.md`'s `NO_GO_FULL_TRANSCRIPT` is a *conditional*
  analytical no-go about **universal** plaintext size/count/timing/header invariance. This experiment
  is squarely on the **TCP/IP-header axis**, which that memo already lists as **UNRESOLVED / OPEN**
  with compile-and-test counterexamples. A clean compile of one such counterexample is **evidence on
  the open header question**; it does **not** overturn or weaken the size/count/timing reasoning, and
  it is not a "full transcript" result.

## Recommended next step (requires separate authorization per the gate discipline)

Run `tests/ptf/test.py` against tofino-model + bf_switchd (procedure in `MODEL_TESTS.md`) to convert
COMPILE_PASS into COMPILE_PASS_MODEL_PASS or _FAIL. Do not proceed to Experiment 3 (endpoint safety)
or any hardware step until the model gate is passed and separately authorized.

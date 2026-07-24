# Phase 2 — Generation-Safe Transaction Core (offline reference model)

**Status: OFFLINE-VALIDATED (reference model + unit tests + real-traffic replay). NOT hardware- or
relay-validated.** Produced during the 2026-07-23 bounded autonomous run while dp8 was physically
blocked (see `OVERNIGHT_RUN_20260723-2255.md`). Normative spec: `research/END_TO_END_IMPLEMENTATION_PLAN.md`
§6 Phase 2. No architecture was redesigned — this mirrors the frozen `dcrn_defense1.p4` transaction
core and adds only the generation-freshness guard that file explicitly deferred.

## What Phase 2 adds

The frozen `dcrn_defense1.p4` already implements the shared transaction core: a canonical bidirectional
CRC16 flow hash over `{client_ip, server_ip, client_port}`, one-outstanding-per-flow, exact pure-ACK
qualification (`armed && flags_ok && ack_no == request_end_seq`), and ACK-before-response ordering. What
it lacks is **generation freshness**: `reg_gen` was dropped and `hdr.bridge.gen` is hardcoded `0`
(`dcrn_defense1.p4:365,581,618`), because reading a generation register on the recirc path would need a
third MAU stage. Without it, a straggler frame left in the recirc loop from a *superseded* transaction on
the same 16-bit `flow_id` — produced by a rapid second request or a hash collision — could be released
against the wrong transaction.

Phase 2 defines the guard: every ARM bumps the per-flow generation (mod 256); each held frame is stamped
with the generation live at hold-enter; on every recirc pass a frame whose stamp ≠ the flow's current
generation is **discarded**, never released.

## Deliverables (this directory)

- `txncore_refmodel.py` — Python mirror of the per-flow transaction state machine + generation guard.
  Faithful to the frozen register lifecycle (`reg_armed`, `reg_expected_ack`, `flow_has_held_ack`,
  `reg_resp_seen`, `reg_ack_gone`); byte-preserving by construction (no field is modelled as mutated).
- `tests/test_txncore.py` — 22 unit tests (TDD; written before the model). Cover every DoD case:
  request/response correlation, physical direction, retransmission, duplicate/stale ACKs, resp-before-ACK
  (combined bypass), FIN/RST abort, timeout/fail-open release, second request while active, TCP seq
  wraparound, generation rollover (mod 256), hash-collision disambiguation, pass-through, and "no stale
  state" after each terminal transition.
- `replay_txncore.py` — drives the model over the committed physical-relay 300-poll pcap.

## Results (reproducible, offline)

```
tests/test_txncore.py     22 passed
replay_txncore.py         PASS: ARM=300, ACK_HELD=300, RESP_HELD=300, ACK_RELEASED=300,
                          RESP_RELEASED=300, STALE_DISCARD=0, residue=0, single flow
```

The replay confirms the transaction core arms exactly 300 transactions, holds each request's qualifying
outstation ACK, admits each response behind its ACK, drains every held frame, and leaves no residual
state — over real relay traffic, with the same DNP3 application + function-code gate the shadow classifier
uses (a short link-layer frame does not arm; only a function-code READ does). Generation freshness never
has to fire on this well-ordered single-flow trace; its behavior is covered by the collision and
second-request unit tests, where a stale straggler is discarded rather than misreleased.

## "Fits a variant" — measured (see COMPILE_FIT_RESULT.md)

Compiled three programs locally on `bf-p4c 9.13.1` (Tofino-1, 12 ingress stages):
- FROZEN `dcrn_defense1.p4`: compiles, **12/12** stages (zero headroom — confirms the plan).
- `dcrn_defense1_gen.p4` (generation **carried**: bump@arm + stamp@hold-enter, replacing hardcoded
  `bridge.gen=0`): **compiles, still 12/12** (`reg_gen` at stage 5). Saved here as a real artifact.
- generation **enforced** (recirc `reg_gen` read + staleness flush): **does NOT fit** — table-placement
  failure against `reg_armed`/`reg_expected_ack` (verbatim error in `evidence/`). This is the compact
  redesign the plan predicted; it is a human-gated architecture decision (red-line #8), not done here.

So Phase-2 logic is offline-complete and the generation is compilable-as-carried; **enforcement on
silicon is the measured boundary** and the first task of the gated Phase-3 fold.

## What remains (gated / not done here)

- The compact redesign to make freshness **enforcement** fit (Phase-3 fold into the Defense-1 variant).
- No hardware or relay validation — dp8 is physically blocked (intermittent link). Nothing in this report
  is silicon-verified.

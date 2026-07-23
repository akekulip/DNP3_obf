# DNP3 Size-Pattern Builder v1 — Report

Off-switch, trace-grounded tooling that puts the queue implementation back on its locked joint
size-and-time path (`CASE_A_QUEUE_DESIGN.md §0`, `QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md §0.5`).
**No switch was touched, reloaded, or reconfigured; `pat_state` was not programmed.** Nothing about
Defense 1/2 was changed here.

- Date: 2026-07-22

## Preserved state (Step 1)
- Branch `research/caseA-ditto-queue`, HEAD `49c1b0b`.
- Loaded queue microbench: `queue_microbench.p4` sha256 `0239af8f58d8…`, binary `fbddefa750827ebf`,
  running under `bf_switchd` on `/home/decps/queue_microbench/out/queue_microbench_abs.conf`,
  in its safe **cover=OFF, metronome=OFF, telemetry_enable=0** state (left UNTOUCHED).
- Compilers: off-switch `bf-p4c 9.13.1 (e558d01)`; on-switch `bf-p4c 9.13.2`.
- Defense-2 telemetry banked: tag `d2-telem-v1-verified` = commit `49c1b0b`; on-switch 9.13.2
  compile-parity PASS (10/12 stages, identical resources). No further Defense-2 work done.
- Not committed/modified: `split_server.py`, Defense 1/2 sources, archived experiments.

## What was built (deliverables)
| File | Role |
|---|---|
| `extract_inventory.py` | Step 2 — per-packet inventory from the real captures |
| `packet_inventory.{json,csv}` | normalized dataset (schema 1.0.0, 9415 records) |
| `generate_candidates.py` | Steps 3–4 — deterministic size-state + per-mode schedule generator |
| `queue_pattern_candidates/{maxonly,quant2,quant3}.json` | candidate patterns (versioned) |
| `evaluate_candidates.py` + `evaluation.json` | Step 5 — joint (P,τ,cover,window) scoring + ranking |
| `queue_microbench_setup.py --pattern-json` | Step 6 — dry-run plan printer (no switch writes) |
| `test_pattern_builder.py` | Step 7 — 6 unit tests (READ, separate-ACK, synthetic SBO) — **all pass** |

## Trace-grounded findings (Step 2)
- Captures: `Traffic Trace/{SEL751,AB1400,ION7550}.pcap`. Roles from parsed DNP3 function codes
  (0x0564 framing); the **SEL-751 flow cross-checks the Zeek `dnp3.log` exactly**
  (READ 198 / DIRECT_OPERATE 400 / RESPONSE 598).
- **Separate vs combined confirmed on the wire:** SEL-751 emits **304 outstation pure-ACKs**
  (separate-ACK) vs **3–4** for AB1400/ION7550 (combined).
- The real traffic is **READ + DIRECT_OPERATE only** — no SELECT/OPERATE/SELECT-confirm/
  OPERATE-confirm/application-CONFIRM appear. Those roles are **marked absent, not inferred**; SBO is
  exercised only by a **synthetic** unit test.
- **Empirical wire sizes:** min 54 B, p50 88 B, p90 115 B, **max 127 B** — small frames. Size states
  are derived from these raw values (never illustrative 128/256).

## Candidate patterns and joint evaluation (Steps 3–5)
Transaction cadence measured ~1 txn/s; RTO ceiling 211 ms; overhead = padding at 1 txn/s (cover=OFF).

| Candidate | States (B) | mean pad | p99 pad | size-leak (bits) | cover=OFF overhead | fits loaded P4? | rank |
|---|---|---|---|---|---|---|---|
| **maxonly** | [127] | 41.4 B | 73 B | **0.00** | 1.99 kbps/dir | **yes (1 of 2 real queues)** | **1** |
| quant3 | [88,115,127] | 16.7 B | 34 B | 1.58 | 0.80 kbps/dir | **no — needs 3rd real queue** | 2 |
| quant2 | [115,127] | 30.4 B | 61 B | 1.00 | 1.46 kbps/dir | yes (2 real queues) | 3 |

- Ranking objective (explicit): `score = 1·mean_pad_B + 20·size_leak_bits` (lower better) — makes the
  padding-vs-size-leak tradeoff visible. All candidates are **feasible even on a 64 kbps link**
  (overhead < 2 kbps/dir) and **RTO-safe** for cover=OFF (deadline 17–60 ms ≪ 211 ms).
- **Residual distinguishability after size mapping:** direction is always observable (hidden only by
  both-direction cover); **device ACK-mode still separates SEL-751 (separate) from AB1400/ION7550
  (combined)** — out of size-normalization scope; READ vs DIRECT_OPERATE are **count-equal** (same
  6-slot shape → no TRANSACTION_WINDOW filler needed to equalize them).

## Strongest candidates (recommendation)
1. **`maxonly` (single 127 B state)** — the strongest for the immediate cover=OFF scope: **zero size
   leakage**, ~2 kbps/dir overhead, and it **fits the loaded P4** (needs 1 of the 2 REAL queues). This
   is the "pad everything to the largest frame" pattern the design calls for on the Tofino-only path.
2. **`quant2` (115/127)** — the fallback if padding must be minimized while still fitting the 2-queue
   P4: 1 bit of residual size info, ~30 B mean padding. At these tiny rates the padding saving is
   negligible, so `maxonly`'s zero-leak is preferred.
3. `quant3` is the lowest-padding option but leaks 1.58 bits AND exceeds the loaded P4's 2 real
   queues — not runnable without a recompile.

## Exact remaining blockers before a real switch run
1. **The loaded P4 pads to COMPILE-TIME sizes (128 B / 256 B via `pad_s1_h`/`pad_s2_h`), not the
   empirical targets.** Realizing any data-derived pattern (e.g. pad-to-127 B) requires changing the
   P4's filler header widths → **a recompile**. Runtime `pat_state` selects the state ORDER, but the
   pad TARGET bytes are fixed in the dataplane.
2. **Real DNP3 classification is absent.** The loaded P4 classifies by synthetic **UDP dport**;
   mapping real DNP3/TCP packets to states needs TCP/DNP3 classification in the P4 → new dataplane
   work (and it must be byte-preserving).
3. **>2 states need another REAL queue** (P4 provides `QID_REAL_S1/S2`) → recompile (blocks `quant3`).
4. **Timing is not from the queue.** The size builder is size-only; the joint pattern's timing/CLRT
   still comes from the recirc-hold defense (dcrn), per the locked architecture. This tooling does not
   change that and makes no timing claim.
5. **Switch load is gated** and would displace the running queue microbench; the agreed restore target
   is the **queue microbench** (not `decoy_paper3`).
6. TRANSACTION_WINDOW / CONTINUOUS cover, the window state machine, encrypted outer encapsulation, a
   receiving sanitizer, and both-direction count/direction equalization are **not built** (out of
   tonight's scope) — required before any READ-vs-SBO indistinguishability claim.

## Scope statement
This is the off-switch size-pattern builder v1 only. It does **not** implement the transaction-window
state machine, encrypted outer encapsulation, a receiving sanitizer, secure cover generation,
ACK-ordering changes, flow-aware P4 state, or any switch load, and it does **not** by itself complete
the locked joint size-and-time architecture — it produces trace-grounded candidate patterns and a
dry-run plan for review.

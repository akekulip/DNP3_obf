# Part 3 — finite-backlog dequeue-order oracle: STRICT_PRIORITY_CONFIRMED

**The corrected `max_priority` produces absolute strict-priority dequeue ordering on Tofino-1
silicon.** Proven with the on-chip dequeue-order oracle (which makes µs-scale scheduler ordering
observable — the measurement limit that blocked the earlier attempts). [OBS/REP]

## Setup
- Program `ibspg_dequeue_oracle` (sha `eeb6de94…`), on-switch 9.13.2, 3 ingress stages, SALU 5, TCAM 0.
  Bounded trace: monotonic `reg_event_ctr` → `trace_role/seq/ts[512]` at a dynamic index, `reg_overflow`.
  Each looped-back packet (`ingress_port==PORT_L=dp8`) has just DEQUEUED → recorded (role, seq,
  `ingress_mac_tstamp[31:0]`) and dropped (single pass). `trace_role[0..event_ctr-1]` in index order
  **is the dequeue order.**
- Loopback L = dp8 (pg2). Q_BLOCK qid7, Q_HOLD qid1. **No ring, no pass-budget loop** — finite
  preloaded backlogs only.
- **Simultaneous release** (the load-bearing methodology fix): per-queue scheduling-enable has a driver
  gap that lets Q_BLOCK fully drain before Q_HOLD is enabled (biasing every config to look "strict").
  Solution — gate the shared **port** with `tf1.tm.port.sched_shaping` max_rate=1 PPS +
  `port.sched_cfg max_rate_enable`: throttle → BOTH queues pile; release → BOTH queues eligible at the
  same instant, so the SCHEDULER (priority) decides. Verified: with the port throttled, preload piled
  Q_BLOCK use≈28, Q_HOLD use≈30 (queue-resident, 0 drop).

## A/B/A result (N=32 Q_BLOCK backlog + M=32 Q_HOLD, port-gated release)
| Config | max_priority (B/H) | representative order | longest B-run | transitions | verdict |
|---|---|---|---|---|---|
| **A** equal | LOW / LOW | `BBHBHBHBH…` | 2 | 61 | INTERLEAVED (DWRR) |
| **B** corrected | **HIGH** / LOW | `BBBBBBBB…(32) HHHH…(32)` | 32 | 1 | **STRICT** |
| **C** reversal | LOW / LOW | `BHBHBH…` | 1 | 63 | INTERLEAVED |

Equal → interleaved, corrected → strict, reversal → interleaved: the behavior tracks `max_priority`
exactly and reverses cleanly.

## Repetition campaign (N=32, M=32, port-gated)
- **Config B (corrected, `max_priority=HIGH`): 20 / 20 reps STRICT, 0 overflow.**
- **Config A (equal, LOW/LOW): 15 / 15 reps INTERLEAVED.**
- Switch healthy throughout; restored to `queue_microbench_abs.conf` after.

## Classification: **STRICT_PRIORITY_CONFIRMED**
- The corrected `max_priority=HIGH` on Q_BLOCK makes **every** Q_BLOCK packet dequeue before **any**
  Q_HOLD packet while both are backlogged and eligible (20/20). No HOLD ever preceded the last BLOCK.
- Equal `max_priority` interleaves via DWRR (15/15) — confirming the oracle discriminates and that the
  prior fair split was the equal-`max_priority`/equal-DWRR configuration, exactly as the root-cause
  audit stated.
- This retires, on silicon, the earlier "strict priority not absolute" reading: it was the
  configuration error, not the hardware.

## What this unlocks
U1 (dequeue order at µs scale) is resolved. Per the directive gate, the blocker-ring / empty-gap work
(Parts 4–11) may now proceed: the residual problem is keeping Q_BLOCK **continuously** non-empty via a
self-replenishing blocker (loop timing → empty-gap model → corrected constructions → no-drain hold →
matched drain → paired ACK-before-response), NOT the retired priority-config error.

## Evidence notes
- `reg_overflow=0` in all reps (trace never truncated). `event_ctr` = N+M each rep.
- The oracle reader's counter-read path had a target bug (irrelevant to the verdict — the trace
  registers are read directly with the proven `$REGISTER_INDEX` idiom); note for a later reader fix.

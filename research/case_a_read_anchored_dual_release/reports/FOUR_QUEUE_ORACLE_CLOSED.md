# Four-queue dequeue oracle — CLOSED at commit `6ffd5e5`

**This work is closed. Do not modify or re-run the four-queue oracle.**

## Accepted claim

> Four-level strict-priority dequeue ordering was behaviorally established on Tofino-1 under
> finite simultaneous backlog.

## Evidence basis

| control | observed |
|---|---|
| **B1, B2** (two randomized `packet_id`→role mappings) | `ABLOCK → ACK → RBLOCK → RESPONSE` |
| **C** | reversing **only** `max_priority` exactly reversed the dequeue order |
| **D** | tied ABLOCK/ACK queues interleaved while RBLOCK and RESPONSE remained strictly below them |

C is the causal control: generation, `packet_id`→role mapping and qid numbering were all held
constant, so the reversal cannot be attributed to emission order or queue numbering.

## Control A did NOT pass — do not claim otherwise

Control A was never validly executed. It is not part of the evidence basis, and D's interleaving
result is a substitute argument for the equal-priority expectation, not a pass for A.

### Final attempted Control A re-run — recorded as INVALID

- second-trial preload had **zero pre-release dequeues** (confirming the first-trial warm-up
  effect: 4, 5 and 6 escapes when A ran first across three earlier runs);
- **dp8 was incorrectly left at `BF_SPEED_10G`** — every run that produced a trace had dp8 at
  `BF_SPEED_25G`. Cause: the priming batch and Control A were driven by calling the setup script
  directly over SSH rather than through the runner, and the runner is what restores dp8's full
  original parameters including `scheduling_speed`;
- **no packets dequeued after release** — `total_dequeues = 0`, `trace_entries_written = 0`, empty
  trace, despite a textbook preload (trigger 1, 128 packets, 32 enqueued per role, zero escapes,
  zero drops, one-write release);
- **no scheduler conclusion was drawn** from it;
- **Defense 2 was restored successfully**, all five facts verified.

Per instruction, **no new runner mode was added to repeat Control A**, and the oracle was not
modified or re-run.

## Not claimed

Recirculating reservoir safety · K=64 minimality · deadline correctness · DNP3 transaction
correctness. Reservoir depth and recirculation empty gaps remain separate evidence.

Evidence: `evidence/four_queue_oracle/pilot5_20260729T150237Z/`,
`shaper_sweep_20260729T140201Z/`, `A_equal_second_trial.json`.
Result write-up: `FOUR_QUEUE_DEQUEUE_ORACLE_RESULT.md`.

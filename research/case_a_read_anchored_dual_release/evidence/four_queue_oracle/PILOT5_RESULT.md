# Five-control pilot — STOP. Two distinct defects; no control is interpretable.

2026-07-29T01:37Z, `pilot5_20260729T013714Z`. 5 controls run, **0 clean**. Restore verified on all
five facts including `dp8 shaping restored`.

Per the stop conditions: *"any packet dequeued before the common release"* and *"any queue was not
simultaneously backlogged"* both fired. **Do not scale to the 160-trial campaign.**

## What DID work — the mechanism is close

Control A, the first trial on a clean switch, produced a genuine preload:

| Fact | Observed |
|---|---|
| pktgen fired | `trigger_counter=1, batch_counter=1, pkt_counter=128` |
| enqueued per role | ABLOCK 32, ACK 32, RBLOCK 32, RESP 32 — **exactly 32 each** |
| all four queues backlogged | usage_cells 31 / 32 / 30 / 31 — **simultaneous** |
| queue drops | 0 |
| misrouted / unclassified | `drop_bad_port=0, drop_non_oracle=0, drop_bad_id=0` |
| role map | 128 entries, exactly 32 per role, seed recorded |
| gate | PPS rate=1 burst=0, armed and still closed at the preload check |

Timer-triggered in-switch generation, the 128-entry `packet_id`→role map, the four-queue enqueue,
the occupancy evidence and the trap-controlled restore all work. **No external dependency was
involved at any point** — no dp11, no Hulk, no capture host, no capabilities.

## Defect 1 — the dp8 port shaper leaks ~4 packets

Control A: `event_ctr_before_release = 4`, expected 0. Occupancy summed to 124; 124 + 4 = 128.
The four missing packets escaped and were traced **while the gate was armed and verified closed**
(`max_rate_enable=True, unit=PPS, max_rate=1, max_burst_size=0`, confirmed by readback both after
close and at the preload check).

Four packets in the ~3.3 ms generation window is ~1200 pps against a configured 1 pps, so the
shaper is not limiting during that window. This is the **burst-credit floor** flagged as the
make-or-break unknown for this construction: `max_burst_size=0` is *accepted and reads back as 0*,
but the hardware evidently still permits a small burst. Now quantified rather than suspected.

## Defect 2 — trials are NOT independent (this is the one that invalidated B1–D)

The cumulative on-chip `traced` counter is decisive:

| control | traced | delta | backlog at preload | escapes |
|---|---|---|---|---|
| A equal | 4 | 4 | **124** | 4 |
| B1 ladder | 256 | **252** | 0 | 0 |
| B2 ladder | 384 | 128 | 0 | 0 |
| C reversed | 512 | 128 | 0 | 0 |
| D tied | 640 | 128 | 0 | 0 |

**B1's delta of 252 = A's 124 leftovers + B1's own 128.** Control A ended INVALID with
`released=False`, so its 124 backlogged packets were never drained — and they were still sitting
in the queues when B1 began. Once the gate state changed they flushed together with B1's batch.

From B1 onward every trial reads backlog 0: each generated its 128 (the `enq_*` counters advance
by exactly 32 per role per trial, cumulatively 64→96→128→160), but the packets did not stay
parked. **There is no inter-trial cleanup**, so a trial that ends without release contaminates
every trial after it.

Note also that `traced` reached 640 against `TRACE_LEN = 512` — the trace array wrapped, though
`trace_overflow` still read 0, which is worth checking on its own.

## Consequence for interpretation — nothing can be concluded

- **A is uninterpretable**: only 4 events were traced, far too few to judge DWRR interleaving.
- **B1, B2, C, D are uninterpretable**: their queues were empty at the preload check, so whatever
  drained was not a controlled simultaneous backlog.
- **C in particular proves nothing yet**, and C is the causal control the whole design rests on.

No claim about strict-priority scheduling is supported by this run, in either direction. The
`max_priority` values read back correctly in every control (4/4/4/4 for equal, the ladder for
B1/B2, and so on) — but as the setup's own WARN says, *readback shows what was written; the
behavioural verdict comes from the trace*, and the trace is not usable here.

## Required fixes before re-running

1. **Inter-trial cleanup, and it must be verified, not assumed.** Between trials: open the gate,
   wait for the queues to drain, then assert `usage_cells == 0` on all four **and**
   `reg_event_ctr == 0` **and** reset the cumulative P4 counters — before the next trial is
   allowed to start. A trial must refuse to run on dirty queues.
2. **Close the gate leak.** The microbenchmark that sweeps `PPS:1:0, PPS:1:1, PPS:0:0, BPS:1:0,
   BPS:1:1` was built for exactly this and has not yet been run — run it before changing the
   architecture. If no configuration yields zero escapes, that is the evidence that justifies the
   predefined **`Q_GATE`** fallback (a fifth, highest-priority queue drained by one register write),
   which does not depend on shaper burst behaviour at all.
3. **Trace geometry**: `traced` reached 640 > `TRACE_LEN` 512 while `trace_overflow` read 0.
   Either the overflow detection or the wrap guard needs checking before the trace is trusted.

## Restore

```
PASS  p4_name                    dnp3_timing_normalizer_pktgen
PASS  strict_priority_verified   true
PASS  app_enable                 false
PASS  exactly one bf_switchd     1
PASS  dp8 shaping restored       true
```

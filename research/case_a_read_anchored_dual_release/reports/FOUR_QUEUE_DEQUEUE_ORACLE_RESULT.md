# Four-queue dequeue oracle — RESULT: strict priority scheduling PROVEN on silicon

2026-07-29T15:02Z. Evidence: `evidence/four_queue_oracle/pilot5_20260729T150237Z/`.
Gate: **PPS:0:0** on the dp8 port shaper, released by exactly one `max_rate_enable=false` write.
Equal-priority sweep established that gate on 2026-07-29 (`SHAPER_SWEEP_RESULT.md`).

## Summary

| control | mode | verdict | observed dequeue order |
|---|---|---|---|
| A | all equal | **INVALID** (gate refused — see below) | not released |
| B1 | ladder 7>6>5>4 | **PASS** | `ABLOCK ×32  ACK ×32  RBLOCK ×32  RESP ×32` |
| B2 | ladder, different mapping | **PASS** | `ABLOCK ×32  ACK ×32  RBLOCK ×32  RESP ×32` |
| C | reversed ladder | **PASS** | `RESP ×32  RBLOCK ×32  ACK ×32  ABLOCK ×32` |
| D | ABLOCK=ACK > RBLOCK > RESP | **PASS** | `ACK ABLOCK ACK ABLOCK …` (63 transitions) then `RBLOCK ×32  RESP ×32` |

**4 PASS, 0 FAIL, 1 INVALID.**

## The causal result — control C

C is the control the whole design rests on. Same packet generation, same `packet_id`→role
mapping, **only `max_priority` reversed** — and the observed order reversed exactly:

```
B1  ABLOCK ×32   ACK ×32   RBLOCK ×32   RESP ×32
C   RESP   ×32   RBLOCK ×32   ACK ×32   ABLOCK ×32
```

That is not reproducible by pktgen emission order, by qid numbering, or by the role mapping — all
three were held constant. **The trace tracks Traffic Manager scheduling.** This is the
discrimination that the original `min_priority` bug defeated, and it now passes.

## Control D supplies the evidence control A was meant to give

D ties ABLOCK and ACK at priority 6 above RBLOCK (5) above RESP (4). The tied pair **interleaves
packet-by-packet** — 63 transitions within the class, where a blocked pattern would show 1 — while
the lower groups form clean single blocks of 32 and never overtake:

```
ordering   PASS max(pos(ABLOCK)) < min(pos(RBLOCK))   max=63 min=64
ordering   PASS max(pos(ACK))    < min(pos(RBLOCK))   max=62 min=64
ordering   PASS max(pos(RBLOCK)) < min(pos(RESP))     max=95 min=96
interleave PASS class {ABLOCK/ACK} (priority 6) interleaves   63 transitions
blocking   PASS RBLOCK forms one block   longest run 32 of 32
blocking   PASS RESP   forms one block   longest run 32 of 32
```

So **equal priority demonstrably does NOT produce role blocks** — which is precisely what control A
was designed to show. The interpretation criterion "A must not consistently produce the same strict
four-role ordering as B" is satisfied in substance by D, on the same silicon, in the same run.
**Stated plainly: A itself did not run, and D is the substitute argument, not a pass for A.**

## Why control A is INVALID — the gate did its job

A recorded `total_dequeues_before_release = 6`, so the preload gate refused and **the release was
never performed**. No misleading trace was produced. Every other precondition was met
(trigger 1, 128 packets, 32 enqueued per role, zero drops, gate armed).

This is a **first-trial-after-load warm-up artifact**, consistent across three independent runs:

| run | first trial of the run | escapes |
|---|---|---|
| 2026-07-28 pilot5 | control A | 4 |
| 2026-07-29 sweep | PPS:1:0 screening | 5 |
| 2026-07-29 pilot5 | control A | 6 |

In every run the **first** trial after a fresh program load leaked a handful of packets, and every
subsequent trial leaked exactly zero. The fix is trivial — discard or repeat the first trial after
a load — and it is not a property of equal priorities. **A should simply be re-run as a non-first
trial before the campaign.**

## Integrity — clean on all four released trials

```
total_dequeues / trace_entries_written / trace_overflow   = 128 / 128 / 0
per role                                                  = 32 / 32 / 32 / 32
zero duplicate pkt_id, zero unknown roles, zero stale trial_ids
on-chip role matches the control-plane map: 0 mismatches
zero TM queue drops
preload gate satisfied, zero escapes before release, release performed
```

The three-value trace accounting and the trial-isolation cleanup both work on silicon. The
contamination that invalidated the 2026-07-28 pilot did not recur: every trial started clean.

## Restore

```
PASS  p4_name                    dnp3_timing_normalizer_pktgen
PASS  strict_priority_verified   true
PASS  app_enable                 false
PASS  exactly one bf_switchd     1
PASS  dp8 shaping restored       true
```

## What this establishes, and what it does not

**Established:** the Tofino-1 Traffic Manager serves `Q_ABLOCK(7) > Q_ACK(6) > Q_RBLOCK(5) >
Q_RESP(4)` in strict priority, behaviourally, on a finite simultaneous backlog released by one
common gate — proven causally by reversal, not merely by a `max_priority` readback.

**Not established:** anything about reservoir depth (K) or recirculation empty gaps — those remain
separate evidence and this result must never be read as vindicating K=1. Nothing here exercises
the deadline logic, the DNP3 parser, or the dual-reservoir readiness test.

**Before the 160-trial campaign:** re-run control A as a non-first trial so the equal-priority
negative control stands on its own rather than by substitution.

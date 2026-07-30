# The repaired build against the physical SEL-751

**2026-07-30. `case_a_defense3_repair_candidate`, live build with R1 + R3 and full
telemetry — 11/12 ingress stages, critical path 10, compiled on the switch with
bf-p4c 9.13.2 (identical to the local 9.13.1 result).**

Everything in `REPORT.md` §10–§11 was measured on the build carrying both state-ordering
defects. R1 had been validated only in the synthetic build, where every packet is generated
inside the chip. This is the repaired **live** build against the real relay — the one thing
the repair had not been subjected to.

**960 attempted transactions, 960 responded, 0 unanswered.** Same six arms, same
interleaving, same 200 ms poll gap, same D values as the original campaign; only the build
and the polls-per-block changed (40, was 20). The switch was returned to the conf it was
found on and verified: one `bf_switchd` on `d3_abs.conf`.

## The comparison that matters: does R1 change the live path?

| arm | READ→ACK median, **repaired** | original | difference |
|---|---|---|---|
| native | 0.457 ms | 0.453 ms | +4 µs |
| d1 | 1.519 | 1.514 | +5 µs |
| d2 | 2.517 | 2.515 | +2 µs |
| d4 | 4.514 | 4.508 | +6 µs |
| d8 | 8.587 | 8.519 | +68 µs |
| d16 | 16.510 | 16.509 | +1 µs |

**The hold is unchanged.** At five values of D spanning 1 to 16 ms the realised
READ→ACK median moves by 1–6 µs, against a hold of 1–16 ms. The one larger difference,
68 µs at D = 8, sits inside this session's own noise (see below). R1 adds a table and a
dependency level inside the chip; on the wire it is invisible.

## The CLRT result reproduces

| arm | D | CLRT med | CLRT sd | CLRT max | collapsed <0.1 ms | sep vs native |
|---|---|---|---|---|---|---|
| native | — | 2.843 | 3.504 | 17.204 | 0/160 | — (floor **0.582**) |
| d1 | 1 | 1.780 | 3.193 | 15.368 | 0/160 | 0.702 |
| d2 | 2 | 0.772 | 2.831 | 13.462 | 39/160 | 0.776 |
| d4 | 4 | **0.033** | 2.635 | 20.964 | 117/160 | 0.893 |
| d8 | 8 | **0.032** | 1.394 | 16.990 | 155/160 | 0.989 |
| d16 | 16 | **0.031** | **0.011** | 0.049 | **160/160** | 1.000 |

At D = 16 ms: median 0.031 ms, sd 0.011 ms, max 0.049 ms, all 160 collapsed — against the
original run's 0.032 / 0.012 / 0.047 and 80/80. The headline compression reproduces on a
different build, a different session and twice the sample.

**And it is still a distribution, not a constant**: 22 distinct CLRT values at D = 16, only
38 of 160 within ±0.5 µs of the median, 17 at or below the 1 µs capture resolution.

## The mechanism, over 800 defended transactions

| measurement | value |
|---|---|
| ordering invariant (ACK committed before the RESPONSE) | **960 / 960**, every arm 160/160 |
| tokens admitted across the campaign | **+51 200** = 800 defended × 64, exactly |
| tokens terminating on the deadline | equal to tokens admitted, at every read |
| stale terminations | **0** |
| budget expiries / fail-open | **0** |
| duplicate suppressions | **0** |
| queue drops (qid1, qid7) | **0** |

The token arithmetic is worth stating plainly because it is an exact check rather than an
approximate one: the admitted counter rose by 51 200 over the campaign, and 800 defended
transactions × 64 tokens is 51 200.

## What this session says that the first one could not

**The fail-open margin is confirmed thin.** Recomputed from this campaign's own worst-case
ACK latencies: 5.51× at D = 1, 5.30× at D = 2, 3.63× at D = 4, 2.84× at D = 8 and
**1.59× at D = 16** — against the original campaign's 1.49×. Two independent sessions now
agree that §6.3's original 8.8× was wrong and that the true headroom at D = 16 is under 2×.
The `D_MAX = 40 ms` clamp remains arithmetically infeasible against H = 30.802 ms.

**Block-clustered intervals** (bootstrap resampling connections, 4 000 resamples):

| arm | READ→ACK separability (95 % CI) | CLRT separability (95 % CI) | leave-one-round-out balanced accuracy |
|---|---|---|---|
| d1 | 0.880 (0.849 – 0.909) | 0.702 (0.657 – 0.744) | **0.903** |
| d2 | 0.921 (0.891 – 0.949) | 0.776 (0.737 – 0.817) | **0.950** |
| d4 | 0.994 (0.983 – 1.000) | 0.893 (0.852 – 0.954) | **0.991** |
| d8 | 1.000 | 0.989 (0.968 – 1.000) | **1.000** |
| d16 | 1.000 | 1.000 | **1.000** |

The central negative result is unchanged and, if anything, sharper: **READ→ACK — the
feature the defense creates — is more separable than the CLRT it removes at every single D**,
and a leave-one-round-out classifier reaches 0.903 even at the sub-threshold arm.

## An honest caveat about comparing the two sessions

**This session's relay was noisier.** The native arm's CLRT standard deviation was 3.504 ms
against 2.854 ms before, its maximum 17.204 ms against 13.175 ms, and the native-versus-native
drift floor rose from 0.530 to **0.582**. The d4 and d8 arms carry visible tails
(CLRT maxima of 20.964 and 16.990 ms) that the first campaign did not have, which is why
their separability reads *lower* here (0.893 and 0.989 versus 0.966 and 1.000) despite an
identical mechanism.

So the cross-session differences in the separability column should **not** be attributed to
R1. They are what the campaign design was built to guard against — it is exactly why arms
are interleaved and every comparison is made within a session. The within-session
comparisons above are sound; the between-session ones are not, and no claim here rests on
them.

## What this establishes, and what it does not

**Established.** The repaired live build runs against the physical relay with the hold
governed by D as before, the CLRT compression reproduced, the ordering invariant held
960/960, and every mechanism counter clean over 800 defended transactions. R1 costs nothing
observable on the wire.

**Not established.** R1's *repair* is not exercised by this campaign: the relay never sent a
mis-sequenced response, so the authorisation table's rejecting arm never fired
(`RESP_DUP_SUPP = 0`, as in the original). What this run shows is that R1 **does no harm on
the live path** — the negative result that had to be obtained before the repair could be
trusted. The repair's positive behaviour is demonstrated in the synthetic build
(`evidence/repaired/RESULTS.md`), where a mis-sequenced response can be injected on demand.

**R3 likewise remains unexercised**: no test injects an `0x88C1` frame from a host port.

**Defect 2 is still open** and unaffected by any of this.

## Files

| file | what |
|---|---|
| `20260730T194855Z/dsweep_blocks.jsonl` | 24 blocks, 960 per-transaction wire rows |
| `20260730T194855Z/dsweep_analysis.json` | the sweep tables above |
| `20260730T194855Z/observer_analysis.json` | per-feature separability + held-out classifier |
| `20260730T194855Z/blocked_analysis.json` | block-clustered CIs, leave-one-round-out |
| `20260730T194855Z/pcaps/` | 24 per-block captures at the master |
| `20260730T194855Z/setup.log` | the live control-plane configuration, 0 FAILs |
| `20260730T194855Z/{pre,post}_state.txt` | the switch conf before and after |

Reproduce: `run/live_r1_campaign.sh` (loads the repaired build, configures the live path
with `--arm-blockers`, checks the relay is reachable *before* measuring, runs the campaign,
pulls the captures, restores).

# Blocker drain time — measured 2026-09-15

How long the defense's blocker reservoirs take to empty after one transaction arms them, measured
on the loaded `defense4_rrc_bor_unified12` binary with D_A = 20 ms, D_R = 4 ms, budget B = 18000.

## The two domains drain independently

The design puts the blocker reservoirs on two separate loopback ports with their own egress
schedulers, so they drain **concurrently**, not one after the other:

| domain | loopback | queues | seeded by |
|---|---|---|---|
| RRC (ACK and RESPONSE blockers) | dp8 | qid7, qid5 | any READ or SELECT |
| BOR (OPERATE blockers) | dp10 | qid3 | only a SELECT, which opens the BOR epoch |

A plain READ never seeds dp10: its OP-range tokens read `epoch == EPOCH_NONE` and are dropped.
Measuring the OPERATE domain therefore needs a SELECT. **No OPERATE was ever sent** — SELECT arms
but does not actuate, so no relay binary output was driven.

## Result

| domain | frames per arm | frame size | drain time | matches |
|---|---|---|---|---|
| RRC (dp8) | 907,908 – 945,420 (varies) | 64 B | **24.4 ms** | D_A + D_R = 24 ms |
| BOR (dp10) | 1,152,064 (bit-exact, every run) | 64 B | **31.0 ms** | 64 x 18,001 orbits, B = 18,000 |

**Time to drain all blockers is set by the slower domain: about 31 ms.**

The two differ in kind, which the counts make obvious. The RRC count varies run to run, so that
reservoir is **deadline-bounded** and stops when the release budget expires. The BOR count is
bit-identical on every run at exactly 64 x 18,001, so that reservoir is **budget-bounded** and
stops after the configured pass budget B = 18,000 is exhausted, K = 64 tokens per orbit.

## Method and why the numbers are trustworthy

Drain time is computed from the byte count at line rate, because polling the counters over gRPC
has only about 6-11 ms resolution and a ~30 ms burst is too short to time by polling alone. Both
loopbacks run at 25 Gb/s, and each frame costs 64 B plus the 8 B preamble and 12 B interframe gap,
so 84 B = 672 bits per frame.

    1,152,064 frames x 672 bits / 25e9 bit/s = 30.97 ms

That conversion assumes the orbit saturates the loopback. It was checked directly rather than
assumed: polling dp10 at a 6.38 ms median interval bracketed the burst at **31.4 ms**, against the
computed **30.97 ms**. The two agree to 0.4 ms, well inside one poll interval, so the reservoir is
confirmed to run at line rate and the conversion holds.

`dp10_bor_poll.txt` and `dp8_rrc_poll.txt` are the raw poll series, one `timestamp count` pair per
line. `drain_exact.py` reads the exact per-arm frame and octet deltas; `drain_poll10.py` is the
fast single-port poller; `select_only.py` and `txn.py` are the master-side triggers.

## Caveat

The on-chip timestamp registers that would have given the drain interval directly
(`reg_ts_first_block`, `reg_ts_block_term`, `reg_ts_ack_arm`, `reg_ts_ack_release`) are **inert in
this binary** — declared, but with no execute site, the same defect the campaign binary has. That
is why the drain had to be inferred from port counters at all. A direct on-chip measurement needs
a new build, and therefore a new binary hash.

These measurements are **not** part of `campaign_v1` and no paper claim rests on them.

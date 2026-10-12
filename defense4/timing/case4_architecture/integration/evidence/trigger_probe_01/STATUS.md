# Trigger / stale-token runaway appears only when hold AND blocker queues are both shaped (2026-10-12)

Question: why do shaped production runs show READ generator triggers of 826-3,499 (and OUT_TOKEN_STALE ~22-27k) for
50 READs, against 64 triggers / 0 stale unshaped? Probes on build close_reset_fix_01, T on, 5 ms fixture, fresh cold
bring-up each, shaped = all six hold+blocker queues at 14,892 PPS (blocker burst 64).

| probe | READ triggers | generated pkts | OUT_TOKEN_STALE |
|---|--:|--:|--:|
| shaped, installed, **10 s idle, no traffic** | 0 | 0 | 0 |
| shaped, 1 READ + SBO | 1 | 4 | 0 |
| shaped, 5 READs + SBO | 5 | 20 | 0 |
| shaped, 10 READs + SBO | 1,449 | 5,796 | 26,656 |
| shaped, 20 READs + SBO (close_silicon_01) | 3,411 | 13,644 | 26,814 |
| unshaped, 20 READs + SBO | 34 | 136 | 0 |

`table_all_snapshots.txt` tabulates every snapshot pair in the evidence tree (reads, achieved hold/blocker rate,
triggers, stale): hold-only shaping (blockers unshaped) 24-25 triggers / 0 stale; blocker-only shaping (50,262 PPS
ACK blocker) 25 / 0; unshaped 23-34 / 0; **both shaped 826-3,747 triggers / 21,885-27,007 stale**. Stale saturates near
22-27k independent of READ count and rate.

T state read after the shaped 10-READ run (`regdump.py`, p1.t_Ingress registers): gen_alloc_reg 11, op_gen_alloc_reg 2,
cur_epoch_reg 1, ack_commit_gen_reg 10, resp_done_reg 10, ack_done_reg 10, op_done_reg 1, quarantine_reg 1. T admitted
exactly 10 READs and 1 OPERATE, so the extra triggers are not new-generation admissions.

## What this says

- No self-sustaining loop at idle. Clean 1:1 trigger-per-READ behaviour at 1 and 5 READs. The runaway starts between
  5 and 10 READs and only when both queue classes are shaped.
- Consequence for earlier results: in both-shaped runs most generated tokens are dropped as stale at ingress (the
  generator's batch counter outruns T's generation, and token_verdict requires batch == live generation), so far fewer
  blockers are seeded than designed. The collapsed blocker-lap counts in the both-shaped configurations therefore
  reflect stale-dropped tokens as well as rate-limited blocker queues. Correctness and CLRT precision are unaffected
  (zero fallback, exact commit/release), and loop-port packets/bytes remain as measured, but the figure "24-67x less
  loop traffic" is a measurement of this operating mode, not yet of the mechanism working as designed. Cause under
  analysis (read_queue_timing.p4 admit_request is not generation-gated; a repeated admit pass mints a clone with the
  same generation without moving gen_alloc).

Rig restored after the probes (relay slot read back, ping .1 -> .7 ok, NIC flag off).

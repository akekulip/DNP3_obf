# Interpretation correction, 2026-10-16 (directive ba50eac69)

The run's verdict stays **FAIL** (`isolation_verdict.json`, unchanged). This note corrects the explanation given
in commit `e1744034b`, STATUS.md and the writing package, which said two old READ timer tokens were rejected after
the pause. The retained snapshots show otherwise.

Read from `token_window_observer.json` (`old_reject_after`, T outcomes indices 24, 23, 6; `read_app_after.pkt_counter`)
and the trial's full-run snapshots (`snapshots/*_before.json`, `*_after.json`):

| observation | READ packets emitted | RAW_READ_TIMER_STALE (24) | RAW_OPERATE_TIMER_STALE (23) | STALE_BLOCKER (6) |
|---|---:|---:|---:|---:|
| c2-ready snapshot | 3 | 2 | 0 | 0 |
| quiet poll 0 | 5 | 4 | 4 | 0 |
| quiet poll 1 | 6 | 5 | 4 | 0 |
| quiet poll 2 = quiet end (permit basis) | 8 | 7 | 4 | 0 |
| full-run after (c1-c3) | 24 | 7 | 4 | 2 |

The quiet rows count c1's delayed cohort; the full-run READ count includes c2/c3 traffic. All 7 old READ timer
rejections (2 before the c2-ready baseline, 5 during the pause) and all 4 OPERATE rejections were present before the
permit; none occurred afterwards. The two later events are STALE_BLOCKER, a different packet class, giving
OUT_TOKEN_STALE 7 + 4 + 2 = 13 against the build bound 12.

What remains open: which connection and generation produced the two STALE_BLOCKER events. The control-timed cleanup
allowance in `protocol/hw_vepa/checks.py` (2k blocker tokens per SBO cycle) does not by itself show that they came from
c2/c3; until a trace attributes them, the run stays FAIL. The generator-only drain predicate is a real general
weakness but not the demonstrated cause of this run.

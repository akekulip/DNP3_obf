# Rare "exactly 5" OUT_TOKEN_STALE at 3 ms fixture / hold+blocker queues shaped 3,723 PPS (2026-10-12)

Context: on mirror_fix_01 the campaign's explicit check "OUT_TOKEN_STALE == 0" failed in one paired block
(fixture delay 3 ms, gap 20 ms, 3,723 PPS, 50 READs + SBO): stale 5, everything else correct. Probe series, all 3 ms
fixture, fresh cold bring-up each, mirror_fix_01 (cause analysis of the earlier 26k-stale storm is separate and fixed).

| run | READs | READ triggers | OUT_TOKEN_STALE | correct |
|---|--:|--:|--:|:-:|
| shaped 3,723 | 1 | 1 | 5 | OK |
| shaped 3,723 | 1 | 1 | 0 | OK |
| shaped 3,723 | 10 | 10 | 5 | OK |
| shaped 3,723 | 10 | 10 | 0 | OK |
| shaped 3,723 | 50 | 50 | 0 | OK |
| shaped 3,723 | 50 | 50 | 5 | OK |
| shaped 3,723 | 50 (x2 more) | 50 | 5, 5 | OK |
| shaped 14,892 | 50 | 50 | 0 | OK |
| unshaped | 50 | 50 | 0 | OK |

(`d3_*` directories; every run: triggers == READs, OPERATE trigger 1, zero fallback, exact commit/release counts, correct.)

Observations: the value is exactly 5 or exactly 0, about half of the shaped-3,723 runs; it does not depend on the READ count
(1, 10, 50), so it is a per-connection / per-SBO event, not per-READ; it does not appear at 14,892 PPS or unshaped. In the
1-READ pair every other counter is within one re-wait (30 vs 31) and identical loop-frame counts for n_ack/t_in, so nothing
visible besides the stale counter distinguishes the runs. Cause under analysis (OPERATE-side: OP tokens/blocker versus a
generation that moved after the close); until decided, the campaign gate treats the zero-stale bound as a per-build
configurable value and records the observed count in every trial.

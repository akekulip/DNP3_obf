# C3 attribution of the two STALE_BLOCKER events (2026-10-16)

Plan: `C3_DIAGNOSTIC_PLAN_20261016.md`. The original block `ctl_m5_stale_iso20_950_01` stays **FAIL**, unchanged.
Both diagnostic blocks ran on m5_10 and are diagnostics only. They qualify no build, and m7 is qualified separately.

| block | run | block rc | restore_verify |
|---|---|---:|---|
| D1, isolation (delayed old-token cohort) | `ctl_m5_c3diag_iso20_950_01`, 17:42–17:45 | 1 | `{"ok": true, "failures": []}` |
| D2, normal-traffic control (no READ-IPG delay) | `ctl_m5_c3diag_control_950_01`, 17:47–17:51 | 1 | `{"ok": true, "failures": []}` |

Each block ran once and neither was rerun. Analysis: `c3_attribution_20261016/` (`c3_attribution.json`,
`c3_attribution_table.md`, `inputs.sha256`), produced by `seg61_02/analysis/c3_attribution.py`.

## Observations (switch poller, about 100 ms period, 366–367 complete samples per block)

Windows are numbered by N's epoch, and every value is a switch register:
- epoch#0 is before c1;
- epoch#1 is c1 (N epoch 1);
- epoch#2 is c2 (N epoch 15), including its 20 s pause;
- epoch#3 is c3 (N epoch 29).

| block | window | stale retirements (outcome 6) | raw READ timer-stale (24) | raw OPERATE timer-stale (23) | READ-lane gens | OPERATE-lane gens |
|---|---|---:|---:|---:|---|---|
| D1 | c1 | 0 | 2 | 0 | 2, 4, 5 | 1, 2, 3 |
| D1 | c2 (incl. pause) | 0 | 5 | 4 | 6, 9, 10 | 4, 5, 6 |
| D1 | c3 | **2** | 0 | 0 | 14, 15 | 8, 9 |
| D2 | c1 | **2** | 0 | 0 | 4, 5 | 2, 3 |
| D2 | c2 (incl. pause) | 0 | 0 | 0 | 6, 9, 10 | 4, 5, 6 |
| D2 | c3 | **2** | 0 | 0 | 14, 15 | 8, 9 |

**Event placement.**
- D1, c3 event: in the sample that also contains c3's handshake and SBO (READ-lane generation 10→14, OPERATE-lane
  generation 6→8), 34.10 s after the poller started and about 5 s after c2 closed.
- D2, c1 event: in the sample containing c1's handshake and SBO (generations 0→4 and 0→2).
- D2, c3 event: in the sample after the generations reached 14 and 8.

The poller reads the 25 outcome cells before the generation registers, about 50 ms apart within one sample. A sample
can therefore show a generation advance before the outcome-6 increment it causes. A 100 ms sample also cannot
separate a SELECT from its OPERATE.

**Raw rejections.** All 7 raw READ and 4 raw OPERATE timer-stale rejections in D1 fall in c1's tail and c2's pause,
at the 2.5 s IPG (5.7 s to 18.2 s poller time). D2 has none.

## Explanations

**E3, accounting or instrumentation: rejected.** In both blocks:
- the poller's totals equal the block's own before/after snapshot deltas (D1 6/7/4 for cells 6/24/23, D2 4/0/0);
- every cell is monotonic and no lane generation decreases;
- no sample carries a read error, and the largest sample gap is 112 ms.

**E1, delayed old-blocker cleanup: not supported for the two events.**
- *Source* (m5_10, `ctl_timing_01/evidence/m5_10/response_only.p4`; sha256 in `inputs.sha256`):
  - The ladder header's `budget` field is a recirculation counter, not an epoch (`parse_ladder`). The blocker roles
    match no `epoch_access` row and take the default `read_epoch()` (epoch_delta 0), so a blocker passes `gen_access`
    with `e_bad == 0` whichever connection seeded it.
  - In `held_verdict` and `hb_verdict`, every `keep_blocking` row requires `lgen_diff == 0`. A blocker whose 16-bit
    generation differs from its lane's live generation reaches `stop_blocking_stale` (outcome 6) on its next pass
    (rows `(0, ROLE_ACK_BLK, _, …)`, `(0, ROLE_RESP_BLK, _, …)` and `(0, ROLE_OP_BLK, _, …)`).
  - So a blocker alive when its lane's generation advances is retired at its next pass, not later.
- *Implication:* a blocker seeded in c1 and still alive at c2's open (READ-lane generation 5→6, OPERATE-lane generation
  3→4) would be retired in the c2 window. D1 shows no outcome 6 in that window, so no c1 blocker survived into c2, and
  none can reach c3.
- *Matched control:* D2, which has no delayed cohort, shows the same 2 events in the same c3 window at the same lane
  generations as D1.

**E2, fresh-connection cleanup: supported.** D1's two events match the control's c3 events in window, count and lane
generations. They are blockers of c3's own exchanges, retired when c3's ladder advanced the lane generation.

**Further observations.**
- **c1:** D1 shows no stale retirement where D2 shows 2. In D1, c1's token cohort is delayed and rejected raw (outcomes
  23/24) rather than seeding blockers that are then retired. The block totals agree: D1 11 raw + 2 stale = 13
  (the original block's 13 against the build bound 12); D2 0 raw + 4 stale = 4, the same 4 that the normal
  three-connection m5 blocks show.
- **c2:** c2 shows no stale retirement in either block. The reason is not determined from these data. It does not
  depend on the delay, because both blocks agree.

## Consequences for acceptance (no bound changed here)

- **The full-run rule contradicts the source.** `token_window.full_run_rejections` requires the final STALE_BLOCKER
  count to equal the quiet-end count. D2, with no delayed cohort at all, fails it:
  `missing full-run rejection evidence: new traffic caused rejection after old batches drained: STALE_BLOCKER`.
  Under the source contract above, fresh SBO traffic retires its own blockers at each lane-generation advance, so the
  rule rejects normal operation. `checks.py` already budgets that cleanup as `2k` per SBO.
- **Proposed acceptance version (to be implemented as a separate versioned recomputation, original FAIL kept):**
  - account the old cohort by raw rejections (23/24) and by any outcome 6 before the permit;
  - bound outcome 6 after the permit as fresh-traffic cleanup per SBO;
  - stop requiring the after-permit outcome-6 count to equal the quiet-end count.
- **Remaining uncertainty:** the poller localizes an event to a window and a pair of generations. It does not name
  the retired blocker's generation or role. If a later decision needs that, the smallest instrumentation is a
  per-generation, per-role stale-retirement record in T, as a separately named diagnostic build.

## D1's cleanup-bound observation (recorded, not acted on)

D1 also failed `cleanup bound exceeded: old tokens observed drained 18597019124 ns after the anchor, bound
18001000000 ns`. The original block passed at 16.24 s. The drain itself did not slow.
- **Drain timing:** the switch poller places the last raw READ rejection about 15.1 s after c1's first READ, at the
  same 2.5 s spacing.
- **Detection:** the harness detects drain only at its next poll. Its polls are about 2.65 s apart in both runs
  (each snapshot takes about 0.3 s). D1's third poll read the READ token counter at 7 just before the last token, so
  drain was first seen at the fourth poll.
- **Bound:** the bound's 3 s snapshot allowance does not cover a full poll period plus the time from snapshot to
  Vision tick. The original run passed on poll phase alone.

This is a harness-bound finding, recorded for review. The bound is not changed.

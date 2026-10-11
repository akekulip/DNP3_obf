# Residency diagnostic + K sweep: original recirculation is structural, not reservoir-bound (2026-10-11)

Diagnostic build residency_diag_01 (bfrt 8c687b72, p0 2855def3, p1 15d226e8), T-on, 5 ms response fixture,
10 READs + 1 SBO per block, fresh cold bring-up per K. Correctness held in every block: master success,
10/10 READs match seed, 1 real SELECT + 1 real OPERATE, 0 decoy, OUT_ACK_COMMIT=10, OUT_RESP_RELEASE=10,
OUT_OP_RELEASE=1, **zero fallback**. Instrumentation splits held-original re-waits per role (outcomes 1/14/15)
and counts blocker laps per domain (16/17/18), which keep_blocking previously left uncounted.

| K | ACK rewait | RESP rewait | OP rewait | ACK blk laps | RESP blk laps | OP blk laps | READ gen pkts | fallback |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 2 | 59,833 | 8,988 | 2,999 | 301,722 | 166,420 | 14,996 | 96  | 0 |
| 4 | 59,177 | 8,900 | 2,977 | 425,060 | 305,065 | 26,793 | 184 | 0 |
| 8 | 59,316 | 8,935 | 2,991 | 668,612 | 584,179 | 50,848 | 368 | 0 |

## Finding

**Held-original re-waits are flat across K; blocker laps grow with K.** ACK original re-waits stay ~59,300
whether there are 2, 4, or 8 ACK blockers per trigger, while ACK blocker laps rise 302k -> 425k -> 669k.
Raising K does not reduce original circulation at all — it only adds internal blocker traffic. By the plan's
own criterion (section 3.4: "if larger K merely trades original traffic for excessive blocker traffic without
reducing original returns, the cause is scheduling, not reservoir size"), **K is the wrong knob**.

The held original re-circulates ~5,900 times per ACK hold (59,300 / 10 READs), a rate set by the loop
turnaround and the hold duration (~12 ms readiness / loop time), independent of the blocker reservoir. The
strict-priority-starvation model of residency (blockers occupy the high-priority BLK queue so the HOLD queue is
never serviced, and the original sits still) is **not what the hardware does**: the original is actively
re-looped on every pass by the rewait action, so its lap count is O(hold_time / loop_time) and more blockers
cannot stop it.

ACK dominates both originals (83% of re-waits) and blocker laps (longest hold at 12 ms readiness).

## Consequence for the work

Reducing original recirculation needs a change to the HOLD mechanism, not the reservoir:
- hold the original without re-looping it (a queue rate/service configuration that parks it until its release
  condition, rather than re-circulating it to re-evaluate each lap), or
- drive release from the blocker/timer path that pulls the original out once, rather than the original
  re-presenting itself every loop.
Either is a T design change (Agent 2), to be measured against this K=2 baseline on the same workload. Blocker
laps themselves (483k at K=2) are also internal traffic to minimize once the original-loop question is settled;
K should then be the smallest value that preserves correct commit/release (K=2 already gives zero fallback).

Evidence: `diag_ton5/` (K=2, also snb.json/sna.json at run root), `k4/`, `k8/`, each with master/outstation/
result JSON, both pcaps, and before/after switch snapshots. `k2_decomposition.md` has the K=2 detail.

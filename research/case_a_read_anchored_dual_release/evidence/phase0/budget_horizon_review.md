# Fail-open budget horizons — the P4's per-pass assumption is ~6x too slow

Found while reviewing the control-plane script before the gated load. **Not a blocker for the
oracle, but it must be measured on silicon rather than assumed, and it bites at R = 25 ms.**

## The assumption in the skeleton

`p4/case_a_dual_release_skeleton.p4:191-194` sizes both budgets from **~10 µs per pass**:

```
ACK  blockers: 10 x A =  30 ms / 10 us =  3 000 passes
RESP blockers: 10 x R = 130 ms / 10 us = 13 000 passes
```

## What silicon actually measured

Defense 2 functional gate (f): `INITIAL_BUDGET = 100000` produced fail-open at **171.5 ms**.

    per-token pass time = 171.5 ms / 100000 = 1.715 us

Cross-check: with K = 64 tokens sharing the loop that is `64 / 1.715 us = 37.3 Mpps`, which
matches the 37.4 Mpps independently derived from the Part 12 pass counts. Two independent
derivations agree. (The 408 ns figure quoted elsewhere is the **single-token** dp8 loop RTT; with
64 tokens in flight each token's revisit period is ~1.7 µs. Both numbers are right, for different
things — do not mix them.)

So the real horizons are about **6x shorter** than the comment claims:

| Budget | passes | real horizon | must survive | margin |
|---|---|---|---|---|
| `BUDGET_ABLOCK = 3000` | 3000 | **5.14 ms** | 3 ms (0 → A) | 1.71x |
| `BUDGET_RBLOCK = 13000` | 13000 | **22.30 ms** | 10 ms (A → R at A=3/R=13) | 2.23x |
| `BUDGET_RBLOCK` at A=8/R=25 | 13000 | **22.30 ms** | 17 ms (A → R) | 1.31x |

## Why it still works — and the load-bearing reason

Every row clears, but the R = 25 ms case clears **only because response blockers are STARVED by
`Q_ABLOCK` until `d_ACK` and therefore consume no budget before then.** If they circulated from
`t_READ`, R = 25 ms would need 14 577 passes against a 13 000 budget and would fail open ~2.7 ms
*before* its own deadline — releasing the response early, which is the failure this mechanism
exists to prevent.

**The strict-priority starvation is therefore doing double duty:** it enforces ordering *and* it
keeps the response-blocker budget viable. That coupling is not obvious from the code and must be
stated in the report, because anyone "simplifying" the queue ladder later would silently break the
budget too.

## Actions

1. **Measure the per-pass time on silicon** during Phase 1 rather than assuming it — the setup
   script's `--loop-us` flag exists for exactly this. Derive both budgets from the measurement.
2. **Correct the comment at `.p4:191-194`** to 1.715 µs when the P4 is next edited (Phase 4, which
   also moves the budgets to runtime action parameters).
3. **Add a Phase 3 assertion** that no blocker terminates by budget before its deadline:
   `ctr_deq[CD_TERM_ABLOCK_TMO] == 0` and `ctr_deq[CD_TERM_RBLOCK_TMO] == 0` on every clean run.
4. Re-check the margin at whatever `(A, R)` the calibration arm selects; 1.31x at A=8/R=25 is the
   thinnest and should not be reduced further without re-deriving the budget.

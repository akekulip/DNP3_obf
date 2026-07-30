# CORRECTION — the C3 "steady-state" corpus contains a connection-cold poll

Found by panel member E, verified independently 2026-07-29.

## The error

`evidence/corrected_v2/cwi/out_C3/native_transactions.csv` was used as an n=100 **steady-state**
native series. Sorted by `read_ts_epoch`, **transaction index 0 has `clrt_ms = 21.6953` and it is
the sample maximum.** It is the first poll on that connection — i.e. connection-cold by definition,
and the repo's own convention is that cold polls are excluded from the steady-state series and
reported separately, never pooled.

## What it changes

| quantity | as previously reported (pooled) | corrected (cold poll excluded) |
|---|---|---|
| max steady CLRT | 21.695 ms | **12.089 ms** |
| D for 100% clamp | **22 ms** | **13 ms** |
| mean added latency at that D | **19.57 ms** | **10.76 ms** |

The D-for-full-concealment figure was **41% too high**, and the latency cost of full concealment
nearly **double** the true value. Both numbers appear in
`research/case_a_fixed_ack_delay/evidence/D_selection_curve.txt`, in the commit message of
`159d78a`, and in project memory.

Everything below the maximum is unaffected: D=2 → 61/100 and D=3 → 84/100 counted concealment
against the whole sample and do not depend on which observation is the largest. The *shape* of the
argument — that D must exceed the native CLRT rather than sit at its centre — is unchanged and
still correct. Only the endpoint moves, and it moves in the mechanism's favour.

## Consequence for Defense 3

Full concealment is **cheaper than previously stated**: ~13 ms rather than ~22 ms, at ~10.8 ms mean
added latency rather than ~19.6 ms. That materially improves the latency-versus-clamping tradeoff
that §15 requires be reported.

**Rule carried into this work:** every native series must have its cold prefix identified and
excluded by a pre-registered rule before any statistic is computed, with the excluded rows retained
and reported separately. A "steady-state" label on a file is not evidence that the file is
steady-state.

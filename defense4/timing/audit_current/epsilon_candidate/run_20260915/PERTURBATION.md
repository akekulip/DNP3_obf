# Does the instrumentation perturb the timing it measures?

Not detectably, at this configuration and this sample size.

## Method

200 READ transactions under each build, back to back on the same testbed within a few minutes,
same configuration each time: mode D4, D_A = 20 ms, configured CLRT_new = 4 ms, `shape_enable`
read back as 1 after `configure-all` and forced to 0 before any traffic ran. CLRT is taken from
the master-facing capture as the response arrival minus the transport acknowledgment arrival, the
same definition the campaign uses. Captures in `perturbation/`.

## Result

| build | n | median | mean | sd | max |
|---|---|---|---|---|---|
| frozen, the campaign build | 200 | 3.9992 ms | 3.9995 ms | 0.0154 ms | 4.0662 ms |
| instrumented candidate | 200 | 3.9998 ms | 4.0003 ms | 0.0153 ms | 4.0751 ms |

Difference in medians **+0.6 microseconds**, in means +0.8 µs. Mann-Whitney U, two-sided,
**p = 0.18**: the two samples are not distinguishable at any conventional threshold.

The standard deviations are equal to three decimal places, 0.0154 against 0.0153 ms, so the
instrumentation does not widen the distribution either.

## Reading it honestly

**What this supports.** The two extra registers and four small tables do not move the released
interval by an amount this experiment can detect. Since the measured epsilon is 1.705 µs, a
perturbation large enough to matter for that figure would have to be of the same order, and a
0.6 µs median shift that fails a significance test at n = 200 is not evidence of one.

**What it does not establish.** Absence of an effect. A 0.6 µs shift is the same order as epsilon
itself, and with 200 samples per arm this experiment cannot exclude a real effect of that size; it
can only say it did not find one. A tighter bound needs more samples or a paired design.

**Scope.** One relay, one configuration, one pair of runs, READ only. The comparison is
master-facing, so it constrains what the master sees and not what happens inside the switch.

# Request-anchored release: what it fixed, what it did not, and what it cost — 2026-09-18

`analysis/anchor_diagnosis/FINDINGS.md` established that the framework *raises* what an adaptive
adversary recovers from the master-visible request-to-acknowledgment interval, and traced it to the
read lane arming its deadlines at the relay's own acknowledgment rather than at the request. This
records what happened when that was changed and measured on the same hardware.

**Design.** Three arms, one loaded binary, one session, interleaved by round with the arm order
rotated so no arm always follows the same predecessor. Eight rounds, 24 blocks, 18,914 exchanges.
Every block proves the size carve off and the anchor state set from a hardware readback before it
captures anything; 24 of 24 blocks passed every guard.

- **OFF** — Timing OFF, the undefended baseline.
- **A0** — obfuscated, `anchor_req=0`: the schedule `campaign_v1` evaluated. A positive control.
- **A1** — obfuscated, `anchor_req=1`: the request-anchored read lane.

Policy is the campaign's own throughout: `D_A` 20 ms, `D_R` 4 ms, `A` 20 ms, `R` 24 ms, `J` drawn
from {2, 6, 12} ms. The traffic reproduces the campaign's pattern exactly — the median idle gap is
20.501 ms for READ, 20.611 for SELECT and 0.354 for OPERATE in `campaign_v1`, and 20.507, 20.615
and 0.354 here — so the comparison is like for like.

## The positive control reproduces the finding

| request-to-acknowledgment, median | READ | SELECT | OPERATE | class spread |
|---|---|---|---|---|
| Timing OFF | 0.551 | 0.547 | 0.561 ms | 0.014 ms |
| A0, this run | 21.330 | 21.237 | 20.654 ms | **0.676 ms** |
| `campaign_v1`, for comparison | 21.336 | 21.239 | 20.650 ms | 0.686 ms |
| A1 | 20.100 | 20.101 | 20.106 ms | **0.006 ms** |

A0 reproduces the evaluated leakage on today's hardware to within 0.01 ms. Without that, nothing
else in the comparison would mean anything.

## What the fix does

| adaptive adversary, retrained on obfuscated traffic, 8 held-out-run folds | A0 | A1 |
|---|---|---|
| request-to-acknowledgment interval alone | **0.7944** | **0.4514** |
| released CLRT alone | 0.3681 | 0.4376 |
| both intervals | **0.7727** | **0.4142** |

| mutual information against a within-run permutation null | A0 | A1 |
|---|---|---|
| request-to-acknowledgment, Timing OFF | 0.0935 bits | 0.0935 bits |
| request-to-acknowledgment, obfuscated | **0.5684 bits** | **0.0402 bits** |
| released CLRT, Timing OFF | 0.4659 bits | 0.4659 bits |
| released CLRT, obfuscated | 0.0088 bits, **inside the null** | 0.0399 bits, outside it |

The framework as evaluated raises the request-to-acknowledgment channel from 0.094 bits undefended
to 0.568 bits. Request anchoring brings it to 0.040 bits, below the undefended level and a
fourteenfold reduction, and the adversary's balanced accuracy on both intervals falls from 0.773 to
0.414 against a 0.333 chance level.

**It does not reach chance, and the residual is not device execution time.** Three measurements say
what it is.

First, the confusion matrix. Under A1 the adversary recovers READ at 0.347 and SELECT at 0.222,
which is at or below chance, and OPERATE at 0.643. The whole residual is OPERATE against the other
two.

Second, the release tails, decomposed. The deadline and the release instant differ by a tail set by
the blocker loop's phase at the moment the deadline is armed:

| | A0 | A1 |
|---|---|---|
| acknowledgment release tail, median | 1.304 ms | **0.102 ms** |
| response release tail, median | 1.306 ms | 0.107 ms |
| correlation between the two tails | 0.9996 | 0.171 |
| CLRT minus `D_R`, standard deviation | 0.0182 ms | 0.0196 ms |
| CLRT minus `D_R`, per class (READ / SELECT / OPERATE) | 0.00113 / 0.00113 / 0.00013 ms | 0.00513 / 0.00513 / 0.00013 ms |

Under A0 both deadlines hang off the same jittery instant, so a 1.3 ms tail appears in full in the
acknowledgment interval and cancels almost exactly in the CLRT — which is why A0's CLRT sits inside
the permutation null while its acknowledgment interval carries 0.568 bits. Under A1 both tails
shrink thirteenfold and stop being correlated, and what is left is a **4 microsecond** offset
between OPERATE and the other two. READ and SELECT, whose execution times differ by 60 microseconds
on this relay, have identical released CLRT to five decimal places.

Third, a control that holds class constant. Split READ alone into its short-gap and long-gap
thirds — one class, one device, one execution time, separated only by when the request arrived —
and give the same forest the same two features:

| | balanced accuracy, chance 0.5 |
|---|---|
| Timing OFF, READ only, gaps 22 µs apart | 0.5770 |
| A0, READ only, gaps 27 µs apart | 0.6858 |
| A1, READ only, gaps 26 µs apart | **0.6141** |

Under A1 the adversary tells two READs whose arrivals differ by 26 microseconds apart *better* than
it tells a READ from an OPERATE (0.614 against 0.414). The residual tracks when a request arrived,
which the adversary observes directly and needs no classifier for, and OPERATE is the class whose
arrival phase differs — it follows its SELECT by 0.354 ms where a READ follows its predecessor by
20.5 ms. Under Timing OFF the same control already scores 0.577, so this channel is a property of
measuring two timestamps at all, not of the defense.

## The arrival-phase explanation, tested on hardware

The account above says the residual is set by when a request arrives relative to the blocker loop.
That is a causal claim, so it was run: one arm, one policy, the relay doing identical work, at four
different master inter-request spacings. Eight blocks, 4,000 exchanges, all guards passed.

READ's release tail, median, by the master's spacing:

| master spacing | 3 ms | 7 ms | 13 ms | 20 ms | range |
|---|---|---|---|---|---|
| A0 | 1.260 | 0.575 | 0.562 | 1.341 ms | **0.779 ms** |
| A1 | 0.107 | 0.108 | 0.107 | 0.100 ms | **0.008 ms** |

Under A0 the tail moves by 0.78 ms when nothing changes but how often the master polls. Under A1 it
does not move at all, to within 8 microseconds. The tail is arrival phase, and request anchoring
removes the dependence on it.

The same sweep says something the eight-round run could not. A0's leakage is itself a function of
the polling interval:

| class spread of the request-to-acknowledgment median | 3 ms | 7 ms | 13 ms | 20 ms |
|---|---|---|---|---|
| A0 | 0.6215 | 0.0110 | 0.0140 | 0.6840 ms |
| A1 | 0.0010 | 0.0010 | 0.0000 | 0.0105 ms |

As evaluated, whether the framework leaks depends on the operator's polling interval: at 7 and 13 ms
the three classes are separated by about 0.01 ms, at 3 and 20 ms by about 0.65 ms, and `campaign_v1`
polled at 20 ms. That is not a property anyone would want to depend on. Under request anchoring the
spread is at or below 0.0105 ms at every spacing tested, and the sign of the residual between
OPERATE and the other two flips between spacings — at 7 ms OPERATE is 1 microsecond below READ, at
20 ms it is 7 microseconds above. A stable device signature does not change sign when the master
polls faster.

## What the fix costs

**A stage: none.** The frozen program is at the 12-stage ingress ceiling and the candidate is too,
with the same critical path of 12, one extra table, and the same ten compiler warnings.

**Release precision: it improves.** The acknowledgment release tail falls from a median of 1.304 ms
to 0.102 ms and its 95th percentile from 1.519 ms to 0.113 ms. Releases later than `D_A` + 2 ms fall
from 210 of 6,310 exchanges to **0 of 6,308**. The largest observed master-visible interval falls
from 26.219 ms to 20.168 ms.

**The response budget: it shortens, by the relay's acknowledgment latency.** This is the one real
cost and it follows from the change: anchoring at the request means the response must arrive by
`T_0 + D_A + D_R`, where before it had until `t_A + D_A + D_R`. On this relay that is about 0.55 ms
of budget given up. The prediction and the measurement agree:

| | predicted from Timing OFF | observed |
|---|---|---|
| A1, releases past the response deadline | 0.080 % | 0.095 % |
| A0, releases past the response deadline | 0.016 % | 0.032 % |

Six exchanges in 6,308. The remedy is arithmetic, not a code change: the availability condition
becomes `t_R <= T_0 + D` rather than `t_R <= t_A + D`, and the operator sizes `D` against the
request. The relay's own request-to-response latency has a 99th percentile of 13.4 ms and a maximum
of 24.7 ms here, against a 24.0 ms budget.

**A telemetry effect, by design.** The relay's acknowledgment now finds the deadline already armed,
so `deadline_arm_once` is a no-op and `ack_first` reads 0. Both `OUT_ACK_HOLD` and
`OUT_ACK_DUP_HOLD` commit through the same `cmt_hold()`, so nothing in the disposition changes;
what moves is which counter increments. That is also a useful on-switch check that the request, and
not the acknowledgment, did the arming.

## What is not established

The residual is characterised on one relay, one policy point and the evaluated Random-Forest
attacker on two features. That an arrival-phase channel of 4 microseconds carries no device
information is argued from the within-class control and from READ and SELECT being identical, not
from a second device. Whether a finer blocker loop removes the residual altogether is untested. The
budget-shortening rate is measured at `D_A` = 20 ms and `D_R` = 4 ms on this relay and does not
transfer to a slower outstation without re-sizing `D`.

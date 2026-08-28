# Result paragraphs for the body

The captions were cut to the DefRec convention (9 to 25 words, descriptive, no interpretation),
so the findings they used to carry belong here. Each paragraph follows the three-move shape
measured in that paper: `In Figure N, we show <what is plotted, axes named inline>.` then the
number with a bound or comparison, then a mechanism sentence introduced by `This is because` or
`Because`. Every number below was recomputed from `derived/transactions.csv` and
`sweep/sweep_points.csv` on 2026-08-28.

---

**Parameter choice (fig_c00).** In Figure C0, we show the fraction of transactions whose
cross-layer response time exceeds a given value with the timing mechanism off, and the fraction
that a given budget cannot cover. The switch releases only a packet it already holds, so the
budget $D = D_A + D_R$ has to exceed the outstation's own response time, and $D$ is therefore both
the coverage knob and the delay the mechanism adds. At $D = 24$ ms, 99.905 percent of transactions
can be placed on the schedule and 0.095 percent arrive too late to be held. Raising $D$ to 60 ms
buys a further 0.082 percentage points for two and a half times the delay, so the curve is already
flat at the operating point.

**Cross-session stability (fig_c01).** In Figure C1, we show the median cross-layer response time
of each session, with the interquartile range as bars, for the three transaction classes. With the
mechanism off, the classes sit at 2.116 ms, 2.050 ms and 2.937 ms and carry a wide spread. With it
on, every session of every class sits at 4.000 ms and the interquartile range stays below 0.01 ms.
This is because the release time is computed from the outstation's acknowledgment and a fixed
offset, so it does not depend on how long the device itself took.

**Distribution (fig_c02, fig_t01).** In Figure C2, we show the empirical distribution of the
cross-layer response time for each class. With the mechanism off the device answers in a small
number of discrete modes, near 1.05, 1.15 and 2.15 ms for READ and near 1.85 and 2.90 ms for
OPERATE, and it is this structure rather than the mean alone that a classifier learns. With the
mechanism on each distribution is a single step at 4.000 ms.

**Spread (fig_c03).** In Figure C3, we show the interquartile range of the cross-layer response
time computed within each session. The mechanism moves it from 2.779 ms to 0.0060 ms for READ,
from 2.690 ms to 0.0060 ms for SELECT and from 2.750 ms to 0.0058 ms for OPERATE, reductions of
466, 451 and 478 times.

**Feature space (fig_c04).** In Figure C4, we show the cross-layer response time against the total
response time, with the mechanism off and on. Off, the three classes occupy different regions. On,
they collapse onto one value of the cross-layer response time, so a single observation no longer
indicates the class.

**Leakage (fig_c05, fig_t02).** In Figure C5, we show the balanced accuracy and the mutual
information of a transaction-class classifier trained on 21 sessions and tested on the session
held out, over all 22 sessions. With the mechanism off, the cross-layer response time alone
identifies the class with balanced accuracy 0.651 against a three-class chance of one third. With
it on, balanced accuracy falls to 0.333 and the mutual information falls from 0.266 to 0.007 bits.
Adding the acknowledgment latency and the response time recovers 0.655. This is because the read
path and the control path are anchored differently, so the acknowledgment arrives at 21.336 ms for
READ and 21.239 ms for SELECT but at 20.650 ms for OPERATE. The confusion matrices show the
consequence directly: OPERATE becomes recoverable while READ and SELECT stay confused with each
other, since they differ by only 0.097 ms.

**Intervals and anchors (fig_c06).** In Figure C6, we show the cross-layer response time and the
acknowledgment latency for each class and arm. The acknowledgment rises from about 0.55 ms to the
configured anchor, and the control path settles 0.686 ms earlier than the read path, at 20.650 ms
against 21.336 ms. That difference is the observable consequence of anchoring the control path to
the request rather than to the acknowledgment, and it is also the residue an observer can still
use.

**Cost (fig_c07).** In Figure C7, we show the end-to-end response time per class and the frames
and bytes carried per transaction. The median response time rises from 2.680 ms to 25.337 ms for
READ, from 2.622 ms to 25.239 ms for SELECT and from 3.465 ms to 24.650 ms for OPERATE, so the
mechanism adds about 21 to 23 ms per transaction. Every one of the 132 captures holds exactly
1,448 frames and 130,708 bytes for 440 transactions in both arms, so with the size carve disabled
the mechanism adds no packet and no byte and only moves packets in time.

**Operating envelope (fig_c08).** In Figure C8, we show the master-facing intervals measured while
sweeping the acknowledgment offset, and while holding the budget fixed and moving the split. The
cross-layer response time follows $D_R$ from 0.998 ms to 22.001 ms while the response time stays
within 25.307 to 25.339 ms, so the cost is set by the budget and the observable by $D_R$, and the
two can be chosen independently. Because the token burst that starves the queue is seeded at the
request, the fail-open horizon of 30.8 ms is counted from the request, and the acknowledgment
saturates at 31.07 ms once $D_A$ passes about 30 ms; beyond that point the cross-layer response
time is no longer pinned.

**Release accuracy (fig_t03).** In Figure T3, we show how far the cross-layer response time departs
from the configured 4.000 ms release. About 99.3 percent of READ transactions stay within 0.05 ms
and 0.091 percent depart by more than 1 ms, the largest departure being 53 ms. Because these are
the transactions whose response reached the switch after its scheduled release, the rate is the
coverage limit of the chosen budget rather than a failure of the release itself, and it agrees
with the 0.095 percent predicted from the undefended tail.

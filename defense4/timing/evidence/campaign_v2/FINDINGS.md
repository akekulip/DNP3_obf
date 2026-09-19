# campaign_v2: what the request-anchored build measures — 2026-09-19

63,360 exchanges over 22 grouped runs and 5 h 18 min, plus a 26-point policy sweep, on the build
whose read lane arms both release deadlines at the request. Every number below is regenerated from
the raw captures by `repro/reproduce.sh` (the attribution numbers by its step 5c, `proof_analyses.py`), which ends by comparing what it rebuilt against what the
repository publishes; 132 tests pass and the publication gate reports no problems.

## The headline

| | Timing OFF | Obfuscated |
|---|---|---|
| released CLRT, median: READ / SELECT / OPERATE | 2.121 / 2.041 / 2.929 ms | 8.005 / 8.005 / 8.000 ms |
| class spread of that median | 888 µs | **5 µs** |
| interquartile range, READ | 2.772 ms | **0.022 ms** |
| fixed adversary, both intervals | 0.8028 | **0.3333, exactly chance** |
| fixed adversary, CLRT only | 0.7284 | 0.3351 |
| mutual information, CLRT | 0.35314 bits | 0.04279 bits |

The adversary the threat model describes — one that trains before the framework is deployed and
applies its classifier afterwards — is left at chance to four decimal places.

## The claim that matters, isolated

READ and SELECT differ **only** in how long the outstation takes. OPERATE differs in that too, but
it also arrives at a different moment, 0.354 ms after its own SELECT response where a READ follows
its predecessor by 20.5 ms. So the contrast that isolates the device's execution time, and nothing
else, is READ against SELECT:

| READ vs SELECT, balanced accuracy, chance 0.5 | Timing OFF | Obfuscated |
|---|---|---|
| CLRT only | 0.7032 | **0.5068** |
| both intervals | 0.7847 | **0.5071** |

Undefended, those two operations differ by 80 µs in median CLRT and a classifier separates them
four times out of five. Obfuscated, their medians are identical to four decimal places — 8.0050 and
8.0050 ms, 20.1010 and 20.1010 ms — and the classifier is within 0.7 points of chance.

## What is left, and what it is

The three-class adaptive adversary, retrained on obfuscated traffic, reaches 0.4452 with both
intervals against a 0.3333 chance level. That is well down from the 0.7727 the
acknowledgment-anchored build allowed, and it is not the device. Three measurements say what it is.

**It is entirely OPERATE.** Row-normalised, the adaptive adversary recovers READ at 0.411, SELECT
at 0.235 and OPERATE at 0.689. Two of the three classes are at or below chance.

**It is six microseconds of queue phase.** OPERATE's release tail has a median of 0.107 ms against
0.101 ms for READ and SELECT, and a tighter spread. The tail's central 99 % runs from 0.036 to 0.127 ms across the
whole arm (`proof.json`) — the switch's own scheduling, not the outstation's work.

**Two identical transactions are more separable than two different ones.** Take READ alone, one
class and one device and one execution time, and split it at the median of the gap that preceded
each request; the two halves' median gaps are 31 µs apart. The same forest on the same two features
separates *those* at 0.6284 against a 0.5 chance level, where READ against SELECT, which differ in
execution time, sits at 0.5071. Under Timing OFF the same split scores 0.5361, so part of this
channel is a property of measuring two timestamps at all. (`repro/proof_analyses.py` →
`proof.json`; an earlier ad-hoc version of this control, with a different split, gave 0.6586 and
0.5683 and was never persisted, so it is superseded.)

What survives is therefore the master's polling schedule, which the adversary reads directly from
the request timestamps it can already see, and for which it needs no classifier.

**Pooling helps it, and that has to be said plainly.** An adversary that averages k exchanges of the
same operation reaches 0.4470 at k=1, 0.5281 at k=2, 0.6151 at k=5 and 0.6500 at k=20. Averaging
suppresses the noise around a systematic six-microsecond offset, so a real offset becomes easier to
see with more samples. Under Timing OFF the same pooling runs 0.8020 to 0.9388.

**No cheap fix exists.** If the release landed on a grid, choosing `D_R` as a multiple of that grid
would cancel the phase term exactly. The tail is not gridded: its central 99 % is a continuous distribution over
36 to 127 µs, with 129 distinct whole-microsecond values across the arm (`proof.json`). Removing the residual needs a design change —
dithering the release — and that trades directly against the property this framework sells, which
is that the released interval *is* the value the operator configured.

## Overhead

| | |
|---|---|
| frames and bytes added | none; 1,448 frames and 130,708 bytes per capture in both arms |
| median request-to-response | 28.1 ms, from 2.7 ms |
| release tail, median | 0.101 ms |
| budget coverage, READ and SELECT | 99.9415 %, 17 exchanges of 29,040 above the 28 ms budget |

The sweep places the released interval anywhere from 2 to 26 ms at that fixed budget and delivers
each setting to within 6 µs: 2.000, 4.000, 8.006, 12.000, 16.001, 20.000, 24.002 and 26.001 ms for
configured values of 2, 4, 8, 12, 16, 20, 24 and 26. The acknowledgment hold tracks its setting to
30 ms and saturates at 31.07 ms beyond that, which bounds the usable range.

## What is not established

One relay, one switch, one policy point for the campaign, and the evaluated Random-Forest attacker
on two features. That the arrival-phase residual carries no device information is argued from the
within-class control and from READ and SELECT being indistinguishable, not from a second device.
Whether a finer blocker loop or a dithered release removes the residual is untested. The J draw and
the relay-facing release remain unobserved, as in campaign_v1.

## Two collection defects found and fixed before these numbers were taken

Both reported success while producing wrong data, which is why each now has a loud check.

The first collection killed `tcpdump` the moment the driver returned, and lost the last half second
of 55 of its 66 Timing OFF captures — 1,107 exchanges — while every obfuscated capture was whole. An
asymmetric loss between the two arms being compared is disqualifying rather than untidy, so that
collection was discarded and re-run. Each block now counts the frames in its own capture and fails
if there are fewer than three per exchange.

The sweep runner fed its point list to a `while read` loop, and the block script shells out to
`ssh`, which reads stdin. The first `ssh` swallowed the list, the loop ended after one point, and
the sweep reported COMPLETE having measured one policy. Every block call now redirects
`</dev/null`, and the runner counts the points it visited against the points in the set.

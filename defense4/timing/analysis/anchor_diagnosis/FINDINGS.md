# Why the framework raises request-to-ACK leakage from 0.479 to 0.809

Phase A of the anchor diagnosis, 2026-09-18. Re-analysis of the existing campaign captures and of
the 2026-09-18 tail sweep. No hardware was run. Every number below is reproduced by
`extract_ordered.py` and the scripts in this directory.

## What the adversary gains

Undefended, the request-to-acknowledgment interval separates nothing: the three classes sit at
0.555, 0.555 and 0.558 ms, and a classifier reaches 0.479 balanced accuracy against a 0.333 chance
level. Under the framework the classes separate to 21.336 (READ), 21.239 (SELECT) and 20.650 ms
(OPERATE), and the same classifier reaches 0.809. Re-running that classifier here gives 0.810,
which confirms the published figure and the pipeline.

## Cause 1: the two lanes are anchored at different events (0.555 ms, design)

The read lane releases the acknowledgment at `t_A + D_A`, so the relay's own acknowledgment latency
sits inside the master-visible interval. The control lane releases at `T_0 + D_A`, so it does not.
The READ minus OPERATE gap is 0.686 ms, of which 0.555 ms is exactly the relay's acknowledgment
latency.

The frozen program records the asymmetry in its own comments: the read lane holds the "pure TCP ACK
to t_ACK + D", while the control lane "arms reg_deadline = T0 + A_DEFAULT_TICKS at admission". The
control lane therefore proves that request-anchoring is implementable in the same program, so this
is a design choice, not a hardware limit.

Simulating the corrected schedule on the measured data drops the classifier from 0.810 to **0.623**
and the spread of class medians from 0.686 to 0.134 ms. The fix is necessary and not sufficient.

## Cause 2: the release tail depends on deadline alignment (0.1 ms, policy)

The remaining separation is the release tail itself, which differs by class: 0.781 ms for READ,
0.684 for SELECT and 0.650 for OPERATE.

The tail is a queue-phase quantity, not a class property. Within READ alone, its median falls
monotonically as the idle gap before the exchange grows, from 1.401 ms at a 20.45 ms gap to 1.261 ms
at 20.58 ms. Matching READ and SELECT at the same idle gap shrinks their difference from 0.097 to
0.031 ms. The classes differ because the workload paces them differently: READ and SELECT arrive
about 20.5 ms apart, while an OPERATE follows its SELECT after 0.355 ms.

The tail sweep shows what sets its magnitude. With `CLRT_new` pinned at 4 ms, the READ tail is 18 to
38 us at `D_A` of 6, 8, 10, 14, 18, 22, 26, 30, 33 and 34 ms, and 262 to 956 us at `D_A` of 12, 16,
20, 24, 28 and 32 ms, growing with `D_A` along that branch. The large-tail budgets are exactly the
multiples of the configured 4 ms interval: the acknowledgment and response deadlines fall in the
same phase of the blocker cycle, their two reservoirs contend on one loopback port, and the drain
lengthens by more than an order of magnitude.

**The campaign ran `D_A` = 20 ms with `CLRT_new` = 4 ms, which is on the collision branch.** Off it,
the whole tail is about 20 us, so the class differences that survive the anchor fix are microseconds
rather than tenths of a millisecond.

## What is not leaking

- **The released interval carries no class information.** Its deviation from the configured 4.000 ms
  has a median of +0.0000 ms and a standard deviation of 0.0095, 0.0093 and 0.0087 ms for READ,
  SELECT and OPERATE. This answers directly whether the release tail reaches the interval the
  security argument protects: within the arm, it does not.
- **The late exchanges are few.** 39 of 31,680 obfuscated exchanges (0.12 per cent) leave more than
  0.10 ms from the configured value: 37 READ, one SELECT, one OPERATE. They carry the device's own
  timing, but one SELECT and one OPERATE give an adversary no class to learn.

## The fix this implies

1. Anchor both lanes at the request instant: `e_A = T_0 + D_A`, `e_R = T_0 + D_A + CLRT_new`.
   Neither deadline depends on `t_R`, so the cancellation stands; neither depends on `t_A`, so the
   relay's acknowledgment latency leaves the observable.
2. Choose a release policy off the collision branch, or have the control plane refuse one on it. At
   `D_A` = 22 ms with `CLRT_new` = 4 ms the measured tail is 24 us against 607 us at `D_A` = 20.

Both are testable together in one hardware run.

# Next load-bearing primitive (Part 4)

## The decision the whole family hinges on
Across IBSPG (strict priority), the backpressure audit (Family A), and the two-stage analysis
(Family B), every construction reduces to one question:

> **Can the data plane actuate a queue-resident hold of a sparse original packet — hold it, then
> release it on a data-plane event — at a bounded low internal rate, without recirculating it?**

The audit answers architecturally **no**: the only true queue-resident holds are (a) scheduling-disable
and (b) PFC/pause, and neither has a per-packet data-plane actuation lever. Two things remain to close
this **empirically**, one safe and decisive, one risky and gated.

## SELECTED primitive (safe, decisive, low-rate): the scheduling-disable hold locus
**Primitive P-SCHED:** *A queue with `scheduling_enable=false` holds an enqueued packet queue-resident
(usage>0, no drop); re-enabling dequeues it. Test whether that enable/disable can be actuated by a
data-plane packet or only by the control plane.*

- **Why this is the load-bearing primitive:** it isolates the exact hinge of the impossibility. If a
  data-plane packet could toggle a queue's scheduling, the entire queue-resident-release problem is
  solved (park in a disabled queue, response-packet re-enables → release). The audit says it cannot;
  P-SCHED confirms/refutes that on silicon, directly.
- **Testable without DNP3:** yes — synthetic marked frames + bfrt `tf1.tm.queue.sched_cfg`.
- **Predicted result:** the queue holds the packet resident under `scheduling_enable=false` (a true
  hold, no drop); only a control-plane `sched_cfg` write re-enables it; no data-plane packet action
  changes it → confirms the hold exists but has **no data-plane actuation** → the missing-primitive
  result is empirically established.
- **Safety:** LOW — one packet, control-plane queue disable/enable on the internal loopback queue,
  low rate, no PFC, no near-line-rate traffic, budgeted, immediate cleanup. Fully within the ceiling.

## GATED residual primitive (risky, predicted-negative): low-rate PFC hold
**Primitive P-PFC:** *Does a bounded, low, safe packet rate ever engage a self-generated PFC pause long
enough to hold one frame queue-resident, and does stopping it release the frame?*

- **Why gated:** PFC carries a **HIGH deadlock/pause-storm risk on a shared chip** (audit), and the
  hold only engages above a tens-to-hundreds-of-cells threshold that a low rate cannot sustain (the
  ~1200 pps TM-engagement floor). Predicted **negative at low rate**; the decisive positive would need
  near-line-rate fill, which the safety ceiling forbids.
- **Recommendation:** do **NOT** run autonomously. It requires explicit human authorization, a **spare
  pipe** (not the shared microbench pipe), a pre-run resource/risk review, and it would at best
  reconfirm what the architecture already says. P-SCHED delivers the decisive result without the risk.

## What P-SCHED will and will not prove
- **Will prove (empirically):** the queue-resident hold is real on TF1 but control-plane-actuated; the
  data plane cannot toggle it → the "missing direct release primitive" is confirmed on silicon.
- **Will NOT prove:** that *no* future construction of any kind can hold a packet — it bounds the
  claim to the actuation locus. Combined with the strict-priority refutation and the backpressure
  audit, it makes the negative result **systematic and evidence-backed**, which is the intended
  scientific contribution (Part 7), not an unqualified impossibility theorem.

## Acceptance-criteria check (Part 6) for P-SCHED as a *demonstration* (not a shippable hold)
P-SCHED is a **diagnostic**, not a candidate hold mechanism, so it is measured against the criteria
only to show *why no candidate passes*: it keeps the packet in TM memory during hold (✓), at zero
internal rate (✓, better than bounded), no recirc (✓), no chaff (✓), no drop-as-hold (✓) — but it
**fails "no controller action after initialization"** because the release is a control-plane
`sched_cfg` write. That single failed criterion **is the result**: the only clean queue-resident hold
on TF1 needs a controller in the release path, which the problem forbids.

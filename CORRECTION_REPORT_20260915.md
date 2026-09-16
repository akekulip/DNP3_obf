# Correction pass, 2026-09-15

> **Status update, 2026-09-16.** Three dispositions below are out of date. The epsilon candidate
> was compiled and loaded, and a measurement exists, though its build attribution is incomplete:
> see `defense4/timing/audit_current/epsilon_candidate/ATTRIBUTION_AND_DECODE_20260916.md`. The
> duplicate test in §1 was run, and what it establishes is narrower than "risk closed": see
> `defense4/timing/audit_current/duplicate_test_20260915/CORRECTION_20260916.md`. The perturbation
> comparison described as not done was also carried out. The analysis in §1 and the priorities in
> §2 otherwise stand.

Base commit `8278346`, branch `fix/offline-corrections-20260915`. Offline only: no hardware was
contacted, no switch written, no binary loaded, no traffic sent, and no hardware-authorisation
flag set. `implementation/` and every raw capture are byte-identical to the base.

The per-change account is in the commit messages. This file holds the two pieces of analysis that
have nowhere else to live: how the program handles duplicates, and what to do next.

---

# 1. Retransmission and duplicate handling

Traced through the frozen P4's outcome constants and its `tbl_commit` map, which pairs every
outcome with exactly one action. No change to the P4 is proposed here.

## What the program does

| situation | outcome | action | lane |
|---|---|---|---|
| duplicate READ request while a transaction is armed | `OUT_ARM_DUP` | **forward** | read |
| a second transaction arming while one is live | `OUT_ARM_BUSY` | **forward** | read |
| duplicate ACK while the original is still held | `OUT_ACK_DUP_HOLD` | **hold**, qid6 | read |
| duplicate RESPONSE while the transaction is live | `OUT_RESP_DUP_SUPP` | **drop** | read |
| response arriving after its deadline | `OUT_RESP_HOLD_LATE` | **hold**, qid4 | read |
| response with the timing mode off | `OUT_RESP_OFF_FWD` | **forward** | read |
| duplicate OPERATE while held or spent | `OUT_OP_DUP` | **drop** | control |
| unmatched flow, unsupported segmentation, bypass | `OUT_UNSUP`, `OUT_BYPASS` | **forward** | either |

Two asymmetries are worth naming because they are easy to assume away. A duplicate
acknowledgment is **held**, not dropped, so it joins the original in the same queue. A duplicate
response is **dropped**, and so is a duplicate OPERATE. Everything the program does not recognise
is forwarded unchanged, which is what keeps an unprotected exchange delivered rather than lost.

## What the evidence can and cannot verify

**The campaign verifies none of it.** Re-reading all 132 captures with the independent reader
gives 63,360 exchanges with **zero** retransmissions, zero duplicate application frames, zero
malformed frames and zero unpaired requests. No duplicate path was exercised, so the campaign is
silent on every row of that table.

**The 2026-09-15 diagnostic verifies one row indirectly.** With acknowledgements withheld, the
relay retransmitted its response three times and **all three reached the master**, in both arms.
That is consistent with copies arriving after the transaction retired being forwarded, and it is
the only duplicate behaviour any capture here demonstrates.

**Exactly-once delivery is not claimable from these traces.** A master-facing capture shows what
arrived at the master. It cannot show a relay-side copy that the switch absorbed, so the absence
of a duplicate at the master is not evidence that no duplicate existed.

## One risk that needs a targeted test, stated as a risk

`OUT_RESP_DUP_SUPP` drops a duplicate response while the transaction is live. If the original
response were lost **downstream of the switch**, the outstation's retransmission is exactly the
packet that would recover it, and it would arrive while the transaction is still live. Whether it
is dropped depends on how long the tag state treats the transaction as live relative to the
outstation's retransmission timer, which the 2026-09-15 diagnostic puts at about 3 s.

This is not a demonstrated defect. Nothing observed here shows a lost response, and the ~3 s
timer is far longer than any hold, which makes the overlap unlikely. It is written down because
it is the one place where the design's duplicate suppression and TCP's loss recovery could
collide, and because the correct test is cheap: hold a response, drop the original on the
master-facing side, and check whether the retransmission is delivered or suppressed. Until that
runs, the program should not be described as preserving loss recovery in all cases, and it should
equally not be described as breaking it.

**What must not be done:** suppress every future copy of a sequence number in the data plane.
That would convert the risk above into a certainty.

### The test that would settle it

One READ transaction, no control traffic, and no change to the loaded program.

1. Configure through `active_control/`, so shaping is never enabled, and archive the
   verification record with the loaded build's identity.
2. Capture on the master-facing link at nanosecond precision.
3. Send one READ. While the response is held, drop **the original response only** on the
   master-facing side, scoped to the probe's own 4-tuple using
   `active_probe/rto_probe_plan.py`, which selects by payload length rather than by guessing
   from PSH and confirms its own removal.
4. Let the outstation's retransmission arrive, roughly 3 s later on the measured timer.

**The outcome is binary and needs no statistics.** If the retransmission reaches the master, the
duplicate suppression does not block loss recovery in this case and the risk is closed. If it
does not, `OUT_RESP_DUP_SUPP` dropped a packet that TCP needed, and the transaction's liveness
window is too long relative to the outstation's retransmission timer.

**What would make the run invalid:** shaping enabled, so the segmentation differs from the
campaign; the filter matching anything but the probe connection; or the rule's removal
unconfirmed. Those are the three things that went wrong on 2026-09-15 and are the reason the
corrected probe checks all of them.

This was run on 2026-09-15 under a separate authorisation. It did not reach the case above: the
filter dropped every copy rather than only the original, and the copies arrived seconds after the
transaction had retired, so the live-window case remains open.

---

# 2. Next steps, in priority order

Four candidates, each with what is actually known, the smallest useful next step, and a
disposition.

## 2.1 A delay-selection guideline — *do now, offline*

**Problem.** Choosing an admissible hold currently leans on a single ambiguous bound.

**Evidence.** The frozen policy collapses three different constraints into one field and fills
unmeasured terms with defaults. Its sub-millisecond detection and drain constants come from
Defense 3 measurements of 2026-07-29, an earlier build, and are not measurements of the loaded
one.

**Smallest step.** Already taken: `active_control/delay_admission.py` keeps the master's timer,
the outstation's timer and the application deadline as three separate named inputs, carries a
provenance tag on every one, and refuses to call transport safety verified when any required
input is unknown or inherited. The cap is deliberately independent of measured RTT so the
mechanism's own inflation of RTT cannot license a longer hold.

**Trade-off.** More inputs to supply, and most deployments will get "provisional" rather than
"admitted" until they measure their own connection. That is the correct answer, not a defect.

**Disposition.** Done offline. No machine learning is needed or proposed; the estimator that is
missing is a measurement, not a model.

## 2.2 Direct epsilon measurement — *run; attribution incomplete*

**Problem.** The post-deadline blocking interval is unmeasured, and two artefacts have been
mistaken for it.

**Evidence.** The four timestamp registers are declared and never executed. The blocker figures
of 2026-09-15 start at arming, so they include the intended hold. Port counters cannot separate
the ACK and RESPONSE reservoirs, which share dp8 and one scheduler.

**Smallest step.** Taken as far as it can go offline: `audit_current/EPSILON_MEASUREMENT_PLAN.md`
for the four events and the procedure, and `audit_current/epsilon_candidate/` for the patch
itself, which applies to the recorded base hash and reproduces the candidate byte for byte. The
writes ride the existing `mark_expired` and `mark_expired_resp` actions, so no new predicate is
introduced, and each action's lane makes the register index a compile-time constant.

**Trade-off.** The program already fills all twelve ingress stages, so the candidate may not
compile, and instrumentation can perturb the timing it measures. Departure remains unobservable
from ingress, so even a successful run measures up to the last blocking action, not to the wire.

**Disposition.** Superseded. The candidate was compiled on the switch and loaded, and an interval
was measured. It is an internal blocker-termination interval rather than epsilon to the wire, and
the loaded build's identity is incompletely recorded, so it is a diagnostic rather than a property
of an identified build.

## 2.3 Residual ACK-timing leakage — *defer*

**Problem.** The acknowledgment interval carries class information that the mechanism creates
rather than removes: balanced accuracy on it rises from 0.379 to 0.662.

**Evidence.** The two lanes compute their releases from different anchors. Reproduced: 0.651
balanced accuracy for a retrained adversary using both intervals, against 0.3333 for CLRT alone.

**Smallest step.** Analyse, on paper, a common-anchor schedule in which both releases derive from
the same event, and state what it would cost in device availability, transport feedback,
operational latency and switch resources.

**Trade-off.** A common anchor lengthens at least one hold, which consumes the master's timer
budget and the application deadline. It is a design change, not a correction.

**Disposition.** Defer. Future work, named in the paper, not implemented in this pass.

## 2.4 A hard elapsed-time limit — *defer, and stop implying one exists*

**Problem.** The paper claimed a horizon the hardware does not enforce.

**Evidence.** The budget counts blocker passes, not time. The sweep's own table settles it: at a
configured 36 ms acknowledgment hold, the median request-to-acknowledgment interval saturates at
31.07 ms while the median request-to-response interval is 40.58 ms, past the 30.8 ms horizon. The
acknowledgment reaches a ceiling and the response does not stop at it.

**Smallest step.** Already taken: design and implementation now describe the horizon as a
control-plane admission test and the saturation as an observed transition in one lane.

**Trade-off.** Whether a true wall-clock limit is needed depends on the deployment's latency
requirement, which is not established. No verified numeric response deadline for a DNP3 poll or a
select-before-operate on a distribution relay was found in primary documentation. The only
verified numeric deadline on the evaluated relay is its own select-to-operate timeout, documented
default 1.0 s, which governs how long a select stays armed rather than how quickly a response
must return. A reading note from another protocol's timing class is not a DNP3 requirement and is
not treated as one.

**Disposition.** Defer the mechanism. The claim is corrected now.

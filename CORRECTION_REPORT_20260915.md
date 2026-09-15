# Correction pass, 2026-09-15

Base commit `18a595a`, branch `fix/offline-corrections-20260915`. Offline only: no hardware was
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

## 2.2 Direct epsilon measurement — *measurement prepared, not run*

**Problem.** The post-deadline blocking interval is unmeasured, and two artefacts have been
mistaken for it.

**Evidence.** The four timestamp registers are declared and never executed. The blocker figures
of 2026-09-15 start at arming, so they include the intended hold. Port counters cannot separate
the ACK and RESPONSE reservoirs, which share dp8 and one scheduler.

**Smallest step.** `audit_current/EPSILON_MEASUREMENT_PLAN.md`: three registers per lane over the
recorded base hash, the four events defined before any register is named, and the procedure with
its failure criteria.

**Trade-off.** The program already fills all twelve ingress stages, so the candidate may not
compile, and instrumentation can perturb the timing it measures. Departure remains unobservable
from ingress, so even a successful run measures up to the last blocking action, not to the wire.

**Disposition.** Prepared. Uncompiled, because `bf-p4c` exists only on the switch. Epsilon stays
unmeasured.

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

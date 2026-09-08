# Release variability: what can be measured now, and what cannot

Written 2026-09-08 for the post-meeting revision. Dr. Lin asked that the small release delay be
measured even though it is hard to see in a plot. This note reports the status honestly:
**with the loaded program the interval cannot be observed at all**, and the reason is in the
program's source, not in the analysis.

## 1. The endpoints, named separately

"Time to drain the queue" is too broad to be a measurement. These are different events and only
some of them are observable.

| # | Event | Observable today? |
|---|---|---|
| 1 | the deadline word is reached, `now_word - stored >= 0` | no |
| 2 | the last blocker of the reservoir is served | no |
| 3 | the traffic manager serves the held packet | no |
| 4 | the packet re-enters the pipeline from the loopback port | no |
| 5 | the packet leaves the front-panel port (`e_A`, `e_R`) | no |
| 6 | the packet arrives at the master's NIC (`m_A`, `m_R`) | **yes**, this is what we capture |

The quantity Dr. Lin asked about is the **post-deadline release delay**, event 1 to event 5. It
includes scheduler service, loopback re-entry and egress serialization. We measure only event 6.

## 2. What the master-facing capture can and cannot separate

Because both deadlines are armed from the one anchor `t_A`, the measured CLRT carries

    measured CLRT = CLRT_target + (release delay of the response - release delay of the ACK)
                    + (differential path and capture delay)

The bracketed term is a **net, signed residual**, not a queueing delay. A fixed target has no
variance of its own, so the variance of the measured CLRT is the variance of that net residual.
That identity is arithmetic; it does not identify the residual's physical cause, and it cannot
apportion the residual between the two packets. Calling it a single non-negative queue delay
would be wrong.

Three populations must also stay separate, and a histogram of the measured CLRT alone does not
separate them:

1. responses present before their deadline, which is the case the model describes;
2. responses that arrive after their deadline and are forwarded on arrival;
3. holds released by the fail-open budget rather than by the deadline.

Only population 1 carries the residual of interest. In `campaign_v1` the obfuscated READ arm has
36 transactions farther than 0.5 ms from the target out of 26,400, which bounds populations 2
and 3 together but does not split them.

## 3. Why the loaded program cannot supply the release instant

The program declares ten timestamp write actions:

    ts_ack_arm_w      ts_ack_release_w   ts_resp_release_w   ts_first_block_w
    ts_last_block_w   ts_block_term_w    ts_clone_w          ts_read_w
    ts_resp_bypass_w  ts_last_term_w

Verified in `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` on
2026-09-08: **each name appears exactly once as a `RegisterAction` declaration, and every
further occurrence is inside a comment.** None of them has an execute site, so none is ever
applied to a packet. Four more sit behind the compile-time switch `D3_SYNTH_EVENTS`, which the
evaluated build does not define.

Two further facts close the door:

* Every declared write takes an **ingress** timestamp. An ingress timestamp is not a wire
  departure, so even if an action were executed it would not answer the question.
* Reading these registers from the control plane therefore returns their initial value. A
  control-plane readback **cannot** be presented as a measurement of release time.

Obtaining event 5 requires a different P4 program with an egress-timestamp write at a real
execute site, and therefore a different binary and a different binary hash. That is outside what
the current handoff authorizes, and its evidence would have to be kept separate from
`campaign_v1`.

## 4. The smallest measurement that would answer the question

Two options, neither executed here.

**A. External synchronized capture.** Tap the switch's relay-facing and master-facing links and
capture both with one clock. This yields `e_A` and `e_R` directly, without touching the program,
and so preserves the evaluated binary. Requirements: a capture device whose timestamping
resolution and stability are documented, both taps on the same clock domain, and transaction
association by TCP sequence number rather than by arrival order. It measures event 5 to event 6
and the deadline instant remains unobserved, so it bounds the residual from above rather than
isolating it.

**B. Minimal instrumentation.** Add one egress-timestamp write on the release path, at an
execute site, into a register the control plane reads per transaction. This observes event 5 and,
with the already-stored deadline word, gives the post-deadline release delay directly. It needs a
new build, a new hash, and a re-verified provenance record.

Either way the report must state timestamp resolution separately from measurement accuracy. The
deadline grid is 256 ns; that is a quantization step, not an accuracy claim, and nanosecond clock
resolution must never be reported as nanosecond measurement accuracy.

## 5. Status for the manuscript

**Unavailable.** The paper should say that the switch-side release instants were not captured,
that the loaded program cannot supply them, and that what the measured distribution shows near
the target is the net residual plus differential path effects rather than a queue delay. It
should not attribute the observed spread to queue draining, and it should not claim the residual
is device-independent: a narrow histogram alone cannot establish that.

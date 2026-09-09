# Blocker-queue drain time: what is measured, what is not, and what would close it

Written 2026-09-08 for the post-meeting revision; rewritten 2026-09-09 after the follow-up
corrections narrowed the question. Dr. Lin asked for the **blocker-queue drain time**: the
elapsed time from the expiry of the relevant hold deadline until the remaining relevant blockers
clear and blocking ceases. This note names those two events against the logic the loaded program
actually implements, reports the one existing measurement that bears on them, and states exactly
what remains open.

The quantity here is **not** a generic error term, **not** total packet latency, and **not** the
difference between the measured and the configured `CLRT_new`. A plot of the CLRT residual does
not measure queue draining; see §4.

## 1. The two events, verified against the implemented logic

Source read on 2026-09-09:
`implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`.

The loaded program runs a four-queue strict-priority ladder on the internal loopback port
`PORT_L` = dp8, declared at lines 372–384:

| queue | constant | contents |
|---|---|---|
| qid7 | `QID_ACK_BLOCK` (`Q_ACK_BLOCK`, HIGH) | ACK blocker reservoir, token slot `SLOT_ACK`, tests `reg_deadline` |
| qid6 | `Q_ACK_HOLD` | the held acknowledgment, queue-resident |
| qid5 | `QID_RESP_BLOCK` (`Q_RESP_BLOCK`) | RESPONSE blocker reservoir, token slot `SLOT_RESP`, tests `reg_tresp` |
| qid4 | `Q_RESP_HOLD` | the held response, queue-resident |

Both reservoirs are seeded from one recirculation-triggered 2K generator batch; `packet_id`
0–63 selects the ACK reservoir and 64–127 the RESPONSE reservoir (line 851). K = 64 tokens per
reservoir. Real packets never loop; only tokens do (line 375).

Expiry is a **timestamp-deadline test**, not a token count. `tbl_deadline_expiry` (lines
2761–2768) matches `meta.age = now_word - deadline_word` on the single ternary entry
`32w0x00000000 &&& 32w0x800000FF`: the sign bit clear (the deadline has passed) and the low byte
zero (the word is armed). `tbl_tresp_expiry` is the symmetric test on `meta.age_resp` against
`reg_tresp`. Each token performs this test on its own loopback pass. A token that is not yet due
takes `dec_loop(OUT_AB_LOOP)` or `dec_loop(OUT_RB_LOOP)` and is re-enqueued to its own queue
(`cmt_block`, `cmt_resp_block`, lines 2323 and 2327); a token that is due takes
`dec_o(OUT_AB_DL)` or `dec_o(OUT_RB_DL)` and is dropped at `tbl_commit`. When the last token of a
reservoir is dropped, that reservoir is empty and the held packet below it becomes the highest
eligible queue.

Therefore, per lane:

* **start event** — the first pass on which that lane's expiry test fires:
  `meta.expired == 1` against `reg_deadline` for the ACK lane, `meta.expired_resp == 1` against
  `reg_tresp` for the RESPONSE lane;
* **end event** — the last token of that lane's reservoir taking its `_DL` disposition, after
  which qid6 (ACK lane) or qid4 (RESPONSE lane) is served.

The two lanes are coupled by the shared port: qid7 sits above qid5 in the ladder, so while the
ACK reservoir is occupied it starves the RESPONSE reservoir, and the RESPONSE reservoir only
circulates at full rate once the ACK reservoir has drained. The two drain intervals must be
reported separately under the queue labels above, never as one number.

## 2. The existing measurement, and the program it belongs to

There is one measurement in the project's history with these endpoints instrumented on silicon.
It is **not** from the campaign build.

**Program.** `ibspg_hold_response`, the direct predecessor of the loaded program (Part 12 of the
IBSPG series). P4 source SHA-256
`fa073cf691a6beb45fa8ffa61146cf481fc81e42f6cf4640bcb44ae6fe08f947`, BF-SDE 9.13.2, Tofino-1,
switch `10.10.54.81`, designed, compiled and run 2026-07-25. Recorded in
`research/ibspg_hold_response/IBSPG_HOLD_RESPONSE_RESULT.md` §17 and
`evidence/part12/rep_campaign_100/campaignA_summary.json`, both preserved in git history at
commit `9adb92e` (the files are not in this pruned tree).

**Blocker population and traffic.** One reservoir, K = 64, in Q_BLOCK (qid7, `max_priority`
HIGH) starving one held RESPONSE in Q_RESP (qid1, LOW). Synthetic protocol roles only: no DNP3
parsing, no SEL-751, an injector spacing responses 0.5–2 ms apart, dp8 `BF_LPBK_MAC_NEAR` at 25G.
The acknowledgment was forwarded immediately and never held, so this program has **one** blocker
queue, not the campaign build's two.

**Clock, units, resolution, association.** All intervals are computed on chip from
`ig_intr_md.ingress_mac_tstamp` register pairs in nanoseconds, with wrapping 32-bit arithmetic
(§18). One clock, so no cross-device synchronization is involved. Each interval is associated
with its transaction by the per-repetition register read: one held response per repetition, read
back and reset between repetitions, 100 unique non-duplicated repetition identifiers. A Vision
host PCAP was taken alongside and is explicitly **corroboration at millisecond scale only**:
kernel capture jitter is about 10 µs, four orders of magnitude coarser, and was never used to
support the nanosecond figures. The 32-bit nanosecond clock is a resolution, not an accuracy
claim.

**Results, n = 100, G = 20 ms** (recomputed from the raw registers by
`harness/aggregate_campaign.py`, not from the reader's derived block):

| component | endpoints | min | median | mean | sd | max |
|---|---|---:|---:|---:|---:|---:|
| c1 | deadline reached → **first** blocker observes expiry | 0 ns | 15 ns | 14.4 ns | 7.16 ns | 26 ns |
| c2 | first blocker termination → response released | 1,717 ns | 1,720 ns | 1,720.13 ns | 1.14 ns | 1,723 ns |
| total | deadline reached → response released | 1,720 ns | 1,735 ns | 1,734.53 ns | 7.34 ns | 1,747 ns |

Across a deadline sweep of {1, 2, 5, 10, 17, 25, 40} ms the total stayed within 1,721–1,744 ns
with nothing tuned per point, so the tail does not scale with the hold.

**What this does and does not answer.** c1 shows that a blocker notices the deadline within one
pass. It is the deadline-to-**first**-termination interval, not the deadline-to-empty interval.
The reservoir's remaining tokens drain inside c2, together with the dequeue and the egress path,
and c2's internal composition is recorded in the source document as `[OPEN]`: there is no
per-token termination timestamp and no queue-depth trace at that resolution. c2 is also about
4.2× the independently measured ≈408 ns single-token dp8 loop traversal, so it is not one loop.
The honest bound from this evidence is therefore

    14.4 ns  ≤  drain interval (deadline → blocking ceases)  ≤  1,734.5 ns   (mean values)

and the evidence cannot place it inside that interval. It is a single-queue result on a
predecessor program, so it does not give an ACK-lane and a RESPONSE-lane figure, and it must not
be reported as a measurement of the campaign build.

## 3. Why the loaded program cannot supply it

The program declares ten timestamp write actions:

    ts_ack_arm_w      ts_ack_release_w   ts_resp_release_w   ts_first_block_w
    ts_last_block_w   ts_block_term_w    ts_clone_w          ts_read_w
    ts_resp_bypass_w  ts_last_term_w

Verified in `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` on 2026-09-08:
**each name appears exactly once as a `RegisterAction` declaration, and every further occurrence
is inside a comment.** None has an execute site, so none is ever applied to a packet. Four sit
behind the compile-time switch `D3_SYNTH_EVENTS`, which the evaluated build does not define.
`ts_last_term_w` and `ts_block_term_w` are precisely the two that would give the end event.

Two further facts close the door:

* every declared write takes an **ingress** timestamp, and an ingress timestamp is not a wire
  departure, so even an executed write would not give event 5 of the chain in §4;
* reading these registers from the control plane therefore returns their initial value, and a
  control-plane readback cannot be presented as a measurement.

See `audit_current/INSTRUMENTATION_AUDIT.md` for the per-register detail.

## 4. What the master-facing capture can and cannot separate

The chain of events, and what `campaign_v1` observes:

| # | event | observable in `campaign_v1`? |
|---|---|---|
| 1 | the lane's deadline word is reached | no |
| 2 | the first blocker of that reservoir observes expiry | no |
| 3 | the last blocker of that reservoir terminates; blocking ceases | no |
| 4 | the traffic manager serves the held packet | no |
| 5 | the packet leaves the front-panel port (`e_A`, `e_R`) | no |
| 6 | the packet arrives at the master's NIC (`m_A`, `m_R`) | **yes** |

The drain interval is event 1 to event 3. The campaign measures event 6 only.

Because both deadlines are armed from the same instant `t_A`, the measured CLRT carries

    measured CLRT_new = configured CLRT_new
                        + (release delay of the response - release delay of the ACK)
                        + (differential path and capture delay)

The bracketed term is a **net, signed residual**, not a queueing delay, and not a drain time. A
fixed configured value has no variance of its own, so the variance of the measured `CLRT_new` is
the variance of that net residual. That identity is arithmetic; it does not identify the
residual's physical cause and it cannot apportion the residual between the two packets. A
histogram of the CLRT residual is therefore not a measurement of queue draining.

Three populations must also stay separate, and the measured CLRT alone does not separate them:

1. responses present before their deadline, which is the case the model describes;
2. responses that arrive after their deadline and are forwarded on arrival;
3. holds released by the fail-open pass budget rather than by the deadline.

Only population 1 carries the residual of interest. In `campaign_v1` the Obfuscated READ arm has
36 transactions farther than 0.5 ms from the configured value out of 26,400, which bounds
populations 2 and 3 together but does not split them.

## 5. The smallest change that would measure it

Not executed here: this handoff authorizes no new build, no binary load, and no hardware run.

**B1 — two register writes, one per lane.** Give `ts_last_term_w` a real execute site on the
disposition that drops the last token of a reservoir (`OUT_AB_DL` for qid7, `OUT_RB_DL` for
qid5), writing `ingress_mac_tstamp` into a per-lane register, and pair it with the deadline word
already stored in `reg_deadline` and `reg_tresp`. The drain interval is then
`ts_last_term − deadline_word` per lane, read back per transaction. "Last" is identified without
a counter by writing unconditionally on every `_DL` disposition of that lane and letting the
final write stand, provided the register is reset per transaction; the reset is the part that
needs care, because the campaign build does not reset per transaction today.

Cost: two execute sites and two 32-bit registers per lane. Both timestamps are ingress-side,
which is correct here — the drain endpoint is a pipeline event, not a wire departure — so this
change does not inherit the ingress/egress objection of §3.

**B2 — external synchronized capture.** Tap the relay-facing and master-facing links on one
clock. This yields `e_A` and `e_R` without touching the program and preserves the evaluated
binary, but it observes event 5, not event 3, so it bounds the drain from above rather than
isolating it. Requirements: documented timestamping resolution and stability, both taps in one
clock domain, and transaction association by TCP sequence number rather than arrival order.

Either way the report must state timestamp resolution separately from measurement accuracy. The
deadline grid is 256 ns; that is a quantization step, not an accuracy claim, and nanosecond clock
resolution must never be reported as nanosecond measurement accuracy.

**What remains open after B1.** The per-lane drain interval would be measured, but the interval
from blocking ceasing to the wire departure would still be unmeasured, because that endpoint is
egress-side. The Part-12 c2 figure suggests it is the larger of the two terms.

## 6. Status for the manuscript

**Unavailable for the evaluated build.** The paper says that the switch-side release instants
were not captured, that the loaded program cannot supply them, and that what the measured
distribution shows near the configured value is the net residual plus differential path effects
rather than a queue delay. It does not attribute the observed spread to queue draining, and it
does not claim the residual is device-independent: a narrow histogram alone cannot establish
that. The Part-12 numbers of §2 belong to a different program and stay out of the manuscript's
results; they are recorded here as the prior observation that motivates B1.

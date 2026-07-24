# Two-stage parking & release — architecture analysis (Part 3)

Three concrete two-stage topologies, each analyzed against the **fundamental Tofino-1 wall** established
by the backpressure audit and the IBSPG results:

> The TF1 data plane sets a packet's fate **only at enqueue** (`ucast_egress_port`, `qid`,
> `ingress_cos`, `packet_color`, `deflect_on_drop`, `bypass_egress`). It has **no lever to retain an
> already-enqueued packet**. A queue-resident hold therefore requires the queue to be un-serviced,
> which on TF1 means one of: strict-priority starvation (**refuted** — shaping serves the low queue,
> unshaped is not absolute), shaping delay (**fails for a sparse/lone packet** — the shaper has credit
> and dequeues it immediately), scheduling-disable (**control-plane only**), PFC/pause (**threshold-
> driven, per-CoS, needs sustained high-rate backlog, unsafe**), or **recirculation** (the packet keeps
> moving; ms-scale ⇒ thousands of passes ⇒ the forbidden "continuous original recirculation").

Language rule honored: no candidate below says "move the packet between queues" unless a supported
mechanism performs it. On TF1 the only supported "move" is *re-enqueue on a recirculation/loopback pass*
(the packet leaves the queue, re-ingresses, and is enqueued again by the data plane).

---

## Candidate A — PARK QUEUE → INTERNAL BACKPRESSURED LOOPBACK → RELEASE QUEUE

- **Packet path:** ACK enqueued (qid=Q_PARK) toward an internal loopback port L whose egress is held
  by backpressure; on the response event the backpressure is lifted and the ACK dequeues to a release
  path → protected egress.
- **ACK location during hold:** Q_PARK on port L (TM queue memory) — *if* the backpressure is a true
  hold and not a drop.
- **Response location:** the response packet's job is to *remove* the backpressure.
- **Queue IDs / internal ports:** Q_PARK (low), an internal loopback L, plus a congesting source.
- **Exact-match slot state:** flow→slot (carried from IBSPG), generation, expected-ack.
- **Response-event action:** stop/redirect the congesting traffic that holds L's queue paused.
- **Release sequence:** backpressure clears → Q_PARK becomes serviceable → ACK egresses.
- **ACK-before-response:** only if the response is itself held behind the ACK in FIFO — needs a second
  held queue (recursion of the same hold problem).
- **Timeout/fail-open:** a pass/epoch budget on the congesting traffic; on expiry, stop congesting → release.
- **HOL:** severe — a per-CoS pause blocks *every* flow in that class, not one transaction.
- **Original passes:** 0 if truly queue-resident; but see verdict.
- **Internal tokens:** the congesting traffic **must run continuously for the whole hold window** to
  keep the pause asserted.
- **Static TM config:** a lossless PPG + PFC honor on L's queue (control-plane, one-time — allowed).
- **Stage/queue estimate:** ~7 stages; ≥3 queues + 1 PPG.
- **Failure modes → VERDICT: REFUTED.** The only backpressure that *holds* (not drops) is PFC/pause
  (audit HOLD-bucket). To keep the pause asserted for a ms hold, the congesting traffic must sustain a
  backlog above the PFC threshold **for the entire window** — i.e. **continuous high internal rate**,
  violating "bounded low internal rate," not low-rate-testable (the ~1200 pps TM-engagement floor), and
  **per-CoS not per-transaction**. Removing congestion is a data-plane action, but *maintaining* it is
  not bounded. Inherits the backpressure family's refutation.

---

## Candidate B — PARK PORT → RESPONSE-ENABLED SECOND-STAGE ADMISSION → RELEASE PORT

- **Packet path:** ACK sent to a "park port"; on the response event it is admitted to a second-stage
  path leading to the release port.
- **ACK location during hold:** to hold *at a port*, the port's queue must be un-serviced. A packet
  sent to a normal port egresses; a packet sent to a loopback port re-ingresses. So "park at a port"
  is physically one of: (i) a blocked queue (same wall as A), or (ii) the ACK **recirculates** at the
  park port until the response admits it to stage 2.
- **Response-event action:** set a per-slot register; on the ACK's next re-ingress the data plane reads
  it and routes the ACK to the release port (stage-2 admission) instead of re-parking.
- **Release sequence:** register set → next pass routes ACK to release port.
- **ACK-before-response:** enqueue ACK then response in the release queue in arrival order (FIFO works).
- **Original passes:** interpretation (ii) is **exactly the frozen recirc-hold** (`dcrn_defense1/2`):
  the ACK spins at the park port, checking a register each pass, released on match. For a ms-scale
  CLRT that is **thousands of passes** at line rate → the forbidden "continuous original recirculation."
- **Internal tokens:** none extra (the original itself carries the state check).
- **Static TM config:** park loopback + release port.
- **Stage/queue estimate:** ~7–9 stages (the frozen defense fits ~9).
- **Failure modes → VERDICT: = the excluded baseline.** Interpretation (ii) is the frozen recirc-hold,
  which the direction designates a comparison baseline, not the deliverable. Interpretation (i) needs a
  blocked-queue hold → the same wall. No new escape.

---

## Candidate C — BOUNDED INTERNAL EPOCH → PARK QUEUE → ACK/RESPONSE FIFO RELEASE

- **Packet path:** the ACK is parked for a bounded epoch, then ACK and response are released in FIFO
  order.
- **The epoch idea + the innovation attempt (paced/shaped recirculation):** instead of spinning at line
  rate (thousands of passes), let each recirc pass spend time *queue-resident* in a **low-rate shaped
  queue**, so a ms hold takes only ~tens of passes (per-pass shaper delay ≈ 1/rate). This would be
  "mostly queue-resident, few passes" — a genuine improvement over the frozen recirc-hold.
- **Why the innovation FAILS on TF1 (measured/architectural):** a queue shaper is a token bucket. A
  **lone/sparse** packet arriving after idle finds accumulated credit and **dequeues immediately** —
  the shaper does not delay it. Per-pass shaper delay only appears under a **sustained** backlog that
  has depleted the credit, i.e. continuous high-rate traffic (the same ~1200 pps TM floor seen in the
  queue-microbench). So for a sparse DNP3 ACK, shaped recirculation collapses back to either
  immediate dequeue (no hold) or continuous fill (high rate). **No paced few-pass hold for a sparse
  packet exists.**
- **ACK-before-response / FIFO:** this part genuinely works — two packets enqueued in one queue egress
  in order; ACK-before-response is a solved sub-primitive **given** a hold. It is not the blocker.
- **Timeout/fail-open:** pass/epoch budget (the proven IBSPG pass-budget), fail-open at expiry.
- **VERDICT: REFUTED for a sparse packet.** The epoch/FIFO framing is sound, but the *hold* inside it
  reduces to the same wall: sparse ms-hold needs either thousands of recirc passes (forbidden) or a
  blocked queue (no data-plane lever). Shaping does not rescue it for sparse traffic.

---

## Convergence — the single wall, across three families

| Family | Hold mechanism attempted | Why it fails for a bounded, low-rate, sparse, per-transaction, non-recirc hold |
|---|---|---|
| IBSPG (strict priority) | high-priority blocker starves low queue | unshaped not absolute (recirc: served at MHz); safely-shaped ⇒ shaper gaps serve the low queue |
| Backpressure (A) | PFC / scheduling-disable | scheduling-disable is control-plane; PFC needs sustained high-rate, per-CoS, unsafe |
| Two-stage (B, C) | park-queue / paced recirc | park = blocked queue (no DP lever) **or** recirc (ms ⇒ thousands of passes, forbidden); shaping can't pace a sparse packet |

**Root cause (one sentence):** the TF1 data plane can choose *which pre-armed lane* a packet enters at
enqueue, but can never *actuate a hold* on an enqueued packet, and shaping/priority cannot detain a
**sparse** packet without continuous high-rate competition — so the only data-plane hold for a sparse
original packet is continuous recirculation, which is excluded.

## The sole residual (empirically, not architecturally, open)
Everything above is a **zero-risk architectural refutation**. The single mechanism that is a *true*
queue-resident hold and is even partially data-plane-influenceable is **self-generated PFC** (Candidate
A with a lossless PPG on a loopback). The audit predicts it needs sustained high-rate fill and is
per-CoS/unsafe — i.e. it will **refute low-rate viability** if tested. That is the one thing a bounded
**low-rate** silicon experiment can still close empirically (Part 4/5): *does a low, safe packet rate
ever engage a PFC pause long enough to hold one frame, and does stopping it release the frame?* —
predicted NO at low rate. It is the only remaining empirical question; the architectural answer is
already a strong negative.

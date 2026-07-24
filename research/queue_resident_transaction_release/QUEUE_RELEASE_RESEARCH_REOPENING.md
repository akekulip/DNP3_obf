# Queue-release research — reopening & record correction (Part 1)

The prior capability audit (`research/unified_queue_release/`) is preserved as evidence. Its
project-level *interpretation* is corrected here. The negative-audit documents are NOT deleted or rewritten.

## SUPPORTED CONCLUSION (unchanged, evidence-backed)

> **Tofino-1 has no *direct* data-plane primitive that changes the eligibility of an already-enqueued TM
> packet in response to a later packet event or an arbitrary per-packet deadline.**

Specifically (all preserved in `TOFINO_QUEUE_RELEASE_CAPABILITY_AUDIT.md`): ingress P4 cannot change the
scheduling eligibility of an enqueued packet; P4 cannot move an enqueued packet between queues; TM
scheduling/shaping/enable controls are control-plane (bfrt) only; there is no per-packet EDT / event-to-
dequeue primitive; the TF1 per-port flush is a TF2-only no-op. This is a statement about **direct TM
control**, and it holds.

## NOT YET PROVEN (the reopened research problem)

> **No composition of queues, fixed-pass loopback, flow control, internal tokens, queue occupancy,
> scheduling hierarchy, mirroring/cloning, or other Tofino-1 primitives can implement transaction-aware
> queue-resident holding with response-event / target-time release.**

The prior report over-generalized the direct-primitive negative into "the constraint set is unsatisfiable"
and recommended accepting continuous real-packet recirculation as the final mechanism. **That
recommendation is withdrawn.** The absence of a *direct* queue-open primitive is the research problem, not
the answer. An *indirect* construction does not need to "open a queue" — it needs to arrange, using only
statically-configured scheduling plus data-plane packet actions, that the held packet's queue *becomes
serviceable at the right moment as a side effect of the response event*.

## The key reframing (why indirect constructions are not excluded)

The audit's own finding contains the opening: **P4 controls a packet's queue and eligibility at ENQUEUE,
per packet, and one packet's arrival can affect ANOTHER queue's service indirectly** — the audit explicitly
notes "one packet [can] cause another queue to receive service … by injecting new work … or by
strict-priority contention." Static strict-priority + DWRR + shaping are configured once (control-plane at
init, allowed) and thereafter the *interaction of packets* determines service order **without any further
control-plane action**. So the design question is:

> Can a held packet be parked in a low-priority queue that is kept un-serviced by a **continuously occupied
> internal higher-priority queue** (an internal blocker token that never egresses the WAN), and then
> released when the **matching response event drains that blocker** — so that strict priority, not a control-
> plane write, services the held packet?

This is a composition of *supported* primitives (qid-at-enqueue, strict priority, internal loopback, a
recirculating internal control token, a per-slot register set by the response) that produces an *indirect*
eligibility change. It is the lead candidate developed in Part 6 and tested experimentally in Parts 10–11.
It is not claimed to work until silicon shows it does; it is claimed to be **not refuted by the direct-
primitive audit** — a distinction the prior report collapsed.

## Constraints carried forward (from `direction.md`, unchanged)

Tofino-1 only; original ACK/response buffered primarily in TM memory; transaction-aware; one unified
normalizer; **no external chaff on the protected link**; **no controller in the packet fast path**; no
SmartNIC/DPU/host/eBPF/platform-split; **no continuous thousands-of-pass recirculation of the original
packet**; ACK-before-response; exact isolation; byte-preserving; bounded fail-open. A **fixed small number**
of loopback/pipeline passes is allowed; **internal control-token recirculation** may be investigated;
continuous recirculation of the original packet remains a **comparison baseline only**.

## What changes in the project record

- The recirc-hold (`dcrn_defense1/2`) is re-designated a **comparison baseline**, not the final mechanism.
- The research is **reopened** on indirect queue-resident constructions (Part 6), with experimental
  microbenchmarks required before any impossibility claim (Part 14 honesty rule: a strong negative is
  acceptable only *after* the relevant indirect constructions and microbenchmarks are investigated).
- All prior negative-audit documents are preserved unchanged as evidence about *direct* TM control.

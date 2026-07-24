# Indirect queue-release design space (Part 6)

The direct primitive is absent (Part 1). The research target is an **indirect composition** of supported
Tofino-1 primitives that makes a queue-resident packet become serviceable *as a side effect of the response
event*, without a control-plane write, without external chaff, and without continuously recirculating the
original.

## The reframing that opens the space

Strict priority + DWRR + shaping are configured **once** (control-plane init, allowed). Thereafter the
**interaction of packets** — which queues are occupied — determines service order, with **no further
control-plane action**. And `qid`/eligibility is chosen by P4 **at enqueue, per packet**. So an event can
change *which queue is occupied*, and occupancy + static priority then change *which queue gets serviced* —
an **indirect** eligibility change. The audit itself notes: "one packet [can] cause another queue to receive
service … by strict-priority contention." That is the lever.

## LEAD CONSTRUCTION — Internal-Blocker Strict-Priority Gate (IBSPG)

**Idea:** park the held packet in a low-priority queue that is kept un-serviced by a **continuously
occupied internal higher-priority queue** (an internal blocker token that never egresses the WAN); the
matching-response event **drains that blocker**, and strict priority — not the control plane — then services
the held packet.

### Topology (per admitted slot; bounded set)
- An **internal loopback port L** (MAC-near loopback, or dp68 recirc used as an internal path). Its egress
  never reaches Vision/Hulk.
- Two queues on L: **Q_HOLD** (low strict-priority) and **Q_BLOCK** (high strict-priority).
- The held ACK (and, in FIFO order, the response) sit in **Q_HOLD** — genuinely **TM-queue-resident**.
- An **internal blocker token** continuously occupies **Q_BLOCK**: dequeue → egress L → loopback re-ingress
  → re-enqueue Q_BLOCK. While Q_BLOCK is non-empty, strict priority **starves Q_HOLD** → the ACK is held.

### Release (HOLD_ACK — response event)
1. READ arms slot state (exact admission, Part 4 of prior branch, carried forward).
2. Pure ACK (matched: armed ∧ flags_ok ∧ ack==expack) → enqueue in **Q_HOLD** (queue-resident, blocked).
3. Matching RESPONSE arrives → (a) enqueue it in **Q_HOLD behind the ACK**, and (b) set `reg_drain[slot]=1`.
4. The blocker token, on its next loopback pass, reads `reg_drain[slot]`; if set it is **DROPPED (not
   re-enqueued)** → Q_BLOCK empties → strict priority now services **Q_HOLD** → **ACK dequeues first, then
   the response** (FIFO order) → each egresses L → one loopback pass → forwarded to the master (dp9).
5. **ACK-before-response is guaranteed by FIFO order in Q_HOLD** (ACK enqueued before the response). The
   original packets made a **fixed, small number of passes** (into Q_HOLD, out on release) — they were
   **queue-resident**, not spinning.

### Release (HOLD_RESPONSE — deadline)
Same topology; the ACK is **forwarded immediately** (not held), `t_ack` recorded; the response is enqueued
in Q_HOLD (blocked). The blocker's own continuous loop is a **clock** (each pass ≈ fixed loopback latency);
counting blocker passes since the response enqueued approximates elapsed time → when `passes ≥ G/latency`
the blocker is drained → the response releases at the ACK-relative deadline. (An internal pktgen periodic
token is an alternative clock — Part 7 internal-token rules apply.)

### Why IBSPG is not refuted by the direct-primitive audit
- It never writes a TM control from the data plane — priority is static; the **occupancy** of Q_BLOCK is
  what changes, via a normal data-plane drop of an internal token.
- The response event **changes queue admission** (drops the blocker; enqueues the response), **not queue
  configuration** — exactly the distinction the audit leaves open.
- The original ACK/response are **TM-queue-resident** in Q_HOLD, not recirculating.
- The blocker is an **internal control token** (never egresses the WAN — proven by capture, Part 7), not
  external chaff.

### The load-bearing uncertainties (why this REQUIRES a microbench, not a claim)
1. **Empty-gap:** when the blocker dequeues from Q_BLOCK to loop, Q_BLOCK is momentarily empty and the
   scheduler could service Q_HOLD prematurely. Mitigation to test: ≥2 phased blocker tokens (Q_BLOCK depth
   ≥1 always), or loopback latency ≪ scheduler service granularity. **Microbench D measures this.**
2. **Strict-priority starvation actually total?** Must confirm a non-empty high strict queue fully starves a
   low queue on TF1 (expected, but verify).
3. **Drain precision:** the release latency = time from `reg_drain` set to Q_BLOCK empty → Q_HOLD serviced.
   Measure jitter (the CLRT determinism claim depends on it).
4. **No external escape:** capture on dp9/dp11 must show zero blocker tokens (Part 7).

## Evaluation of the 20 candidate constructions

Legend: **O-store** = where the original ACK/response is stored; **TM?** = original resident in TM most of
the hold; **passes** = original-packet passes; **evt** = response event changes *admission* (not config);
**tok-hidden** = any internal token non-observable; **sparse** = supports sparse DNP3; **backlog** = needs
persistent backlog; **A<R** = guarantees ACK-before-response; **multi** = >1 txn; **HOL**; verdict.

| # | Candidate | O-store | TM? | passes | evt=adm | tok-hidden | sparse | backlog | A<R | multi | HOL | verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Ditto 2-stage hierarchical | per-state pri queues | yes | 2 | no (schedule) | chaff visible? internal only | no (skips empty) | **yes (chaff)** | via slot order | yes | per-state | needs chaff → **REFUTED w/o chaff** |
| 2 | per-flow ACK park→release queue | Q_HOLD | yes | 1-2 | — | — | needs a gate | — | yes | per-flow | low | = IBSPG core; **REQUIRES MICROBENCH** |
| 3 | per-flow response park→release | Q_HOLD | yes | 1-2 | — | — | needs a gate | — | yes | per-flow | low | = IBSPG (HOLD_RESPONSE); **REQUIRES MICROBENCH** |
| 4 | fixed 2-pass loopback, eligibility between | queue between passes | yes | 2 | yes | yes | needs hold gate | — | if ordered | yes | dep | building block of IBSPG; **INDIRECTLY CONSTRUCTIBLE** |
| 5 | internal response-derived release token | Q_HOLD + token | yes | 1-2 | yes | yes | yes | no | yes | per-flow | low | **the IBSPG drain** — **REQUIRES MICROBENCH** |
| 6 | internal pktgen timing token | Q_HOLD + pktgen | yes | 1-2 | deadline | must prove hidden | yes | no | yes | shared | low | HOLD_RESPONSE clock; **REQUIRES MICROBENCH** (P7 escape proof) |
| 7 | mirror/clone as internal control work | copy | n/a | — | maybe | must prove hidden | yes | no | — | — | — | control-only use; **INDIRECTLY CONSTRUCTIBLE** (token generation) |
| 8 | queue occupancy/watermark-triggered | — | — | — | no (egress read-only, post-deq) | — | — | — | — | — | — | ingress can't read occupancy to act; **REFUTED** (direct) |
| 9 | PFC/pause-frame class gating | class buffer | yes | — | no (HW threshold, not P4 per-pkt) | — | maybe | — | — | class | class | not P4-per-packet triggerable; **UNKNOWN→likely UNSAFE** |
| 10 | HW backpressure on internal loopback | loopback buffer | yes | — | indirect | yes | maybe | — | — | — | — | backpressure ≈ blocker; **REQUIRES MICROBENCH** (relation to IBSPG) |
| 11 | port pause/resume via internal packet | queue | yes | — | no direct | — | — | — | — | port | — | pause is CP/threshold; **REFUTED** as per-packet DP |
| 12 | priority inversion as temporary gate | Q_HOLD | yes | 1-2 | yes | yes | yes | blocker | yes | per-flow | low | = IBSPG mechanism; **REQUIRES MICROBENCH** |
| 13 | continuously-occupied INTERNAL blocker queue | Q_HOLD | yes | 1-2 | yes | **internal, no WAN egress** | yes | blocker (internal) | yes | per-flow | low | **LEAD (IBSPG) — REQUIRES MICROBENCH** |
| 14 | finite blocker sequences → bounded windows | Q_HOLD | yes | 1-2 | timed | yes | yes | finite | yes | per-flow | low | HOLD_RESPONSE deadline variant; **REQUIRES MICROBENCH** |
| 15 | ACK+resp into one FIFO only after match | Q_HOLD | yes | 1-2 | yes | — | yes | — | **yes (FIFO)** | per-flow | low | the IBSPG ordering rule; **INDIRECTLY CONSTRUCTIBLE** |
| 16 | response-triggered transfer to 2nd-stage schedule | 2 queues | yes | 2 | yes | yes | yes | — | yes | per-flow | dep | 2-stage IBSPG; **REQUIRES MICROBENCH** |
| 17 | multiple loopback ports = lifecycle stages | staged queues | yes | fixed | yes | yes | yes | — | yes | bounded | low | generalizes IBSPG; **INDIRECTLY CONSTRUCTIBLE** |
| 18 | queue-pair sched, eligibility encoded pre-enqueue | Q_HOLD/Q_BLOCK | yes | 1-2 | yes | yes | yes | blocker | yes | per-flow | low | = IBSPG (eligibility = qid choice at enqueue); **REQUIRES MICROBENCH** |
| 19 | bounded fixed # of passes for original | queue between | yes | fixed | — | — | — | — | — | — | — | the pass-budget rule; **INDIRECTLY CONSTRUCTIBLE** |
| 20 | ghost-thread / egress-state / arch-specific | — | — | — | — | — | — | — | — | — | — | **UNKNOWN** — search TF1 egress-parser/ghost facilities before dismissing |

## Convergence

Candidates 2, 3, 5, 12, 13, 14, 16, 18 are all facets of ONE mechanism: **the Internal-Blocker
Strict-Priority Gate** (park in a low queue, block with an internal high-priority token, drain on the
response event / deadline, release ACK-then-response by FIFO). Candidates 4, 7, 15, 17, 19 are its building
blocks (fixed-pass loopback, internal-token generation, FIFO ordering, staged lifecycle, pass budget).
Candidates 1, 8, 11 are refuted (chaff-dependent or direct-only). 9, 10, 20 are UNKNOWN and must be probed,
not dismissed.

**The IBSPG is the lead architecture to prove.** It is a composition of only supported primitives; it keeps
the original packets TM-queue-resident; the response event changes *admission/occupancy*, not TM config; the
blocker is internal (no WAN egress); and it needs only a fixed, small number of original-packet passes. Its
correctness is not asserted — it **requires the microbenchmarks** (Parts 10–11), whose central unknowns are
the empty-gap, starvation totality, drain precision, and the no-escape proof.

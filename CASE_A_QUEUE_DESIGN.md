# CASE_A_QUEUE_DESIGN.md — Queue-based timing design space for DNP3 Case A

_Master direction Phase 3 ("Define the DNP3 queue research questions"). Produced 2026-07-21 on
`research/caseA-ditto-queue`. Builds on `DITTO_QUEUE_RECONSTRUCTION.md` (cited source S1–S15) and
`DITTO_TO_DNP3_MAPPING.md` (mechanism verdicts M1–M16)._

> **★ This document does NOT select a design.** Master direction Phase 3: *"Do not select one
> without hardware evidence and documentation support."* It enumerates the alternatives, states
> each one's mechanism, hardware-feasibility risk, and evaluation axes, and lists exactly **what
> must be measured (Phase 4) or observed on the physical SEL-751 (Phase 5) before any selection.**
> Where I give an analytical lean, it is labelled *lean (unproven)* and is a hypothesis for the
> microbenchmark, not a decision.

---

## 1. Scope and what carries over from the recirculation baseline

The queue work replaces the **timing-release mechanism** (recirculate-until-event/deadline →
Traffic-Manager slot/shaper), **not** the surrounding correctness machinery. The following are
**already proven on silicon** (frozen baseline `dcrn_defense1.p4`/`dcrn_defense2.p4`, tag
`ack-delay-caseA-c3-pass`) and are **carried over unchanged** — the queue design must preserve all
of them (master direction §Phase 6 requirements; `ASSUMPTIONS_AND_UNKNOWNS.md` #6, #7, #18):

- **Exact pure-ACK qualification:** `armed && (flags & 0x17)==0x10 && reg_expected_ack==tcp.ack_no`,
  first-only. No FIN/RST/keepalive/dup-ACK/window-update admission.
- **Response matching** to the armed transaction; **one outstanding transaction** initially.
- **ACK-before-response ordering** as a hard invariant (TCP/DNP3 correctness).
- **Byte preservation** of the DNP3 response (no padding on the timing path).
- **Fail-open on ambiguity;** complete per-transaction cleanup; **no cold reload between
  transactions; zero stale state.**
- **MAX_PASS / equivalent is a safety valve only,** never the normal release.

The **open** part is purely: *how does a held frame get released — by recirculation (baseline) or by
a Traffic-Manager queue/slot — and with what measured timing, jitter, loss, and load-stability?*

### Minimal queue substrate (from Ditto M5/M8, one level — not the full 2-level hierarchy)
A single **shaped/"delayed" TM queue** (configured drain rate or slot boundary) plus a **normal
pass-through queue**, with a per-packet **class mark** (immediate vs delayed). This is the smallest
mechanism worth measuring (Phase 4 / `QUEUE_MICROBENCH_PLAN.md`) before touching the DNP3 program.
Escalation to Ditto's 2-level priority-pair-with-chaff hierarchy (M4/M7) is considered **only if**
the single shaped queue cannot hold a lone sparse frame to a predictable slot — and only with
measured justification.

---

## 2. QUESTION 1 — Defense 1 (delay the ACK): event-driven vs schedule-driven

**The core mismatch (meeting §12, master direction Phase 3 Q1, the project's central design
question).** Defense 1 is **event-driven**: hold the pure ACK, and when the **response arrives**,
release the ACK just before it (gap → ~0). Ditto is **schedule-driven**: a packet leaves in its
**predefined slot**, independent of any event. The queue gives us the *slot* primitive (M1–M3,
M8) but **not** the event→slot coupling — that coupling is what these alternatives must design and
measure.

### D1-A — Hybrid event-detect + queue-controlled release
- **Mechanism.** Keep **event detection** (recirculation or a register flag) to learn
  `response_seen`. Once seen, assign **both** the held ACK and the response into **controlled TM
  slots**; the queue controls the final release timing. Recirculation degrades to a *detector*
  only; the *queue* owns timing. (Master direction Phase 3 Q1-A; Ditto M6/M8.)
- **Ordering.** Preserved by construction — the ACK is placed in the earlier slot.
- **Hardware-feasibility risk.** Moderate. We already detect `response_seen` on silicon (baseline).
  The new part is **injecting an already-held frame into a specific TM queue/slot at the event** —
  needs the TM to accept a redirected packet into a shaped queue deterministically. Measure in
  Phase 4.
- **Recirc dependence.** Retains a (small, bounded) recirculation loop as the *detector*, so it does
  **not** fully answer Dr. Lin's "move off recirculation" concern — but it isolates recirc to
  detection (low, measurable load) and moves *timing* to the queue. Honest framing required.
- **Added latency.** ≈ the slot quantum after `response_seen`; expected small. Measure.
- **Lean (unproven).** Most likely to *work* first because it reuses the proven event detector; the
  weakest on the "pure queue, no recirculation" narrative. Good **first microbenchmark target** and
  a defensible **hybrid** for the paper (master direction Phase 6 explicitly allows a justified
  hybrid).

### D1-B — Queue-resident ACK with response-triggered eligibility
- **Mechanism.** Place the ACK **into a controlled queue immediately**; the response **event flips
  its release eligibility** (the ACK drains only once the response is seen). No recirculation hold.
- **Ordering.** Preserved if eligibility fires strictly before the response is scheduled.
- **Hardware-feasibility risk.** **High / unverified.** This requires the TM to gate a *queued*
  packet's dequeue on a *later ingress event* — Tofino TM queues are FIFO/shaped, not
  content-addressable or externally gateable per-packet. Whether this can be done safely (e.g. via
  a pause/resume on a dedicated queue, or a mirror/resubmit trick) is **unknown hardware behavior**
  and must be checked against SDE docs + a microbenchmark **before** it is considered viable
  (master direction §14 STOP: "the queue cannot provide the assumed scheduling behavior").
- **Recirc dependence.** None (the goal) — the cleanest "no recirculation" story **if** the hardware
  supports the eligibility gate.
- **Lean (unproven).** Highest payoff for the narrative, highest risk of being **infeasible on
  Tofino-1**. Do **not** assume it works; it is a documented hypothesis to test, and a likely STOP
  if the TM cannot gate dequeue on an event.

### D1-C — Adjacent-slot release
- **Mechanism.** Release the ACK and the response in **two consecutive scheduled slots** of a short
  periodic pattern, preserving order; the gap becomes **one slot quantum** (a fixed, public,
  device-independent value), not ~0.
- **Ordering.** Preserved (ACK in slot *k*, response in slot *k+1*).
- **Hardware-feasibility risk.** Lower — it is closest to Ditto's native round-robin-over-slots. But
  it needs the response to be **ready** by its slot; if not, the slot is empty (the M6 empty-slot
  problem) → either skip (breaks the fixed cadence) or idle-wait.
- **Effect on the feature.** Note this does **not** reduce CLRT to ~0 (Defense-1's stated goal); it
  **fixes** CLRT to one slot quantum — arguably a *Defense-1.5* that blends into Defense 2's
  "normalize" goal. Flag this: it may satisfy "reduce/normalize the gap" but changes the Defense-1
  objective; confirm with Dr. Lin whether a fixed small gap is acceptable as "Defense 1."
- **Added latency.** One slot quantum on the ACK; plus any wait for response readiness.
- **Lean (unproven).** Cleanest mapping to Ditto's scheduler, but semantically drifts Defense 1
  toward "small fixed gap." Quantify the added delay (master direction Phase 3 Q1-C).

### Question-1 evaluation axes (fill from Phase-4/5 evidence)
| Axis | D1-A hybrid | D1-B eligibility-gate | D1-C adjacent-slot |
|---|---|---|---|
| Preserves ACK-before-response | yes (by construction) | yes if gate fires first | yes (slot order) |
| Recirculation load | detector-only (small) | none (goal) | none |
| Tofino feasibility | moderate (measure) | **high risk / unverified** | lower |
| CLRT effect | ~0 (event) | ~0 (event) | fixed slot quantum (not ~0) |
| Answers "off recirculation" | partially | fully (if feasible) | fully |
| First to measure? | **yes** | after A (feasibility probe) | with A |
| Key STOP risk | TM won't take redirected frame deterministically | TM can't gate dequeue on event | empty-slot when response not ready |

**Selection: DEFERRED to Phase 4 microbenchmark + SDE-doc verification of TM eligibility/redirect
behavior.** Start by measuring D1-A (reuses the proven detector) and running a **feasibility probe**
for D1-B's eligibility gate; treat D1-B as a STOP candidate if the gate is not supported.

---

## 3. QUESTION 2 — Defense 2 (delay the response): target or pattern

Defense 2 forwards the ACK immediately and **delays the response**; it maps **cleanly** onto Ditto's
scheduled-slot release (mapping M3 monotone assignment, M8 shaper). The open part is **which timing
policy is defensible** — not "40 ms slowest → 60 ms" (meeting §10, master direction Phase 3 Q2;
`ASSUMPTIONS_AND_UNKNOWNS.md` #11). Five candidates (master direction Phase 3 Q2 A–E):

- **P-A Fixed common target.** Every response leaves at `t_ack + G` for one public constant `G`.
  *Calibration baseline only* — creates a new constant fingerprint (meeting §11).
- **P-B Common bounded target distribution.** `G` drawn from one public, device-independent bounded
  band shared by all protected devices.
- **P-C Repeating Ditto-style schedule.** Responses occupy slots of a short predefined periodic
  timing pattern (Ditto M1/M6). Needs empty-slot handling (idle or minimal chaff — meeting §8 says
  no chaff initially).
- **P-D Next-valid-slot scheduling.** Response released at the next scheduled slot boundary ≥ its
  readiness (monotone; the no-chaff simplification of P-C — empty slots simply idle).
- **P-E Load-aware pattern with a fixed public policy.** The schedule/band adapts to switch load but
  by a **public, device-independent** rule (so the policy, not the device, sets timing).

### Evaluation against the master-direction Q2 criteria (fill from Phase-4/5 evidence)
| Criterion | P-A fixed | P-B bounded | P-C Ditto pattern | P-D next-slot | P-E load-aware |
|---|---|---|---|---|---|
| Security rationale | weak (new constant) | medium (band hides device) | strong (traffic-shaping argument) | medium–strong | strong if rule is public |
| Added latency | low, constant | low–medium | medium (slot wait) | low (next slot) | variable |
| Detectability (new fingerprint) | **high** (constant gap) | lower | lowest (looks shaped) | low–medium | depends on rule |
| Queue requirements | 1 shaped queue | 1 shaped queue + RNG/band | L-slot schedule (maybe loopback) | slotting | slotting + load input |
| Implementation complexity | lowest | low | **highest** | medium | high |
| Load sensitivity | shaper drift (measure) | shaper drift | worst for small pkts (S13) | shaper drift | designed-for load |
| TCP safety (`G < RTO_MIN`) | must hold `G<~207 ms−margin` | band max `<RTO_MIN` | slot span `<RTO_MIN` | `<RTO_MIN` | `<RTO_MIN` |
| DNP3 operational impact | fixed added delay | bounded added delay | slot-dependent | low | variable (budget unknown, #13) |
| Classifier performance | poor (constant → detectable) | better | best (device-independent) | good | good |

**Constraints that bound every candidate (measured / to-measure):**
- `max(readiness relative to ACK) < G < RTO_MIN − margin`. RTO_MIN rig-measured **~207 ms**
  (`ASSUMPTIONS_AND_UNKNOWNS.md` #12); the **real SEL-751 readiness tail (~170 ms) sits near RTO** —
  so a real-device band must trade tail-coverage vs retransmit safety and **must be re-measured on
  the physical device (Phase 5)**; do not reuse the 60 ms rig value.
- Queue **slot precision** for small DNP3 packets is Ditto's *worst* rate-control regime (S13) — the
  achievable band granularity is a Phase-4 measurement, not an assumption.

**Selection: DEFERRED.** *Lean (unproven):* **P-B (common bounded) or P-D (next-valid-slot)** are the
most defensible without chaff — P-B for a distribution argument, P-D for a shaping argument —
pending (a) the physical SEL-751 readiness distribution (Phase 5) and (b) the queue's measured slot
precision/jitter under load (Phase 4). **P-A is calibration-only; P-C requires the empty-slot/chaff
decision** deferred to a separate argued extension (meeting §8).

---

## 4. The final policy must be justified by (master direction Phase 3, do not shortcut)

physical SEL-751 timing distribution · high-percentile native readiness · DNP3 operational
constraints · TCP retransmission behaviour · queue scheduling precision · latency budget · classifier
performance · a **device-independent** policy · related-work (Ditto) principles. Every one of these is
either **gated on hardware** (Phase 4/5) or **currently OPEN** (`ASSUMPTIONS_AND_UNKNOWNS.md`
#11–#13). No selection is defensible until they are in hand.

---

## 5. What must be measured before ANY selection (feeds `QUEUE_MICROBENCH_PLAN.md`, Phase 4)

1. **Single shaped queue, lone sparse frame:** can it hold one frame to a target slot? residence
   time, realized vs configured delay, jitter, first-packet behaviour. (Bears on D1-A, P-B, P-D.)
2. **Empty-slot behaviour** of round-robin without chaff: does the schedule skip, idle, or stall?
   (Bears on D1-C, P-C, P-D — the M6 crux.)
3. **Eligibility-gate feasibility probe:** can a queued frame's dequeue be gated on a later ingress
   event on Tofino-1 TM? (Bears on D1-B — likely STOP if not.)
4. **Slot precision vs packet size:** granularity achievable for small (DNP3-sized) frames (S13).
5. **Load sensitivity:** delay/jitter/loss/reordering under idle→low→moderate→high background load,
   head-to-head vs the recirculation hold (Phase 8 metrics).
6. **TCP safety envelope:** confirm 0 retransmits/resets across the candidate band, `G < RTO_MIN`.

---

## 6. Decision gates and STOP conditions (master direction §14)

- **STOP** if the TM cannot provide the assumed scheduling/eligibility behaviour (kills D1-B; forces
  hybrid D1-A).
- **STOP** if a candidate reorders the ACK after the response, or drops/loses frames, or grows queue
  occupancy without bound.
- **STOP** if the only way to keep a fixed cadence is chaff on the live DNP3 flow (revisit as a
  separate, argued extension — not in the first prototype, meeting §8).
- **DECISION GATE:** selection of the Defense-1 mapping and the Defense-2 policy happens **only after**
  Phase-4 microbenchmark evidence **and** (for the Defense-2 target) the physical SEL-751 readiness
  distribution (Phase 5). Until then this document stands as the analysed design space.

_Next off-switch deliverables: `QUEUE_MICROBENCH_PLAN.md` (Phase 4 experiment spec, from meeting §18)
and `SEL751_DIRECT_CONNECTIVITY_PLAN.md` (Phase 5 connectivity plan). Both are planning docs (no
hardware); execution is gated._

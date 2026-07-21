# DITTO_TO_DNP3_MAPPING.md — What of Ditto transfers to DNP3 Case A timing

_Master direction Phase 2. Produced 2026-07-21 on `research/caseA-ditto-queue`. Companion to
`DITTO_QUEUE_RECONSTRUCTION.md` (the cited source reconstruction). Every Ditto claim referenced
here is sourced there by tag (S1…S15) or by §/page._

> **Framing (do not skip).** Ditto and our problem differ on **two axes at once**, and the mapping
> only makes sense once both are stated:
> 1. **Feature:** Ditto shapes **packet SIZE + VOLUME** for *volume/timing/path anonymity* of a
>    WAN aggregate. Our current scope is **TIMING only** — the Formby **CLRT** (ACK→response gap)
>    of a **single SEL-751 request/response transaction**. (Packet-SIZE obfuscation is Part 1 of
>    the paper, a *separate* line; Ditto's padding/chaff machinery is a Part-1 input, not a
>    Case-A-timing input.)
> 2. **Scale:** Ditto shapes a **high-rate continuous aggregate** (Gbps, always-busy link). DNP3
>    Case A is a **low-rate, bursty, one-outstanding-transaction** flow. Machinery Ditto needs to
>    keep a 100 G link's pattern unbroken (chaff flooding, L parallel queues, 2-pass loopback)
>    may **collapse to something much smaller** for one sparse flow — or may be unnecessary.
>
> So the guiding question is **not** "how do we port Ditto?" but "**which of Ditto's queue-and-
> schedule primitives give us a more load-stable, more defensible TIMING release than
> recirculation-until-event/deadline?**" (Dr. Lin's stated goal, meeting §6–7.)

---

## 1. The core asymmetry (Ditto ↔ DNP3 Case A)

| Axis | Ditto (NDSS'22) | DNP3 Case A (our scope) |
|---|---|---|
| Obfuscated feature | packet **size + volume** (+ timing, path) | **ACK→response timing (CLRT)** only |
| Traffic | high-rate continuous WAN aggregate | low-rate, bursty, 1 outstanding txn |
| Pattern element | a **packet size** `P_i` | a **release time / slot offset** |
| "Never-empty" need | constant — link is always busy | rare — flow is mostly idle |
| Chaff | essential (fills every slot every round) | **avoided initially** (meeting §8); risky on a DNP3 flow |
| Ordering constraint | keep pattern order | **ACK strictly before response** (hard TCP/DNP3 invariant) |
| Event coupling | none (pure schedule) | Defense 1 is **event-driven** (release ACK when response arrives) — the central mismatch |
| Determinism | "correct on average," bursty (S10,S13) | we need a **defensible, measured** timing — same caveat applies, must measure (Phase 4) |

---

## 2. Per-mechanism classification

Verdict key: **DR** = directly reusable · **RM** = reusable with modification · **UN** =
unnecessary (for Case-A timing now) · **US** = unsuitable · **?** = unresolved (needs Phase-3
decision or Phase-4 measurement).

| # | Ditto mechanism | Ditto role (source) | Verdict | Rationale / how it changes for DNP3 Case A |
|---|---|---|---|---|
| M1 | **Fixed repeating pattern** (ordered list, infinite repeat) | S1,S3 | **RM** | Becomes a **timing schedule** (ordered *release-slot offsets*), not a size list. For Defense 2 the "pattern" is a repeating set of ACK→response gap targets; for Defense 1 there may be no periodic pattern at all (see §3). |
| M2 | **Pattern computation from distribution** (percentiles, eqn 2) | S4 | **RM** | Same *statistical* idea, different input: choose slot offsets from the **SEL-751 ACK-to-response readiness distribution** (real captures / physical Phase 5), not a size CDF. Percentile selection → e.g. a bounded target band (meeting §11 Pattern 2). |
| M3 | **Next-larger assignment, minimal padding, cannot split** (eqn 3) | S5 | **RM** | Timing analogue is **monotone**: assign a response to the **next release slot ≥ its readiness time** (never earlier). This *automatically preserves ACK-before-response* and adds only forward delay — a clean fit. |
| M4 | **2-level hierarchical queueing** (real-high + chaff-low pair per state) | S6 | **?** | The **priority** half is useful (real always wins). The **chaff** half is what we're told to omit initially (meeting §8). Without chaff the "never-empty" guarantee is gone → the **empty-slot problem** (M6) becomes the open question. Whether we ever need the pair at all for a single flow is unresolved. |
| M5 | **Priority queuing** (real > chaff within a state) | S6,§VI | **RM** | Keep the principle "**real packet has strict priority**"; drop the chaff counterpart initially. For one outstanding txn this may reduce to a single priority level. |
| M6 | **Round-robin over states emits the pattern; RR skips empty queues** | S7 | **?** | This is the crux. Ditto keeps queues full with chaff so RR never skips. With **no chaff and a sparse flow**, RR would skip almost every slot. Options (Phase 3 Q1): (a) **next-valid-slot** scheduling — the response is released at the next scheduled slot boundary, empty slots simply idle (no chaff, no fixed cadence emitted); (b) reintroduce **minimal chaff** only if a fixed public cadence is required for the security argument. Undecided — needs the Phase-3 security rationale. |
| M7 | **Two-pass loopback architecture** (approximate the hierarchy) | S8,§VIII | **?** | Needed by Ditto only because it runs **L parallel priority-pairs at line rate**. For a **single low-rate DNP3 flow**, a **single shaping stage** (one shaped/deadline queue) may suffice → loopback possibly **UN**. If a 2-level slot hierarchy is chosen, budget loopback ports (eqns 4–5) on the shared switch. Resolve in `CASE_A_QUEUE_DESIGN.md`. |
| M8 | **Fixed per-queue rate = 1/L of port rate** (shaper config) | S13,§VIII | **RM** | The **TM shaper is the timing lever** we adopt in place of recirculation. But our target is a **per-response release deadline/slot**, not a sustained pps. We configure a shaper/queue so that a held response **drains at the intended slot** — and we **measure** the realized timing (S10/S13 say the rate is only average-correct, worst for **small** packets = our regime). |
| M9 | **Chaff generation** (continuous recirc + clone into low-priority queues) | S6,§IV | **UN → US** | UN now (meeting §8: no chaff in the first prototype). Potentially **US** on a DNP3 flow: a chaff packet on the SEL-751↔master TCP connection could perturb TCP state or be a *new* fingerprint; a chaff DNP3 frame would violate byte-preservation/observe-only. Only revisit as a deliberate, separately-argued extension. |
| M10 | **Padding via custom headers** (32..1 B, EtherType-marked) | S9,§VI | **UN** (for timing) | Pure **size** obfuscation → Part 1, not Case-A timing. Also conflicts with our current **byte-preservation** timing constraint (we do not modify DNP3 bytes on the timing path). Relevant only to the separate size-normalization line. |
| M11 | **Recirculation for padding overflow / chaff** | S9,§VIII | **UN** | Padding overflow is size (M10); chaff is M9. Note: our *existing* Case-A defenses use recirculation for the **hold**, which is a *different* use than Ditto's — and is exactly what Dr. Lin wants to compare the queue against (meeting §6), not import. |
| M12 | **Volume / path anonymity goals** | §II-C | **UN** | Out of scope: we target the **CLRT timing feature** (and size, Part 1), not WAN volume/path anonymity. Our attacker fingerprints a *device*, not a link's aggregate volume. |
| M13 | **Pattern hot-swap without interrupting the switch** | S4,§V | **RM** | Nice operational property to keep: the timing policy (target/band/schedule) should be **control-plane-loadable and updatable live**, mirroring how our current defenses load `G_i` from the control plane. |
| M14 | **Padding removal at receiver** | §VI,§VIII | **UN** | Ditto is a *pair* of switches (add at ingress site, strip at egress site). Our timing defense is **single-point** and **byte-preserving** — nothing to strip. (A future size line with a black-hole/PREPEND filler would need its own removal story — separate.) |
| M15 | **Encrypted-tunnel assumption** (MACsec/IPsec) | §II | **DR (contextual)** | Same threat premise: attacker sees metadata, not payload. We **assume** the SEL-751 link is/where-needed encrypted (attacker sees timing/size/direction/ACK-mode only). We do **not** add encryption; record as an assumption (`ASSUMPTIONS_AND_UNKNOWNS.md`). |
| M16 | **Evaluation method** (IPG independence Fig 8; DF→random-guess Fig 10; measured recirc/reorder) | S12,S14,S15 | **RM** | The *evaluation template* transfers: show the **defended CLRT distribution is independent of the native** (analogue of IPG-independence), and run an **adaptive classifier** to random-guessing (analogue of DF). Our metrics/attacker differ (CLRT + ACK-mode + size on SEL-751, grouped splits) — see Phase 9. |

---

## 3. The two Case-A defenses mapped onto Ditto's queue

### Defense 1 (delay the ACK) — the hard mapping
Defense 1 is **event-driven**: hold the pure ACK, and when the **response arrives**, release the
ACK just before it. Ditto is **schedule-driven**: a packet leaves in its **predefined slot**,
independent of any event. These are **not the same** (meeting §12 "major unresolved design
question"). Candidate mappings to evaluate in Phase 3 (do not pre-select — meeting §12):
- **D1-A Hybrid event→slot:** keep **event detection** (recirc or a register flag) to know
  *response_seen*; once seen, place the ACK (and response) into **controlled TM slots** for final
  release. Recirc becomes only the *detector*, the **queue controls timing** (meeting §12 bullet 3;
  master direction Phase 3 Question 1-A).
- **D1-B Queue-resident ACK with response-triggered eligibility:** ACK sits in a queue; the
  response event flips its **release eligibility**. Whether Tofino can safely gate a queued
  packet's eligibility on a later event is **unverified hardware behavior** → measure/document
  (Phase 3 Q1-B, Phase 4).
- **D1-C Adjacent-slot release:** release ACK and response in **consecutive scheduled slots**,
  preserving order, and **quantify the added delay** (Phase 3 Q1-C).

**Verdict:** Defense-1-on-queue is **? (unresolved)** and is the project's central design question.
Ditto gives us the *slot* primitive but **not** the event→slot coupling — that is ours to design
and measure.

### Defense 2 (delay the response) — the natural mapping
Defense 2 forwards the ACK immediately and **delays the response to a target/pattern**. This maps
**directly** onto Ditto's "release the packet in its scheduled slot":
- The ACK is unshaped (forwarded now).
- The response is **assigned to the next release slot ≥ its readiness** (M3, monotone) or to a
  **target gap** drawn from a device-independent policy (M2 percentile band).
- Candidate policies to compare (meeting §11, master direction Phase 3 Q2): **fixed common gap**
  (calibration only), **common bounded distribution**, **repeating Ditto-style schedule**,
  **next-valid-slot**, **load-aware public policy**.
**Verdict:** **RM** — the cleanest Ditto fit. The open part is **which policy is defensible** (not
"40 ms → 60 ms"; master direction Phase 3 Q2, meeting §10), and the **measured** slot accuracy
under load (S10/S13, Phase 4).

---

## 4. What we deliberately will NOT take from Ditto (and why)

1. **Chaff generation (M9)** — omitted initially per meeting §8; risky on a live DNP3/TCP flow.
2. **Padding / custom-header machinery (M10, M14)** — that is Part-1 *size* obfuscation and
   conflicts with the byte-preserving *timing* path; kept out of the Case-A-timing binary
   (master direction §2: "Do not combine all mechanisms into one P4 binary").
3. **Volume / path anonymity (M12)** — not our threat model.
4. **Full L-way parallel priority-pairs + mandatory 2-pass loopback (M4, M7)** — likely
   over-provisioned for one low-rate flow; adopt only the minimal slotting that a measurement
   justifies.
5. **The complete Ditto system** — master direction §Phase 2 and meeting §8 both forbid blind
   reproduction; extract the **timing primitives** only.

---

## 5. Minimal viable queue mechanism to prototype (feeds `CASE_A_QUEUE_DESIGN.md` + `QUEUE_MICROBENCH_PLAN.md`)

The smallest thing worth measuring (Phase 4) before touching the DNP3 program:
- **One shaped/"delayed" TM queue** with a **configured drain rate/slot** (Ditto's M8 shaper, one
  level — not the full 2-level hierarchy), plus a **normal pass-through queue** (meeting §18).
- Packet classes: **immediate** vs **delayed** (meeting §18) — no DNP3 parsing yet, just a mark.
- Measure (per master direction Phase 4 / meeting §18): configured-vs-actual rate, residence time,
  output inter-packet timing, **jitter**, queue depth, **loss**, **ordering**, drain/first-packet/
  sparse-packet behavior, and **background-load sensitivity** (idle → high). Compare head-to-head
  against the **existing recirculation hold** (Phase 8 metrics).
- **Only if** a single shaped queue cannot hold a lone sparse packet to a predictable slot do we
  escalate to the 2-level (chaff-or-idle) hierarchy — and that escalation must be justified by the
  measurement, not assumed.

**Bottom line:** From Ditto we take **(a) the slot/schedule abstraction (M1–M3), (b) strict real-
packet priority (M5), (c) the TM shaper as the timing lever (M8), (d) live pattern reconfiguration
(M13), and (e) the evaluation template (M16).** We **defer** chaff/padding/volume machinery, and
we treat the **event→slot coupling for Defense 1 (M6, §3)** and the **measured slot accuracy under
load (S10/S13)** as the two unresolved items that Phases 3–4 must settle **with measurement, not
assumption**.

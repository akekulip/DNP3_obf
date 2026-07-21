# PLAN.md — Case A / SEL-751 timing obfuscation (consolidated roadmap)

_The single human-readable plan. Authority: `meeting_direction.md` + `meeting.md` (Dr. Lin,
2026-07-21). Machine-readable status: `phase_status.json`. Updated 2026-07-21, branch
`research/caseA-ditto-queue`._

## Goal
Move Case-A timing obfuscation from the proven recirculation feasibility baseline to a measured
Ditto-inspired queue or hybrid mechanism, validate the design using the physical SEL-751, compare
the mechanisms under load, and maintain the size-and-timing paper throughout the project.

## Paper policy
Writing begins now and continues during every phase. Motivation, design, related work, methodology,
confirmed results, and limitations are updated as evidence becomes available. Final polishing and
submission preparation occur after the technical evaluation is complete.

## Terminology
Case A is SEL-751-style separate pure ACK and DNP3 response traffic.
Defense 1 delays the ACK.
Defense 2 forwards the ACK and delays the response.
Case B is AB1400/ION7550-style combined ACK-bearing response traffic and is out of scope for the
current phase.
Defense 2 is not Case B.
CLRT is used only for Case A.

---

## Order of work (do not skip gates — `meeting_direction.md` §7)

| Phase | What | Status | Deliverable(s) | Gate |
|---|---|---|---|---|
| **0** | Repository and hardware audit | ✅ **PASS** | `CURRENT_STATE_AUDIT.md` | none |
| **1** | Paper foundation and continuous writing | 🟡 **IN PROGRESS** | `PAPER_OUTLINE.md`, `ASSUMPTIONS_AND_UNKNOWNS.md`, `FORMBY_SOURCE_MAP.md` ✅; `.tex` two-part skeleton ⬜ | none (Overleaf = Philip) |
| **2** | Ditto reconstruction and DNP3 mapping | ✅ **PASS** | `DITTO_QUEUE_RECONSTRUCTION.md`, `DITTO_TO_DNP3_MAPPING.md` | none |
| **3** | Queue design alternatives | 🟡 **DESIGN COMPLETE, SELECTION PENDING** | `CASE_A_QUEUE_DESIGN.md` | selection → Phase 4.5/5.5 |
| **Track A · 4** | Traffic-Manager microbenchmark | 📋 **planned** | `QUEUE_MICROBENCH_PLAN.md` ✅ → `..._RESULT.md` ⬜ | **hardware window** |
| **Track B · 5** | Physical SEL-751 direct connectivity + baseline | 📋 **planned** | `SEL751_DIRECT_CONNECTIVITY_PLAN.md` ✅ → `..._REPORT.md` ⬜ | hardware + relay + topology |
| **4.5 / 5.5** | **Architecture and timing-policy selection** | ⬜ **pending both tracks** | (selection note → updates `CASE_A_QUEUE_DESIGN.md`) | needs Track A + Track B evidence (off-switch decision) |
| **6** | Queue or hybrid Defense 1 (delay ACK) | ⬜ not started | (P4 + evidence) | hardware; after 4.5/5.5 |
| **7** | Queue-based Defense 2 (delay response) | ⬜ not started | (P4 + evidence) | hardware; Phase 6 understood |
| **8** | Recirculation versus queue evaluation | 📋 **planned** | `QUEUE_VS_RECIRC_EVALUATION_PLAN.md` ✅ → `..._RESULT.md` ⬜ | hardware; Phases 6/7 |
| **9** | Adaptive security and classifier evaluation | ⬜ not started | (results) | hardware; defended data |
| **Paper** | Maintained through every phase; **finalized after evaluation** | ⬜ **LAST** | `paper/dnp3_obfuscation_paper.tex` (size + timing) | after Phases 6–9 |

Legend: ✅ done · 🟡 in progress · 📋 plan written, execution gated · ⬜ not started.

**Tracks A and B run in parallel** (`meeting_direction.md` Phase 5: the physical-device work "may
proceed while the queue microbenchmark is being developed"). Both feed **Phase 4.5/5.5**, where the
Phase-3 alternatives are actually chosen — the Defense-1 mapping (D1-A/B/C) using the microbench's
measured queue precision and load-stability (Track A), and the Defense-2 timing policy (P-A…P-E)
using the physical SEL-751 readiness distribution and TCP-safety envelope (Track B). No selection is
made before both tracks report.

---

## Where we are now (2026-07-21)
All **off-switch** planning + source-grounding is **complete and committed** (Phases 0–3, plus the
Track-A/B/8 plans). **Nothing has touched the switch.** Everything from Track A / Track B onward
needs an explicit **hardware-authorization window** (`meeting_direction.md` §10) — a previous GO does
not carry to a modified P4 source.

## Immediate execution order (current focus, per Philip 2026-07-21)
1. **[off-switch — NOW] Determine the TM queue pattern from the pcap traces.** Run the SEL-751
   traces we have, extract the timing distribution, and compute the queue release pattern / target
   (Ditto-style pattern computation on our own data). → `QUEUE_PATTERN_FROM_TRACES.md`.
2. **[hardware] Implement the queue.** Build the TM-queue P4 from the determined pattern.
3. **[replay] Test the queue using the traces we have.** Validate the implemented queue against the
   captured traces (rig replay), as we did for the recirculation baseline.
4. **[planning → hardware] Plan the physical SEL-751 addition** to the hardware setup (Track B /
   Phase 5) — after the queue is built and trace-tested.
5. **Size + padding (Part 1)** added and implemented.
6. **Writing — LAST.** Only after **both** size/padding **and** timing are implemented. No paper /
   `.tex` work before then.

> This linear order supersedes the earlier "Track A ‖ Track B first" framing for the *immediate*
> work: the queue pattern + implementation + trace-test come first; the physical SEL-751 follows.
> The Phase 4.5/5.5 selection is informed by step 1 (pattern) and refined by the trace-test.

## Coordination items (Philip / Dr. Lin)
- **Hardware window** authorization for Track A (Phase 4) — and/or Track B if the relay is ready.
- **Physical SEL-751** access + verified lab topology (Track B / Phase 5).
- **Overleaf** (URI email, share with Dr. Lin) — `meeting_direction.md` §15.

---
_Detailed per-phase plans are the files named above; live status is in `phase_status.json`._

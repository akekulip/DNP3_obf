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

## Critical path to the paper (in order)
1. **[hardware, parallel] Track A (Phase 4)** queue microbenchmark **and** **Track B (Phase 5)**
   physical SEL-751 baseline. These can proceed independently.
2. **Phase 4.5/5.5 — selection** (off-switch decision): choose the Defense-1 mapping and Defense-2
   policy from the two tracks' evidence; update `CASE_A_QUEUE_DESIGN.md`.
3. **[hardware] Phases 6–7** — queue Defense 1 / Defense 2 on real traffic.
4. **[hardware] Phase 8** recirc-vs-queue head-to-head; **Phase 9** adaptive classifier.
5. **Paper finalize** — the two-part (size + timing) `.tex`, filled with the above results.

## Off-switch work available now (no hardware)
- Continuous paper writing (Phase 1): expand `paper/dnp3_obfuscation_paper.tex` to the two-part
  (size + timing) **skeleton with placeholders** per `PAPER_OUTLINE.md` — not final prose (finalized
  last, per Paper policy).
- Consolidate the `paper/` variant files (`PAPER_OUTLINE.md` §XII, recommendation-only).

## Coordination items (Philip / Dr. Lin)
- **Hardware window** authorization for Track A (Phase 4) — and/or Track B if the relay is ready.
- **Physical SEL-751** access + verified lab topology (Track B / Phase 5).
- **Overleaf** (URI email, share with Dr. Lin) — `meeting_direction.md` §15.

---
_Detailed per-phase plans are the files named above; live status is in `phase_status.json`._

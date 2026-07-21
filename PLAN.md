# PLAN.md — Case A / SEL-751 timing obfuscation (consolidated roadmap)

_The single human-readable plan. Authority: `meeting_direction.md` + `meeting.md` (Dr. Lin,
2026-07-21). Machine-readable status: `phase_status.json`. Updated 2026-07-21, branch
`research/caseA-ditto-queue`._

**Goal:** move Case-A (SEL-751, separate-ACK) timing obfuscation from the proven **recirculation**
feasibility baseline to a more defensible **Ditto-inspired queue** mechanism, validate on the
**physical SEL-751**, and **write the paper** — with every timing claim measured, not assumed.

**The paper is the LAST end.** It is *maintained continuously* from Phase 1 but *finalized last*,
after the technical results (queue + physical device + evaluation) are in hand. We do **not**
front-load paper polishing ahead of the experiments.

---

## Order of work (do not skip gates — `meeting_direction.md` §7)

| Phase | What | Status | Deliverable(s) | Gate |
|---|---|---|---|---|
| **0** | Repo + hardware audit | ✅ **DONE** | `CURRENT_STATE_AUDIT.md` | none |
| **1** | Paper + literature foundation (source-grounding) | 🟡 **in progress** | `PAPER_OUTLINE.md`, `ASSUMPTIONS_AND_UNKNOWNS.md`, `FORMBY_SOURCE_MAP.md` ✅; `.tex` two-part expansion + Overleaf ⬜ | none (Overleaf = Philip) |
| **2** | Reconstruct Ditto's queue design | ✅ **DONE** | `DITTO_QUEUE_RECONSTRUCTION.md`, `DITTO_TO_DNP3_MAPPING.md` | none |
| **3** | Define DNP3 queue research questions (design space) | 🟡 **design done, selection deferred** | `CASE_A_QUEUE_DESIGN.md` | selection needs Phase-4 evidence |
| **4** | Traffic-Manager **queue microbenchmark** | 📋 **planned** | `QUEUE_MICROBENCH_PLAN.md` ✅ → `QUEUE_MICROBENCH_RESULT.md` ⬜ | **hardware window** |
| **5** | **Physical SEL-751** direct connectivity | 📋 **planned** | `SEL751_DIRECT_CONNECTIVITY_PLAN.md` ✅ → `..._REPORT.md` ⬜ | hardware + relay + topology |
| **6** | Queue-based **Defense 1** (delay ACK) | ⬜ not started | (P4 + evidence) | hardware; Phase 4 understood |
| **7** | Queue-based **Defense 2** (delay response) | ⬜ not started | (P4 + evidence) | hardware; Phase 6 understood |
| **8** | **Recirculation vs queue** evaluation | 📋 **planned** | `QUEUE_VS_RECIRC_EVALUATION_PLAN.md` ✅ → `..._RESULT.md` ⬜ | hardware; Phases 4/6/7 |
| **9** | **Classifier / security** evaluation (adaptive attacker) | ⬜ not started | (results) | hardware; defended data |
| **P** | **PAPER** — finalize | ⬜ **LAST** | `paper/dnp3_obfuscation_paper.tex` (two-part: size + timing) | after Phases 6–9 results |

Legend: ✅ done · 🟡 in progress · 📋 plan written, execution gated · ⬜ not started.

---

## Where we are now (2026-07-21)
All **off-switch** planning + source-grounding is **complete and committed** (Phases 0–3 done/design,
Phases 4/5/8 plans written). **Nothing has touched the switch.** Everything past this line needs an
explicit **hardware-authorization window** (`meeting_direction.md` §10) — a previous GO does not
carry to a modified P4 source.

## The critical path to the paper (in order)
1. **[hardware] Phase 4 — queue microbenchmark.** The gate that unblocks everything: does a TM queue
   hold a lone small frame predictably, and is it more load-stable than recirculation? Its numbers
   **select** the Phase-3 Defense-1 mapping and Defense-2 policy.
2. **[hardware] Phase 5 — physical SEL-751.** Replaces replay with the real device; fixes the paper
   baseline (real 12.9 ms) and the defensible Defense-2 target band.
3. **[hardware] Phases 6–7 — queue Defense 1 / Defense 2** on real traffic.
4. **[hardware] Phase 8 — recirc-vs-queue** head-to-head; **Phase 9 — adaptive classifier** eval.
5. **Paper finalize** — the two-part (size + timing) `.tex`, filled with the above results.

## Off-switch work available right now (no hardware)
- Expand `paper/dnp3_obfuscation_paper.tex` from size-only to the two-part structure per
  `PAPER_OUTLINE.md` — a *skeleton with placeholders*, not final prose (the paper is maintained now,
  finalized last).
- Consolidate the `paper/` variant files (`PAPER_OUTLINE.md` §XII, recommendation-only).

## Coordination items (Philip / Dr. Lin)
- **Hardware window** authorization for Phase 4 (the first blocker).
- **Physical SEL-751** access + verified lab topology (Phase 5).
- **Overleaf** (URI email, share with Dr. Lin) — `meeting_direction.md` §15.

---
_Detailed per-phase plans are the files named above; live status is in `phase_status.json`._

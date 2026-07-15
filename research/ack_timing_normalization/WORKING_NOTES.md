# WORKING NOTES — ACK-bearing DNP3 response timing-normalization study

**Task source:** `dnp3_multicrob_harness/ack.md` (Dr. Lin research-study spec).
**Deliverables dir:** `research/ack_timing_normalization/` (repo root; cross-cutting
both harnesses — chosen over burying it inside multicrob).
**Constraint:** research/design only — do NOT modify harness source code. Byte-preserving
phase rule (see GROUNDING.md). Started 2026-07-13.

## Decisions
- `ack.md` IS the PI delegation map → executing it directly (main session = synthesizing
  lead) rather than re-running principal-investigator (would serialize + duplicate).
- Using the Agent tool (parallel subagents), NOT the Workflow tool (user did not opt into
  ultracode/workflow; ack.md only asks for "subagents in parallel").
- Deliverables at repo-root `research/` (cross-cutting), not inside a harness.

## Grounding done (this session)
- Read prior brief `ack_timing_obfuscation_research.md`, analyze_ack.py, fingerprinting
  report, RESUME_STATE, both WORKING_NOTES, memory index.
- MEASURED (rig, this session): CROB-count↔response-time linear, R²=0.9985/0.9954 →
  `measured_timing_data.md`. This is the empirical anchor.

## Agent dispatch (Phase 1, parallel) — map A–F
- A → sdn-networks-expert : traffic-analysis/WF/timing-defense literature + RAINCOAT diff + novelty
- B → general-purpose     : TCP/transport primary sources (RFCs, RTO, delayed ACK, kernel)
- C → power-systems-expert : DNP3/SCADA/protection timing; which transactions may be shaped
- D → sdn-networks-expert : software impl (tc/netem/eBPF/XDP/DPDK/timing-wheel) + replay-server scheduler
- E → p4-dataplane-engineer: Tofino/DPU/SmartNIC/FPGA feasibility (hardware_design)
- F → research-scientist   : attacker model + statistical evaluation methodology (evaluation_plan)
Each reads GROUNDING.md + prior brief, writes agent_reports/agent_<X>_*.md, returns summary +
PAPER_MATRIX_ROWS + BIBTEX.

## Phase 2 (synthesis, by lead)
Assemble: executive_summary.md, literature_review.md, paper_matrix.csv, bibliography.bib,
software_design.md, hardware_design.md, evaluation_plan.md, research_gaps_and_novelty.md,
advisor_brief.md, sources_audit.md. Then Agent G (ieee-journal-reviewer) reviews every
deliverable; resolve contradictions; verify citations; final synthesis block.

## Phase 1 COMPLETE — all 6 agent reports in (agent_reports/agent_{A..F}_*.md)
Key results captured: measured CROB↔time R²>0.99 (A3); RTO-binding not DNP3 timers (B/C);
no link ACK (C); replay server schedules send() directly → app-layer scheduler (D); Tofino
first-packet absolute-delay only via unbuilt recirc-hold, native on BlueField/FPGA (E);
attacker ladder A1–A8 + claim ladder + must report I(T;N|size) conditional (F). RAINCOAT
verified: Lin TSG 2019 DOI 10.1109/TSG.2018.2870362.

## Phase 2 COMPLETE — all 10 deliverables written
- Promoted D/E/F reports → software_design.md / hardware_design.md / evaluation_plan.md (headers added).
- Assembled paper_matrix.csv (101 papers, 21 cols, 0 malformed) + bibliography.bib (100 entries, deduped).
- Authored literature_review.md, research_gaps_and_novelty.md, executive_summary.md,
  advisor_brief.md, sources_audit.md.
- Inventory verified; CSV well-formed; no codename leak.

## Phase 3 COMPLETE — Agent G skeptical review returned (verdict: major-revision).
G verified all 6 named citations resolve; codename clean; praised evaluation_plan + sources_audit.
Blocking fixes M1–M4 + should-fix S1–S7 + nits applied across ALL deliverables AND the HTML:
- device-identity → device-CONFIGURATION/complexity (identity needs ≥2 stacks).
- leak sweep is n=1 per N → "clean 10-point line, not replicated law"; A3 confidence High→Med.
- "destroys / software-validated / measured budget" → "designed to remove / designed / provisional".
- config safety: rto_guard 150ms → 0.5× MEASURED RTO; budget_ms 150→25.
- CROB≠DB-size struck from measured "interpretation"; DB-size = unmeasured Class-0 channel.
- novelty: byte-preserving alone isn't the wedge (NetWarden) → the COMBINATION is.
- H3 beacon (lone shaped device is separable); added E1'(Class-0 DB-size), E7(detectability), RTO precond.
- added Traffic Morphing (Wright 2009) to bib+matrix (now 102 papers, 101 bib); NetWarden HotNets→HotCloud'19; β-power number fixed.
- final_synthesis.md written (§13 format, corrected).

## Phase 4 COMPLETE — interactive HTML briefing (user request)
- ack_timing_briefing.html — self-contained, both-theme, interactive (measured-leak canvas chart
  native↔normalized toggle, filterable 102-ref library, reviewer-hunt accordion, traffic-class + platform
  matrices). Integrates exec summary + advisor brief + literature + citations. Validated (node --check,
  tag balance, CSP-safe, codename clean). Published PRIVATE Artifact:
  https://claude.ai/code/artifact/e5051b83-acf3-4089-8678-c0ba2d81f976

## STATUS: COMPLETE. 10 spec deliverables + final_synthesis + measured data + HTML briefing.
Remaining is future EXPERIMENT work (E1'/E2/RTO-measure), not doc work.

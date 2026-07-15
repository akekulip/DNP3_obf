# WORKING NOTES — split/pad/timing combined-policy study

**Source:** `when_how.md` (Dr. Lin). **Dir:** `research/split_pad_timing_policy/`.
**Constraint:** research/design only; byte-preserving phase. Started 2026-07-13.
**Builds on:** `research/ack_timing_normalization/` (reuse timing/lit/hardware/eval; don't redo).

## Decisions
- Executing when_how.md as the delegation map (main session = synthesizing lead), Agent tool
  (parallel), not Workflow (no ultracode opt-in) — same pattern as the ack.md study.
- Deliverables at repo-root `research/split_pad_timing_policy/` (19 files).

## Grounding done
- Read split evidence (split_aggressiveness_sweep, baseline_segmentation) + padding negative
  result (padding_candidate_results) + reused the full ack package.
- MEASURED this session (NEW): response SIZE also encodes CROB count — 14.6 B/CROB, R²=0.9999,
  37→256 B (N=1→16). ⇒ timing normalization alone can't hide CROB count; size leak is residual.
  Also size ∝ point count read-plane (5.7 B/pt). → `measured_evidence.md`.

## Agent dispatch (Phase 1, parallel) — A–I, then J reviewer
- A → power-systems-expert : DNP3 split boundaries + DNP3 padding fields/no-op mechanisms (split+padding DNP3 side)
- B → general-purpose      : TCP/NIC effects on split (MSS/GSO/TSO/GRO/Nagle/coalescing/reorder), RTO measure, budgets
- C → sdn-networks-expert  : residual fingerprints after split/pad/timing; new fingerprints (pkt count/total bytes/buckets); strongest attacker
- D → sdn-networks-expert  : padding/cover-traffic/WF literature; what transfers to DNP3; future padding architectures; overhead
- E → general-purpose      : low-overhead software policy engine (classify→split→pad→schedule); mechanism comparison
- F → p4-dataplane-engineer: staged Tofino design (classify/telemetry → chunk pacing/gap-norm → first-response timing → future)
- G → sdn-networks-expert  : DPU/SmartNIC/FPGA comparison (timed send/PTP/calendar queue/DOCA)
- H → power-systems-expert : 3-axis semantics/safety taxonomy; traffic-class shape/pad/bypass; criticality allowlist; fail-open
- I → research-scientist   : evaluation methodology (split+pad+timing) + multi-objective optimization + overhead model + Pareto
Each reads GROUNDING.md + measured_evidence.md + relevant ack files; writes agent_reports/agent_<X>_*.md.

## Phase 2 (synthesis): 19 deliverables (many extend ack versions).
## Phase 3: Agent J (ieee-journal-reviewer) → fixes → §16 final synthesis.

## Phase 1 COMPLETE — all 9 agent reports in (agent_reports/agent_{A..I}_*.md)
Consistent thesis: CROB count leaks on BOTH size (14.6 B/CROB R²=0.9999, measured this session) AND
timing (R²≈0.99 n=1/N). Timing closeable now (class-indep normalization); size is NOT (split preserves
total bytes + relocates leak to packet count; NO byte-preserving DNP3 padding exists, parser-level
negative; only future tunnel padding closes size, ~+590%). Corrections captured: master reassembles
ANY byte-offset split (CRC-align = auditability choice); split needs PACING not NODELAY; split RTO =
Hulk tail vs hold RTO = Vision; per-flow FIFO not min-heap; target host Python 3.8; Tofino can pace
but not CREATE the split; beacon risk (shape fleet not one device). 14 new verified citations.

## Phase 2 COMPLETE — all 19 deliverables written
Promoted E/F/G/H/I → software/tofino/dpu_fpga/safety/evaluation. Authored split/padding/timing_analysis,
combined_decision_policy, terminology, overhead_model, literature_review, gaps_novelty, exec_summary,
advisor_brief, sources_audit, roadmap. bibliography.bib=115 (101+14), paper_matrix.csv=14 new (21-col).
Inventory verified; CSV/bib wellformed; codename clean.

## Phase 3 COMPLETE — Agent J review returned (verdict: major-revision).
J: package holds on 8/9 attack points; all 5 flagged new citations verify; codename clean; praised
the honesty/self-critique. Fixes applied:
- BLOCKER C1 (RTO): evaluation_plan §9.1/c6/§11.1 + overhead_model §1 rewritten to the THREE-inequality
  model (per-hop gap + initial hold < RTO; cumulative < 5s app/10s SBO). bpc=1 now correctly feasible
  (matches measured 0-retransmit split). Removed "cumulative<RTO / bpc bounded from below" overclaim.
- BLOCKER F1 (threat model): terminology_and_threat_model rewritten — two-tier observer (no-DPI metadata
  vs full-DPI cleartext), explicit cleartext-now/tunnel-later mechanism discontinuity, + A0 direct-read
  baseline experiment (the value of the current-phase defense). Mirrored in research_gaps §4(0).
- BLOCKER Fix3 (CSV): rows 2-10 (B/C/G) were column-misaligned → realigned all 14 rows to 21-col schema.
- M1: timing_analysis §1 table — stack-class discrimination retagged [P/I] (one device can't measure it).
- Fix5: n=1/N caveat attached to inline size-line mentions (exec_summary, GROUNDING, tofino_design).
- Fix6: software_design size_decorrelate default conditioned on the self-leak test I(choice;S|Y)≈0
  (constant = safe default until it passes).
- Added experiments A0 (direct-read baseline), RTO-feasibility sweep, tunnel-mechanism probe to eval §14.
- Nice-to-have: 102-matrix/101-bib bookkeeping reconciled in sources_audit. (Author-list/DOI completions
  are self-flagged, camera-ready.)
- final_synthesis.md written (§16 format, corrected).

## Phase 4 COMPLETE — interactive HTML briefing (user request)
split_pad_timing_briefing.html — self-contained, both-theme, pedagogical/interactive: dual-channel leak
chart (toggle normalize-timing → size still leaks), split simulator (bpc slider + sum-the-chunks reveal),
9-category padding cards, averaging-attacker animation (jitter separates classes / normalization doesn't),
decision-policy explorer (pick transaction → split/pad/timing/bypass), safety 3-inequality, platform matrix,
caveats accordion, 116-ref filterable library. Validated (node --check, tags, CSP-safe, codename clean).
Published PRIVATE Artifact: https://claude.ai/code/artifact/bd9fe88b-fe41-4881-b59d-1e14ca9e0714

## STATUS: COMPLETE. 19 spec deliverables + final_synthesis + measured_evidence + GROUNDING + HTML briefing.
Remaining = future EXPERIMENT work (A0, RTO measure, E1/E1′ replication, defended run), not doc work.

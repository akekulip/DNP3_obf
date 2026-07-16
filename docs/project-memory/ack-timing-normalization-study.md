---
name: ack-timing-normalization-study
description: "ACK-bearing DNP3 response timing-normalization research study — measured leak, deliverables, and the honest caveats that bound the claims"
metadata: 
  node_type: memory
  type: project
  originSessionId: 62e3e612-b15f-440c-86bd-58db8d47cd63
---

Seven-agent evidence study (2026-07-13, per `dnp3_multicrob_harness/ack.md`, Dr. Lin) on
**byte-preserving randomized timing normalization of ACK-bearing DNP3 responses** — the third
(timing) obfuscation axis, complementing CRC-boundary splitting. RESEARCH/DESIGN ONLY; no harness
code changed. All artifacts in repo-root `research/ack_timing_normalization/`.

**Measured anchor (this session, `dnp3_split_harness/analyze_ack.py` over existing multi-CROB rig
PCAPs, no code changed):** response processing time rises linearly with CROB count — SELECT-resp
0.179 ms/CROB **R²=0.9985**, OPERATE-resp 0.214 ms/CROB **R²=0.9954**, 3× over N=1→16; baseline
READ 9/9 piggyback, req→ACK 0.239 ms / req→response 1.014 ms. Data: `measured_timing_data.md`.

**Deliverables:** 10 spec files (executive_summary, literature_review [4 tiers], paper_matrix.csv
[102 papers], bibliography.bib [101 verified entries], software_design, hardware_design,
evaluation_plan, research_gaps_and_novelty, advisor_brief, sources_audit) + final_synthesis.md +
GROUNDING.md + `agent_reports/` (6 evidence reports). Interactive HTML briefing
`ack_timing_briefing.html` → private Artifact https://claude.ai/code/artifact/e5051b83-acf3-4089-8678-c0ba2d81f976

**Load-bearing caveats (a skeptical IEEE reviewer pass forced these — respect them in any paper):**
- The R²>0.99 leak is **n=1 per N-level** — a clean 10-point line, NOT a replicated law. Replicate
  (≥30/N, bootstrap CI) before "near-deterministic" wording.
- Measured variable is **CROB count = control-command complexity, NOT database size**. The DB-size
  channel lives on the **Class-0 read plane** and is **unmeasured** (the study is named for it).
- Say **device-configuration/complexity** leak, NOT device-identity/fingerprint (identity needs ≥2
  stacks — not yet available). The measured leak also sits on CONTROL responses the safety rule
  bypasses; a lone shaped device is a **beacon** (separable from unshaped traffic).
- **No defense has been run** — primitive is designed (scheduler in `split_server.py`), not
  validated; RTO budget is provisional. Binding constraint = master's **effective TCP RTO** (MEASURE
  on Vision; ~200 ms is the Linux floor, not universal), not DNP3 timers (5–60 s).
- Normalization beats jitter only vs a **repeated-poll** passive observer. Report **conditional**
  I(T;N|size), not marginal. Tofino absolute-delay = unbuilt recirc-hold (BlueField/FPGA are native).

Key prior context this builds on: `dnp3_split_harness/docs/ack_timing_obfuscation_research.md`
(earlier scoping brief), RAINCOAT = Hui Lin et al. IEEE TSG 2019 (DOI 10.1109/TSG.2018.2870362,
the differentiation anchor), Formby NDSS 2016 (the CLRT attack this defends). See
[[dnp3-harness-verified]] and [[lab-hosts-dnp3]]. **Next experiments:** measure RTO on Vision →
E1' replicated Class-0 point-count sweep → E2 one defended run.

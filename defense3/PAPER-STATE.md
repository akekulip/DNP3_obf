# PAPER-STATE — Defense 3 (research-pipeline memory)

**Artifact:** `defense3/REPORT.{md,tex,pdf}` — currently an *engineering/audit report*; the goal
is to turn it into an *explaining paper* (grounded in prior work, argument-first, readable).
**Venue class:** IEEE journal / ICS-CPS security (TDSC/TIFS/TSG or NDSS/CCS class) — exact venue
deferred.

## Stage location (from artifacts, 2026-07-31)

- A (Ideation): implicit — the work exists and is validated.
- B (Literature): **NOT DONE** — the report has ~1 prior-work mention (Formby), no Related Work
  section, no bibliography, no citation grounding. **This is the current stage.**
- C/D (Design/Results): done — synthetic gates + 3 physical campaigns + analysis exist.
- E (Figures): mostly done — 12 figures incl. the new lifecycle/safe-D/non-regression; a
  consistent-visual-language retrofit of the existing 9 remains.
- F (Drafting as a PAPER): **NOT DONE** — no Introduction (context→gap→contribution), no Threat
  Model section, no explicit Contributions; the structure is a chronological build/audit log.
- G (Revision & style): **NOT DONE** — prose is dense; `[AUDIT]` markers and "Every mistake
  made" read as an internal log, not a paper.

## Plan (this run)

1. **Stage B — Literature.** Anchor papers via arXiv + Semantic Scholar MCP: Formby et al.
   (CLRT/PLC device fingerprinting — the threat model), Ditto NDSS 2022 (in-network traffic
   shaping — closest prior defense), DNP3/ICS-protocol security, programmable-dataplane/P4
   in-network defenses, timing side-channels. Build a related-work map + `.bib` + objection
   ledger. Gate: anchors swept both directions; every load-bearing claim has a neighbor.
2. **Stage F — Reframe as a paper.** Add: Introduction (context → however → contribution),
   Threat Model, explicit Contributions; move "Every mistake made" and the `[AUDIT]` framing
   into an appendix/lessons section; keep the deep technical content. Voice: paper-voice.
3. **Stage G — Readability.** Drive flesch/fk-grade down (simpler language), calibrate claim
   strength (ban prove/law/universal-from-one-testbed), Summary-pattern abstract, then
   academic-humanizer. Record before/after metrics here.

## Metrics (before/after — Stage G)

- (to be filled by voice_check.py / manuscript_audit.py)

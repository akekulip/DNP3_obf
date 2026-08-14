# Rewrite log — Defense 4 paper

Governing prompt: `paper/writing.md`. Scope: rewrite four sections (Introduction, Related Work,
Threat Model/Assumptions/Goals, Implementation) as the **Defense 4 hardware paper**, grounded in the
frozen evidence. Writing-only; no hardware action.

## Key decisions (author-confirmed)
- **Paper target = Transform to Defense 4 (hardware).** The current manuscript is the earlier
  *software* CRC-boundary-splitting paper (split-replay server, OpenDNP3 two-host testbed, ~141
  chunks). It is being transformed into the Defense 4 RRC+BOR / Tofino / physical-SEL-751 paper.
  CRC-boundary splitting becomes the **Carve** step of RRC.
- **Base file = `dnp3_obfuscation_paper_desmoothed.tex`** (IEEEtran `conference`). The other file
  (`dnp3_obfuscation_paper.tex`) is retained, not deleted.
- Consistency consequence (flagged): the out-of-scope sections — abstract, the mechanism section
  ("CRC-Boundary Splitting"), Evaluation, Discussion — currently describe the *software* line and
  will be inconsistent with the rewritten four sections until updated. These are tracked as
  unresolved items for the author (§ Unresolved).

## Environment / fallbacks
- **MinerU: not invoked.** Fallback used and recorded: `pdftotext -layout` on all five target PDFs
  → `paper/rewrite/target_extract/*.txt`. Layout-aware section/caption/figure/table extraction is
  approximate (text only), not MinerU's structured layout. Style analysis is done from these text
  extracts.
- Baseline build: `tectonic dnp3_obfuscation_paper_desmoothed.tex` → 6-page PDF (baseline, software
  content). Warnings: a few underfull hboxes; no fatal errors. Baseline committed at `647b3bb`.
- Citations currently inline (`thebibliography`, 8 `\bibitem`s). New verified BibTeX being built at
  `paper/rewrite/refs.bib`; Zotero collection `OBfus_defense` being populated (citation agent).

## Target corpus (identified)
| file | paper | role |
|---|---|---|
| target/10139606.pdf | DefRec (Hui Lin et al.) | PRIMARY style: Intro, threat framing, contributions |
| target/10336809.pdf | Cyber-Physical Testbed (Hui Lin et al.) | PRIMARY style: implementation, testbed, limitations |
| target/RAINCOAT (2).pdf | RAINCOAT (Hui Lin et al.) | PRIMARY style: threat progression, mechanism→goal |
| target/who-control-...pdf | Formby et al. (NDSS 2016) | fingerprinting terminology + threat accuracy |
| target/2022_NDSS_ditto...pdf | Ditto (NDSS 2022) | programmable-switch shaping related work |

## Phase-A artifacts produced
- `paper/rewrite/CLAIM_EVIDENCE_LEDGER.md` — 25 claims (CL-1..25), each with evidence source, status
  (Measured/Verified/Design), allowed wording, prohibited overclaim.
- `paper/rewrite/STYLE_PROFILE.md` — target-style matrix + unified Lin-priority profile (in progress).
- `paper/rewrite/CITATION_AUDIT.md` + `refs.bib` — verified citations by category (in progress).
- `paper/rewrite/target_extract/*.txt` — text extractions of the five target PDFs.

## Figure plan (map to §9 needs; adapt existing explainer figures, do not redraw from scratch)
| §9 need | existing source | action |
|---|---|---|
| system/threat + observation point | explainer FIG-7 (topology) | adapt to NDSS 2-col, mark observer |
| native-vs-defended timeline (T0, A, R, R−A) | explainer FIG-9 (BOR timing) | adapt; add native track |
| RRC queue reservoirs qid7/6/5/4 | explainer FIG-8 (pipeline+TM) | adapt |
| 49-byte → [28,21] carve | explainer FIG-11 | vectorize for print |
| BOR SELECT→OPERATE with relay-facing gap marked | explainer FIG-12 | vectorize; mark unobserved gap |
| shared-scheduler vs two-domain | new (from CL-20) | draw via diagram-design |
| one-program P4 pipeline | explainer FIG-13 | vectorize |

## Status
Phase A (inspect) largely complete. Awaiting STYLE_PROFILE + CITATION_AUDIT to begin drafting the
four sections. No prose changed yet; baseline preserved.

## Unresolved (for author)
1. Out-of-scope sections (abstract, mechanism, Evaluation, Discussion) need updating to the Defense 4
   content for a coherent paper — do that now, or in a later pass?
2. Venue format: keep IEEEtran or switch to the NDSS `usenix`/`ndss` class? (Prompt says NDSS-oriented
   organization; current file is IEEEtran conference.)

---

## Completion status (first coherent rewrite)

**New manuscript:** `paper/dnp3_obfuscation_paper_defense4.tex` (IEEEtran conference, `\input`s the
five section fragments in `paper/rewrite/`). Builds with `tectonic` → 8 pages, 0 undefined
references, 0 unresolved citations, 4 figures, 16-of-19 refs cited. Original files preserved.

### Section-by-section diff summary
- **Introduction** — fully rewritten (software CRC-splitting → Defense 4). DefRec 8-step arc: Ukraine
  anchor → Formby CLRT + segment shape → First/Second/Third/Last prior-art drawbacks (encryption,
  fixed firmware/CRC, padding/morphing/WF defenses, host/controller) → gap → RRC/BOR → quantified
  previews → bounded limitations → four artifact-mapped contributions with one "to the best of our
  knowledge" claim.
- **Related Work** — new; RAINCOAT category structure, five run-in groups (fingerprinting; network
  timing; padding/morphing/segmentation; anti-recon ICS; programmable-switch shaping), each closed by
  an explicit contrast. Ditto positioned as the closest in-network precedent.
- **Threat Model** — replaces "Background and Threat Model". DefRec/RAINCOAT/Formby order: system +
  observation model → passive adversary (cross-layer response time + segment shape) → TCB/deployment
  (no TCP timestamps) → testable goals G1–G6 → explicit non-goals.
- **Implementation** — replaces the software harness. Testbed "six major parts" template; per-mechanism
  `problem→state→decision→queue effect→release→observable→failure→evidence`; ports/queues/`meta.outcome`/
  `tbl_commit` named (no source-file names, per author instruction); RRC (Release-Replicate-Carve) and
  BOR (Block OPERATE, then Release); two-scheduling-domain rationale.
- **Out-of-scope, updated for coherence:** abstract rewritten; a concise Defense-4 Evaluation,
  Discussion, and Conclusion drafted from the ledger (the software mechanism/Evaluation sections were
  superseded, not polished).

### Overclaims removed / limitations added
- "byte-identical" → "CRC-valid, checksum-valid 49-byte reconstruction"; no source oracle.
- "exactly once" removed; relay-facing `T0+J` and delivery multiplicity marked not observed.
- "size hiding" → "segment-vector normalization; total length unchanged".
- "only safe cut" → "chosen block-aligned carve point; not a TCP requirement".
- BOR "defeats" → "designed to mitigate"; multi-device anonymity explicitly not claimed.

### Deliverable status
STYLE_PROFILE.md ✓ · CLAIM_EVIDENCE_LEDGER.md ✓ · CITATION_AUDIT.md + refs.bib ✓ (19 verified, 2
corrected) · REWRITE_LOG.md ✓ · new figures (4) placed and referenced ✓ · compiled PDF ✓ ·
remove-ai-marks Layer A run on all prose + PDF (0 marks; PDF metadata stripped) ✓.

### Fallbacks (not silently skipped)
- **MinerU** unavailable → `pdftotext -layout` extraction of the five target PDFs.
- **Semantic Scholar MCP** exposed no callable tools → metadata verified against DBLP/ACM DL/IEEE
  Xplore/NDSS/USENIX/doi.org directly.
- **Zotero** collection `OBfus_defense` created (key `DP4TQCSF`) but **empty** — the local API
  (`localhost:23119`) was refused because Zotero desktop was not running; populate with
  `zotero_add_by_bibtex(refs.bib, collections=["DP4TQCSF"], if_exists="file")` once desktop is open.
- **Figure vectorization** — FIG-8/FIG-9 SVG→PDF failed (Inkscape/rsvg); vector-rendered PNGs used;
  FIG-11/FIG-12 remain raster. Full IEEE/NDSS 2-column vector treatment via `ieee-paper-figures` is a
  refinement pass.

## Unresolved decisions (need author input)
1. **Out-of-scope sections.** The abstract, Evaluation, Discussion, and Conclusion were rewritten to
   Defense 4 for coherence, but only at a concise level. Do you want a full-depth Evaluation section
   (per-figure results, tables, the MI/JS/classifier detail) now, or is the concise version enough
   for this pass?
2. **Venue class.** Kept IEEEtran `conference` (the working build). Switch to the actual NDSS class
   for submission formatting?
3. **Code-symbol exposure.** Source-file names are removed. P4 constructs (`meta.outcome`,
   `tbl_commit`) and port/queue IDs (`dp8`/`dp10`, `qid7`–`qid2`) are kept because they let a reviewer
   map prose to mechanism — confirm that level is acceptable, or strip those too.
4. **Zotero population** is blocked on Zotero desktop being open (see fallback above).

## Terminology change (author directive)
- The defense is **unnamed**; the label "Defense 4" is removed throughout (title, abstract, all
  sections) and the defense is referred to descriptively ("the defense", "an in-network obfuscation
  layer").
- The internal mechanism acronyms **RRC** and **BOR** are removed; the mechanisms are described
  functionally as **response shaping** (hold → release at policy offsets → replicate → carve) and the
  **control-command hold/mode** (block the OPERATE, release once at a hidden delay, anchor ACK/echo).
- Added an explanation of the defense's **selectable modes**: passthrough; ACK-hold, response-hold,
  and combined timing modes (the combined mode normalizes the CLRT); and a separate control-command
  mode. No source-file names appear in the manuscript.

## "Do all" pass (target-corpus deepening + Zotero)
- **Style audit applied** (STYLE_AUDIT.md): removed the unsubstantiated "at line rate"; added the
  DefRec desirability step (First/Second) to complete the 8-step intro arc; relabeled G5 as an
  evaluation-validity property (not a security goal); split five long sentences; surfaced the
  "to the best of our knowledge, first" claim to lead the contributions; varied the Related-Work
  contrast openings; "places in" -> "fits in".
- **Figures modeled on the targets** (FIGURE_BRIEF.md): redrew the native-vs-defended timing figure
  on Formby's CLRT-sequence model with a mandatory tri-state legend (measured / modeled / UNOBSERVED),
  marking the relay-facing T0+J as unobserved; vectorized the pipeline and timeline figures (SVG->PDF
  via cairosvg). fig_system and the carve/pipeline figures retained.
- **Related Work strengthened with 14 top-tier additions** (per the quality-venue directive):
  7 mined from the targets (liufdia2009 CCS, panchenko2016 NDSS, tamaraw2014 CCS, walkietalkie2017
  USENIX, sppifo2020 NSDI, nethide2018 USENIX, apthorpe2019 PoPETs) + 7 from the Defense-3 Zotero
  library (securitas2026 NSDI, minos2025 USENIX ATC, hulin2023 SmartGridComm, pacer2022 USENIX Sec,
  netshaper2024 USENIX Sec, kohno2005 IEEE TDSC, gu2018 IEEE S&P). Workshop-tier candidates dropped.
  refs.bib now has 32 entries; 30 cited; 0 undefined; 8 pages.
- **Extraction fidelity** (EXTRACTION_NOTES.md): PyMuPDF re-extraction of the five targets found NO
  metadata contradictions vs refs.bib (it decoded the font-obfuscated LASER footer to confirm).
- **Zotero**: local API up; the `OBfus_defense` collection (DP4TQCSF) now holds all 32 references
  (25 added from refs.bib + 7 existing Defense-3 items linked in).

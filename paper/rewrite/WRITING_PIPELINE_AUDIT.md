# Audit — research & writing pipeline (assessment only, no changes)

Groundwork before aligning to Dr. Lin's format/communication feedback. Three parallel audits:
toolchain health, writing-skill wiring, and the actual paper artifacts. 2026-08-19.

## Bottom line

The machine works and a real manuscript already exists. The problem is **not** broken tooling
and **not** a missing draft — it is (1) the two skills that encode *Dr. Lin's own voice and venue*
sit outside the default routing, (2) the current draft's **scope and format diverge from what Dr.
Lin asked for in the meeting**, and (3) the *polished, reader-facing* outputs are explainers
(DOCX/PDF), not the shared IEEE submission he expected. All three are alignment/wiring issues, not
capability gaps.

---

## Finding 1 — Toolchain: HEALTHY (not the cause)

`verify.sh` = **28 PASS, 0 FAIL**; a live markdown→PDF citation build produced a valid IEEE PDF;
`$RESEARCH_PYTHON` (3.12) + all libs import; arxiv + semantic-scholar MCP connected; Inkscape
1.4.2 + IEEE fonts + diagram-design all present. Only real caveats:
- **`library.bib` is ~6 weeks stale (Jul 6, 85 entries) and Zotero isn't running**, so it can't be
  refreshed; and the paper's own bib is **hand-managed, not Zotero-synced** (Semantic-Scholar MCP
  exposed no callable tools during drafting, Zotero local API was down → manual DBLP/DOI
  verification, ingestion into the `OBfus_defense` collection still pending).
- Conclusion the health check itself reached: since output builds cleanly, "not producing as
  expected" points at the **content/structure/voice layer**, not the machinery.

## Finding 2 — Writing-skill wiring: the diagnosis (the decisive one)

**`paper-voice` is mined from Dr. Lin's group's own papers** — DefRec (NDSS), RAINCOAT (TSG), the
DNP3/Bro IDS paper, the SDN in-network honeypot paper. So "match the advisor's format and
communication" maps almost exactly onto two skills: **`paper-voice`** (his prose voice) and
**`security-paper-writing`** (his venue's structure — threat-model-first, adaptive-adversary,
ethics/disclosure). **Both are unwired from every default routing surface** (the always-on
CLAUDE.md skill table, the PI delegation map, and the research-pipeline Stage-F list).

What the defaults do instead, for a security paper:
- Route drafting to the generic **`academic-paper`** pipeline (higher-ed default; bilingual zh-TW
  abstract; APA citations; mandatory CRediT/ethics) **or** **`systems-paper-writing`** (the
  OSDI/SOSP page-budget blueprint) — both the wrong genre for an IEEE/NDSS security paper.
- Then run prose through the generic **`humanizer`** ("add soul / inject personality") — the wrong
  post-processor for neutral technical writing; `academic-humanizer` (which preserves scholarly
  voice) is only a parenthetical fallback.
- Two competing routing surfaces (research-pipeline vs the CLAUDE.md table) that **disagree**, so
  which chain runs depends on whether the full pipeline was explicitly invoked → **inconsistent
  voice/format run to run**, which an advisor perceives as unreliable communication.
- Even when `paper-voice` runs, optimizing only the style *fingerprint* (not `flesch`/`fk_grade`
  readability) reproduces a "too dense / inaccessible" complaint despite a green check — a failure
  mode the skill itself has logged before.

Fix (when authorized) = a **routing change**, not new tooling: put `security-paper-writing` +
`paper-voice` on the default academic-manuscript path, enforce the readability metric, and use the
`ieee-journal-reviewer` agent (not the generic reviewer) for the review gate.

## Finding 3 — The artifacts: a real manuscript exists, but scope/format drift from the mandate

**`paper/dnp3_obfuscation_paper_readerfirst.tex`** is a complete IEEEtran double-column draft (615
lines; all standard sections; a disciplined 5-item contribution list; abstract with committed
numbers — 4.001 ms CLRT, all 1,280 responses in `[28,21]`, classifier at chance; 41 wired
citations; 7 figures) that compiles to a 1 MB PDF and **reads as a genuine academic
systems-security paper**, with "(measured)" vs "(modeled)" discipline tracing to
`E_FINAL/CLAIM_MATRIX.md`. Notably it **already names Dr. Hui Lin as the style model**
(`paper/writing.md`) and carries his papers as the target corpus — so some advisor-alignment was
done by hand.

The gaps that most plausibly read as "not what I expected":
- **Scope vs. the meeting mandate.** `meeting.md` §14–15 records Dr. Lin confirming a **two-part
  paper — Part 1 packet-size obfuscation AND Part 2 timing — that "explains how size and timing
  complement each other,"** as a **double-column IEEE template, ~12 pages before references, in a
  shared Overleaf.** The current draft is a **single unified NDSS conference paper** where size
  becomes one "Carve" step; the co-equal size contribution and the size↔timing complementarity
  narrative are under-developed, and `PAPER_OUTLINE.md`'s two-part plan is effectively abandoned.
  **⚠ This must be reconciled with the NEW transcript:** you said the latest meeting deemed
  *timing obfuscation adequate* — which may deliberately supersede the old two-part mandate. If so,
  the "scope mismatch" is resolved by the new direction; if not, size needs to return as Part 1.
- **Venue/format ambiguity.** Meeting notes say "IEEE, ~12 pages, shared Overleaf"; the draft
  targets **NDSS** and is built **locally with tectonic, not in the shared Overleaf**. The Overleaf
  co-writing Dr. Lin asked for (he adds paragraph-level ideas) is not the current workflow — a
  direct **communication-channel** gap.
- **Polished outputs are explainers, not the submission.** The nicely-rendered DOCX/PDF artifacts
  (`DEFENSE4_EXPLAINER`, `MEETING_REFERENCE`, `DEFENSE4_SIMPLE`) are internal explainers; the IEEE
  manuscript is the compact `.tex`. If he judged "the output," he may have seen explainers.
- **Figures underused.** The manuscript pulls 7 (mostly schematics); ~30+ publication-grade data
  plots (CLRT CDF/violin, MI, classifier BA, latency, resources) sit in `defense4/figures/` and
  `defense4_release/figures/publication/` **unused** — the strongest quantitative evidence isn't in
  the paper.
- **Author/affiliation still placeholders; no Stage-H review pass run; eval bounded** to one device
  / one response class, exactly-once modeled-not-measured (a known reviewer target).

---

## What I recommend once you share the transcript (not doing yet)

1. **Reconcile scope first** from Dr. Lin's actual words: is it timing-only now, or still two-part
   size+timing? Everything downstream (structure, figures, length) keys off this.
2. **Lock venue + format + channel:** IEEE 12-page vs NDSS; and move to the **shared Overleaf** he
   asked for so his paragraph-level edits land where he expects.
3. **Rewire the writing path** to `security-paper-writing` + `paper-voice` (his corpus) +
   `academic-humanizer` (not the generic humanizer), with the readability metric enforced, and the
   `ieee-journal-reviewer` gate.
4. **Pull the strong data plots** into the manuscript; close the citation loop (start Zotero →
   `refresh-bib.sh`).

Nothing changed in this pass — this is the map. Share the transcript and I'll align each item to
exactly what he said.

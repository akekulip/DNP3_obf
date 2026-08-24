# Writing-pipeline rebuild — audit & test verdict

Tests the built pipeline (contract A + check B + global routing/skills/doctrine C+D) against what
Dr. Lin SAID (meeting) and WROTE (his papers + the annotated intro). All numbers below were
produced by real `lin_check.py` runs, verified by the main session. 2026-08-19.

## What was built
- **A — spec:** `paper/LIN_STYLE_CONTRACT.md` (all transcript + papers + annotated-intro keys, incl.
  the 7 completeness-pass gaps).
- **B — enforcement:** `paper/pipeline/lin_check.py` + `build.sh` — 7 checks, wraps
  `paper-voice/voice_check.py`, fail-closed.
- **C — routing (global, additive, reviewed):** CLAUDE.md auto-table row, PI delegation map,
  research-pipeline Stage F → `security-paper-writing` + `paper-voice` + `academic-humanizer` +
  `ieee-journal-reviewer`.
- **D — durable (global, additive, reviewed):** `paper-voice` SKILL.md section-order contract;
  `research-philosophy/WRITING-SYSTEM.md` "ICS/security manuscript (Lin)" profile.

## Test 1 — FIDELITY (does the pipeline match what he WROTE?) — PASS
Dr. Lin's own introduction paragraphs (verbatim from the annotated draft) score **PASS** on
`lin_check` (exit 0): connective spine **57.1%** of sentences (Consequently/Because/Since/
Unfortunately), **0** fragments. His real writing satisfies the contract that was mined from it.
The contract's rules trace to `paper-voice`'s five-paper Hui-Lin corpus (`LIN_STYLE_PROFILE.md`).

## Test 2 — DISCRIMINATION (does it capture HIS style, not noise?) — PASS
Same check, same section, both hands:

| | connective spine | fragments | fact hygiene | result |
|---|---|---|---|---|
| **Lin's paragraphs** | 57.1% PASS | 0 PASS | PASS | **PASS (exit 0)** |
| **Philip's paragraphs** | 0.0% FAIL | 1 FAIL | WARN (Ukraine 2025) | **FAIL (exit 1)** |

The check named the exact defects — the dangling "By learning…, because…" sentence and the
Ukraine date slip. It separates his writing from non-his on the dimensions his feedback targeted.

## Test 3 — REPRODUCTION (can the pipeline REPLICATE his voice?) — PASS
The end-to-end run: `paper-voice` skill + the contract rewrote Philip's paragraph 2 into Lin's
voice; `lin_check` scored before/after:

| | connective spine | fragments | fact hygiene | result |
|---|---|---|---|---|
| before (Philip) | 0.0% | 1 | WARN 2025 | FAIL |
| after (pipeline) | **28.6%** (Consequently, Because) | **0** | PASS | **PASS (exit 0)** |

The pipeline does not just flag bad prose — it produces Lin-voice prose that passes the gate.

## Test 4 — STORYTELLING / STRUCTURE — encoded, enforced
His narrative machinery is captured and checkable: the 4-sentence intro funnel + the
gap-paragraph-that-premaps-contributions (contract §3), the framework-as-contribution / two-case-
studies framing (§1, §4), the section order with threat-model-early + a distinct Design section +
RO-labelled evaluation (§2), and the passive/proactive/active threat taxonomy (§6). `lin_check`'s
`structure` and `contribution_grammar` checks enforce the structural half; `paper-voice` carries
the sentence-level storytelling voice.

## Honest boundary (what these tests do and do NOT prove)
- They prove **structural + stylistic** reproduction — connective spine, sentence health, section
  order, contribution grammar, his measured voice fingerprint. That is exactly what Dr. Lin's
  feedback was about (structure, flow, "linking sentences").
- They do **NOT** prove the prose is indistinguishable-from-human to an AI *detector*
  (`voice_check` measures surface style, not per-token perplexity — its own docs say so), nor that
  a rewrite is factually correct. Fact-checking and any AI-use disclosure remain human/authorial.
- The current full draft baselines as expected: `lin_check` FAILs it on connective spine (0.9%),
  contribution grammar (noun headlines, no first-ness claim), and structure (threat model late, no
  distinct Design section, goals not reused in Evaluation) — the concrete worklist for the rewrite.

## Verdict
The rebuilt pipeline **faithfully encodes, enforces, and reproduces** Dr. Lin's structure and
voice on the dimensions his feedback named, validated on his own writing (fidelity), against
non-his writing (discrimination), and end-to-end (reproduction). It is reproducible: every run is
a deterministic `lin_check` score, and the routing/skills/doctrine now put his voice-and-genre
skills on the default path so future sessions do not drift.

**Next (on Philip's go):** apply the pipeline to the manuscript — rewrite Philip's sections to the
contract (starting with the intro), add the distinct Design section and move design content there,
convert contributions to verb-first headlines + the first-ness claim, and drive `lin_check` to
PASS section by section.

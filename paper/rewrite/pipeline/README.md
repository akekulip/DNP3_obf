# `paper/pipeline/` — Lin-style enforcement gate (writing-pipeline layer B)

This is the re-runnable scorer that makes "write like Dr. Lin" reproducible. It grades a draft
against the checkable signals in [`../LIN_STYLE_CONTRACT.md`](../LIN_STYLE_CONTRACT.md) §9 and
fails closed, so drift from his structure and voice is visible on every run instead of only when
he reads it.

## Files

| File | Purpose |
|---|---|
| `lin_check.py` | The scorer. Accepts `.tex`, `.md`, or `.txt` (LaTeX/Markdown is stripped for analysis). Emits a per-check PASS/WARN/FAIL/NA report; `--json` for machine output. |
| `build.sh` | `tectonic` compile (offline) → run `lin_check` → write the scorecard into `reports/`. One reproducible "draft → PDF + score" command. |
| `samples/lin_intro.txt` | Dr. Lin's intro paragraphs (verbatim quotes from `../LIN_VS_PHILIP_DIFF.md`), for the discrimination test. |
| `samples/philip_intro.txt` | Philip's intro paragraphs (verbatim, same source). |
| `reprod/philip_p2_orig.txt` | Philip's paragraph 2 before rewriting (worse), for the non-regression demo. |
| `reprod/philip_p2_lin.txt` | The Lin-method rewrite of the same paragraph (better). |
| `reports/` | Timestamped `.txt` + `.json` scorecards from `build.sh`. |
| `build/` | `tectonic` output (PDF, logs). |

## Usage

```bash
RP=/home/philip/.venvs/research/bin/python      # $RESEARCH_PYTHON: numpy present, textstat optional

# Score the live draft (human report). Exit 0 if all hard checks pass, non-zero on any FAIL.
$RP lin_check.py ../main.tex

# Machine-readable
$RP lin_check.py ../main.tex --json

# Adjust the connective-spine target (default 0.12 = 12% of sentences lead with a connective)
$RP lin_check.py draft.tex --connective-target 0.15

# Full reproducible gate: compile the PDF (offline) then score
./build.sh                                       # defaults to ../main.tex
./build.sh path/to/other.tex
```

## Non-regression gate (`--compare BEFORE AFTER`)

Mechanically enforces the rule **"a humanize/edit pass must not lower the Lin-voice score."**
`BEFORE` and `AFTER` may each be either a draft file (scored on the spot) or a prior `--json`
scorecard (loaded; same shape as `--json` output). The gate recomputes/loads both, prints a
per-check delta table, and **fails closed with exit code 3 if `AFTER` regressed on any hard
dimension**:

- a hard check went PASS/WARN → FAIL,
- `connective_spine` overall fraction dropped,
- `sentence_health` fragment count increased,
- `voice_fingerprint` deviation count (sum of AI-pattern flags, em-dashes included) increased, or
- `readability` moved further outside the band.

It passes (exit 0) only when every hard dimension is equal-or-better. `--json` emits the full
comparison. It is additive: the single-draft scoring behavior and thresholds are unchanged.

### Worked example — guard a humanize pass

```bash
RP=/home/philip/.venvs/research/bin/python

# 1. Snapshot the score BEFORE humanizing
$RP lin_check.py paper.tex --json > before.json

# 2. Humanize with academic-humanizer (edits paper.tex) ...

# 3. Reject the edit if it lowered the Lin-voice score
$RP lin_check.py --compare before.json paper.tex        # exit 0 = ok, exit 3 = regression
```

Demonstrated on the two `reprod/` files (a real "before" paragraph and its Lin rewrite):

```bash
# AFTER = the Lin rewrite (better) -> NO REGRESSION, exit 0
$RP lin_check.py --compare reprod/philip_p2_orig.txt reprod/philip_p2_lin.txt
#   connective_spine.fraction  0.000 -> 0.714  better
#   sentence_health.fragments      1 ->     0  better
#   VERDICT: NO REGRESSION (equal or better on every hard dimension)   [exit 0]

# AFTER = the original (worse) -> REGRESSION, exit 3
$RP lin_check.py --compare reprod/philip_p2_lin.txt reprod/philip_p2_orig.txt
#   connective_spine.fraction  0.714 -> 0.000  WORSE
#   sentence_health.fragments      0 ->     1  WORSE
#   VERDICT: REGRESSION  [exit 3]
```

`build.sh` exits non-zero if **either** the compile **or** the `lin_check` gate fails; the gate
always runs even when the compile fails, so a scorecard is always produced.

## What it checks (maps 1:1 to `LIN_STYLE_CONTRACT.md` §9)

| Check | Signal | Hard? |
|---|---|---|
| `connective_spine` | fraction of sentences led by a logical connective (Consequently / Because / Since / However / Unfortunately / For example / Therefore / Thus / Instead / …); per-paragraph and overall vs `--connective-target`. | **FAIL** |
| `contribution_grammar` | locates the contributions list; every bold headline must be verb-first; a "to the best of our knowledge" first-ness claim must be present. | **FAIL** |
| `structure` | threat model appears in/before Background; a *distinct* Design/Approach section exists (not merged into Background); goal labels `G1..`/`RO1..` are defined and **reused** in the Evaluation. | **FAIL** |
| `readability` | Flesch reading ease + FK grade, overall and per section, within a band (the "too dense" guard: Flesch ≥ 15, FK ≤ 18). | WARN |
| `sentence_health` | flags the no-main-clause fragment class (the "By learning X…, because Y…" dangler) as FAIL; sentences with no obvious finite verb as WARN. | **FAIL** on fragments |
| `fact_hygiene` | duplicate marquee examples across paragraphs; a marquee example near a wrong year (e.g. Ukraine near a year ≠ 2015). | WARN |
| `voice_fingerprint` | wraps `paper-voice/voice_check.py` (sentence length, "we"-agency, hedges, banned AI words, em-dashes). | WARN on em-dashes |

Hard-check FAIL ⇒ non-zero exit. WARN and NA never change the exit code. Structural and
contribution checks report **NA** on a short fragment with no sections (nothing to check).

## Reuse and determinism

- **Reuses** `~/.claude/skills/paper-voice/scripts/voice_check.py` for the sentence-splitting,
  markup-stripping, and voice/lexicon/stance metrics — imported by absolute path, not
  reimplemented. Only the connective/contribution/structure/readability/sentence-health/fact
  checks are new code.
- **Readability degrades gracefully:** uses `textstat` if importable, else falls back to the
  Flesch / Flesch-Kincaid formulas already in `voice_check`. `$RESEARCH_PYTHON` currently has no
  `textstat`, so the fallback is what runs.
- **Deterministic:** no randomness, no network. Two runs on the same input produce byte-identical
  JSON.

## Discrimination test (proves the check captures *his* style, not noise)

Scoring Dr. Lin's intro paragraphs against Philip's (the exact texts from `../LIN_VS_PHILIP_DIFF.md`)
must put Lin higher on connective-spine and sentence-health:

| | connective_spine | sentence_health (fragments) | fact_hygiene | exit |
|---|---|---|---|---|
| `samples/lin_intro.txt` | **0.571** (4/7 led) — PASS | **0** — PASS | PASS | 0 |
| `samples/philip_intro.txt` | **0.000** (0/4 led) — FAIL | **1** — FAIL | WARN (Ukraine near 2025) | 1 |

Lin's connective density is higher and his fragment count is lower — the check discriminates. If a
future edit breaks this ordering, the check is wrong; fix the check, not the samples.

The sample files are assembled from the verbatim quotes in `../LIN_VS_PHILIP_DIFF.md`; the only
non-verbatim additions are minimal ellipsis fills drawn from the same diff / the contract (e.g.
completing "Consequently, fingerprinting shifts the focus …" and naming "packet-size and latency
features"). Philip's broken sentence, the garbled Ditto enumeration, and the mis-dated
"December 2025" Ukraine reference are preserved exactly, because they are what the sentence-health
and fact-hygiene checks must catch.

## Where this sits in the reproducible flow

`draft in Lin's method` → `security-paper-writing` (structure) → `paper-voice` (voice) →
`academic-humanizer` (AI-tell sweep) → **`lin_check` gate (this dir)** → `remove-ai-marks` Layer A →
`build.sh` → PDF + score. See `../WRITING_PIPELINE_REBUILD_PLAN.md`.

# Cleanup plan — 2026-08-26

Disposition of every candidate item on the final branch `paper/final-timing-rewrite-20260826`.
The 2026-08-24 cleanup (`defense4/timing/CLEANUP_PLAN.md`, `REMOVAL_REPORT.md`) reduced the
repository from 6,480 tracked files to 144; this plan covers what the manuscript rewrite made
stale. Nothing here is deleted before it is (a) recoverable from Git history on this branch's
parent commits, the tags and the bundles, and (b) copied, hash-verified and listed in the
external archive `/home/philip/Projects/DNP3-local-archive-20260826/` (outside the worktree).

Classes: KEEP ACTIVE · REMOVE FROM ACTIVE, RECOVERABLE IN GIT HISTORY · COPY TO EXTERNAL LOCAL
ARCHIVE, THEN REMOVE · DUPLICATE SAFE TO REMOVE · GENERATED REBUILDABLE · REMOVE WORKTREE AFTER
VERIFICATION · UNRESOLVED.

## Manuscript tree `paper/rewrite/`

| item | class | reason |
|---|---|---|
| `main.tex`, `sections/00…08_*.tex`, `library.bib`, `figures/timing/*`, `figures/fig_{design,ladder,observation}.{svg,pdf}`, `FIGURE_PROVENANCE.md`, `FINAL_FIGURES.md`, `README.md` | KEEP ACTIVE | the manuscript and its provenance |
| `main.pdf` (2026-08-24 build, 7 pages, placeholders) | COPY TO EXTERNAL LOCAL ARCHIVE, THEN REPLACE | superseded by the 2026-08-26 build committed under the same name |
| `introduction_pipeline_v1.tex`, `background_pipeline_v1.tex`, `threatmodel_pipeline_v1.tex`, `design_pipeline_v1.tex`, `evaluation_pipeline_v1.tex` | COPY TO EXTERNAL LOCAL ARCHIVE, THEN REMOVE | replaced by `sections/`; the design file carried the wrong read-path rule and the evaluation file was a figure scaffold |
| `LIN_STYLE_CONTRACT.md`, `LIN_STYLE_PROFILE.md`, `LIN_VS_PHILIP_DIFF.md`, `PIPELINE_AUDIT_VERDICT.md`, `WRITING_PIPELINE_AUDIT.md`, `WRITING_PIPELINE_REBUILD_PLAN.md` | COPY TO EXTERNAL LOCAL ARCHIVE, THEN REMOVE | consolidated into `pipeline/DR_LIN_WRITING_GUIDE.md`; the contract's firstness and section-order rules are superseded by the brief; the audit and plan are historical |
| `TITLE_OPTIONS_2026-08-24.md` | COPY TO EXTERNAL LOCAL ARCHIVE, THEN REMOVE | size+timing titles, stale; title chosen |
| `refs.bib` | COPY TO EXTERNAL LOCAL ARCHIVE, THEN REMOVE | legacy keys; `main.tex` cites only `library.bib` and every cited key resolves there (`CLAIM_CITATION_MATRIX.md`) |
| `LIN_WRITING_GUIDANCE.md` | KEEP ACTIVE | the extraction of Dr. Lin's spoken guidance; evidence for the protected text |
| `pipeline/samples/lin_intro.txt` | KEEP ACTIVE | his introduction paragraphs verbatim |
| `pipeline/samples/philip_intro.txt`, `pipeline/reprod/philip_p2_{orig,lin}.txt` | COPY TO EXTERNAL LOCAL ARCHIVE, THEN REMOVE | demonstration inputs for the retired connective-density check |
| `pipeline/{build.sh,lin_check.py,make_final_figures.py,README.md,DR_LIN_WRITING_GUIDE.md}` | KEEP ACTIVE | the build and gate |
| `pipeline/reports/{PRE_REWRITE_KNOWLEDGE,PRE_REWRITE_RECONCILIATION,EVENT_SEMANTICS_TRUTH_TABLE,LIN_TEXT_CHANGELOG,CLAIM_CITATION_MATRIX,FINAL_MANUSCRIPT_AUDIT}.md` | KEEP ACTIVE | required reports |
| `pipeline/reports/main_*.{txt,json}` (scorecards), `pipeline/build/` | GENERATED REBUILDABLE | ignored; the 2026-08-24 scorecards are copied to the archive for the record |

## Timing tree `defense4/timing/`

| item | class | reason |
|---|---|---|
| everything tracked | KEEP ACTIVE | the evidence authority; `implementation/` and `raw_pcaps/` unchanged since capture |
| `build/`, `.venv/`, `uv.lock`, `__pycache__/` | GENERATED REBUILDABLE | ignored |
| `REPOSITORY_AUDIT.md`, `CLEANUP_PLAN.md`, `CLEANUP_REPORT.md`, `BRANCH_MAP.md` (2026-08-24) | KEEP ACTIVE | record of the earlier cleanup; superseded for current state by the root `REPOSITORY_AUDIT.md` and this file, which say so |

## Root

| item | class | reason |
|---|---|---|
| `README.md`, `CLAUDE.md`, `WORKING_NOTES.md`, `REPOSITORY_AUDIT.md`, `CLEANUP_PLAN.md`, `FINAL_TIMING_ALLOWLIST.txt`, `REMOVAL_MANIFEST.csv`, `REMOVAL_REPORT.md`, `VERIFICATION_REPORT.md` | KEEP ACTIVE | orientation and the record of the prune |
| `corrections.md` | UNRESOLVED (left untracked) | the task brief for this session; Philip's file, not committed and not removed |

## Worktrees

None to remove: `git worktree list` shows only `/home/philip/Projects/DNP3` (see `REPOSITORY_AUDIT.md`).

## Duplicate evidence

None on the branch. The two historical `E_FINAL` trees were proven identical by shared git tree
object `1d1a5f3c…` and removed on 2026-08-24 (`REMOVAL_REPORT.md`).

## Ignore rules

`.gitignore` covers `__pycache__/`, `*.py[cod]`, LaTeX intermediates (`*.aux *.bbl *.blg *.out
*.toc *.fls *.fdb_latexmk *.synctex*`), `paper/rewrite/pipeline/build/`, the timestamped
scorecards, `defense4/timing/build/`, `.venv/` and `uv.lock`.

## Method

Explicit `git rm` on the listed paths after the archive copy verifies by SHA-256; no recursive
or wildcard deletion; verification that each removed path is gone from the worktree and present
in the archive. Recovery: `git show <parent commit>:<path>` on this branch, the bundle
`DNP3-before-final-paper-rewrite-20260826.bundle`, or the archive directory.

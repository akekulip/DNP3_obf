# `paper/rewrite/` — the one active manuscript

Everything the timing-obfuscation paper is built from lives here. The entry point is `main.tex`;
no other `.tex` file in the repository is a manuscript.

## Build

```sh
cd paper/rewrite
./pipeline/build.sh                 # tectonic compile -> pipeline/build/main.pdf, then the gate
tectonic -X compile main.tex        # compile only, PDF lands beside main.tex
```

`build.sh` fails closed if the compile fails or the gate (`pipeline/lin_check.py`) reports a hard
failure; the scorecard goes to `pipeline/reports/main_<stamp>.{txt,json}` (untracked). The gate
checks the flattened manuscript against `library.bib` and the compiled PDF. The reviewed build is
committed once as `main.pdf` beside this file.

## Layout

```
main.tex                        entry point: title, author block, abstract, section inputs
sections/00_abstract.tex        the Abstract
sections/01_introduction.tex    Dr. Lin's protected paragraphs + the gap paragraph + contributions
sections/02_background.tex      Background and Motivation
sections/03_threat_model.tex    Threat Model and Research Objectives (RO1, RO2, RO3)
sections/04_design.tex          Framework Design (the two release rules)
sections/05_implementation.tex  Tofino Implementation
sections/06_evaluation.tex      Evaluation, organised by RO1..RO3, with Limitations
sections/07_related_work.tex    Related Work (second-last)
sections/08_conclusion.tex      Conclusion
library.bib                     bibliography (Zotero export; cited entries verified, see reports/)
figures/timing/                 THE FIVE FINAL FIGURES, vector PDF + PNG preview
figures/fig_design.{svg,pdf}    design schematic (Section IV)
figures/fig_ladder.{svg,pdf}    DNP3 transaction ladder (Section II)
figures/fig_observation.{svg,pdf}   observation model (Section III)
FINAL_FIGURES.md                generated: one row per final figure, paths, hashes, references
FIGURE_PROVENANCE.md            silicon -> capture -> script -> figure, by hash
LIN_WRITING_GUIDANCE.md         Dr. Lin's guidance extracted from the 2026-08-19 meeting (evidence)
pipeline/DR_LIN_WRITING_GUIDE.md   the active writing guide (structure, voice, terminology, gates)
pipeline/lin_check.py           the manuscript gate
pipeline/build.sh               compile + gate
pipeline/make_final_figures.py  regenerates FINAL_FIGURES.md from the figures
pipeline/samples/lin_intro.txt  his introduction paragraphs, verbatim
pipeline/reports/               PRE_REWRITE_KNOWLEDGE, PRE_REWRITE_RECONCILIATION,
                                EVENT_SEMANTICS_TRUTH_TABLE, LIN_TEXT_CHANGELOG,
                                CLAIM_CITATION_MATRIX, FINAL_MANUSCRIPT_AUDIT
```

## Writing rules

`pipeline/DR_LIN_WRITING_GUIDE.md`. In short: the framework is the contribution and READ and
SELECT/OPERATE are case studies; the arms are Timing OFF and Obfuscated; the read path is anchored
to the relay acknowledgment (CLRT = D_R) and the control path to the request (echo − ACK = R − A);
no size claim, no system name, no firstness claim, no em dashes; every result number traces to
`defense4/timing/evidence/final_read_sbo/timing_stats.json`.

## Claim boundaries

`../../defense4/timing/CLAIMS_AND_LIMITATIONS.md`. Timing only, one SEL-751A, one session,
master-facing; size shaping active in both arms; relay-facing timing and exactly-once delivery
unobserved; configuration provenance PARTIAL.

## Regenerating the figures

```sh
cd ../../defense4/timing && TIMING_PYTHON=/usr/bin/python3 ./reproduce.sh
cp build/figures/fig0*.{pdf,png,caption.md,provenance.json} build/figures/fig0*_data.csv figures/publication/
cp build/figures/fig0*.{pdf,png} ../../paper/rewrite/figures/timing/
cd ../../paper/rewrite && python3 pipeline/make_final_figures.py     # refresh FINAL_FIGURES.md
```

Then refresh the hashes in `FIGURE_PROVENANCE.md`.

## Open items

Author block (marked `[AUTHOR BLOCK PENDING]` in `main.tex`), venue and page limit, and a
licence file: see `pipeline/reports/FINAL_MANUSCRIPT_AUDIT.md`.

# `paper/rewrite/` — the one active manuscript

Everything the timing-obfuscation paper is built from lives in this directory. There is one
entry point, `main.tex`; no other `.tex` file in the repository is a manuscript.

## Build

```sh
cd paper/rewrite
./pipeline/build.sh                 # tectonic compile -> pipeline/build/main.pdf, then the Lin gate
tectonic -X compile main.tex        # compile only, PDF lands beside main.tex
```

`build.sh` fails closed if the compile fails **or** the Lin-style gate (`pipeline/lin_check.py`)
fails; the scorecard is written to `pipeline/reports/` either way. Both `pipeline/build/` and
`pipeline/reports/` are outputs and are not tracked.

The final compiled manuscript is committed once as `main.pdf` beside this file.

## Layout

```
main.tex                        canonical entry point
introduction_pipeline_v1.tex    sections, in the order the structure contract fixes
background_pipeline_v1.tex
threatmodel_pipeline_v1.tex     defines RO1 (read timing), RO2 (control timing), RO3 (safety)
design_pipeline_v1.tex
evaluation_pipeline_v1.tex      FIGURE SCAFFOLD ONLY — places fig01–fig05 under RO1–RO3; no prose yet
library.bib                     bibliography (Zotero export, BetterBibTeX keys); resolves every citation
refs.bib                        legacy keys from the earlier draft lineage, kept for reference
figures/timing/                 THE FIVE FINAL FIGURES, vector PDF + PNG preview, nothing else
figures/fig_design.{svg,pdf}    design diagram used by the Design section
figures/fig_ladder.{svg,pdf}    DNP3 transaction ladder used by Background
figures/fig_observation.{svg,pdf}   observation model used by the Threat Model
FINAL_FIGURES.md                one row per final figure: paths, section, caption, source, inputs, hashes
FIGURE_PROVENANCE.md            silicon -> capture -> script -> figure, by hash and commit
LIN_STYLE_CONTRACT.md           the writing contract (voice, structure, threat model)
LIN_STYLE_PROFILE.md, LIN_WRITING_GUIDANCE.md, LIN_VS_PHILIP_DIFF.md   the contract's evidence base
WRITING_PIPELINE_AUDIT.md, WRITING_PIPELINE_REBUILD_PLAN.md, PIPELINE_AUDIT_VERDICT.md   pipeline record
TITLE_OPTIONS_2026-08-24.md     open decision: title and system name
pipeline/                       build.sh, lin_check.py (the gate), samples/, reprod/
```

## Writing rules

Every section is drafted and revised through the pipeline the contract describes:
draft → `security-paper-writing` (structure) → `paper-voice` → `academic-humanizer` →
`lin_check` gate (no regression) → `remove-ai-marks` Layer A. See `LIN_STYLE_CONTRACT.md`.

## What is not yet written

Abstract, Implementation, the Evaluation prose, Related Work and Conclusion. `main.tex` marks
each with a `TODO` comment. The Evaluation section currently contains only the five figure
floats so that every final figure is referenced from the manuscript.

## Claim boundaries for the text

The paper evaluates **timing only**: READ CLRT, the SELECT phase of SBO, master-visible
OPERATE timing, and transaction-class feature suppression, on one SEL-751 in one capture
session. Both experimental arms ran the same unified switch binary with the size-shaping
datapath active, so the baseline is called **Timing OFF**, never an unmodified native
baseline. Relay-facing timing and exactly-once delivery were not observed. No size,
segmentation, padding or splitting claim belongs in this manuscript. Full statement:
`../../defense4/timing/CLAIMS_AND_LIMITATIONS.md`.

## Regenerating the figures

The figures are produced by the timing evidence tree in this same repository:

```sh
cd ../../defense4/timing && ./reproduce.sh     # rebuilds fig01–fig05 from the raw captures
```

Copy the resulting `figures/publication/fig0*.{pdf,png}` into `figures/timing/` and refresh
the hashes in `FINAL_FIGURES.md` and `FIGURE_PROVENANCE.md`.

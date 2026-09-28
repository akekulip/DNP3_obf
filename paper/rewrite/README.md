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
checks the flattened manuscript against `References.bib` and the compiled PDF. The reviewed build is
committed once as `main.pdf` beside this file.

## Layout

```
main.tex                        entry point: title, author block, abstract, section inputs
sections/00_abstract.tex        the Abstract
sections/01_introduction.tex    the authors' Introduction, verbatim (citations only)
sections/02_background.tex      Background and Motivation
sections/03_threat_model.tex    Threat Model and Research Objectives (RO1, RO2, RO3)
sections/04_design.tex          Framework Design (the two release rules)
sections/05_implementation.tex  Tofino Implementation
sections/06_evaluation.tex      Evaluation, organised by RO1..RO3, with Limitations
sections/07_related_work.tex    Related Work (second-last)
sections/08_conclusion.tex      Conclusion
References.bib                  bibliography the manuscript builds from (49 entries, 40 cited)
library.bib                     Zotero export, reconciled into References.bib on 2026-09-19; not cited
corpus/                          local reference PDFs (ignored by Git) and style notes
archive/                         superseded paper drafts and figure exports; not build inputs
figures/ndss/                   seven campaign figures: vector PDF (authoritative),
                                600-dpi PNG preview, figure-data CSV, caption,
                                method and limitations notes, provenance sidecar
figures/fig_design.{svg,pdf}    design schematic (Section IV)
figures/fig_ladder.{svg,pdf}    DNP3 transaction ladder (Section II)
figures/fig_observation.{svg,pdf}   observation model (Section III)
figures/SCHEMATICS.sha256       hashes of the three schematics (svg, pdf, png)
FIGURE_PROVENANCE.md            historical final_read_sbo provenance; current provenance
                                lives in each figure's sidecar and campaign_v2/
main.pdf.sha256                 hash of the committed build, written with PDF_MANIFEST.json by
                                pipeline/publish_manuscript.py
pipeline/DR_LIN_WRITING_GUIDE.md   the active writing guide (structure, voice, terminology, gates)
pipeline/lin_check.py           the manuscript gate
pipeline/build.sh               compile + gate
pipeline/samples/lin_intro.txt  his introduction paragraphs, verbatim
pipeline/publish_manuscript.py  publishes main.pdf, its hash and PDF_MANIFEST.json together
pipeline/tests/                 tests for the venue page-budget rule
pipeline/reports/               EVENT_SEMANTICS_TRUTH_TABLE, LIN_TEXT_CHANGELOG,
                                CLAIM_CITATION_MATRIX, POST_MEETING_REVIEW_HANDOFF,
                                and the dated gate reports
```

## Writing rules

`pipeline/DR_LIN_WRITING_GUIDE.md`. In short: the framework is the contribution and READ and
SELECT/OPERATE are case studies; the arms are Timing OFF and Obfuscated; both lanes arm their
deadlines at the request, so the observable is the configured `CLRT_new` on both, and the notation
is fixed by `../../defense4/timing/NOTATION_MAPPING.md`; no size claim, no system name, no firstness
claim, no em dashes; every result number traces to `figures/ndss/MANUSCRIPT_VALUES.json`, which is
regenerated from the raw captures by `defense4/timing/evidence/campaign_v2/repro/reproduce.sh` and
is the only file the manuscript quotes from.

## Claim boundaries

`../../defense4/timing/CLAIMS_AND_LIMITATIONS.md`. Timing only, one SEL-751A, one Tofino-1, 22
grouped runs in one 5.3-hour campaign, master-facing; size shaping off in both arms; the realized
per-transaction `J`, relay-facing timing and exactly-once delivery unobserved; classification is of
transaction classes, not device models, and is scoped to the evaluated Random-Forest attacker; an
adaptive attacker stays above chance, and the residual tests associate timing information with
request spacing without isolating its cause; every block and sweep point has a control-plane readback.

## Regenerating the figures

Each figure family has one generator, and a figure is never edited by hand:

```sh
# campaign results (figures/ndss/) and MANUSCRIPT_VALUES.json
../../defense4/timing/evidence/campaign_v2/repro/reproduce.sh /tmp/cv2_out
../../defense4/timing/evidence/campaign_v2/repro/.venv/bin/python \
    ../../defense4/timing/evidence/campaign_v2/repro/publication_gate.py /tmp/cv2_out --update
# READ CLRT histograms (figures/clrt/)
$RESEARCH_PYTHON ../../defense4/timing/audit_current/tools/clrt_distribution_and_variance.py
# release tail (figures/tail/)
$RESEARCH_PYTHON ../../defense4/timing/evidence/campaign_v2/_bin/make_tail_figure.py
# release-timeline model (figures/model/)
$RESEARCH_PYTHON ../../defense4/timing/audit_current/tools/make_model_figures.py
# schematics: draw.io sources, then export
./pipeline/drawio/build.sh && ./pipeline/export_schematics.sh
# mechanism only, preserving the other schematic documents
./pipeline/drawio/build.sh --design && ./pipeline/export_schematics.sh --design
```

Each figure carries its own `.caption.md`, `.method.md`, `.limitations.md`, `_data.csv` and
`.provenance.json`, and each directory's `FIGURES.sha256` is checked by its generator's `--check`
mode (for the campaign figures, by the publication gate run without `--update`).

The evaluation includes two additional contrasts from the existing campaign:
`fig_replacement_evidence` compares measured READ timing with a median-aligned constant-shift
counterfactual and shows the paired-run variance ratios; `fig_residual_information` shows
within-arm binary classifier results for READ versus SELECT and for arrival-gap groups within
READ. The latter is an observational comparison, with held-out-run ranges rather than confidence
intervals. Neither adds an experiment or changes the underlying measurements.

The mechanism source `figures/fig_design.drawio` contains three pages. Only its `design` page
is exported into the manuscript; the observation and timeline pages are retained in the editable
document. The mechanism maps the campaign implementation's ingress decisions, two queue scheduling
domains and internal loopback to packet flow, without attributing the campaign to the later
seven-stage implementation. Its geometry and labels live in
`pipeline/drawio/fig_design.spec.yaml` (JSON-compatible YAML), rendered by
`gen_design_drawio.py` using the Python standard library. `fig_design_mapping.yaml` records the
corresponding P4 and control-plane source anchors. Regeneration preserves both other pages
byte-for-byte.

## Open items

The three flagged points in the verbatim Introduction, the NDSS template switch, and a licence
file: the gate reports under `pipeline/reports/` carry the current state.

## Archived paper files

Older PDF and architecture-figure exports live under `archive/` so the paper root contains only
the active manuscript and its published build. Local reference PDFs live under `corpus/`; they are
ignored by Git and are not publication artifacts.

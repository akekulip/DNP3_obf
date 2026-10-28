# Manuscript

`main.tex`, `sections/`, `tables/`, `References.bib`, `IEEEtran.cls` and the figures in
`figures/` are the manuscript inputs. The PDF figures and their available SVG/draw.io
originals were moved without changing their content. The manuscript's scientific text
and historical measurements were preserved; this repository cleanup does not update
them to describe the current switch implementation or new runs.

From the repository root:

```sh
RESEARCH_PYTHON=/home/philip/.venvs/research/bin/python ./paper/pipeline/build.sh
python3 paper/pipeline/publish_manuscript.py
python3 -m pytest -q paper/pipeline/tests
```

The build uses the installed offline Tectonic cache. It fails on a compile error, a hard
style/structure failure, or a changed protected paragraph. The original protected text
is `tests/fixtures/paper/lin_main_20261019.tex`.

All build outputs, including PDF, TeX log, flattened source, gate reports, hashes and
manifest, go to `results/paper/<UTC-build-id>/`. Set `PAPER_BUILD_ID` to choose the build
directory. `results/paper/latest.json` points to the latest successful build; it is not
a second PDF. The record checker detects changes to the manuscript, tables,
bibliography, class or included figures after a build.

`pipeline/export_schematics.sh --check` checks the two introductory SVG exports; without
`--check` it regenerates their PDF/PNG files. It requires Inkscape 1.x or later and writes
only to `paper/figures/`. The retained `.drawio` and `.svg` files are the editable
schematic originals. Procedural draw.io generators are archived: the old observation
generator did not reproduce its checked-in drawing, so it is not a current build step.

`pipeline/ndss_preflight.py [PDF]` is a separate venue diagnostic. The manuscript is not
currently a submission-ready anonymous NDSS document; those pre-existing failures do
not change the local manuscript build result. Four small template files remain under
`ndss/` for this diagnostic.

Old drafts, reviews, exported builds, reference material, unused figures and historical
campaign-dependent figure generators are in `Archive/paper/`. Supplied manual inputs
are in `Archive/manual_inputs/`. They are not needed to build the current manuscript.

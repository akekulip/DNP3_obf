# Model figures published into the manuscript

`fig_m01_release_timeline` is included by `sections/04_design.tex`. It is **not** copied here by
hand. `defense4/timing/audit_current/tools/make_model_figures.py` generates it into
`defense4/timing/figures/model/` and, in the same run, publishes it here and writes
`FIGURES.sha256`.

```
python3 defense4/timing/audit_current/tools/make_model_figures.py     # generate and publish
python3 defense4/timing/audit_current/tools/make_model_figures.py --check
```

`--check` recomputes the manifest, compares the published bytes against the generating tree, and
exits non-zero on any difference. The generating run performs the same check on itself and
refuses to finish quietly if it fails.

This exists because an earlier hand-copy drifted from its source in the provenance sidecar and
nothing detected it.

`FIGURES.sha256` gates the vector PDF, the figure-data CSV and the caption. It deliberately does
not gate the `.png` preview, whose Agg raster bytes vary with the interpreter build, or
`.provenance.json`, whose `source_commit` changes with every commit by design. Both are still
carried here so the published figure stands on its own.

`fig_m02_timeout_model` is a working diagram that the manuscript does not include, so it is not
published.

# Superseded campaign figures — archived, not deleted

These twelve files were `paper/rewrite/figures/campaign/` until 2026-09-07. The manuscript never
referenced them: `main.tex` and the section files include only the three root schematics and
`figures/ndss/`. They are the earlier campaign_v1 figure set, superseded by the five NDSS figures
that the manuscript now uses.

**They are archived rather than removed because most of them are the only copy of what they
show.** Compared against `evidence/campaign_v1/figures/`, which holds the generator's own
outputs:

| file | vs `evidence/campaign_v1/figures/` |
|---|---|
| `fig_c00_parameter_choice.pdf` | **differs** |
| `fig_c01_cross_session_stability.pdf` | **differs** |
| `fig_c02_clrt_ecdf.pdf` | **differs** |
| `fig_c05_leakage_session_disjoint.pdf` | **differs** |
| `fig_c07_overhead.pdf` | **differs** |
| `FIGURES.sha256` | **differs** |
| `MAIN_PDF.sha256` | **no counterpart** |
| `fig_c06_interval_summary.pdf` | identical |
| `fig_c08_operating_envelope.pdf` | identical |
| `fig_g1_offsets.pdf` | identical |
| `fig_g2_leakage.pdf` | identical |
| `fig_t02_confusion.pdf` | identical |

Seven of the twelve therefore cannot be recovered from the evidence tree, so calling the set
"duplicates" and deleting it would have destroyed content. Five are duplicates and are kept with
the rest so the set stays intact.

`MAIN_PDF.sha256` records `5dd9ea50e8fffbda1ef5f3e6a73765aea4693047a461b3a54c8bbd077870ee9a` for
`main.pdf`. The current `main.pdf` hashes to `796712b8…`, so that file records a **superseded**
build and is part of what makes this set historical.

Moved with `git mv`, so `git log --follow` reaches each file's original path.

## What replaced them

`paper/rewrite/figures/ndss/` — the five figures the manuscript includes, regenerated only by
`evidence/campaign_v1/repro/reproduce.sh` and gated by its publication gate. Nothing here is on
the reproduction path, and nothing here is rebuilt by any script.

## Related

* `defense4/timing/figures/publication/` — the five earlier `final_read_sbo` figures, also
  historical, and the originals of the ten files that were removed from
  `paper/rewrite/figures/timing/` on the same day as exact duplicates.
* `defense4/timing/figures/model/` and `defense4/timing/figures/shift/` — the DRAFT diagrams and
  the constant-shift evaluation added in September 2026. Not manuscript figures.

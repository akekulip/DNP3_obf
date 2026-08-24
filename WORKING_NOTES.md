# WORKING_NOTES.md — final timing-paper repository

Last updated 2026-08-24 (end of the manuscript consolidation session).

## Task

Reduce the research repository to a minimal, reproducible timing-only paper repository and
connect the five verified timing figures to one canonical manuscript. The experiment is
finished; no further hardware or size work.

## Status — COMPLETE, nothing pushed

- `/home/philip/Projects/DNP3` → `final/timing-paper-20260824` @ `b3adcfe` (97 files, 8 MB): `defense4/timing/` only. `reproduce.sh` → 102/102 tests.
- `/home/philip/Projects/DNP3-size-probe` → `final/manuscript-20260824` @ `b78c47d` (140 files): timing tree + `paper/rewrite/` (43 files). `paper/rewrite/main.tex` is the only manuscript entry point; `./pipeline/build.sh` compiles and runs the Lin gate on a flattened copy.
- Five final figures in `paper/rewrite/figures/timing/fig01…fig05.{pdf,png}`, all referenced by `evaluation_pipeline_v1.tex`; hashes and provenance in `FINAL_FIGURES.md` / `FIGURE_PROVENANCE.md`.
- Everything removed is in `/home/philip/Archives/DNP3_nonfinal_20260824/` (10,949 files, verified, untracked) and in `wip/size-probe-uncommitted-20260824` (9b9cb2c) / `wip/caseA-uncommitted-20260824` (348999e); four bundles under `~/Projects/*.bundle`.

## Open decisions (Philip's)

1. Lin gate `structure` FAIL: threat model comes after Background — reorder or not.
2. Evaluation section is a figure scaffold only; Abstract, Implementation, Evaluation prose, Related Work, Conclusion are TODO in `main.tex`.
3. No licence file exists.
4. Whether/when to push the `final/*` branches.

## Next action

Draft the remaining sections through the pipeline (draft → paper-voice → academic-humanizer → `lin_check` non-regression → remove-ai-marks). Keep the claim boundaries in `defense4/timing/CLAIMS_AND_LIMITATIONS.md`: arms are Timing OFF / Timing ON, never an unmodified native baseline; SELECT = SELECT phase of SBO; relay-facing T0+J and exactly-once unobserved; config provenance PARTIAL; no size claims.

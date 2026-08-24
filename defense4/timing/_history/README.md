# `_history/` — superseded timing-core development (archived 2026-08-24)

Everything in this directory is the **earlier Defense-4 timing-core development line**
(Case-A `defense4_caseA.p4`, bring-up probes, bootstrap compile probes, campaign specs,
policy analysis). It was moved here unchanged from `defense4/timing/<subdir>` by
`git mv` on the `cleanup/timing-read-sbo-20260824` branch.

**Path mapping is mechanical:** every former path `defense4/timing/X` is now
`defense4/timing/_history/X`. Nothing was renamed, edited, or deleted. Older documents
elsewhere in the repository (`RESUME_STATE.md`, `defense4/overninght.md`, `defense4/dir.md`,
`defense4/Defense4_Completion_Experiment_Prompts.md`) still cite the former paths; insert
`_history/` after `timing/` to resolve them.

## Why it was archived

No result in the frozen `E_FINAL` evidence package depends on any file here. That was
checked before moving: the E_FINAL `reproduce.sh` and all of its `scripts/*.py` reference
only paths inside `E_FINAL/`, and the loaded silicon program for the E-phase campaign was
`defense4_rrc_bor_unified12` (compiled from `defense4/size/native_parity/p4/`), not the
Case-A program archived here.

This material remains part of the scientific record — it documents how the timing core was
developed and which approaches failed — but it is **not** the active timing authority.
The active authority is the rest of `defense4/timing/`.

# WORKING NOTES

**Task:** CORRECTIONS.md release-hardening audit — COMPLETE and hardware-validated.

**Status:** Defense 3 is release-ready. Canonical `defense3/p4/case_a_defense3.p4` (R1/R2/R3
unconditional + the B/C fixes), validated on Tofino-1 9.13.2 (compile, assembly, Gate 2).
Switch on Defense 2; `main` clean. Provenance guarded by `defense3/MANIFEST.yaml` +
`analysis/verify_manifest.py`.

**Next action:** none required for release. Optional future experiments (not release gates)
are in `defense3/MANIFEST.yaml` open_items and `REPORT.md` §12. The detailed worklog for this
pass is archived at `archive/worklogs/WORKING_NOTES_release_hardening_20260731.md`. Current
state: `RESUME_STATE.md`.

# WORKING_NOTES.md — final timing-paper repository

Last updated 2026-08-26 (end of the manuscript rewrite session).

## Task

Complete the timing-only IEEE manuscript in Dr. Lin's structure from the verified timing
evidence, on one branch, with every claim bounded by `defense4/timing/CLAIMS_AND_LIMITATIONS.md`.
The experiment is finished; no hardware, size, or push actions.

## Status — manuscript complete to the evidence; branch pushed, draft PR open, not merged

- Branch `paper/final-timing-rewrite-20260826` (from `final/timing-paper-20260824` at `22db6e0`),
  single checkout `/home/philip/Projects/DNP3`. Commits: Phase 0 reports and audit; evidence
  corrections (truth table, manifest D_A/D_R, Obfuscated arm name); figure relabel; manuscript
  and gate; cleanup and archive; final build and audit.
- `paper/rewrite/main.tex` + `sections/00…08` build to a 10-page IEEEtran conference PDF; the
  gate (`pipeline/lin_check.py`, rewritten to the brief's check list) passes; all eight figures
  are in the body before References; every result number traces to `timing_stats.json`.
- Two release rules established from the source and the wire (`pipeline/reports/EVENT_SEMANTICS_TRUTH_TABLE.md`):
  read path anchored to the relay ACK (`t_A + D_A`, `t_A + D_A + D_R`; D_A = 20 ms, D_R = 4 ms;
  CLRT = D_R) and control path anchored to the request (`T0 + A`, `T0 + R`, OPERATE to relay at
  `T0 + J`; echo − ACK = R − A = 4 ms). The earlier Design draft had the read rule wrong.
- Arms are **Timing OFF / Obfuscated** everywhere (figures regenerated with that legend under
  Python 3.8.10 / matplotlib 3.7.5; data CSVs unchanged).
- Stale writing-pipeline documents, the old section drafts, `refs.bib`, the old `main.pdf` and
  the retired checker's demo inputs are in `/home/philip/Projects/DNP3-local-archive-20260826/`
  (hash-verified manifests) and in Git history (`git show e8382d0:<path>`).

## Open decisions (Philip's)

1. Author block supplied (Akekudaga, Lin; University of Rhode Island; uri.edu emails).
2. Venue: NDSS, 13-page limit (confirmed 2026-08-26); the build is 10 pages in the IEEEtran
   conference template, to be moved to the NDSS template at submission.
3. The Introduction is Philip's verbatim text (2026-08-26 evening). Flagged, not changed: "offsets
   from the request" (reads are ACK-anchored), the firstness claim, and "turning framework".
4. `paper/final-timing-rewrite-20260826` is pushed; a draft PR is open and not merged; `main` untouched.
5. No licence file exists.
6. `remove-ai-marks` (the global final-writing step) was not run: the brief for this session
   forbids watermark-removal and detector-evasion tools in this repository.

## Next action

Philip reviews the PDF (`paper/rewrite/main.pdf`) and the open decisions above; then supply the
author block, choose the venue, and decide on the push. Future validation of the evidence, if
ever authorised: a rerun with `shape_enable=0` and a relay-facing tap (`EVIDENCE_AUDIT.md` §9).

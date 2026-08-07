# ►► Introduction QUARANTINED (2026-08-07)

`INTRODUCTION_DRAFT.tex` and `INTRODUCTION_CLAIM_SOURCE_MATRIX.md` are quarantined. Do not revise,
integrate, or submit them.

Reason: the experimental evidence freeze they rest on
(`../timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md`) was **reopened and marked INVALID** after a
repository audit at commit `b0e1752`, confirmed by recomputation from the committed evidence:

- The Introduction's D4 evidence claim ("normalizes the measured response time from a variable native
  distribution to a fixed value") is **false as stated**: D4 is a mixture distribution, 160/240 held
  at the deadline and 80/240 (33%) bypassing at native timing.
- D2's non-shaping is framed in the supporting freeze as a boundary; it is actually an **open
  `tag_retire_if_unmarked` lifecycle defect** (the ACK release retires the transaction before the
  response is pending, so the response bypasses). The same defect causes the D4 bypass fraction.

The Introduction may be revised only after the next authorized run fixes the retirement defect,
regression-tests D2 and D4, recalibrates D4, completes the authorized negative testing, repairs the
scorer and manifest, re-runs the affected modes, and re-validates the freeze.

Do not merge this branch into `main`.

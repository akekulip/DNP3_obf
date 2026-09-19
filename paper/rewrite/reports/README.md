# Reports

Adversarial reviews and build scorecards for the manuscript.

## The reviews, rescued 2026-09-19

Three `ieee-journal-reviewer` passes were run against the **campaign_v1** manuscript on 2026-09-17
and 2026-09-18. All three existed only inside Claude session transcripts, which no backup covers
and which a context reset discards. They are the defect ledger for the campaign_v2 rewrite, so they
are committed here.

| file | pass | shape |
|---|---|---|
| `REVIEW_20260918.md` | the full venue review | Major Revision, NDSS score 2 (weak reject). 5 critical, 16 major, 12 minor, 7 questions for the authors |
| `REVIEW_20260918_EVAL_GAP.md` | evaluation-gap review | eight objections around one question: one classifier, one observation at a time, one policy setting, no baseline defense |
| `REVIEW_20260918_SELF_UNDERMINING.md` | prose review | sixteen findings on self-undermining prose, ordered by damage |

**They review the build that was replaced.** Some findings are answered by the request-anchored
build rather than by any edit — C2, where the framework made one observable *more* identifying than
before deployment, and the epsilon contradiction in C3. See
`defense4/timing/anchor_fix/FINDINGS.md`. The rest is written work.

`POST_MEETING_REVIEW_HANDOFF.md` is the earlier 2026-09-08 revision handoff and is historical.

`main_<UTC>.txt` / `.json` are `pipeline/build.sh` gate scorecards, one pair per build.

# WORKING NOTES — post-meeting revision

## Status: complete on the branch, pending push

Branch `paper/lin-post-meeting-revision-20260908`, cut from `fe42ada` on
`paper/campaign-v1-ndss-corrections-20260828`.

Full account: `paper/rewrite/pipeline/reports/POST_MEETING_REVIEW_HANDOFF.md`.

## Done
- Dr. Lin's Introduction paragraphs 1-3 installed verbatim; gated by
  `paper/rewrite/pipeline/check_lin_intro_verbatim.py` (PASS, word for word).
- Superseded paragraph 3 removed with its provenance established (`3b9a812`, `4e2d105`).
- Notation migrated: `D_R` is now the RESPONSE hold, `CLRT_target` is the configured gap.
  Bridge in `defense4/timing/NOTATION_MAPPING.md`. No archived field renamed.
- Design rebuilt: model, parameter choice, control anchor, boundary.
- Implementation rebuilt: queues before P4; the K x drain-time timer description corrected to
  the timestamp-deadline test the code actually uses.
- Evaluation reordered into the reader's questions, RO tags retained; histograms are now the
  primary spread view.
- Research: ACK delay (transport is not the binding constraint), response latency (no standard
  verifiable), release variability (UNAVAILABLE, needs external capture or a new binary).
- Writing guide updated with what the meeting superseded.
- Build PASS, publication gate 0 problems, 131/131 tests, 16 pages, no undefined references.

## Not done, and why
- `02_background.tex` and `03_threat_model.tex` untouched: they compile and do not contradict
  the new Design; a voice pass over them is outstanding.
- The release residual is still unmeasured; it needs hardware or a new binary, neither authorized.

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
  **SUPERSEDED 2026-09-09** by the follow-up below: `CLRT_target` is withdrawn and `D_R` is the
  response latency.
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

## Follow-up: the four CLRT corrections, 2026-09-09

Branch `paper/clrt-four-corrections-20260909`, cut from `24c52b4`.
Full account: `paper/rewrite/pipeline/reports/CLRT_FOUR_CORRECTIONS_HANDOFF.md`.

- Notation standardized on `CLRT_original` and `CLRT_new`, with configured/measured qualifiers.
  `CLRT_target` and `C_target` are withdrawn everywhere, including the figure generators.
- `D_R` corrected: it is now the response latency `m_R - t_R`, not the response hold. The hold is
  written from its endpoints, `e_R - t_R`, and has no symbol. `NOTATION_MAPPING.md` rewritten.
- The distribution figure is now four aligned histograms: 1 ms linear bins over the full range
  and 0.005 ms bins in the zoom, following Formby's Equation 1 and Figure 6(b), with n, mean,
  sample sd and sample variance annotated per panel.
- Blocker-queue drain time: endpoints verified against the P4 expiry and recirculation logic per
  lane (Q_ACK_BLOCK qid7 against `reg_deadline`, Q_RESP_BLOCK qid5 against `reg_tresp`). Still
  UNMEASURED for the loaded build. The one existing silicon measurement belongs to the Part-12
  predecessor program and bounds the interval between 14.4 ns and 1,734.5 ns without placing it;
  it stays out of the manuscript. Remaining dependency: a new P4 build with two execute sites.
- Build PASS, 131/131 tests, publication gate 0 problems, intro verbatim gate PASS.

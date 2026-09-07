# WORKING_NOTES.md — final timing-paper repository

Last updated 2026-09-07 (end of the audit, harness and rerun-package session).

## Task

Complete the timing-only manuscript in Dr. Lin's structure from the verified timing evidence, on
one branch, with every claim bounded by `defense4/timing/CLAIMS_AND_LIMITATIONS.md`. The
experiment is finished; no hardware, size, or push actions.

## Status — audit and rerun package complete; nothing pushed; manuscript unedited

Working on `paper/campaign-v1-ndss-corrections-20260828`, ahead of `origin/` by the commits of
2026-09-07, all from `0a3cbd8`. Nothing pushed. No manuscript section, figure or `main.pdf` was edited.

- **Repository.** The four paths the task specification names are one repository: `origin` of
  `/home/philip/Projects/DNP3` is `github.com/akekulip/DNP3_obf`, and `DNP3_obf`,
  `DNP3-size-probe` and `DNP3-timing-core` do not exist as directories. `BRANCH_MAP.md` is
  rebuilt from a fresh fetch; its three stale statements are corrected there. All five bundles
  verify. The archive tag and cleanup branch already existed and were not recreated.
- **Evidence.** Every published number holds. 18 of 18 interval statistics and both corpus
  counts re-derive from a from-scratch pcap and TCP parser; the full pipeline runs with 0
  validation problems, 131 tests and a clean publication gate, twice, byte-identical on all 14
  artefacts. The one 0.4 microsecond gap is an even-sample median convention, explained.
- **The timeout question is answered.** `TIMEOUT_AND_RETRANSMISSION_AUDIT.md`. The campaign
  driver's receive timeout is 3.0 s, not the frozen harnesses' 2.0 s; those contributed the
  frame builders only. Zero retransmissions, resets and duplicate acknowledgments in 63,360
  exchanges; worst acknowledgment wait 29.150 ms and worst request-to-response 77.713 ms against
  a 200 ms retransmission floor and a 3,000 ms application timeout; zero `NO_SELECT`. Two
  quantities were never recorded and stay unknown: the master's kernel RTO and the relay's
  select-validity window.
- **Terminology.** `TIMING_MODEL.md` separates the master-observed instants from the switch's
  own, defines the reported interval as `m_r - m_a`, gives the shift-versus-replacement algebra
  in both cases, and maps every symbol to the name the code already uses. Nothing was renamed.
- **Two corrections that matter.** The loaded binary arms only for the dual-deadline mode, so
  the sweep is 16 configured policies and three native controls, not 18 policies and one
  control, and no fixed-shift arm exists on this hardware. Both are in the proposed manuscript
  patch as P1 and P2, the only two unsupported statements found.
- **Harness.** `active_harness/`, corrected, frozen files untouched, 42 offline tests passing on
  Python 3.8 and 3.13, and the suite catches all six deliberate regressions it was checked
  against. Nothing has run live.
- **Figures.** Two DRAFT diagrams in `figures/model/`, deliberately not in the manuscript's
  figure set. Both rendered outputs were inspected and their label collisions fixed.
- **Manifest.** `CAMPAIGN_V1_CAPTURE_MANIFEST.csv`/`.json`, 132 rows, 73 columns, no field
  inferred from a filename, every configuration field carrying its evidence and status.
- **Provenance gap found.** Configuration readback is one summary line per block for 126 of 132
  captures; s01's six blocks have none. Provenance stays PARTIAL, now with a reason.
- **Gate table.** `audit_current/SESSION_20260907.md`, 47 rows: 31 pass, one historical FAIL
  that stays frozen, seven unresolved, one partial, seven not run.

## Next action

Two decisions, in this order, both the author's:

1. **Authorize or reject the manuscript patch** in `paper/rewrite/PROPOSED_PATCH_20260907.md`.
   Nine changes with exact replacement text. P1 and P2 fix statements the evidence does not
   support and should go in whatever else is deferred. P8 is last because it re-exports two
   figures and recompiles `main.pdf`.
2. **Authorize or reject the hardware rerun** in `defense4/timing/TIMING_ONLY_RERUN_PLAN.md`.
   Approving it means lifting this repository's no-experimentation rule for it, reconfiguring
   the traffic manager per block, and sending physical READ, SELECT and OPERATE traffic to the
   SEL-751A on isolated points {1, 3}. Nothing in it has been run.

Still open from before, and not decided this session: whether to push the branch, and the HotCRP
paper number in `paper/rewrite/ndss/submission.tex`, which is empty and must not be invented.

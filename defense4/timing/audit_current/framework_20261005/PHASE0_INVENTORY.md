# Phase 0 inventory — framework track, 2026-10-06

Assignment: `Codex_Implementation_and_Experiment_Prompt_2026-10-05.txt` (given by Philip).
Scope change recorded: that file supersedes the 2026-09-29 "READ response-ready only; no BMv2, size work or
experiments" restriction for this new working track. The frozen evidence, live-operation guards, the {1,3}
point allowlist and the attended-OPERATE rule are unchanged. Historical claims are unchanged.

## Base and provenance

| item | value |
|---|---|
| remote `origin/main` (checked 2026-10-06) | `f8be278eb` — equals the SHA in the assignment; single head |
| local branch at start | `optimize/timing-only-eight-stages` @ `817355077`; `origin/main` is its ancestor, 117 local commits ahead, 0 behind |
| review branch | `codex/framework-implementation-20261005`, created in place (untracked work could not move to a worktree) |
| baseline commit | `e8cc2d148` — response_ready candidate, compiler `out/` trees excluded (SDK artifacts) |
| archive revisions | `ef82faed3` (pre-final-timing-prune) and `9ffa9102d` resolve locally as commits |
| AGENTS.md | none in the repository; `CLAUDE.md` is the instruction file |
| commit identity | `akekulip <akekulip@gmail.com>`, no co-author trailer (repository rule) |

## What exists locally that the remote does not have

`defense4/timing/response_ready/` and `defense4/timing/evidence/campaign_v2/` are both present on the lab
machine. The assignment's "unverified handover assertions" about them are therefore checkable, not missing.
Not yet re-derived this session: the 32-build history, the 8.005 ms figure, the classifier numbers.

## Candidate baseline (response_ready)

- Source `src/defense4_response_ready.p4`, sha256 `cedded03dfbf80dec671f73cf51767a608ae9a91bda71d7e528d7ab4e5498e79 (was ceececa3… until 2026-10-06)`.
- `python3 -B -m unittest discover -s defense4/timing/response_ready/tests`: **46 tests OK** (run this session).
- The "4/7 release failures, 1 failure + 2 errors recovery" in the handover are the committed *RED* logs
  (`evidence/red_p4_release.log`, `red_p4_recovery.log`, 2026-09-29), written before the implementation as the
  test-first record. They are not current failures.
- 2026-10-05 change (nine `tbl_decide_deq` rows to a timeout note, plus a parity-test exemption) was
  reviewed by `code-reviewer` on 2026-10-06 and **reverted**. The returning note was not dropped by the
  parser path any more, so in MODE_OFF and MODE_FAIL_OPEN with `read_release=1` it re-enqueued as
  `OUT_*_TMO` on every pass (reproduced at table level; D4_DUAL terminated after one pass). That breaks the
  finite-watchdog requirement. Fix, test first: `test_timeout_note_terminates_in_every_mode`
  (multi-pass, both lanes, three modes) failed on the 2026-10-05 source, passes on the restored drop path.
  The unused `finish_path_2` action was also deleted (the "every fused action exercised" gate rejects an
  orphan). `test_commit_parity` now carries a narrower exemption that also asserts the inline
  `owner_release` that replaces the note. Only four of the nine rows ever changed behaviour.
  Source sha256 is now `cedded03dfbf80dec671f73cf51767a608ae9a91bda71d7e528d7ab4e5498e79`.
- Residual from the same review: in MODE_OFF / MODE_FAIL_OPEN a timeout drop leaves the owner armed
  (build 22 behaved the same). Not reachable under `control.py`, which always sets D4_DUAL.
- Compile of the *current* source: SDE 9.13.1 `evidence/local_build_34` — 7 ingress / 0 egress, 88 tables,
  `verify_build.py` passes. Builds 32 and 33 and `sde_9_13_2_build_01` are of earlier sources and are
  correctly rejected as stale. **SDE 9.13.2 rebuild on the switch host is still to do.**

## Offline regression baseline (run this session)

| suite | result |
|---|---|
| `active_harness/tests` | 58 OK |
| `active_control/tests` | 98 OK |
| `active_probe/tests` | 39 OK |
| `response_ready/tests` | 46 OK |

Total for the three assignment suites: 195, matching the assignment's count.

## Not done in Phase 0 yet

- campaign_v1 reproduction in its pinned environment into a new build directory, with manifest, independent
  extractor, statistics and publication comparison.
- 2026-09-29 authorization: the only written record is the `CLAUDE.md` paragraph and the candidate README; no separate file exists.
- The implementation/evidence matrix (assignment 0.4); its rows are in `STATUS_MATRIX.md` beside this file.
- Reading the full authority list and the chronological handovers.

## Current lab state (from WORKING_NOTES, 2026-10-05; not re-verified today)

Loaded switch program is `rrc_bor_build_v2` (pre-test state to restore). The candidate is not loaded. No
hardware traffic since the rack move. Relay SFP must sit in E1/33. ION 7550 is off. Vision isolation applied.
Re-read live state before any hardware step; never infer it from this note.

# Phase 0 inventory — framework track, 2026-10-06

*Status of the whole track is in `STATUS.md`. This file records the start-of-track inventory; the source hash below was superseded (`df599101…` now) after hardware found two over-capacity tables.*

Assignment: `Codex_Implementation_and_Experiment_Prompt_2026-10-05.txt` (given by Philip).
Scope change recorded: that file supersedes the 2026-09-29 "READ response-ready only; no BMv2, size work or
experiments" restriction for this new working track. The frozen evidence, live-operation guards, the {1,3}
point allowlist and the attended-OPERATE rule are unchanged. Historical claims are unchanged.

## Base and provenance

| item | value |
|---|---|
| remote `origin/main` (checked 2026-10-06) | `f8be278eb` — equals the SHA in the assignment; single head |
| local branch at start | `optimize/timing-only-eight-stages` @ `817355077`; `origin/main` is its ancestor, 117 local commits ahead, 0 behind |
| review branch | `codex/framework-implementation-20261005`, created in place (untracked work could not move to a worktree); merged to `main` by PR #6 (`20eef2019`) |
| baseline commit | `e8cc2d148` — response_ready candidate, compiler `out/` trees excluded (SDK artifacts) |
| archive revisions | `ef82faed3` (pre-final-timing-prune) and `9ffa9102d` resolve locally as commits |
| AGENTS.md | none in the repository; `CLAUDE.md` is the instruction file |
| commit identity | `akekulip <akekulip@gmail.com>`, no co-author trailer (repository rule) |

## What exists locally that the remote does not have

`defense4/timing/response_ready/` and `defense4/timing/evidence/campaign_v2/` are both present on the lab
machine. The assignment's "unverified handover assertions" about them are therefore checkable, not missing.
Not yet re-derived this session: the 32-build history, the 8.005 ms figure, the classifier numbers.

## Candidate baseline (response_ready)

- Source `src/defense4_response_ready.p4`, sha256 `6387c588b5019ee473153bb89e572cd1bbf326daa00d3b4a514c831e6798778e` (was `cedded03…` before the Case 2 rows, `ceececa3…` before 2026-10-06).
- `python3 -B -m unittest discover -s defense4/timing/response_ready/tests`: **47 tests OK** (run this session).
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
- Compile of the *current* source: SDE 9.13.1 `evidence/local_build_35` (build 34 was the source before the Case 2 rows) — 7 ingress / 0 egress, 88 tables,
  `verify_build.py` passes. Builds 32 and 33 and `sde_9_13_2_build_01` are of earlier sources and are
  correctly rejected as stale. **SDE 9.13.2 rebuild on the switch host is still to do.**

## Offline regression baseline (run this session)

| suite | result |
|---|---|
| `active_harness/tests` | 58 OK |
| `active_control/tests` | 98 OK |
| `active_probe/tests` | 39 OK |
| `response_ready/tests` | 47 OK |

Total for the three assignment suites: 195, matching the assignment's count.

## campaign_v2 reproduction (run 2026-10-06, pinned env: Python 3.13.12, numpy 2.3.5, scikit-learn 1.7.2)

The pinned repro is `evidence/campaign_v2/repro/reproduce.sh`; `campaign_v1` has no standalone entry point.
Output went to `defense4/timing/framework/build/repro_20261006/` (untracked). Results:
- 22 dataset manifests verified, 264 entries, 0 problems; 132 captures, 63,360 exchanges; 26 sweep points
  (9,360 transactions) verified against 54 manifest entries, 0 problems.
- Obfuscated median CLRT 8.005 ms for READ and SELECT, 8.000 ms for OPERATE (matches the handover's "8.005 ms").
- Step 8 (publication gate) reports 21 problems. All 21 are path-only: for all seven figures the input, PDF and
  data-CSV SHA-256 values equal the published ones; only the recorded output directory differs because a
  non-default out dir was used. No golden file was updated. Frozen and tracked evidence paths are unmodified.

## Not done in Phase 0 yet

- 2026-09-29 authorization: the only written record is the `CLAUDE.md` paragraph and the candidate README; no separate file exists.
- The implementation/evidence matrix (assignment 0.4); its rows are in `STATUS_MATRIX.md` beside this file.
- Reading the full authority list and the chronological handovers.

## Current lab state (from WORKING_NOTES, 2026-10-05; not re-verified today)

Loaded switch program is `rrc_bor_build_v2` (pre-test state to restore). The candidate is not loaded. No
hardware traffic since the rack move. Relay SFP must sit in E1/33. ION 7550 is off. Vision isolation applied.
Re-read live state before any hardware step; never infer it from this note.

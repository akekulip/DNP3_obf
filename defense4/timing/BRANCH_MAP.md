# Branch map

One repository, `https://github.com/akekulip/DNP3_obf`, default branch `main`. Verified
2026-08-24 after `git fetch --all --prune`. No branch was deleted, renamed, or force-pushed
by this cleanup, and nothing has been pushed.

## A note on the local layout

On this machine the repository lives at `/home/philip/Projects/DNP3`, and
`/home/philip/Projects/DNP3-size-probe`, `/home/philip/Projects/DNP3-timing-core` and
`/home/philip/Projects/DNP3-timing-cleanup` are **git worktrees of that same repository**,
not separate repositories. All four share one object store and one remote. The manuscript
under `paper/` and the implementation under `defense4/` are therefore in the same repository
on different branches, not in two repositories.

## Branches

| branch | tip | last commit | ahead of `main` | what it is |
|---|---|---|---|---|
| `main` | `883d8cd` | 2026-08-06 | — | **Stale relative to the physical final evidence.** Predates the 2026-08-13 hardware campaign entirely. Nothing in the timing result is on it. |
| `defense4-timing-core` | `3aa945e` | 2026-08-11 | 90 | Earlier timing-core development: Case-A program, bring-up, control plane. Superseded by the unified program; archived in this branch under `defense4/timing/_history/`. |
| `defense4-caseA-hw-integration` | `796b41b` | 2026-08-12 | 88 | Case-A hardware integration line. Local tip is ahead of `origin/…` (`7c4a5a7`) with unpushed work. |
| `defense4-size-read-range-probe` | `31b630f` | 2026-08-11 | 97 | Historical size research. |
| `defense4-size-transport-kernel-repair` | `979426f` | 2026-08-12 | 104 | Historical size research: transport-ledger repair. |
| `defense4-size-readsbo-normalizer` | `0b6fdba` | 2026-08-12 | 113 | Historical size research: padnorm kernel; records the multi-boundary wall. |
| `defense4-size-native-parity-crc-split` | remote `8a6896e`, local `02923cb` | 2026-08-14 | 211 | **The frozen authoritative source branch for the 2026-08-13 evidence.** See below. |
| `defense4-real-size-normalization` | `d06ca8b` | 2026-08-18 | 240 | Later size work, descends from `8a6896e`. Checked out at `/home/philip/Projects/DNP3-size-probe`. |
| `cleanup/timing-read-sbo-20260824` | `0da6f00` | 2026-08-24 | 204 | **This branch.** The proposed timing-only active branch. Local only, never pushed. |
| `origin/fixed-transcript-experiments` | `901c120` | 2026-08-11 | — | Remote-only, no local checkout. |

## The authoritative evidence branch, and a divergence to know about

`origin/defense4-size-native-parity-crc-split` is at `8a6896e`, which is exactly the tip the
audit expected. It has not moved.

The **local** branch of the same name is at `02923cb`, ten commits ahead and unpushed. All
ten are manuscript work under `paper/` — a reader-first NDSS rewrite, target-paper extracts,
and a bibliography. A path-limited diff confirms they touch nothing outside `paper/`: the
`defense4/` tree is byte-identical between `8a6896e` and `02923cb`.

This cleanup branch forks from **`8a6896e`**, the verified evidence tip, so it carries no
manuscript commit. The ten unpushed paper commits are preserved by the tag
`archive/defense4-local-unpushed-paper-20260824` and cannot be orphaned.

## Safety artifacts created by this cleanup

| artifact | points at | purpose |
|---|---|---|
| `archive/defense4-full-before-timing-cleanup-20260824` | `8a6896e` | annotated tag on the verified evidence tip |
| `archive/defense4-local-unpushed-paper-20260824` | `02923cb` | protects the ten unpushed manuscript commits |
| `/home/philip/Projects/DNP3_obf-before-timing-cleanup-20260824.bundle` | all refs | full bundle, 108 MB, verified "records a complete history"; sha256 `70bad1361f6fd9872d94bab00b74ecfbad56e988e75abccf65918eb6b6610d9f` |

Everything excluded from the active timing tree remains recoverable through the original
remote branch, these two tags, the bundle, and ordinary git history.

## Not done

Nothing has been pushed. `main` is untouched, the default branch is unchanged, and no remote
branch was deleted. Pushing `cleanup/timing-read-sbo-20260824` — and only that branch —
awaits explicit authorisation.

## 2026-08-26 addendum

* `final/timing-paper-20260824` (`22db6e0`) became the base of `paper/final-timing-rewrite-20260826`,
  the branch that carries the completed manuscript. Local only; nothing pushed.
* The worktrees named above no longer exist; `/home/philip/Projects/DNP3` is the single checkout
  (root `REPOSITORY_AUDIT.md`).
* Bundle `/home/philip/Projects/DNP3-before-final-paper-rewrite-20260826.bundle`, sha256
  `c2749c0d6245b335c436dd8933d8f994102319ae8c20e58c7b5fc476206990b9`, records every ref before
  the rewrite began.

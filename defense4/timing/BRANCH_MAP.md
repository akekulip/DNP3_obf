# Branch map

One repository, `https://github.com/akekulip/DNP3_obf`, default branch `main`. **Verified
2026-09-07** after `git fetch --all --prune`, with no pull, merge or rebase. No branch has been
deleted, renamed or force-pushed, and no history has been rewritten.

The previous version of this file described the state of 2026-08-24. Three of its statements
have since stopped being true and are corrected below rather than left standing: the local
worktree layout, the tip of the cleanup branch, and the claim that nothing had been pushed.

## The local layout, as it actually is

```
/home/philip/Projects/DNP3                                                   main checkout, on
                                                                             paper/campaign-v1-ndss-corrections-20260828
/home/philip/Projects/DNP3-worktrees/campaign-v1-ndss-corrections-20260828   detached at ceb5bea, inert
```

That is the whole of it. `git rev-parse --git-common-dir` returns `.git` in the main checkout,
so there is one object store.

**The paths the task specification names do not exist.** `/home/philip/Projects/DNP3_obf` is the
remote repository's name, not a directory; `/home/philip/Projects/DNP3-size-probe` and
`/home/philip/Projects/DNP3-timing-core` were worktrees of this same repository and have been
removed. The bundles record that they once existed: `DNP3_obf-before-timing-cleanup-20260824.bundle`
lists `worktrees/DNP3-timing-core/HEAD` and `worktrees/DNP3-size-probe/HEAD`, and
`DNP3-after-timing-cleanup-20260824.bundle` also lists `worktrees/DNP3-paper-timing-figures/HEAD`
and `worktrees/DNP3-timing-cleanup/HEAD`. So the implementation, the evidence and the manuscript
are in **one** repository, not two or four, and there is no separate paper repository to copy
figures into.

## Local branches

Ahead counts are commits reachable from the branch but not from `main`.

| branch | tip | date | ahead of `main` | remote state | what it is |
|---|---|---|---|---|---|
| `paper/campaign-v1-ndss-corrections-20260828` | `b3bf07c` | 2026-09-07 | 263 | tracks `origin/…` at `0a3cbd8`, **6 ahead** | **The current branch.** The campaign_v1 correction line, plus this session's audit, harness, figure, manifest and rerun-plan commits. The six local commits are not pushed. |
| `paper/final-timing-rewrite-20260826` | `7eb8887` | 2026-08-28 | 234 | in sync with `origin/…` | The 22-session campaign and the first NDSS-form manuscript. **Pushed.** |
| `paper/timing-figures-20260824` | `0095923` | 2026-08-24 | 241 | local only | Timing figures T1 to T4, taken from `2ea2daf`. |
| `final/timing-paper-20260824` | `22db6e0` | 2026-08-24 | 222 | local only | The merged final timing plus manuscript branch of 2026-08-24. |
| `final/manuscript-20260824` | `860efc1` | 2026-08-24 | 217 | local only | The manuscript side of that merge. |
| `cleanup/timing-read-sbo-20260824` | `2ea2daf` | 2026-08-24 | 208 | local only | The timing-only cleanup branch. **Its tip is `2ea2daf`, not the `0da6f00` this file used to record.** |
| `defense4-size-native-parity-crc-split` | `02923cb` | 2026-08-14 | 211 | tracks `origin/…` at `8a6896e`, **10 ahead** | The frozen authoritative source branch for the 2026-08-13 evidence. See below. |
| `defense4-real-size-normalization` | `d06ca8b` | 2026-08-18 | 240 | local only | Later size work, descends from `8a6896e`. Its former checkout at `DNP3-size-probe` is gone. |
| `defense4-size-readsbo-normalizer` | `0b6fdba` | 2026-08-12 | 113 | in sync | Historical size research: the padnorm kernel and the multi-boundary wall. |
| `defense4-size-transport-kernel-repair` | `979426f` | 2026-08-12 | 104 | in sync | Historical size research: transport-ledger repair. |
| `defense4-size-read-range-probe` | `31b630f` | 2026-08-11 | 97 | in sync | Historical size research. |
| `defense4-timing-core` | `3aa945e` | 2026-08-11 | 90 | in sync | Earlier timing-core development, superseded by the unified program. |
| `defense4-caseA-hw-integration` | `796b41b` | 2026-08-12 | 88 | `origin/…` is at `7c4a5a7`; local is ahead and untracked | Case-A hardware integration, with unpushed work. |
| `wip/size-probe-uncommitted-20260824` | `9b9cb2c` | 2026-08-24 | 241 | local only | Preserves every uncommitted file from the `DNP3-size-probe` checkout before it was reorganised. **Do not delete: this is the only committed copy of that work.** |
| `wip/caseA-uncommitted-20260824` | `348999e` | 2026-08-24 | 89 | local only | The same, for the main checkout before it moved to the final timing branch. |
| `main` | `883d8cd` | 2026-08-06 | 0 | in sync | **Stale relative to the evidence.** Predates the 2026-08-13 campaign and the 2026-08-27 campaign_v1 entirely. Nothing in the timing result is on it. |

`main` is at `883d8cd5d83eb283aac905d8398e0c5f97d219a7`, which matches the value the task
specification quotes.

## Remote branches

| ref | tip | note |
|---|---|---|
| `origin/main` | `883d8cd` | default branch |
| `origin/paper/campaign-v1-ndss-corrections-20260828` | `0a3cbd8` | 6 behind the local branch |
| `origin/paper/final-timing-rewrite-20260826` | `7eb8887` | current |
| `origin/defense4-size-native-parity-crc-split` | `8a6896e` | the frozen evidence tip |
| `origin/defense4-timing-core` | `3aa945e` | current |
| `origin/defense4-size-read-range-probe` | `31b630f` | current |
| `origin/defense4-size-readsbo-normalizer` | `0b6fdba` | current |
| `origin/defense4-size-transport-kernel-repair` | `979426f` | current |
| `origin/defense4-caseA-hw-integration` | `7c4a5a7` | behind its local branch |
| `origin/fixed-transcript-experiments` | `901c120` | remote only, no local checkout |

Two branches have been pushed since this file was last written, so its statement that "nothing
has been pushed" no longer holds: `paper/final-timing-rewrite-20260826` and
`paper/campaign-v1-ndss-corrections-20260828`. Nothing has been pushed **by this session**.

## The authoritative evidence branch, and its divergence

`origin/defense4-size-native-parity-crc-split` is at `8a6896e`, exactly the tip the task
specification names, and it has not moved. The local branch of the same name is at `02923cb`,
ten commits ahead and unpushed.

All ten are manuscript work under `paper/`. Re-verified 2026-09-07: `git diff 8a6896e 02923cb --
defense4/` is **empty**, so the `defense4/` tree is byte-identical between the frozen tip and
the local tip. The divergence cannot affect any evidence or implementation artefact.

The four frozen harness files in `implementation/harness/` were also compared against their
versions at `8a6896e` and are byte-identical, at both paths that commit carries them under
(`TIMEOUT_AND_RETRANSMISSION_AUDIT.md` §1).

## Tags

| tag | commit | date | what it preserves |
|---|---|---|---|
| `archive/defense4-full-before-timing-cleanup-20260824` | `8a6896e` | 2026-08-14 | the full pre-cleanup tree, including both `E_FINAL` copies and the whole size line |
| `archive/defense4-local-unpushed-paper-20260824` | `02923cb` | 2026-08-14 | the ten unpushed manuscript commits |
| `archive/pre-final-timing-prune-20260824` | `2ea2daf` | 2026-08-24 | the tree before the allowlist prune |
| `checkpoint/timing-read-sbo-20260824` | `2ea2daf` | 2026-08-24 | the same commit, as a checkpoint |
| `checkpoint/paper-timing-figures-20260824` | `0095923` | 2026-08-24 | the timing figures checkpoint |
| `timing-final-meeting-v1` | `9cdcf18` | 2026-07-25 | the meeting deliverable |
| `queue-trace-level1-hw-pass` | `43b3ed0` | 2026-07-23 | queue-trace level 1 hardware pass |
| `d1-telem-v1-verified` | `8077c40` | 2026-07-22 | Defense-1 telemetry |
| `d2-telem-v1-verified` | `49c1b0b` | 2026-07-22 | Defense-2 telemetry |
| `ack-delay-caseA-c3-pass` | `bf4acdf` | 2026-07-20 | the Case-A ACK-delay pass |

No tag was created, moved or deleted by this session.

## Bundles

Five, all outside the working tree at `/home/philip/Projects/`, all verified 2026-09-07 with
`git bundle verify`; each reports **"The bundle records a complete history."**

| bundle | bytes | dated |
|---|---|---|
| `DNP3_obf-before-timing-cleanup-20260824.bundle` | 112,292,049 | 2026-08-24 |
| `DNP3-after-timing-cleanup-20260824.bundle` | 114,473,247 | 2026-08-24 |
| `DNP3-before-final-timing-prune-20260824.bundle` | 113,319,900 | 2026-08-24 |
| `DNP3-before-final-manuscript-20260824.bundle` | 120,650,020 | 2026-08-24 |
| `DNP3-before-final-paper-rewrite-20260826.bundle` | 123,654,562 | 2026-08-26 |

The first is the path the task specification asks to create. It already existed, it verifies,
and it was **not** overwritten. A bundle does not carry uncommitted files, Git LFS payloads or
external dependencies; the uncommitted work of 2026-08-24 is preserved instead on the two
`wip/…` branches above, and one untracked file is present in the working tree today, a
reference PDF, which is deliberately not committed.

## How to recover the size line

Its code and evidence are not on the current branch. Any of these reaches them:

```sh
git switch --detach archive/defense4-full-before-timing-cleanup-20260824   # the full tree
git switch defense4-size-native-parity-crc-split                           # the source branch
git show 8a6896e:defense4/size/native_parity/evidence/E_FINAL/README.md    # one file
git clone /home/philip/Projects/DNP3_obf-before-timing-cleanup-20260824.bundle recovered
```

At the archive tag, `defense4/size/native_parity/evidence/E_FINAL` and
`defense4/defense4_release/evidence/E_FINAL` resolve to the identical tree object
`1d1a5f3c94cf8d34c1b390baa1c921e47cdbc79c`, which is byte-identical content by construction, so
the two are redundant copies of one dataset (`audit_current/REPOSITORY_AUDIT.md` §4).

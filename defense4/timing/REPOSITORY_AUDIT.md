> **Historical.** A dated record of work that preceded the campaign_v1 correction of
> 2026-08-28. Where it names evidence, figures or claims as current, read it as describing
> the `final_read_sbo` state of that date. The active evidence authority is
> `defense4/timing/evidence/campaign_v1/`, the active claim authority is
> `defense4/timing/CLAIMS_AND_LIMITATIONS.md`, and the active figures are
> `paper/rewrite/figures/ndss/`. Kept for provenance.
>
> **The worktree layout it records is also historical.** The auxiliary worktrees named
> below (`DNP3-size-probe`, `DNP3-timing-core`, `DNP3-timing-cleanup`) existed on
> 2026-08-24 and were removed; only `/home/philip/Projects/DNP3` and one detached
> worktree remain. There is no separate paper repository. Current state:
> `defense4/timing/BRANCH_MAP.md`, verified 2026-09-07.

# Repository audit — 2026-08-24

State of the repository before the timing cleanup, and the safety steps taken before
anything was moved.

## Repository identity, and a correction to the brief

The task named `/home/philip/Projects/DNP3_obf` as the implementation repository and
`/home/philip/Projects/DNP3-size-probe` as a separate manuscript repository. On this machine
that is not the layout.

`/home/philip/Projects/DNP3_obf` does not exist. The repository whose remote is
`https://github.com/akekulip/DNP3_obf.git` lives at `/home/philip/Projects/DNP3`, and
`DNP3-size-probe` and `DNP3-timing-core` are **worktrees of it**, sharing one object store
and one remote:

```
/home/philip/Projects/DNP3                 796b41b [defense4-caseA-hw-integration]
/home/philip/Projects/DNP3-size-probe      d06ca8b [defense4-real-size-normalization]
/home/philip/Projects/DNP3-timing-core     3aa945e [defense4-timing-core]
/home/philip/Projects/DNP3-timing-cleanup  0da6f00 [cleanup/timing-read-sbo-20260824]   (added by this cleanup)
```

Code, evidence and manuscript are one repository on different branches. The audit proceeded
on that basis. The practical consequence for Phase 7 is that the manuscript handoff is a
branch in the same repository rather than a copy into a second one.

## State recorded before any change

`git fetch --all --prune` was run; no pull, merge or rebase. Expected values were checked
rather than assumed:

| item | expected | found |
|---|---|---|
| default branch | `main` | `main` |
| `origin/main` | `883d8cd5…` | `883d8cd5…` — matches |
| authoritative evidence branch tip | `8a6896e…` | `origin/…` is `8a6896e…` — matches, has not moved |
| commits ahead of `main` | 201 | 211 for the local branch, **204** for `8a6896e` itself |
| E_FINAL frozen by | `5a0fb73` | `5a0fb73` exists (2026-08-13 21:21:39 −0400); E_FINAL itself was introduced by `fc20528` and `5a0fb73` froze the surrounding campaign evidence |
| experiment source sha256 | `7ce30494…c55e861` | matches the blob at commit `c1871384`, **not** the copy at the branch tip |
| loaded binary sha256 | `33fa3a77…` | recorded in the E0 record and the build summary |

Local branch tips ahead of their remotes, all preserved:

* `defense4-size-native-parity-crc-split` — local `02923cb`, ten unpushed manuscript commits
  above `origin`'s `8a6896e`; `defense4/` identical between the two.
* `defense4-caseA-hw-integration` — local `796b41b` ahead of `origin`'s `7c4a5a7`.
* `defense4-real-size-normalization` — local only, `d06ca8b`.

Uncommitted work existed in two worktrees at audit time and was left untouched: the main
worktree had six modified files and five untracked paths; the `DNP3-size-probe` worktree had
four modified files and about thirty untracked paths, mostly manuscript drafts. The cleanup
was done in a **new worktree**, so nothing in either was disturbed.

## Safety artifacts, created before the first modification

1. **Bundle** — `/home/philip/Projects/DNP3_obf-before-timing-cleanup-20260824.bundle`,
   108 MB, created with `git bundle create --all`, verified by `git bundle verify`: "The
   bundle records a complete history." sha256
   `70bad1361f6fd9872d94bab00b74ecfbad56e988e75abccf65918eb6b6610d9f`.
2. **Tag** `archive/defense4-full-before-timing-cleanup-20260824` → `8a6896e`.
3. **Tag** `archive/defense4-local-unpushed-paper-20260824` → `02923cb`, so the ten unpushed
   manuscript commits cannot be orphaned by forking the cleanup branch from `8a6896e`.
4. **Worktree** `/home/philip/Projects/DNP3-timing-cleanup` on a new branch
   `cleanup/timing-read-sbo-20260824`, forked from the verified tip `8a6896e`.

None of the forbidden operations was used: no hard reset, no `git clean`, no checkout-discard
of a path, no force push, no interactive rebase, no remote branch deletion, no recursive
delete. Nothing has been pushed.

## The duplicate E_FINAL

`defense4/size/native_parity/evidence/E_FINAL` and
`defense4/defense4_release/evidence/E_FINAL` resolve to the **same git tree object**,
`1d1a5f3c94cf8d34c1b390baa1c921e47cdbc79c`. That is stronger than a file-by-file comparison:
one tree, therefore byte-identical recursively. The `native_parity` copy is the original
(`fc20528`, 2026-08-13); the release copy was made a day later by `8a6896e`.

Both are left in place on this branch. The active timing tree holds its own selected copy of
the timing subset, so no third duplicate of the full package was created.

## What was found in the evidence

Full account in `evidence/final_read_sbo/audit/EVIDENCE_AUDIT.md`. The four findings that
change what can be claimed:

1. **`shape_enable` was 1 during every timing capture**, native and defended alike, proved
   from the wire rather than from a log. Size shaping is a held constant across arms, not a
   difference between them, and the reported native CLRT is measured through the shaping
   datapath.
2. **`e1_native_size_shapeoff.pcap` is not a native-timing capture.** Its CLRT is 4.000 ms —
   the defended value. It is byte-identical to a campaign file whose log says "size defense
   OFF". It supports the size claim only.
3. **The experiment source is not at the branch tip.** Commit `8a6896e` added a
   documentation header to the P4 the day after the campaign. The recorded hash belongs to
   the blob at `c1871384`, which is what the timing tree now carries.
4. **The readback marked FAIL cannot be explained**, and the file is a hand-assembled
   excerpt rather than a run transcript. The configuration proof is PARTIAL. The frozen file
   was not edited.

## Reproduction check

Every published timing value regenerates from the raw captures and matches the frozen CSVs
to within one microsecond. 102 tests pass. The one number that moves further — the defended
mutual-information estimate — moves for a reason that is documented and quantified, and the
conclusion it supports is unchanged.

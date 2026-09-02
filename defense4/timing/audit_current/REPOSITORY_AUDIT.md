# Repository audit — timing study, current state (2026-09-02)

This audit records the repository and evidence state as it actually is on 2026-09-02, and
reconciles it against a task specification written against the 2026-08-24 tree. Where the two
disagree, the verified current state governs; each disagreement is stated so no later reader
inherits a stale assumption.

## 1. Repositories

| role | path | note |
|---|---|---|
| implementation + evidence + manuscript | `/home/philip/Projects/DNP3` | the working checkout; remote `origin` = `github.com/akekulip/DNP3_obf.git` |
| (spec-named) `/home/philip/Projects/DNP3_obf` | — | **does not exist as a path.** `DNP3_obf` is the remote repository name, not a local directory. |
| (spec-named) `/home/philip/Projects/DNP3-size-probe` | — | **does not exist.** There is no separate paper repository; the manuscript lives inside this checkout at `paper/rewrite/`. |

The manuscript and the evidence are one repository. The spec's instruction to copy final figures
into a separate paper repo has no target and was not executed.

## 2. Git state, verified 2026-09-02

* `git fetch --all --prune` run; no pull, merge, or rebase.
* Checkout on `paper/campaign-v1-ndss-corrections-20260828` at `ceb5bea` (this session's line),
  one commit ahead of `origin/`, not pushed.
* `origin/main` = `883d8cd5d83eb283aac905d8398e0c5f97d219a7`. The spec quoted
  `883c8cd5d83e…`; that object is **not** in the repository. The real default-branch tip is
  `883d8cd`. The spec's SHA is a transcription slip.
* Authoritative evidence branch `defense4-size-native-parity-crc-split` tip = `02923cb`. The
  spec's `8a6896e` **is an ancestor** of that tip: the branch moved forward, it was not rewritten.
  Reported per the spec's requirement not to silently use the old commit.
* Frozen source SHA-256 `7ce30494…` and loaded-binary SHA-256 `33fa3a77…` are unchanged and
  match the spec.

## 3. Preservation artifacts — already exist, not recreated

All four required pre-cleanup artifacts already existed from 2026-08-24 and were left untouched:

| artifact | state |
|---|---|
| `../DNP3_obf-before-timing-cleanup-20260824.bundle` | present, 112,292,049 bytes |
| tag `archive/defense4-full-before-timing-cleanup-20260824` | present, `50f91a1` |
| branch `cleanup/timing-read-sbo-20260824` | present, `2ea2daf` |
| worktree | `DNP3-worktrees/campaign-v1-ndss-corrections-20260828`, now detached at `ceb5bea` (inert) |

No `git reset --hard`, `git clean`, `git checkout --`, force push, interactive rebase, remote
branch deletion, or recursive delete was run. No dirty or untracked work was lost. One untracked
file is present and preserved: `DefRec-Establishing Physical Function.pdf` (a reference copy).

## 4. Evidence layout — moved since the spec was written

The spec's frozen paths `defense4/size/native_parity/evidence/E_FINAL` and
`defense4/defense4_release/evidence/E_FINAL` **do not exist in the working tree**; they were
pruned into the archive tag on 2026-08-24. They exist at that tag (64 files each).

**E_FINAL twin identity is PROVEN**, not by file diff but by git tree hash: at the archive tag
both `…/size/native_parity/evidence/E_FINAL` and `…/defense4_release/evidence/E_FINAL` resolve to
the identical tree object `1d1a5f3c94cf8d34c1b390baa1c921e47cdbc79c`. Identical tree hash is
byte-identical content by construction. The two are redundant copies.

The evidence now lives at:

* `defense4/timing/evidence/final_read_sbo/` — the retired six-capture dataset (size-shaping
  active in both arms), kept for provenance.
* `defense4/timing/evidence/campaign_v1/` — the active 132-capture, 22-session, size-off dataset
  that the manuscript reports.

## 5. Which numbers are authoritative — the spec has this inverted

The spec instructs reproduction of MI `0.424356 → 0.001837` and balanced accuracy
`0.5921 → 0.5000` as "frozen authoritative," and removal of `0.652 → 0.333`, MI
`0.383 → 0.00394`, and `0.651` as "unreproduced slide values."

Verified on 2026-09-02:

* `0.42436 / 0.00184 / 0.5921` are the **`final_read_sbo`** values (`audit/verdict_stats.json`).
  They reproduce exactly and describe the **retired** six-capture dataset.
* `0.38315 / 0.00394 / 0.6515 / 0.6510` are the **`campaign_v1`** values now in the manuscript
  (`paper/rewrite/figures/ndss/MANUSCRIPT_VALUES.json`). They are **not** slide values; they are
  the current authority, regenerated from 132 raw captures and gated by the publication gate.

Treating the spec literally would revert the paper from the 22-session campaign to the
six-capture dataset. This was not done. The campaign_v1 values stand.

## 6. Required reading — current locations

Several spec-named files do not exist under their spec paths (`RESUME_STATE.md`, `AGENTS.md`,
`defense4/README.md`, `defense4/CLAIMS.md`, `E_FINAL/README.md`, `CLAIM_MATRIX.md`). Their
current equivalents were read: `CLAUDE.md`, `WORKING_NOTES.md`,
`defense4/timing/README.md`, `defense4/timing/CLAIMS_AND_LIMITATIONS.md`,
`defense4/timing/evidence/final_read_sbo/audit/{VERDICT.json,verdict_stats.json,EVIDENCE_AUDIT.md}`,
and `MANIFEST.sha256`.

## 7. Stop-gates hit

Per the spec's §15, the following were reported rather than worked around: the paper repo does
not exist; the spec's frozen values are the retired dataset; the frozen paths moved; the
hardware rerun (Levels B/C) is barred by this repository's own `CLAUDE.md` no-experimentation
rule and by the hardware-authorization gate. No hardware operation was attempted.

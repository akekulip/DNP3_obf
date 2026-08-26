# Repository audit — 2026-08-26

State of the repository at the start of the final timing-paper rewrite, recorded before any
file was changed. The 2026-08-24 audit that preceded the cleanup is kept at
`defense4/timing/REPOSITORY_AUDIT.md`; this file supersedes it for the current state.

## Identity

| item | value |
|---|---|
| repository root (`git rev-parse --show-toplevel`) | `/home/philip/Projects/DNP3` |
| remote | `origin  https://github.com/akekulip/DNP3_obf.git` (fetch and push) |
| branch at audit | `final/timing-paper-20260824` |
| HEAD | `22db6e06ed9a826955dbc9fa7a7fb3a5254d46cd` |
| working branch created from HEAD | `paper/final-timing-rewrite-20260826` (did not exist before) |
| `git fetch --all --prune` | run; no remote ref changed; nothing pulled, merged, rebased or pushed |

## Working tree

| item | value |
|---|---|
| modified tracked files | none |
| untracked | `corrections.md` (the task brief for this session) |
| ignored, present | `.claude/`, `.omx/`, `defense4/timing/build/`, `paper/rewrite/pipeline/build/`, `paper/rewrite/pipeline/reports/` (two 2026-08-24 scorecards), `__pycache__/` |
| stash | empty |
| tracked files | 144, 11 MB (`defense4/` 5.5 MB, `paper/` 2.3 MB, `.git/` 141 MB) |

## Branches

| branch | tip | remote state | what it is |
|---|---|---|---|
| `main` | `883d8cd` | = `origin/main` | stale; predates the 2026-08-13 campaign |
| `final/timing-paper-20260824` | `22db6e0` | local only | the consolidated timing + manuscript branch (this rewrite's base) |
| `final/manuscript-20260824` | `860efc1` | local only | manuscript line, merged into the above by `28158d4` |
| `cleanup/timing-read-sbo-20260824` | `2ea2daf` | local only | pre-prune timing cleanup; tagged `archive/pre-final-timing-prune-20260824` |
| `paper/timing-figures-20260824` | `0095923` | local only | earlier figure handoff |
| `wip/size-probe-uncommitted-20260824` | `9b9cb2c` | local only | every uncommitted file of the retired size-probe worktree |
| `wip/caseA-uncommitted-20260824` | `348999e` | local only | every uncommitted file of the pre-switch main checkout |
| `defense4-size-native-parity-crc-split` | `02923cb` | ahead 10 of `origin` (`8a6896e`) | frozen evidence branch; the ten local commits are manuscript work, tagged `archive/defense4-local-unpushed-paper-20260824` |
| `defense4-caseA-hw-integration` | `796b41b` | ahead of `origin` (`7c4a5a7`) | Case-A hardware line |
| `defense4-real-size-normalization` | `d06ca8b` | local only | later size work |
| `defense4-timing-core`, `defense4-size-read-range-probe`, `defense4-size-readsbo-normalizer`, `defense4-size-transport-kernel-repair` | as `git branch -vv` | = origin | historical |
| `origin/fixed-transcript-experiments` | `901c120` | remote only | no local checkout |

Unpushed commits: every `final/*`, `cleanup/*`, `paper/*`, `wip/*` branch is local only; the two
`defense4-*` branches above are ahead of origin. Nothing was pushed in this session.

## Worktrees

Exactly one: `/home/philip/Projects/DNP3`. The auxiliary worktrees named in the brief
(`DNP3-size-probe`, `DNP3-timing-core`, `DNP3-timing-cleanup`, `DNP3-paper-timing-figures`) were
removed on 2026-08-24 and do not exist on disk. No worktree removal remains.

## Safety artifacts

| bundle | sha256 | verify |
|---|---|---|
| `/home/philip/Projects/DNP3_obf-before-timing-cleanup-20260824.bundle` | `70bad1361f6fd9872d94bab00b74ecfbad56e988e75abccf65918eb6b6610d9f` | complete history |
| `/home/philip/Projects/DNP3-after-timing-cleanup-20260824.bundle` | `a4d7849b17a51b7ab7f7a67754d1b1ffdc6d23d56116c0fc9c0a2c45949a0dd4` | complete history |
| `/home/philip/Projects/DNP3-before-final-timing-prune-20260824.bundle` | `c2b4a2d29a98b183830fa321931ae6f3ee165e0a637d820f59af398128ceb5b4` | complete history |
| `/home/philip/Projects/DNP3-before-final-manuscript-20260824.bundle` | `1fa380a6f7a66b291d152522b2515c16ba5900c965d8e9f5929ef4026440e09c` | complete history |

The newest bundle (`before-final-manuscript`, 2026-08-24 16:53) predates the last four commits on
`final/timing-paper-20260824` (`28158d4`, `2fb287f`, `09d5e6e`, `22db6e0`) and the manuscript
merge. A current bundle is therefore created before the first change of this session:
`/home/philip/Projects/DNP3-before-final-paper-rewrite-20260826.bundle`, verified "records a
complete history", sha256 `c2749c0d6245b335c436dd8933d8f994102319ae8c20e58c7b5fc476206990b9`. Tags `archive/defense4-full-before-timing-cleanup-20260824`,
`archive/defense4-local-unpushed-paper-20260824`, `archive/pre-final-timing-prune-20260824`,
`checkpoint/timing-read-sbo-20260824`, `checkpoint/paper-timing-figures-20260824` all exist and
are not touched.

## Where things are

| what | where |
|---|---|
| final manuscript | `paper/rewrite/main.tex` (+ section files, `library.bib`, `pipeline/`) |
| authoritative timing evidence | `defense4/timing/evidence/final_read_sbo/` (six raw captures, derived CSVs, readbacks, audit, manifests) |
| exact experiment source | `defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` (sha256 `7ce30494…`, verified this session) |
| final figures | `defense4/timing/figures/publication/` (authority) and `paper/rewrite/figures/timing/` (manuscript copies, byte-identical at audit) |
| removed material | git history, the tags and bundles above, and `/home/philip/Archives/DNP3_nonfinal_20260824/` (untracked, 776 MB, manifest-verified) |

## Duplicates, stale trees, candidates

* No duplicate evidence tree remains on the branch (the two `E_FINAL` copies were removed on
  2026-08-24 after proof of equality by shared git tree `1d1a5f3c…`).
* Stale paper material on the branch: `paper/rewrite/WRITING_PIPELINE_AUDIT.md`,
  `WRITING_PIPELINE_REBUILD_PLAN.md`, `PIPELINE_AUDIT_VERDICT.md`, `TITLE_OPTIONS_2026-08-24.md`
  (size+timing titles), `refs.bib` (legacy keys), the `*_pipeline_v1.tex` section files (to be
  restructured), `main.pdf` (2026-08-24 build with known defects). Disposition in `CLEANUP_PLAN.md`.
* Candidate for external archival: the above documents where their content is unique and
  non-rebuildable.
* Candidate worktrees for removal: none.

## Tree before this session's changes

```
CLAUDE.md  README.md  FINAL_TIMING_ALLOWLIST.txt  REMOVAL_MANIFEST.csv  REMOVAL_REPORT.md
VERIFICATION_REPORT.md  WORKING_NOTES.md  .gitignore
defense4/timing/{README,CLAIMS_AND_LIMITATIONS,PROVENANCE,BRANCH_MAP,REPOSITORY_AUDIT,CLEANUP_PLAN,CLEANUP_REPORT}.md
defense4/timing/{reproduce.sh,pyproject.toml,.gitignore}
defense4/timing/analysis/          12 files (pcap_reader, dnp3_timing, extract_*, timing_stats, compare_frozen, figstyle, utils_mpl, paper_palettes, env_report, make_capture_manifest, requirements.txt)
defense4/timing/evidence/final_read_sbo/   MANIFEST.sha256, CAPTURE_MANIFEST.{csv,json}, timing_stats.json, raw_pcaps/6, derived_csv/7, readbacks/4, audit/4
defense4/timing/figures/source/    _common.py + fig01…fig05.py
defense4/timing/figures/publication/   26 files (pdf, png, data csv, caption, provenance per figure; ENVIRONMENT.txt)
defense4/timing/implementation/    README.md, exact_experiment_source/1, control/6, harness/4
defense4/timing/tests/test_timing.py
paper/rewrite/main.tex, main.pdf, library.bib, refs.bib, five *_pipeline_v1.tex, README.md,
paper/rewrite/FIGURE_PROVENANCE.md, FINAL_FIGURES.md, LIN_STYLE_{CONTRACT,PROFILE}.md, LIN_VS_PHILIP_DIFF.md,
paper/rewrite/LIN_WRITING_GUIDANCE.md, PIPELINE_AUDIT_VERDICT.md, WRITING_PIPELINE_{AUDIT,REBUILD_PLAN}.md, TITLE_OPTIONS_2026-08-24.md
paper/rewrite/figures/{fig_design,fig_ladder,fig_observation}.{svg,pdf}, figures/timing/fig01…fig05.{pdf,png}
paper/rewrite/pipeline/{build.sh,lin_check.py,make_final_figures.py,README.md}, samples/2, reprod/2
```

## Forbidden operations

None used: no `reset --hard`, `clean`, `checkout --`, `restore .`, force push, interactive rebase,
remote branch deletion, `worktree remove --force`, `rm -rf`, or wildcard deletion.

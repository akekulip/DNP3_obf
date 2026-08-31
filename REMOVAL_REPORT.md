> **Historical.** A dated record of work that preceded the campaign_v1 correction of
> 2026-08-28. Where it names evidence, figures or claims as current, read it as describing
> the `final_read_sbo` state of that date. The active evidence authority is
> `defense4/timing/evidence/campaign_v1/`, the active claim authority is
> `defense4/timing/CLAIMS_AND_LIMITATIONS.md`, and the active figures are
> `paper/rewrite/figures/ndss/`. Kept for provenance.

# Removal report — final timing-paper branch

Branch `final/timing-paper-20260824`, cut from `2ea2dafe4517b5893fac5e06fc5db2ae63ba13b8`
(the Phase 6 timing-cleanup commit) on 2026-08-24.

The objective is a minimal, reproducible repository for the timing-obfuscation paper: the
exact program that ran, the captures it produced, the code that turns those captures into
the four figures, and the documents that bound the claims. Nothing else.

**6,480 tracked files at the base; 85 retained; 6,395 removed.** Every removed path is listed
in `REMOVAL_MANIFEST.csv` with its classification, the reason, its canonical replacement
where one exists, and the branch, tag and commit it is recoverable from.

---

## Preservation, done before anything was removed

| artifact | value |
|---|---|
| bundle | `/home/philip/Projects/DNP3-before-final-timing-prune-20260824.bundle`, all refs, sha256 `c2b4a2d29a98b183830fa321931ae6f3ee165e0a637d820f59af398128ceb5b4` |
| tag | `archive/pre-final-timing-prune-20260824` → `2ea2daf` |
| source branch | `cleanup/timing-read-sbo-20260824` → `2ea2daf`, untouched |
| earlier bundles retained | `DNP3_obf-before-timing-cleanup-20260824.bundle`, `DNP3-after-timing-cleanup-20260824.bundle` |
| earlier tags retained | `archive/defense4-full-before-timing-cleanup-20260824`, `archive/defense4-local-unpushed-paper-20260824`, `checkpoint/timing-read-sbo-20260824`, `checkpoint/paper-timing-figures-20260824` |

Nothing is preserved inside an `archive/` directory on this branch. Git history, the tag, the
bundle and the original branches are the archive.

The uncommitted work in `/home/philip/Projects/DNP3` (11 entries) and
`/home/philip/Projects/DNP3-size-probe` (39 entries) was not touched, and their file contents
were hashed before and after so "unaffected" means byte-for-byte.

---

## What is retained, and why

**Root — 2 files.** `.gitignore` and `CLAUDE.md` (repository instructions). A `README.md` is
added by the prune to orient a reader arriving at the reduced tree. **There is no licence
file in this repository** — none was tracked at the base commit, so none could be retained.
That is a gap to fill before any public release, not something the prune removed.

**`defense4/timing/` — 80 files.** The canonical timing tree: the exact combined P4 source and
its control-plane and driver dependencies, the six authoritative PCAPs, the timing-derived
CSVs the paper uses, the configuration readbacks, manifests, provenance and audit documents,
the self-contained extraction/statistics/plotting/reproduction code, the tests and
environment specification, and the fig01–fig05 sources, data, captions, PDFs and PNG previews.

**Three Defense-3 modules — a proved exact dependency.** See below.

## The one Defense-3 dependency, proved rather than assumed

The retained control plane loads a Defense-3 module at runtime. This is the "exact final
dependency" exception, and the closure was traced rather than guessed:

```
defense4_rrc_bor_unified12_setup.py
  └─ defense4_caseA_setup.py
       └─ case_a_defense3_fixed_ack_delay_setup.py     (loaded by path)
            ├─ parameter_policy.py                     (imported)
            └─ counter_map.py                          (imported)
```

Three files, out of 1,582 in `defense3/`. Their contents are unchanged:

| file | sha256 |
|---|---|
| `case_a_defense3_fixed_ack_delay_setup.py` | `927c9eea21f79980a391873717f797d4658beed6d34ff19dde9c47a9785b6e80` |
| `parameter_policy.py` | `1c76ab95bdcc295408f4e8325b3e16a35f6e54d454087298bf266ad6647b4afc` |
| `counter_map.py` | `4e3f3236614132eabc4e779e37448a35a7dfce85822485bf247c4d17cf99599e` |

They are relocated by `git mv` into `defense4/timing/implementation/control/`, beside
`defense4_caseA_setup.py`. That is not an ad-hoc arrangement: the loader tries
`$D4_D3SETUP`, then **a sibling in its own directory**, then a repo-relative path, and its
comment says "When staged on the switch it is a SIBLING in the same directory". The Defense-3
module in turn puts its own directory on `sys.path`, so it finds `parameter_policy` and
`counter_map` there. This is the layout the campaign itself used on the switch. **No source
file was modified.**

One caveat, recorded rather than patched. `defense4_rrc_bor_unified12_setup.py` resolves
`defense4_caseA_setup.py` through `$D4_CASEA_SETUP` or a repo-relative fallback written for
the *original* directory depth. Because Phase 6 moved the control chain one level deeper into
`implementation/control/`, that fallback no longer resolves, and the environment override is
required:

```sh
D4_CASEA_SETUP=defense4/timing/implementation/control/defense4_caseA_setup.py \
  python3 defense4/timing/implementation/control/defense4_rrc_bor_unified12_setup.py --help
```

This is the same override the campaign's own `shape_set.py` set. With it, the whole chain
imports offline, with no SDE and no hardware. Patching the fallback would mean editing a file
the brief requires to stay unchanged, so it is documented instead.

None of this is on the reproduction path: `reproduce.sh`, `analysis/`, `figures/source/` and
`tests/` import nothing outside `defense4/timing/`, which was verified by scan before any
removal.

---

## What is removed

Counts by classification. Full per-path detail in `REMOVAL_MANIFEST.csv`.

| classification | files | what it is |
|---|---|---|
| `EARLIER_RESEARCH` | 1934 | queue studies, feasibility work, pre-silicon capture corpus, earlier evidence |
| `DEFENSE_1_3_DEV` | 1625 | Defense-1/2/3 development trees, less the three proved dependencies |
| `EARLIER_TIMING_CORE` | 1074 | the Case-A timing-core line, superseded by the unified program |
| `OBSOLETE_PROTOTYPE` | 590 | pre-silicon software harnesses |
| `PADDING_SPLITTING_COVER_DECOY` | 516 | padding, splitting, segmentation, cover-frame and decoy experiments |
| `COMPILER_PROBE` | 174 | negative compile and feasibility probes |
| `DUPLICATE_EVIDENCE` | 129 | the second `E_FINAL` tree and the release repackaging |
| `MEETING_SLIDES_DEMO` | 118 | meeting packages, slides, demo deliverables |
| `DEFENSE4_NON_TIMING` | 48 | Defense-4 planning and reporting outside the timing line |
| `HISTORICAL_ARCHIVE` | 47 | in-checkout archive directories |
| `SIZE_EXPERIMENT` | 45 | size-obfuscation experiments, CSVs and claims |
| `OTHER_RESEARCH_NOTE` | 24 | root-level planning and direction notes |
| `OLD_FIGURE` | 22 | the FIG-1…FIG-10 set, superseded by fig01–fig05 |
| `UNRELATED_PAPER_DRAFT` | 17 | manuscript drafts belonging to the paper branches |
| `SUPERSEDED_ANALYSIS` | 13 | the frozen analysis scripts |
| `DUPLICATE_DERIVED` | 7 | timing CSVs duplicated under the old evidence path |
| `DUPLICATE_PCAP` | 6 | the six captures, duplicated under the old evidence path |
| `DOWNLOADED_PAPER` | 2 | publisher-copyrighted reference PDFs |
| `TEMPORARY_EXPORT` | 2 | packaged `.zip` exports of earlier trees |
| `SHAPEOFF_PCAP` | 1 | `e1_native_size_shapeoff.pcap` |
| `OFF_PROBE_PCAP` | 1 | `off_probe.pcap` |

### The two captures the brief asked to be justified individually

**`off_probe.pcap` — removed.** Eight warm-up READ transactions over 0.12 s. No published
timing result depends on it; a repository-wide search found its only references were three
`MANIFEST.sha256` listings.

**`e1_native_size_shapeoff.pcap` — removed.** The audit does not show it supporting an active
timing claim; it shows the opposite. Its measured CLRT is 4.000 ms with a standard deviation
of 0.009 ms — the *Timing ON* value — so the timing mechanism was active while it was
captured and it is not a timing baseline. It is byte-identical to
`hw_campaign_20260813T172014Z/phase6_h1/h1a_defoff_100.pcap`, whose run log reads "100 READs
(**size** defense OFF)". It supports the size claim only.

### The two frozen `E_FINAL` trees

Equality was already proved by shared git tree object
`1d1a5f3c94cf8d34c1b390baa1c921e47cdbc79c`, so both copies leave the active branch. The
timing subset they contain lives on under `defense4/timing/evidence/final_read_sbo/` with its
own manifest, capture manifest and audit.

---

## Claims that must survive the reduction

These are properties of the evidence, not of the file layout, and the prune does not soften
any of them. They are stated in `defense4/timing/CLAIMS_AND_LIMITATIONS.md` and
`defense4/timing/evidence/final_read_sbo/audit/EVIDENCE_AUDIT.md`, both retained.

* **`shape_enable` was 1 in both arms.** Size shaping was active during every timing capture.
  It is a held constant across the arms, not a difference between them, so the comparison
  isolates the timing-mode change — but the Timing OFF arm is **not** an unmodified native
  SEL-751 baseline and is never described as one.
* **Configuration provenance is PARTIAL.** `hw_config_readback.txt` reports one failed
  assertion while showing none; it is a hand-assembled excerpt whose `RESULT:` line does not
  belong to its rows, and the failing check cannot be recovered from archived evidence. The
  file is retained unedited.
* **Relay-facing `T0+J` and exactly-once delivery remain unobserved.**
* **Figures 1, 2, 3 and 5 are READ-versus-SELECT transaction timing, not device identification**, and
  SELECT means the SELECT phase of SBO, not a complete SBO transaction.

## Documentary references to removed paths

The retained audit documents cite paths that no longer exist in this checkout — the frozen
`E_FINAL` package, the August campaign directory, `_history/`. Those are citations of
evidence, not runtime dependencies, and they resolve against
`archive/pre-final-timing-prune-20260824`, the `cleanup/timing-read-sbo-20260824` branch, and
the bundle. Rewriting them would break the chain of custody they exist to record, so they are
left as written and this paragraph explains where they point.

## Method

Explicit `git rm` over a reviewed path list derived from `FINAL_TIMING_ALLOWLIST.txt`. No
recursive filesystem deletion, no `git clean`, no history rewriting, no force push, no remote
branch deletion. The allowlist, the removal and the verification are three separate commits.

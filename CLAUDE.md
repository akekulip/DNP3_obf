# CLAUDE.md — final timing-paper repository

This repository holds the verified timing evidence, its active manuscript, and separate
implementation work such as stage reduction and delay search. The approved publication evidence
remains `campaign_v2`. The frozen manuscript already contains later engineering results that have not been reconciled with that authority; their presence is
an open audit finding, not approval. Promotion requires Dr. Lin's acceptance and an explicit
claim/provenance update.

## Layout

- `defense4/timing/` — the timing authority: exact P4 source that ran, the captures,
  extraction and statistics code, tests, and the audit and claim documents. The active evidence is
  `defense4/timing/evidence/campaign_v2/` (22 grouped runs, 132 captures, 63,360 exchanges,
  size carve disabled and proved off per block), collected on the request-anchored build.
  `campaign_v1/` has the same shape and is the record of the acknowledgment-anchored build it
  replaces — kept because the correction is measured against it, not because it is current;
  `final_read_sbo/` is historical. The fix, and the before-and-after on one set of hardware, are in
  `defense4/timing/anchor_fix/FINDINGS.md`.
  Start at `defense4/timing/README.md`. Rebuild the active corpus with
  `defense4/timing/reproduce.sh`, which dispatches to `campaign_v2/repro/reproduce.sh`; the
  retired corpus needs the explicit `--historical` flag.
- `paper/rewrite/` — the one active manuscript. Entry point `main.tex`, sections under
  `sections/`; build with `paper/rewrite/pipeline/build.sh`. Start at `paper/rewrite/README.md`.
- Root: `README.md`, `REPOSITORY_MAP.md` and `FINAL_TIMING_ALLOWLIST.txt` record how this tree was
  reduced from the full research repository.

### Documents removed from the tree, and where they are

Prose that recorded a plan, a session or a state that has since been superseded is kept in git
history rather than on disk, so that one document is authoritative per subject and a reader cannot
follow a stale one. Nothing was lost: each is a `git show` away.

| removed | at | what it was |
|---|---|---|
| `REMOVAL_REPORT.md`, `VERIFICATION_REPORT.md`, `REPOSITORY_AUDIT.md` | `f6dd821` | the 2026-08-26 reduction of the full repository |
| `CLEANUP_PLAN.md` | `f573eec` · also `dc721cdf` | disposition of every candidate in that reduction |
| `REMOVAL_MANIFEST.csv` | `6e2eff2` | the per-path record of it |
| the six root review and correction reports of 2026-09-15 and 2026-09-16 | `48373e39` | the reviews this repository answered |
| twenty superseded notes under `defense4/timing/`, `audit_current/` and `paper/rewrite/` | `dc721cdf` | branch maps, rerun plans, session logs, pre-rewrite reconciliations, an applied patch proposal, a duplicate writing guide and a duplicate definitions table |
| `WORKING_NOTES.md` | removed in the repository refactor | dated session log with completed figure, paper, and experiment tasks; current authority is the map and subsystem runbooks |

**One subject, one document.** The response latency `D_R` is defined in
`defense4/timing/NOTATION_MAPPING.md` and nowhere else; the claim boundaries in
`defense4/timing/CLAIMS_AND_LIMITATIONS.md`; the writing contract in
`paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md`. A second copy of any of those is a defect, and
on 2026-09-17 a review found one that had already caused the manuscript to be edited against a
stale definition.

Sizing experiments, earlier defenses, and prototypes remain engineering history. They do not
support current manuscript claims. Refactoring them must preserve hash-bound sources, raw evidence,
and the distinction between measurements and later candidates.

## Hard rules

- **Commit authorship:** all commits must use Philip's Git identity
  (`akekulip <akekulip@gmail.com>`) for both author and committer. Do not add
  co-author trailers or attribution to any other contributor.
- **Current authorization (2026-09-29): offline audit and corrections only.** Philip
  authorized the September 26 focused study and September 27 matched delay grid in this
  thread; their frozen protocols record what ran. That historical authorization does not
  authorize new experiments. Offline analysis, provenance repairs, tests, and compilation
  of separate bug-fix candidates are authorized. Do not contact the testbed, load a
  pipeline, change hardware configuration, or generate traffic without new authorization.
- **Paper freeze pending Dr. Lin's acceptance.** Do not change `paper/rewrite/`, including
  manuscript prose, figures, Design, Implementation, or the mechanism diagram. Record
  paper findings in `defense4/timing/audit_current/verification_20260929/` instead. Existing
  engineering-study text in the paper does not promote its results to approved evidence.
  Preserve measured sources, binaries, captures, configurations, and results; repairs
  belong in separate candidate/build directories. Sizing remains outside this task.
- **Never modify** `defense4/timing/implementation/`,
  `defense4/timing/evidence/campaign_v1/s*/raw_pcaps/`,
  `defense4/timing/evidence/campaign_v1/sweep/raw_pcaps/` or
  `defense4/timing/evidence/final_read_sbo/raw_pcaps/`. They are the record of what ran.
- **Claim boundaries** (`defense4/timing/CLAIMS_AND_LIMITATIONS.md`): the two arms are
  *Timing OFF* and *Obfuscated*, and in `campaign_v2` (as in `campaign_v1`) the size carve is off
  in both, so the measurement is timing only; SELECT means the SELECT phase of SBO; on the shipped
  build both lanes are request-anchored (`campaign_v1`'s read lane was ACK-anchored); the read
  lane (READ and SELECT) is the only lane the release budget `D` governs, and OPERATE, whose
  command is held for `J`, is never placed in the read-lane coverage denominator. OPERATE's offsets
  are the read lane's own, so its master-visible observable is `O = CLRT_new`, not `R − A`:
  `A` and `R` are admission parameters the control plane checks, not release instants
  (measured 2026-09-18, `evidence/tail_sweep_20260918/`; `CLAIMS_AND_LIMITATIONS.md`); results are transaction-class timing, not device identification, and are scoped
  to the evaluated Random-Forest attacker; the realized per-transaction `J` and the relay-facing
  release are unobserved. Exactly-once delivery is **not** provided and is not claimed. Two records bear on this and
  neither shows loss recovery working. On 2026-09-15 a response was withheld from the master and
  further copies crossed the switch and reached the master's interface, but the filter dropped
  every copy for the whole test, so the application recovered nothing and what was observed was
  arrival at the interface rather than delivery
  (`audit_current/duplicate_test_20260915/CORRECTION_20260916.md`). Separately, the frozen
  control path keeps a spent OPERATE generation after release and drops a matching
  retransmission, so a command lost on the relay-facing link cannot be repaired by its own
  retransmission; that is a source-level reading, not a hardware observation
  (`audit_current/OPERATE_RETRANSMISSION_RISK_20260916.md`). Configuration provenance: every `campaign_v2` block and sweep point has a control-plane readback; the per-transaction `J` and the horizon `H` are unobserved (`CLAIMS_AND_LIMITATIONS.md` L12). No
  size, segmentation, padding or splitting claim anywhere in the manuscript.
- **Never push** without explicit instruction. No history rewriting, no force push, no
  remote branch deletion.
- The internal project codename must never appear in any file.

## Paper writing (STRICT — Dr. Lin structure + manuscript gate)

All manuscript prose follows `paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md` and is gated by
`paper/rewrite/pipeline/lin_check.py` (`pipeline/build.sh` compiles and gates). The gate fails
on forbidden names, stale arm labels (`native`, `defended`, `Timing ON`), firstness claims, em
dashes, size claims, wrong section order, a figure after References, an undefined citation key,
non-verb-first contributions and fragments. Arms are *Timing OFF* and *Obfuscated*. Firstness is
not required and not asserted. Humanize with `academic-humanizer` only; the generic `humanizer`
is barred. `remove-ai-marks` and any watermark-removal or detector-evasion tool are barred in
this repository. Re-run `build.sh` after every edit; `lin_check --compare` must show no regression.

## Figures

The manuscript draws on five figure families, not one. Each has exactly one generator, and no
figure may be hand-edited:

| family | files | generated by |
|---|---|---|
| campaign results | `paper/rewrite/figures/ndss/*.pdf` | `campaign_v2/repro/reproduce.sh`, in the pinned environment under `campaign_v2/repro/`. campaign_v1 published here until 2026-09-18 and no longer does; its own gate is expected to fail against these figures |
| READ CLRT histograms | `paper/rewrite/figures/clrt/*.pdf`; the manuscript includes only `fig_clrt`, the 2x2 of both arms at both scales | `defense4/timing/audit_current/tools/clrt_distribution_and_variance.py` |
| release tail | `paper/rewrite/figures/tail/*.pdf` | `defense4/timing/evidence/campaign_v2/_bin/make_tail_figure.py`, from campaign_v2's sweep and campaign table (regenerated 2026-09-19; the 2026-09-18 tail sweep measured the acknowledgment-anchored build and no longer feeds the manuscript) |
| release-timeline model | `paper/rewrite/figures/model/*.pdf` | `defense4/timing/audit_current/tools/make_model_figures.py` |
| schematics | `paper/rewrite/figures/fig_{ladder,observation,design}.{svg,pdf,png}` | all three are draw.io documents (`*.drawio`, Cisco network stencils) generated by `paper/rewrite/pipeline/drawio/build.sh`, which writes their SVG through draw.io Desktop. The SVGs are then exported by `paper/rewrite/pipeline/export_schematics.sh`, which also mirrors byte-identical copies to `defense4/timing/figures/schematics/` |

Every figure carries `.caption.md`, `.method.md`, `.limitations.md`, a `_data.csv` and a
`.provenance.json` beside it, and each directory's `FIGURES.sha256` is checked by its
generator's `--check` mode. The older `figures/timing/fig01…fig05` were removed on 2026-09-07
as byte-identical duplicates; those originals are at `defense4/timing/figures/publication/`.
The superseded campaign set that used to sit under `defense4/timing/history/` was removed on
2026-09-15 and is recoverable from git history. IEEE sizing and fonts come from
`defense4/timing/analysis/figstyle.py` and `campaign_v1/repro/figstyle_ndss.py`.

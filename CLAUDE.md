# CLAUDE.md — final timing-paper repository

This repository holds exactly two things: the verified timing evidence and the manuscript
that reports it. The experiment is finished.

## Layout

- `defense4/timing/` — the timing authority: exact P4 source that ran, the captures,
  extraction and statistics code, tests, and the audit and claim documents. The active evidence is
  `defense4/timing/evidence/campaign_v1/` (22 grouped runs, 132 captures, 63,360 exchanges,
  size carve disabled); `final_read_sbo/` is historical.
  Start at `defense4/timing/README.md`. Rebuild the active corpus with
  `defense4/timing/reproduce.sh`, which dispatches to `campaign_v1/repro/reproduce.sh`; the
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

**One subject, one document.** The response latency `D_R` is defined in
`defense4/timing/NOTATION_MAPPING.md` and nowhere else; the claim boundaries in
`defense4/timing/CLAIMS_AND_LIMITATIONS.md`; the writing contract in
`paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md`. A second copy of any of those is a defect, and
on 2026-09-17 a review found one that had already caused the manuscript to be edited against a
stale definition.

Everything else — size experiments, earlier defenses, prototypes, meeting material, old
drafts — is out of scope here. It lives in git history (tag
`archive/pre-final-timing-prune-20260824`, the original branches, the bundles) and in the
local, untracked archive `/home/philip/Archives/DNP3_nonfinal_20260824/`.

## Hard rules

- **No further experimentation.** Do not run hardware, load or change a Tofino program,
  contact the SEL-751, generate traffic or captures, restart size work, add a defense or a
  protocol function, or explore compilers or implementations. Only organise the verified
  evidence, finish the existing figures, and write the paper.
- **Never modify** `defense4/timing/implementation/`,
  `defense4/timing/evidence/campaign_v1/s*/raw_pcaps/`,
  `defense4/timing/evidence/campaign_v1/sweep/raw_pcaps/` or
  `defense4/timing/evidence/final_read_sbo/raw_pcaps/`. They are the record of what ran.
- **Claim boundaries** (`defense4/timing/CLAIMS_AND_LIMITATIONS.md`): the two arms are
  *Timing OFF* and *Obfuscated*, and in `campaign_v1` the size carve is off in both, so the
  measurement is timing only; SELECT means the SELECT phase of SBO; the read lane (READ and
  SELECT) is ACK-anchored and is the only lane the release budget `D` governs, while OPERATE is
  request-anchored with observable `R − A` and is never placed in the read-lane coverage
  denominator; results are transaction-class timing, not device identification, and are scoped
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
  (`audit_current/OPERATE_RETRANSMISSION_RISK_20260916.md`). Configuration provenance is PARTIAL. No
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

The manuscript draws on four figure families, not one. Each has exactly one generator, and no
figure may be hand-edited:

| family | files | generated by |
|---|---|---|
| campaign results | `paper/rewrite/figures/ndss/*.pdf` | `campaign_v1/repro/reproduce.sh`, in the pinned environment under `campaign_v1/repro/` |
| READ CLRT histograms | `paper/rewrite/figures/clrt/*.pdf` | `defense4/timing/audit_current/tools/clrt_distribution_and_variance.py` |
| release-timeline model | `paper/rewrite/figures/model/*.pdf` | `defense4/timing/audit_current/tools/make_model_figures.py` |
| schematics | `paper/rewrite/figures/fig_{ladder,observation,design}.{svg,pdf,png}` | hand-drawn SVG in `paper/rewrite/figures/`, exported by `paper/rewrite/pipeline/export_schematics.sh`, which also mirrors byte-identical copies to `defense4/timing/figures/schematics/` |

Every figure carries `.caption.md`, `.method.md`, `.limitations.md`, a `_data.csv` and a
`.provenance.json` beside it, and each directory's `FIGURES.sha256` is checked by its
generator's `--check` mode. The older `figures/timing/fig01…fig05` were removed on 2026-09-07
as byte-identical duplicates; those originals are at `defense4/timing/figures/publication/`.
The superseded campaign set that used to sit under `defense4/timing/history/` was removed on
2026-09-15 and is recoverable from git history. IEEE sizing and fonts come from
`defense4/timing/analysis/figstyle.py` and `campaign_v1/repro/figstyle_ndss.py`.

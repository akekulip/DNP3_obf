# CLAUDE.md — final timing-paper repository

This repository holds exactly two things: the verified timing evidence and the manuscript
that reports it. The experiment is finished.

## Layout

- `defense4/timing/` — the timing authority: exact P4 source that ran, the six captures,
  extraction and statistics code, the five figures, tests, and the audit and claim documents.
  Start at `defense4/timing/README.md`. Rebuild everything with `defense4/timing/reproduce.sh`.
- `paper/rewrite/` — the one active manuscript. Entry point `main.tex`; build with
  `paper/rewrite/pipeline/build.sh`. Start at `paper/rewrite/README.md`.
- Root: `README.md`, `FINAL_TIMING_ALLOWLIST.txt`, `REMOVAL_MANIFEST.csv`, `REMOVAL_REPORT.md`,
  `VERIFICATION_REPORT.md` record how this tree was reduced from the full research repository.

Everything else — size experiments, earlier defenses, prototypes, meeting material, old
drafts — is out of scope here. It lives in git history (tag
`archive/pre-final-timing-prune-20260824`, the original branches, the bundles) and in the
local, untracked archive `/home/philip/Archives/DNP3_nonfinal_20260824/`.

## Hard rules

- **No further experimentation.** Do not run hardware, load or change a Tofino program,
  contact the SEL-751, generate traffic or captures, restart size work, add a defense or a
  protocol function, or explore compilers or implementations. Only organise the verified
  evidence, finish the existing figures, and write the paper.
- **Never modify** `defense4/timing/implementation/` or
  `defense4/timing/evidence/final_read_sbo/raw_pcaps/`. They are the record of what ran.
- **Claim boundaries** (`defense4/timing/CLAIMS_AND_LIMITATIONS.md`): the two arms are
  *Timing OFF* and *Obfuscated* — both ran the same unified binary with the size-shaping
  datapath active, so the baseline is never described as an unmodified native SEL-751
  baseline; SELECT means the SELECT phase of SBO; Figures 1–3 and 5 are transaction-class
  timing, not device identification; Figure 4 is master-visible OPERATE timing only,
  relay-facing `T0+J` and exactly-once delivery unobserved; configuration provenance is
  PARTIAL. No size, segmentation, padding or splitting claim anywhere in the manuscript.
- **Never push** without explicit instruction. No history rewriting, no force push, no
  remote branch deletion.
- The internal project codename must never appear in any file.

## Paper writing (STRICT — Dr. Lin voice + structure gate)

All manuscript prose follows `paper/rewrite/LIN_STYLE_CONTRACT.md` and is enforced by
`paper/rewrite/pipeline/lin_check.py` (`pipeline/build.sh` compiles and gates). Every
drafting, rewriting or polishing pass on any section runs through the `paper-voice` skill and
must PASS `lin_check`: connective spine, verb-first contributions and the "To the best of our
knowledge, first …" claim, threat model early, a distinct Design section, RO-labelled
evaluation. Humanize with `academic-humanizer` only; the generic `humanizer` is barred. No
pass may lower the score — re-run `lin_check` (use `--compare`) after every edit.
Order: draft → `security-paper-writing` → `paper-voice` → `academic-humanizer` → `lin_check`
gate → `remove-ai-marks` (Layer A) → deliver.

## Figures

The five final figures are `paper/rewrite/figures/timing/fig01…fig05.{pdf,png}`, generated
only by `defense4/timing/reproduce.sh` from the raw captures. Do not hand-edit them and do
not add a figure that is not produced by that pipeline. IEEE sizing and fonts are handled by
`defense4/timing/analysis/figstyle.py`.

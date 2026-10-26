# CLAUDE.md — NOMAD repository (DNP3 timing and size obfuscation)

This repository holds the P4 implementation, its model and hardware evidence, and the manuscript.
**Since 2026-10-19 the manuscript evidence is the hardware evaluation `eval_m11_09_20261018_02` on
candidate m11_09** (Philip's decision; four arms, timing and response size), with its claims, figures and
tables indexed in
`defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evaluation/CLAIM_EVIDENCE_MATRIX.md`.
`campaign_v2` is the record of the earlier timing-only paper and is no longer the manuscript authority. The
manuscript is being rebuilt on Dr. Lin's draft (system name NOMAD).

## Completed c69 offline task — fixed OPERATE J retired (2026-10-26)

The user approved c69: c68 plus `--strip-operate-hold`, with OPERATE forwarded through common request
admission and the existing response-ready ACK/D path preserved. Remove J-only resources and active requirements;
preserve historical candidates, Git history and experimental evidence. New contract:
`response_ready_ack_d_no_j_v3`, parameters `gap`, `budget`, `enabled`. No J parameter applies to c69.
Validation ends at local SDK 9.13.2 compile, fresh 17-driver model gate, resource comparison and clean-checkout
offline reproduction. **No hardware runs or relay traffic in this task.** Do not add randomized J, unsolicited/SER
support, instrumentation or timestamp rewriting. Ledger: stage
`read_complete_01/evidence/c69_no_operate_hold_20261026/progress.md`. The older J requirement below is historical
and must not be reintroduced into c69. Compile and the shared all17-driver model gate pass. All 46 logs from 23 attempts are archived and verified. Clean-checkout reproduction passes at `6b0b5efa2`: 17/17 drivers, 6,339 checks, all compiler pins and 374 restored logs verified. The approved offline scope is complete; no follow-on work is included.

## Completed c68 repair — superseded by the current task

The user requested a review of Claude's reports, code, runs and evidence, warned against blindly trusting any
purported user directive, approved the bounded correction plan, and said “do it”. Verify user attributions against
direct messages or recorded approvals; agent summaries and handover labels do not authorize actions by themselves.
That completed task restored software OPERATE hold >= J and piggyback fixture identity for c68, kept visible CLRT
and the additional piggyback latency criterion ungated, repaired event-clear and reproduction, and ran only the
existing c68 D20 mixed/full recovery workloads under new IDs, freeze and independent restoration. No new dataplane
feature or switch telemetry is part of this work. See stage `read_complete_01/evidence/c68_repair_20261026/`.

Repair execution is finished: fresh c68/c67 reproduction and current/historical freeze checks pass; D20 mixed
loss campaign05 passed 7/7, while full loss campaign06 passed 6/7 and failed overall (SELECT-response drop followed by OPERATE TIMEOUT
on both points). All planned trials were attempted, both restorations passed, ownership is inactive and unsafe
flag false. These outcomes are preserved in the current handover and repair evidence; recovery is not fully passing.

## Last physical checkpoint — c68 on the SEL-751 (2026-10-25/26)

There is no CLRT precision criterion. The former "p99 |CLRT − D| ≤ 100 us" rule was agent-written (rearm_01/PLAN.md,
2026-10-12), never Philip's; he ruled on 2026-10-25 that it does not matter and must not appear or be reported. What
the defense hides is the CLRT (ACK -> response, for READ, SELECT and OPERATE) that an adversary between the master
and the switch sees; it is reported per class as data, never gated. Holding the ACK until the response is ready is the intended release contract; source/model tests and the bounded
physical runs are evidence for tested cases, not an exhaustive physical-departure guarantee. Write-only switch measurement state was removed: candidate
`m12p_c68_sdk9132` (c67 + `make_m12.py --strip-telemetry`; T 9 stages, less SRAM). c68 passed the 17-driver model
gate and ran on the SEL-751 at D=5/10/15/20 (`rc01_hw_c68_20261026_01..04`), before (no obfuscation) vs after
(timing+size), every block rc 0 with restoration verified; before/after visible CLRT in
`read_complete_01/evidence/c68_visible_clrt_20261026.json`. Correctness gates (exact sizes, DNP3 application success
incl. SELECT->OPERATE, TCP, generator/loop-port checks, guard {1,3}, freeze, ownership, restoration) are unchanged.
The relay can raise class-2 events on its own (IIN1.2); the integrity READ then stops matching the 134-octet shape —
see WORKING_NOTES 2026-10-25/26 and `active_harness/event_clear.py`.

## Earlier: timing correction — Philip, 2026-10-25 (historical; superseded by the section above)

Handover of that time: [CLAUDE_HANDOVER_20261025.md](CLAUDE_HANDOVER_20261025.md) (current: CLAUDE_HANDOVER_20261026.md). Philip requested takeover by
Claude and explicitly prohibited scope expansion. The c67 model gate and all planned physical blocks are done
(handover Closeout section): model PASS, smoke PASS, FIN PASS, timing FAIL, mixed-loss SBO recovery FAIL, physical
J unproven; c67 has not passed hardware qualification. Revised scope (Philip, 2026-10-25): bounded hardware
debugging and retesting of the existing timing and mixed-loss failures only, on the existing testbed, profiles,
guarded operations and restoration procedure. Each test must address a specific hypothesis or verify a concrete
fix; preserve failed evidence and the original thresholds. No new features, production defaults, additional relay
profiles, instrumentation project, package/OS changes or threshold relaxation. The Vision-jitter and select-window
explanations remain unproven. Read the handover's scope limits before acting.

### Historical c67 implementation directive (superseded; retained record)

At that checkpoint, Codex was implementing response-ready ACK-then-D timing on c67 (v2):
D=5/10/15/20ms qualification is now authorized for READ and SBO, superseding the earlier blanket D-campaign
exclusion only for this bounded qualification. J remains2.4ms; physicalJ measurement is explicitlyunproven.
No exchange deadline: suppress retries only while an original request/response is retained; otherwise allow TCP recovery. FIN/RST/epoch clean up ownership. r150 is superseded. c52 evidence is immutable.
No new attacker/J-codebook campaign, relay observer, syntheticACK, generalreassembly or sizing redesign.
Existing guarded SEL-751 authorization/restoration remain in force (the 100us criterion was removed 2026-10-25). c62 v1 passed its strict model but is superseded; c67 v2 passed its 17-driver model gate and ran every planned physical block; its mixed-loss SBO recovery failed; WORKING_NOTES tracks progress.

## Agent start

0. Read root `CLAUDE_HANDOVER_20261026_C69.md`, then `plan.md`. c69 is the new offline candidate without fixed
   OPERATE J; compile, full 17-driver model gate, retention and clean-checkout reproduction PASS. The offline task is complete. No hardware operation belongs to this task.
   `CLAUDE_HANDOVER_20261026.md` is the completed c68 physical/repair record; the October25/24 handovers and c67
   are historical. c68's recovery failure and old measurements remain preserved, and c52 is immutable.
1. Read `defense4/timing/case4_architecture/ACTIVE_CODE_MAP.md`: the active code path with commands.
2. Read the run's status file `.../stage_experiments/read_complete_01/CURRENT.md` (history in `STATUS.md`,
   full record in `COMPLETION_RECORD.md`).
3. The current c69 task permits no testbed operations. The historical hardware authorization below records
   completed earlier tasks and does not extend this task beyond compile/model verification.
4. `REPOSITORY_MAP.md` classifies every area; `HISTORY_MAP.md` lists what is historical, the superseded
   authorizations, the removed documents and the proposed moves.

## Layout

- `defense4/timing/case4_architecture/` — the active implementation: generator
  (`.../stage_experiments/m12_fullsize/make_m12.py` with `m12gen/`), builds and model gate
  (`.../ctl_timing_01`), the manuscript evaluation (`.../seg61_02`), the current run (`.../read_complete_01`),
  the hardware supervisor (`integration/evidence/rearm_01/hw`) and the endpoint library (`protocol/hw_vepa`).
  Current offline candidate: `m12p_c69_sdk9132` (c68 without the fixed OPERATE hold; compile/model only).
  Last physical candidate: `m12p_c68_sdk9132` (without write-only measurement state; ran on the SEL-751
  at every D, before vs after). c67 (`m12p_c67_sdk9132`) is its predecessor. The measured
  `m12p_c52_sdk9132` baseline remains immutable; see CURRENT.md and the October 25 handover.
- `defense4/timing/` (outside `case4_architecture/`) — the timing-only record: the P4 that ran
  (`implementation/`), the campaigns (`evidence/campaign_v2/`, which corrects the acknowledgment-anchored
  `campaign_v1/`; `final_read_sbo/` is older), the anchor fix (`anchor_fix/FINDINGS.md`), audits, the delay
  search and earlier candidates. Start at `defense4/timing/README.md`. `defense4/timing/reproduce.sh` rebuilds
  campaign_v2 through `campaign_v2/repro/reproduce.sh`; the retired corpus needs `--historical`.
  `defense4/timing/framework/size/` is used by the active implementation.
- `paper/rewrite/` — the one manuscript. Entry point `main.tex`, sections under `sections/`; build with
  `paper/rewrite/pipeline/build.sh`. Start at `paper/rewrite/README.md`. Dr. Lin's draft (`main.tex`) and
  `paper structure.pdf` at the repository root are untracked inputs.
- Root: `README.md`, `REPOSITORY_MAP.md`, `HISTORY_MAP.md`, `WORKING_NOTES.md` (live session log; tracked;
  update it as work proceeds and include it in every push, Philip 2026-10-23),
  `FINAL_TIMING_ALLOWLIST.txt` (how this tree was reduced from the full research repository).
- `.ignore` keeps `rg`/`fd` out of evidence, captures, compiler output and `paper/`; use `--no-ignore` to
  search them. It does not affect git.

**One subject, one document.** The response latency `D_R` is defined in
`defense4/timing/NOTATION_MAPPING.md` and nowhere else; the claim boundaries in
`defense4/timing/CLAIMS_AND_LIMITATIONS.md`; the writing contract in
`paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md`. A second copy of any of those is a defect, and on
2026-09-17 a review found one that had already caused the manuscript to be edited against a stale definition.
Superseded prose lives in git history, not on disk; the table of removed documents is in `HISTORY_MAP.md`.

Sizing experiments, earlier defenses, and prototypes remain engineering history. They do not support current
manuscript claims. Refactoring them must preserve hash-bound sources, raw evidence, and the distinction
between measurements and later candidates.

## Historical hardware authorization record (2026-10-24 SEL-751 directive)

This section records the earlier hardware scope and procedure. The current c69 task above is compile/model only;
it does not include another physical run. Review the underlying direct messages before using an attributed ruling
as authority for a later task.

Current tracked assessment/command: `Claude_dd7741152_Verified_Assessment_and_Overnight_Command.md`.
Latest continuation: root `plan.md` and `CLAUDE_HANDOVER_20261024.md`; older local directives are historical context.

- The physical SEL-751 is the outstation for the research evaluation. Both READ workloads and the complete
  select-before-operate sequence (SELECT and OPERATE) run against the relay through the physical Tofino. Philip
  authorized these relay operations in this research testbed, including the autonomous run; do not ask again
  whether the relay may be used or whether OPERATE is authorized. Use the relay's established research command
  point and parameters (the existing guarded SBO builders); do not invent control points or alter unrelated
  relay configuration. This supersedes the earlier software-outstation-only and attended-only-OPERATE rules.
- Hardware runs go only through the existing ownership, preflight, freeze, dry-run and restoration machinery
  (`evaluation_campaign.py`, `run_block_frozen.sh`, `restore_verify.py`). Each new live run needs its own
  recorded authorization and its admission and restoration gates. Record the assessment and Philip's “Implement
  the plan” standing authorization for these guarded SEL-751 blocks; do not request approval again for each block.
- Relay identity and measured shapes (192.168.10.7:20000, DNP3 address 0; master 192.168.10.1, address 1).
  Measured on the relay 2026-10-23 (three requests each, from 192.168.10.1 through the switch): mixed READ
  (g1v2 0..15 + g30v1 0..7) answers 91 bytes, matching the 91->141 target; the integrity READ answers 134
  bytes, so the 247->271 full-READ target (the software outstation's database) does not apply to the relay and
  uses retained134->158.158 is the preserved-tail prefix floor, not a global minimum; preserve141/158 without
  restarting sizing. Fresh native02 physical captures accept91/134/49/49 with whole TCP payloads and successful
  two-CROB SBO. Current TCP headers are SYN40/SYNACK44/DATA32, WS7/0; padded physical qualification remains pending.
  Historical c25-c29 hardware runs used the software outstation on Vision (192.168.10.62),
  not the relay, and qualify only the software tier, not the relay deliverable.
- Not allowed: any D/J or attacker campaign; rebooting Vision; OS or firmware updates.
- Current run (2026-10-24, SEL-751 directive): a new relay-shape candidate, its READ/SBO shapes derived from
  decoded relay captures, model gate on one SDK-9.13.2 bundle, then the four-arm and recovery blocks against the
  SEL-751. The IEEE 1815 audit and paper writing remain OUT OF SCOPE. No Vision reboot, kernel/firmware change,
  keep-alive traffic, D/J or attacker campaign, manual ownership edits, or weaker restoration checks (there is no
  CLRT threshold; the visible CLRT is reported only). Keep three evidence tiers distinct in every record: software-reference
  encoding; software master/outstation through the switch; physical SEL-751 through the switch (only the third
  qualifies the relay deliverable).
- Implementation work (separate candidate code, offline tests, protocol-aware padding and response carving,
  isolated BMv2 work, compiler evidence, analysis) is authorized, as it has been since the 2026-10-06 Case 4
  scope. Cases 1–3 remain explanation-only history.
- Work directly on `main`; no new branch. Push only on explicit instruction. Philip explicitly requested commit/push
  for this2026-10-24 handover; that authorizes publishing the completed task work and retained evidence now.
- Implementation work does not touch `paper/`. The manuscript rebuild is a separate stream governed by the
  paper rules below.
- Earlier authorizations (the 2026-09-29 offline-only boundary, the 2026-09-29 paper freeze, the campaign_v2
  authority statements) are superseded; their text and dates are in `HISTORY_MAP.md`.

## Hard rules

- **Manuscript rebuild (2026-10-19, Philip).** The paper is rebuilt on Dr. Lin's draft (`main.tex` at the
  repository root, structure in `paper structure.pdf`). His non-[Archive] text is installed word for word;
  [Archive] parts are deleted or rewritten. Response-size claims are allowed, scoped to the measured
  normalization (every READ and select-before-operate response 61 bytes, conformant; requests stay native).
  Every number the paper states must trace to a row of `CLAIM_EVIDENCE_MATRIX.md`. Figures and tables come
  only from `seg61_02/analysis/paper_evidence.py` (`--check` must pass). New citations go through Zotero
  collection `OBfus_defense` from their sources of record, avoiding arXiv.
- **Commit authorship:** all commits use Philip's Git identity (`akekulip <akekulip@gmail.com>`) for both
  author and committer. Do not add co-author trailers or attribution to any other contributor.
- **Never push** without explicit instruction. No history rewriting, no force push, no remote branch deletion.
- **Preserve** all existing local edits, frozen sources, binaries, captures, configurations, raw measurements
  and results. Repairs belong in separate candidate or build directories.
- **Never modify** `defense4/timing/implementation/`,
  `defense4/timing/evidence/campaign_v1/s*/raw_pcaps/`,
  `defense4/timing/evidence/campaign_v1/sweep/raw_pcaps/` or
  `defense4/timing/evidence/final_read_sbo/raw_pcaps/`. They are the record of what ran.
- The internal project codename must never appear in any file. "NOMAD" is the published system name Dr. Lin
  chose for the paper (Philip, 2026-10-19) and is not covered by this rule.

## Claim boundaries

The campaign_v2 record (`defense4/timing/CLAIMS_AND_LIMITATIONS.md`): the two arms are *Timing OFF* and
*Obfuscated*, and in `campaign_v2` (as in `campaign_v1`) the size carve is off in both, so the measurement is
timing only; SELECT means the SELECT phase of SBO; on the shipped build both lanes are request-anchored
(`campaign_v1`'s read lane was ACK-anchored); the read lane (READ and SELECT) is the only lane the release
budget `D` governs, and OPERATE, whose command is held for `J`, is never placed in the read-lane coverage
denominator. OPERATE's offsets are the read lane's own, so its master-visible observable is `O = CLRT_new`,
not `R − A`: `A` and `R` are admission parameters the control plane checks, not release instants (measured
2026-09-18, `evidence/tail_sweep_20260918/`; `CLAIMS_AND_LIMITATIONS.md`); results are transaction-class
timing, not device identification, and are scoped to the evaluated Random-Forest attacker; the realized
per-transaction `J` and the relay-facing release are unobserved. Configuration provenance: every
`campaign_v2` block and sweep point has a control-plane readback; the per-transaction `J` and the horizon `H`
are unobserved (`CLAIMS_AND_LIMITATIONS.md` L12). For the campaign_v2 paper: no size, segmentation, padding
or splitting claim. For the 2026-10-19 rebuild, see the manuscript-rebuild rule above.

In every manuscript: exactly-once delivery is **not** provided and is not claimed. Two records bear on this and
neither shows loss recovery working. On 2026-09-15 a response was withheld from the master and further copies
crossed the switch and reached the master's interface, but the filter dropped every copy for the whole test,
so the application recovered nothing and what was observed was arrival at the interface rather than delivery
(`audit_current/duplicate_test_20260915/CORRECTION_20260916.md`). Separately, the frozen control path keeps a
spent OPERATE generation after release and drops a matching retransmission, so a command lost on the
relay-facing link cannot be repaired by its own retransmission; that is a source-level reading, not a hardware
observation (`audit_current/OPERATE_RETRANSMISSION_RISK_20260916.md`).

## Paper writing (STRICT — Dr. Lin structure + manuscript gate)

**Since 2026-10-19 (NOMAD rebuild):**
- `pipeline/build.sh` also runs `check_lin_verbatim.py`, which checks Dr. Lin's protected paragraphs word
  for word.
- The gate's section order follows his structure.
- The arms are *No obfuscation*, *Timing*, *Size* and *Timing+Size*.
- Response-size claims scoped to the measured normalization no longer fail.
- The evaluation figures and tables come from `seg61_02/analysis/paper_evidence.py`, mirrored by
  `pipeline/sync_nomad_evidence.py`; the schematics come from `pipeline/drawio/build_nomad.sh`.

**In force for every manuscript:** all manuscript prose follows `paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md`
and is gated by `paper/rewrite/pipeline/lin_check.py` (`pipeline/build.sh` compiles and gates). The gate fails
on forbidden names, em dashes, wrong section order, a figure after References, an undefined citation key,
non-verb-first contributions and fragments. Firstness is not required and not asserted. Humanize with
`academic-humanizer` only; the generic `humanizer` is barred. `remove-ai-marks` and any watermark-removal or
detector-evasion tool are barred in this repository. Re-run `build.sh` after every edit; `lin_check --compare`
must show no regression.

**Campaign_v2-era record (the earlier timing-only manuscript):** its gate also failed on stale arm labels
(`native`, `defended`, `Timing ON`), firstness claims and size claims, and its arms were *Timing OFF* and
*Obfuscated*. The rebuild replaces the arm labels and the size rule as stated above.

## Figures

No figure may be hand-edited; each family has exactly one generator. Every figure carries `.caption.md`,
`.method.md`, `.limitations.md`, a `_data.csv` and a `.provenance.json` beside it, and each directory's
`FIGURES.sha256` is checked by its generator's `--check` mode. IEEE sizing and fonts come from
`defense4/timing/analysis/figstyle.py` and `campaign_v1/repro/figstyle_ndss.py`.

The rebuilt manuscript includes these families (from `paper/rewrite/sections/*.tex`):

| family | files | generated by |
|---|---|---|
| evaluation | `paper/rewrite/figures/nomad_eval/*` | `seg61_02/analysis/paper_evidence.py`, mirrored by `paper/rewrite/pipeline/sync_nomad_evidence.py` |
| NOMAD schematics | `paper/rewrite/figures/nomad/*` | `paper/rewrite/pipeline/drawio/build_nomad.sh` |
| ladder and observation schematics | `paper/rewrite/figures/fig_{ladder,observation}.{svg,pdf,png}` | draw.io documents (`*.drawio`, Cisco network stencils) generated by `paper/rewrite/pipeline/drawio/build.sh` through draw.io Desktop, exported by `paper/rewrite/pipeline/export_schematics.sh`, which also mirrors byte-identical copies to `defense4/timing/figures/schematics/` |

Campaign_v2-era families, kept as that record and not used by the rebuilt manuscript:

| family | files | generated by |
|---|---|---|
| campaign results | `paper/rewrite/figures/ndss/*.pdf` | `campaign_v2/repro/reproduce.sh`, in the pinned environment under `campaign_v2/repro/`. campaign_v1 published here until 2026-09-18 and no longer does; its own gate is expected to fail against these figures |
| READ CLRT histograms | `paper/rewrite/figures/clrt/*.pdf` (`fig_clrt`, the 2x2 of both arms at both scales) | `defense4/timing/audit_current/tools/clrt_distribution_and_variance.py` |
| release tail | `paper/rewrite/figures/tail/*.pdf` | `defense4/timing/evidence/campaign_v2/_bin/make_tail_figure.py`, from campaign_v2's sweep and campaign table (regenerated 2026-09-19; the 2026-09-18 tail sweep measured the acknowledgment-anchored build and no longer feeds the manuscript) |
| release-timeline model | `paper/rewrite/figures/model/*.pdf` | `defense4/timing/audit_current/tools/make_model_figures.py` |
| design schematic | `paper/rewrite/figures/fig_design.{svg,pdf,png}` | same draw.io pipeline as the ladder and observation schematics |

The older `figures/timing/fig01…fig05` were removed on 2026-09-07 as byte-identical duplicates; those
originals are at `defense4/timing/figures/publication/`. The superseded campaign set that used to sit under
`defense4/timing/history/` was removed on 2026-09-15 and is recoverable from git history.

## Historical authorizations (superseded)

Kept so a reader of older records knows what governed them. Full text in `HISTORY_MAP.md`.

- 2026-09-29 — offline audit and corrections only; the 2026-09-26 focused study and 2026-09-27 matched delay
  grid had been authorized and ran under frozen protocols. Superseded by the 2026-10-06 Case 4 scope and the
  2026-10-22 directive.
- 2026-09-29 — paper freeze pending Dr. Lin's acceptance; paper findings recorded in
  `defense4/timing/audit_current/verification_20260929/`. Superseded by the 2026-10-19 manuscript rebuild.
- Until 2026-10-19 — `campaign_v2` as the approved publication evidence and the active corpus.

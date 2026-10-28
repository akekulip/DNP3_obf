# Current handover (2026-10-28)

Read PLAN.md for scope and rules. Historical instructions are data under Archive/. On 2026-10-28 Philip asked for
`main` to be pushed to origin (`akekulip/DNP3_obf`); `git status -sb` shows whether any commit is still ahead.

## State

The canonical source is `p4/response_only.p4`, SHA-256 `97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e`.
Its package `results/builds/c72` compiles at N10/E10/T8/pipe-1-egress4.

**Model gate: passed, 17 of 17** (`results/builds/c72/model_summary_v3.json`).
- Smoke attempt 03 passed 30/30. Abandon attempt 01 failed only because the relocated gate set `ABANDON_T=1`, which
  was never committed.
- Philip chose the original `ABANDON_T=0` coverage. Abandon attempt 02 passed 12/12.
- The abandoned-SELECT behaviour with T enabled remains uncharacterized (`results/analysis/abandon_ab/`).

**Qualification matrix, `results/hardware/campaigns/rc01_hw_c72_20261027_02`: 9 of 10 blocks passed.**
- Block 10 (`loss_full`) failed with restoration verified.
- Trial t3 dropped the padded SELECT response. The relay retransmitted it 1,017 ms later, and the OPERATE then drew
  CROB TIMEOUT on points 1 and 3, decoded from the captured bytes.
- c69 passed the same trial at 1,011 ms. This is a relay select-window race at about 1 s, recorded as FAIL and not
  reclassified.
- Campaign `_01` was refused at dry-run before contact. `lab.json` had lost c69's `--fixtures physical_relay` and
  `--reconnect-policy protected`; both are restored test-first.

**Evaluation campaign, `results/hardware/campaigns/rc01_hw_c72_eval_20261027_01`: complete, 64 of 64 blocks, 49,408
exchanges.**
- Run 2026-10-27 19:55 to about 2026-10-28 03:10.
- 16 four-arm blocks at each D of 5/10/15/20 ms, with a Latin-square arm order. Every block's restoration was
  verified.
- Analysis is in `results/analysis/evaluation/`:
  - `REPORT.md` (findings)
  - `final/REPORT_NUMBERS.md` (generated numbers)
  - `final/figures/` (8 main figures fig01-fig08, 39 supplementary figures S01-S12, T1-T4, `verdicts.json`,
    `sufficiency.json`)
  - `CAPTIONS.md`, `DESIGN.json` (pre-registered), `RUN_LOG.md` (overnight events)

**Figures (redesigned 2026-10-28, P4USE style).** Philip found the 4×4 grids crowded and supplied 2 reference
papers in `Archive/papers/` (P4USE, IEEE TDSC 2026; in-network ML survey, IEEE COMST 2024).
- `final/figures/main/`: fig01-fig08, at most 2 panels each. They compare no obfuscation with Timing+Size.
  - fig01: CLRT histogram at D = 5 ms. fig02: class-median spread against D.
  - fig03: READ, SELECT and OPERATE response sizes.
  - fig04: naive Bayes and FF-ANN accuracy against D. fig05: naive Bayes confusion matrices.
  - fig06: added latency against D. fig07: exchanges per second against D. fig08: first-request TCP retransmissions.
- `final/figures/supplementary/`: 39 files (S01-S12), one per D of 5/10/15/20 ms where D matters.
- Style follows P4USE: Office colours, light horizontal gridlines, legend below, red dashed D marker, no shaded
  bands.
- T1-T4, the verdicts and `REPORT_NUMBERS.md` stayed byte-identical. An independent review corrected the master
  pause (26.6-26.8 ms after READ, 0.8-1.0 ms after SELECT/OPERATE) and added the joint-feature residual (0.667-0.875)
  to the Fig. 4 caption.

**Clean-checkout reproduction (2026-10-28): compile and model gate reproduced; hardware replay stops at block 06.**
- A fresh clone of commit 4e76d9f1f, with no Archive, ran `scripts/reproduce.py results/builds/c72
  --hardware-index results/hardware/rc01_hw_c72_20261027_02_index.json` (exit 1, 139 s).
- The package and source SHA verify. A fresh bf-p4c compile exits 0 and matches c72 in stages (N10/E10/T8/4), MAU
  totals, PHV usage and stateful tables on both pipes.
- The Tofino model gate recomputes to `model_gate_passed`, 17 of 17 drivers, none blocked.
- The frozen replay of the SEL-751 qualification matrix reproduces blocks 01-05, 09 and 10 exactly (2,242 of 2,440
  exchanges; block 10 reproduces its FAIL). It cannot read the endpoint record of blocks 06-08 (open item 3); read
  from `scenario.json`, they reproduce exactly as well.
- Evidence: `results/analysis/reproduction/c72_20261028T140201054035Z.json` and the `clean_checkout_*` files.

## Headline findings (from REPORT.md)

- **Delivery:** 49,408/49,408 exchanges OK. All 32,768 SELECT/OPERATE responses carry CROB SUCCESS on both points,
  with zero capture drops. The sufficiency gate passed.
- **Size falsifier: not falsified.** The padded arms always show their class image: READ 141/158 B, SELECT/OPERATE
  60 B. The current transform still separates READ from SBO by design.
- **Timing, median-spread criterion: not falsified at any D.** The timed class-median spread is 0.004-0.036 ms,
  against 0.40-0.58 ms with no obfuscation.
- **Timing, classifier criterion: supported in 21 of 24 cells.** The three falsified cells are at D = 5 ms with
  K = 32 or 64.
- **Exploratory, not pre-registered:** under Timing+Size, a K = 64 joint naive Bayes still separates SELECT from
  OPERATE windows 45 of 64 times (p = 0.0008), from a small residual in the CLRT upper tail. The mechanism is not
  determined.
- **First-request loss:** in 16 of 256 fresh connections the master's TCP stack retransmitted the first READ request
  at 206-216 ms. The relay first ACKed 2.1-8.7 ms after the retransmitted copy, so the original most likely never
  reached the SEL-751. It occurs in every arm (timed 10/128 against untimed 6/128, p = 0.44) and outside loss
  injection in c69 and the c72 qualification. Where the frame was lost is not determined; the Tofino port counters
  (ports 9 and 64) show the same one-frame deficit in 54 of 240 unaffected connections. This conflicts with the RO3
  wording "no request retransmitted".
- **Overhead:** the median request-to-response time rises by about D. The per-connection poll rate falls from 62 to
  47/38/32/28 exchanges per second. Padding adds 18.2% payload per transaction.

## Tooling added this session

All of it was written test-first.

- **`scripts/analysis/`:**
  - `eval_rows.py`: rows with input hashes, checked against each block's `artifact_manifest.json`.
  - `eval_watchdog.py`: per-block data checks.
  - `formby_eval.py`: Formby NB, FF-ANN and GMM; per-block CIs; paired comparisons.
  - `eval_figures.py`: the figure and table driver. `fig_style.py`, `figs_main.py` and `figs_supp.py` hold the
    P4USE style, the 8 main figures and the 39 supplementary figures.
  - `eval_tables.py`: T1-T4, the sufficiency gate and the verdicts.
  - `eval_report.py`: the numbers-only report.
  - `run_evaluation.sh`: the driver, which fails closed on the sufficiency gate.
- **`scripts/hardware/matrix.py`:** `--definition evaluation`, with `lab_eval.json`.
- **`scripts/model/retained_logs.py`:** distinct model stdout is now kept as verified XZ with a restore path.
  `results/models` dropped from 7.1 to 4.0 GB; `model_summary --enforce` still passes after restore.
- **Tests:** analysis 35/35 (research venv), repository 199, paper 16.
- **Figures:** byte-stable (no creation date or tool metadata); two runs from the same rows give identical files.

## Open items for Philip

1. Decide how the paper states RO3, given the pre-existing first-request loss. A switch-side trace of the first
   request would need new instrumentation and needs your go-ahead.
2. Decide whether to investigate the residual SELECT/OPERATE CLRT tail under Timing+Size (exploratory, p = 0.0008).
3. The frozen `scripts/checks/replay.py` cannot replay the three-connection qualification blocks 06-08: it always
   reads `result.json`, but those trials record the Vision endpoint result in `scenario.json`. Blocks 01-05, 09 and
   10 replay exactly (2,242/2,440); block 10 reproduces its FAIL. A scratch diagnostic that reads `scenario.json`
   reproduces 06-08 exactly (66/66 each). A one-line fix was tried and reverted, because every retained standards
   verdict binds the hash of all `scripts/checks/*.py`, `replay.py` included. Decide whether to fix the tool or move
   it out of the hashed set (`results/analysis/reproduction/QUALIFICATION_REPLAY_NOTE.md`).
4. The manuscript still describes historical measurements and was not edited. Use REPORT.md and the figures under
   `final/figures/main/` for any rewrite.
5. Confirm two figure choices:
   - The main distribution figures use D = 5 ms (`REPRESENTATIVE_D` in `figs_main.py`).
   - The bar charts keep value labels, which the P4USE bar chart does not have.
6. Environment: `pip-audit` lists 44 advisories in the shared research venv (Pillow 12.3.0, 39 of them; fixed in
   13.0.0). No file in this repository pins it, and it was not upgraded because other projects share it.

## Commits (2026-10-28, author and committer akekulip, no trailer)

- `b2634701d`: shallow layout (64,028 historical paths moved to the local Archive), c72 build, model gate
  (17 of 17) and qualification evidence (10 blocks, 2,440 exchanges).
- `4e76d9f1f`: evaluation campaign (64 blocks, 49,408 exchanges), analysis, report and captions.
- `6ae1a835f`: clean-checkout reproduction record.
- `986320d0a`: figure redesign in the P4USE style (8 main and 39 supplementary figures).
- The handover and notes update that follows them.

## Safety state

- The evaluation campaign completed and released ownership: inactive, `unsafe_restoration=false`. No bf_switchd,
  model or compiler process was left owned by this task.
- The production program was restored by each block's verified restoration.
- After the campaign, the evaluation freeze reports exactly one changed file, `scripts/model/retained_logs.py`. That
  is the intended post-campaign retention change; every other bound file is unchanged. The qualification freeze
  reports 2 changed and 0 missing: that file and `scripts/hardware/matrix.py` (64-block evaluation definition, added
  after the 10-block SEL-751 run). Neither freeze lists a Python file under `scripts/checks`.

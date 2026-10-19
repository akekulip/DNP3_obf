# Case 4 handover — START HERE (current as of 2026-10-19)

Trust this section first. Everything from section 00b down is history. Written so a different model can continue
without the conversation.

## 00. Current state (2026-10-19): m11_09 evaluated on hardware

**Candidate.** `integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m11_09`, source
`f1de2b30…`. It is the N stage-cut successor of m10_03, at N11/E12/T11 on SDK 9.13.1 and 9.13.2. Model gate passed
(`m11_09/model_summary_v3.json`; packets and smoke re-run after the evaluation changed `wire_check.py`).

**Evaluation (Codex's `seg61_02/evaluation/HARDWARE_EVALUATION_PLAN.md`, run by Claude 2026-10-18/19):**

| campaign | outcome | evidence |
|---|---|---|
| `eval_m11_09_20261018_01` | **stopped** at block 6 (reference) on the host-observed CLRT precision gate: one ~1 ms late exchange per arm. Kept as recorded | `5ed45f0c2` |
| `eval_m11_09_20261018_02` | **COMPLETE, 154 of 154 blocks**, 0 failed, every restore verified. Option 1: host precision reported, not gated (Philip, 2026-10-18, no ceiling) | `ec4bda169` |

**Results:** `seg61_02/evidence/evaluation_campaigns/eval_m11_09_20261018_02_RESULTS.md`.
- **Primary:** fixed joint-feature RF at D10/J2.4. Native 0.950 → combined 0.333. Reduction **0.617, 95% CI
  [0.593, 0.635]** (8 paired test blocks, 10,000 resamples).
- **Residuals, reported:**
  - adaptive joint attacker on combined: 0.36–0.46;
  - adaptive metadata diagnostic: 0.69–0.80 (requests are native by design);
  - the fixed attacker's drop to chance is partly distribution shift.
- **Host precision:** 99.705% of timed exchanges within 100 µs; 73 outside, maximum 1.93 ms.
- **Reproduction:** offline replay of `release/` regenerated 39/39 outputs byte-identically.

**Evidence storage.** The raw block evidence (about 11 GB) stays on Gambit's disk and is not committed (Philip,
2026-10-19). All 50,158 files are hashed in `eval_m11_09_20261018_02_EVIDENCE.sha256`; see
`eval_m11_09_20261018_02_EVIDENCE_LOCATION.md`.

**Campaign machinery** (for any future run):
- `rearm_01/hw/evaluation_campaign.py`: detached Gambit user-systemd controller and block services; deadline; locks.
- `seg61_02/hw/evaluation_prepare.py`: the 154-block order, the envelope, and the qualify and fit hooks.
- `seg61_02/analysis/{publication_analysis,reproduce_evaluation,publication_figures}.py`.
- Operator guide: `seg61_02/evaluation/README.md`.
- Lessons:
  - verify detachment after `start`;
  - a changed harness file can stale the model drivers' dependency closures, so re-run them before the freeze;
  - every reader of `campaign_run.json` must accept `gate_ok` when precision is reported.

**Labels that must not drift:**
- the restart path is model-proven, not exercised on silicon;
- m9 timing measurements are inherited;
- host precision is reported, not gated, for the evaluation;
- training-lock replay checks hashes but does not refit;
- results are transaction-class results for the evaluated attackers, not device identification.

**Open items:**
- the paper stays frozen pending Dr. Lin;
- the deleted `DNP3_Implementation_Directive_492013014.md` in the working tree is Philip's to decide.

**Standing rules** are unchanged: main only; akekulip identity, no trailers; gated commits; push only on Philip's
word; hardware only through `run_block_frozen.sh` with restore_verify; evidence is immutable; never rerun for a pass.


Trust this section first, then the documents it links. Everything from section 0a down is history (the m5/m6 cycles of
2026-10-15/16) and is partly superseded. Written so a different model can continue without the conversation.

## 00b. (history) m10_03 state, 2026-10-18 morning

**Candidate.** `integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m10_03`, source
`d9b84fcc…`: m9_01 plus `transform_n_m10`. A stage-1 master RST restarts at stage 0 when the response claimed N's
cell in between (`count_busy[5]` counts restarts). N 12, E 12, T 11 stages on SDK 9.13.1 and 9.13.2, the same as m9_01.

**Where it stands.** Every item below is committed and pushed:

| gate | result | evidence |
|---|---|---|
| model gate (summary v3, dependency closures mandatory) | **PASS**, `d60d5dd00` | `m10_03/model_summary_v3.json`; contention attempt 07 413/413, abort 07 79/79 |
| earlier model attempts | 01–03 and 05 resolved; 04 and 06 **disclosed, unresolved** (simulator / packet-path stalls of unknown cause), each accepted only beside attempt 07; 06's disposition approved by Philip retrospectively | FAILURE notes in each `model_contention_m10_03_0N/`; `m10_03/DECISIONS_20261017.md` |
| freeze v3 | written, `ff179e740` | `m10_03/freeze_v3.json`: one candidate record, six Step 4 configs |
| silicon recovery (persistence graceful/RST, loss core, reconnect, held OPERATE) | **PASS**, restore verified after every block | `seg61_02/evidence/hw_campaigns/ctl_m10_*_01/`, `b286cf090` |
| restart path on silicon | **NOT EXERCISED** (interleave block NOT_EXERCISED; host offsets 4–17 µs against 0–5 requested) | `ctl_m10_interleave_950_01/` |
| claim table | written | `m10_03/CLAIMS_20261017.md` |
| Part 2 (four-arm timing grid) | **prepared only, not launched** | `m10_03/PART2_DESIGN_20261018.md`, `2ab3bc1f8` |

**Labels that must not drift.**
- **Restart path:** model-proven, not exercised on silicon.
- **m9 timing measurements** (switch-side 7 µs at the egress parser, host-observed p99 FAIL, isolation results):
  inherited evidence, not re-measured on m10_03.
- **Isolation cleanup deadline:** INDETERMINATE, argued not needed for correctness
  (`m10_03/ISOLATION_ARGUMENT_20261017.md`).

**Contention-harness changes this round** (`ctl_timing_01/model_contention.py` and helpers):
- the duplicate-OPERATE watch confirms a copy by direction, sequence and command payload;
- an inconclusive abort order is decided by T's own passes in the model log;
- a held abort counts only if T's admission of the response is observed;
- restart coverage comes from a log-triggered targeted section;
- a handshake that gets nothing back stops the whole run, and later cases count as not executed (Philip accepted
  this);
- the committed-path precondition is classified after each run.

Model-build trap: master and relay share **dev port 9**, so direction must be read from the frame. Bounded
diagnostics: `m10_03/diag_harness_fixes_01.README.md`.

**Part 2, prepared.**
- **Reconciliation:** the historical 5/10/15/20 ms were request-anchored ACK deadlines, so they map to `da`, not to D.
- **Grid:** `seg61_02/hw/part2_grid.py`, 10 conditions with one fixture delay of 5 ms. It adds a new check,
  readiness ≥ max(da, L + J) + gap + slack.
- **Configs:** 50 `part2_m10_*`. They are deliberately not `ctl_m10_*`, which names the supported-profile blocks.
- **Attacker:** `seg61_02/analysis/leakage_four_arm.py`. It uses campaign_v2's estimators, has a competence gate, and
  equals campaign_v2 exactly when restricted to two arms. The table comes from `four_arm_transactions.py`.

**Next actions** (each needs Philip):
1. Decide the Part 2 power: three blocks per condition give three folds.
2. Write a freeze naming the Part 2 configs. Freeze v3 refuses them.
3. Authorize the feasibility gate (`part2_m10_feas_*`, all ten conditions), then the campaign.
4. Optional, new scope: exercise the restart on silicon. That needs a sub-microsecond injector or a switch-side
   trigger.

**Read in this order:**
1. `m10_03/CLAIMS_20261017.md`;
2. `m10_03/DECISIONS_20261017.md`;
3. `m10_03/PART2_DESIGN_20261018.md`;
4. `m10_03/STEP4_PLAN_20261017.md`;
5. `m10_03/failure_analysis_20261017/README.md`;
6. `ctl_timing_01/supported_profile.json`;
7. the review directive `DNP3_Review_and_Completion_Directive_af7bd434.md` (repo root, untracked) and the session
   plan.

**Standing rules** (unchanged; see the repository CLAUDE.md):
- main only;
- commits as akekulip, through `gated_commit.sh`;
- push only when Philip says so;
- hardware only through `run_block_frozen.sh`, detached, with restore_verify;
- software endpoints only; no physical-relay OPERATE;
- no default promotion;
- never rerun to obtain a pass;
- evidence is immutable.

**Rig at end:** switch on production `case4_response_path` (restore verified after the last block,
`ctl_m10_interleave_950_01`).

**Earlier milestones, briefly** (details in `integration/evidence/rearm_01/STATUS.md`):
- **m6_07:** T's 32-bit readiness aliasing found (C1).
- **m7:** fixed T time base.
- **m8:** E places a held-ahead outstation RST.
- **m9_01:** N waits out a busy cell instead of dropping a master RST. Not qualified: ACK tail localized downstream
  of the egress parser; the reset race still lost the RST.
- **m10:** fixes that race.

---

HISTORY (2026-10-16 and earlier) below.


Everything below the line "HISTORY" is older and partly superseded; trust this section first, then the
documents it links. Written so a different model can continue without the conversation.

## 0a. (history) m6 continuation (from 72d85875b; started 2026-10-15 22:11 EDT)

Plan: `integration/evidence/rearm_01/PLAN_m5.md`, section "m6 continuation" (directive at the repo root,
`DNP3_m5_Continuation_Prompt_72d85875b.md`). m5_10 stays the immutable record. Progress:
`integration/evidence/rearm_01/STATUS.md` (newest first).

Outcome (2026-10-16 morning): successor `ctl_timing_01/evidence/m6_07` compiled and source-tested, **not run on
silicon** (hour-5 gate missed). Quiet isolation on m5_10 FAILED its verdict with delivery correct and restore
verified (drain test reads generator counters, not pipeline rejections). Contention probe offline only. Writing
package `stage_experiments/seg61_02/evidence/writing_packet_72d85875b/` (CLAIMS.md first).

Next action, in order: (1) classify the m6_07 model failure (`ctl_timing_01/evidence/model_contention_m6_07_01`, `sweep_SELECT_000ms`: a retried SELECT response lost with no counter) before freezing m6_07 (its N diff is reviewed);
(2) fix the isolation drain test to require the raw timer-stale counters to reach the old-token population before
the permit, and attribute STALE_BLOCKER by connection, then one block; (3) the 14-block qualification set on
m6_07 on a new port range (configs not yet built: sealed profile bfrt -> p4pp, CONTROL_TIMED_SOURCES,
build_candidate61_configs.py `ctl_m6_*`); (4) contention probe after switch rows for its tuple are authorized.

## 0. (history) m5 cycle (approved 2026-10-15)

**Plan:** `integration/evidence/rearm_01/PLAN_m5.md` (verbatim approved plan, with the full read-in-order file index).
**Progress (2026-10-15 evening, pushed through a6e4c4bef):** T0, S0, S1, S2 (m5_10 `b758c981…`, model: every driver passes) and S3 (offline) committed; S4 silicon run (STATUS.md, newest first): recovery and piggyback pass, repeated-SBO b1 qualified, b2/b3 rejected on the index-127 timing outlier; N contention gate clean.
**Next action:** S3's three silicon-safety fixes (restore deadline, 10 s pause option, Vision kill permission; WIP saved in the session scratchpad), then `ctl_m5_stale_tokens_950`. S5 waits for Philip: m5 timing qualification is not fully passed (outlier), so the plan's "after m5 correctness passes" precondition is not met.
**Open decisions for Philip:** RST refused after an admitted response (pre-existing m4 behaviour, ctl_timing_01/DESIGN.md m5); S3 drains old tokens before c2 instead of during c2/c3 (commit ed9907f89); whether to run S5 with the outlier unresolved.
Progress: `integration/evidence/rearm_01/STATUS.md` (newest first).

The five amendments that bind m5 (details in PLAN_m5.md "Design"):
1. **Generation accounting:** every `allocate` and register write on the retry path is traced; preferably a retry
   allocates an N generation only when it obtains the work cell; otherwise allocations are bounded, budgeted and
   exhaustion is tested.
2. **Incarnation isolation:** a retry carrying a different epoch or connection identity is dropped and counted before
   it can claim the cell or touch connection state; tested with RESET and same-tuple reconnect while responses wait.
3. **Budget from measurement:** retry budget chosen from the measured spacing sweep, competing connections,
   duplicates and RESET; exhaustion is a counted drop and a failed delivery objective. Success = zero
   switch-induced retransmissions and zero exhaustion drops on the supported workload.
4. **Strict validation:** the stage-0 exception to the port-68 deny gateway admits only the complete retry form
   (port, marker, reserved, budget range, epoch, identity); every other port-68 frame stays denied; mutation tests.
5. **No E side effects:** retries bypass E; mapper registers unchanged by retry laps; exact 61-octet image and growth
   on the eventual delivery.

Philip's constraints for this cycle: N-only change, E and T byte-identical to m4; retain the original failing race;
delivery across spacing, competing connections, duplicates, RESET and reconnect; qualify the exact compiled successor
before reconfirming shaping; never change timing gates or exclude outliers to obtain acceptance; report p99 and
maximum separately, and call the index-127 delay a "timing outlier of unresolved origin" until localized. Silicon
runs unattended on the overnight terms (software endpoints, `run_block.sh` + `restore_verify.py` per block, stop on
an unverified restore, no NIC-wide Vision change, no relay OPERATE). Splitting and default promotion are deferred.

Open decisions still Philip's: push (local commits after `d50ed9b78`); NIC/driver localization of the timing outlier;
m4/m5 as candidate; real-relay READ; promotion.

## 1. Where things stand

- **Repository:** `/home/philip/Projects/DNP3`, branch `main` only. All work through `d50ed9b78` is pushed to `origin/main`; the handover-doc commits after it are local until Philip says push (`git log origin/main..main`).
  Philip-owned uncommitted paths that must be preserved and never committed by you: `WORKING_NOTES.md`
  (append/prepend notes only), the deleted `DNP3_Implementation_Directive_492013014.md`, root audit/prompt/zip files.
- **Latest audit cycle:** `DNP3_9c4a2cfdc_Audit.md` + `DNP3_Next_Efficiency_Correctness_Prompt_9c4a2cfdc.md`
  (root, untracked). Overnight execution and results: **`integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/QUALIFICATION_9c4a2cfdc.md`**
  (read it fully). Plan with Philip's eight binding execution requirements: `integration/evidence/rearm_01/PLAN.md`,
  section "9c4a2cfdc audit: overnight plan (2026-10-15)". Status log: `integration/evidence/rearm_01/STATUS.md` (newest first).
- **Switch:** production `case4_response_path` running (verified 06:55 2026-10-15). No candidate is loaded; no
  default is promoted.

## 2. Builds (abbreviation X = integration/core/response_only_rearm/stage_experiments)

| build | path | source SHA256 | role |
|---|---|---|---|
| candidate61 | `X/seg61_02/evidence/full_04` | `1b2d62d1…65aa` | encoding reference (61-octet READ/SELECT/OPERATE), READ timed only |
| ctl_timing m3 | `X/ctl_timing_01/evidence/m3_01` | `c4819dba…9204` | SELECT/OPERATE CLRT timed, piggyback bound pb |
| **ctl_timing m4** | `X/ctl_timing_01/evidence/m4_01` | `35e896eb…79cf` | **current candidate**: m3 + IEEE 1815 Table 4-9 selection cancel/replace in N + fail-closed OPERATE lane exhaustion in T |

All three share E byte-identical (`a144cd30…1c10`); N11/E12/T11 on SDK 9.13.1 (local) and 9.13.2 (switch);
mirror guard PASS. Generator: `X/ctl_timing_01/generate.py OUT_DIR m4` (m1–m4 reproduce byte for byte; tests assert it).
Design: `X/ctl_timing_01/DESIGN.md` (m4 section at the end). Resource review: `X/ctl_timing_01/resource_review.py BUILD`.

## 3. Results that matter (details in QUALIFICATION_9c4a2cfdc.md)

- m4 model: all suites pass on the current drivers (`X/ctl_timing_01/evidence/m4_01/model_summary.json`).
- m4 silicon recovery: held OPERATE 350 ms, persistence graceful/RST, seven loss classes, protected reconnect PASS.
  **Stale-token isolation UNMET** (`candidate_isolation.py` window sized for candidate61's READ-only tokens; m4's SELECT
  blocker tokens lengthen the old batch; hypothesis recorded, not fixed).
- m4 piggyback qualification (3 blocks): **qualified**.
- m4 repeated-SBO qualification (3 blocks): **rejected**. Cause: exactly one exchange per timed connection near request
  index 116–127 whose ACK arrives ~1 ms late with the response on time — a **timing outlier of unresolved origin**
  (consistent with a delay after switch release, not localized; also in m3 and candidate61 data and on untimed
  traffic). Nearest-rank p99 at n=64 = the maximum, so it fails the 100 us gate. Retrospective exclusion only (decides
  nothing): without that exchange every arm ≤ 94 us. The gate was NOT loosened. **m4 is not fully qualified.**
- Asymmetric shaping (unchanged binary): ACK_HOLD 14,892 PPS, RESP/OP HOLD and all BLOCK 59,570 — **efficiency
  measured; correctness not passed (shared timing outlier)**: −19..−25 % internal frames, −18..−24 % octets per
  exchange, request→ACK +6..+50 us; pilot b2 fails SELECT CLRT on the full gate (S0 comparator: full gate, no exclusion; a new failure against base b2, while the same outlier fails baselines b1).
  Experimental; reconfirm on m5 only after m5 correctness passes.
  ACK_HOLD 3,723 screened only (−26 % frames, +125..+220 us). Zero-pause block robust.
- Open N limitation: ACK and response microseconds apart can busy-drop the response (single N work cell); TCP
  retransmission recovers it late and un-normalized. Model asserts the two known paths; never acceptance evidence.

## 4. Open decisions (Philip's; do not decide them)

1. The index-127 timing outlier of unresolved origin: authorize NIC/driver localization (Vision i40e; NIC-wide changes need explicit
   authorization), or rule on the gate.
2. Whether m4 becomes the candidate and ACK_HOLD 14,892 its default shaping.
3. Real-relay READ qualification; default promotion. Physical relay OPERATE is attended-only, always.

## 5. Ready next work (no new authorization needed for offline items)

- Adapt `integration/evidence/rearm_01/hw/candidate_isolation.py` for control-timed builds (old-token batch size /
  window), then rerun `ctl_m4_stale_tokens_950` (hardware: within the overnight-style authorization only if Philip renews it).
- Endpoint response-delay control so piggyback response availability can be set below/near/above pb (fixtures are
  integer-ms netem on the data path, producing separate-ACK exchanges; `protocol/hw_vepa/vision_run.py`).
- Optional offline: splitting analysis (61 vs 28+33 vs 28/19/14; audit table), residual request→ACK leakage note for
  Dr. Lin (request→ACK still tracks the fixture), tail observation-point map (Ubuntu 6.8.0-146 i40e vs upstream v6.8).
- Review suggestion not applied (needs recompile + full model rerun): move m4's new T `tin_verdict` OPERATE-exhaustion
  row after the `enabled==0` passthrough row (`X/ctl_timing_01/DESIGN.md`).

## 6. How to work here (commands)

```bash
cd /home/philip/Projects/DNP3
C4=defense4/timing/case4_architecture; E=$C4/integration/core/response_only_rearm/stage_experiments
# integrated suite (commit gate; must exit 0; 873 passed on 2026-10-15)
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider "$E/read_reencode_01/tests" "$E/seg61_01/tests" \
  "$E/seg61_02/tests" "$E/seg61_02/hw/tests" "$C4/protocol/hw_vepa/tests" "$C4/integration/evidence/rearm_01/hw/tests" \
  "$C4/integration/evidence/rearm_01/repeat_sbo_endpoint/tests" "$E/seg61_e_crc_01/tests" "$E/ctl_timing_01/tests"
git status --porcelain $C4/integration/evidence/rearm_01/candidate_endpoint   # must be empty after the suite
# model run (local tofino-model, no hardware): BUILD must have compile_local/out
python3 $E/ctl_timing_01/run_model.py evidence/m4_01 {control_timing|select_lifecycle|smoke|packets|rearm|dup|repeat} N --milestone m4 [--pb 300000000 for seg61_02 drivers]
# ('abandon' asserts m3's wedge and fails on m4 by design; select_lifecycle replaces it. N = a new attempt number; evidence is never overwritten)
# compile: local  python3 $C4/build.py SRC OUT --compiler /home/philip/bf-sde-9.13.1/install/bin/bf-p4c
#          switch python3 $E/ctl_timing_01/compile_switch_orchestrator.py BUILD_DIR SOURCE_SHA256
# configs: python3 $E/seg61_02/hw/build_candidate61_configs.py   (needs compiler out/ trees; existing configs must stay byte-identical)
# one hardware block (only with Philip's authorization): plan, run --apply, independent restore check; exit 2 = STOP everything
bash $C4/integration/evidence/rearm_01/hw/run_block.sh candidate_campaign CONFIG RUN_ID --arms ... --fixtures ...
# analysis
python3 $E/seg61_02/analysis/m4_summary.py -o out.json
python3 $E/seg61_02/analysis/shaping_pilot.py --pair BASE_RUN PILOT_RUN -o out.json
```

## 7. Rules and traps (each cost time)

- Commits: author and committer `akekulip <akekulip@gmail.com>`, **no Co-Authored-By trailer**. Never push, force-push or
  rewrite history without Philip saying so in the current conversation. Do not edit `paper/rewrite/` or frozen trees
  (`defense4/timing/implementation/`, campaign_v1/final_read_sbo raw_pcaps). Codename must not appear in files.
- Barred tools here: `remove-ai-marks`, watermark/detector-evasion tools, the generic humanizer.
- Never `git add -f` evidence (pulls ignored `*.out`). Logs > 50 MiB stay untracked and go in `UNTRACKED_LARGE_LOGS.sha256`.
  `*_token*` is gitignored: stale-token configs/evidence need the narrow exceptions already in `.gitignore`.
- Any new runner/verdict path must pass `control_timed`, `piggyback_bound` and `gen_exhausted_outcome` from the build to
  `checks.evaluate`/`evaluate_switch` — four paths missed this on 2026-10-15 and failed m4's first recovery runs.
- New standards artifacts are schema v3 and must carry `observed.objectives`; p99 is nearest-rank everywhere in gates.
- A model PASS counts only for the source SHA and driver SHA recorded in its `launch_command.json`.
- The model's N laps are slow (ms): the ACK/response race and capture windows behave differently from silicon.
  Reconnects in model drivers need increasing client ISNs (N refuses an older SYN as stale).
- After every hardware block run `rearm_01/hw/restore_verify.py` (run_block.sh does it); on failure stop all hardware,
  preserve state, follow `seg61_02/hw/RUNBOOK.md`. Vision restore baseline: `rearm_01/hw/restore_baseline/vision_state_20261015.txt`.
- Hosts: switch `decps@10.10.54.81` (SDE 9.13.2), Vision `decps@10.10.54.19`; repeated-SBO endpoint dir
  `/home/decps/pad58b_repeat_sbo_20261014c`, recovery endpoint dir `/home/decps/pad58b_rearm_controls_20261012`.

---

HISTORY (pre-2026-10-15 handover text follows unchanged)

# Case4 continuation checkpoint — 2026-10-07 (size pattern updated 2026-10-08; T's status corrected same day)

Resumed at the user's request from commit190a4c603 and [lab checkpoint](integration/evidence/rearm_01/PAUSE.md). Candidate55 fully compiles on both SDK versions: N12/E12/T12, mirror guard PASS,42 source tests and private compiled-model80/80+382/382 PASS. First hardware attempt stopped at installer dry-run before traffic; all five baseline restorations passed. A candidate-only provenance parser port-check repair passes120 helper tests; review/retry and silicon qualification remain pending. Root remains the sole hardware owner.

Current resume status (2026-10-12): candidate55 graceful/RST same-tuple hardware gates and four-arm smoke PASS; each restoration passed. Candidate56 preserves all counters while reducing stages to **N11/E12/T11** on local9.13.1 and installed9.13.2. Mirror/artifact checks and **519/519 compiled-model assertions PASS**; silicon qualification is separate and active. First56RST attempt stopped before traffic on an omitted Vision transitive helper; failed evidence and all five successful restores retained, deployment repaired. A fresh56RST retry is active. Separate bounded10s endpoint fixture is built and pinned; old-token gates now require split READ24/OP23 packet attribution, complete old batches, unchanged current authority and strict zero rejection suffix after the quiet window. Helper tests142PASS. Old external/token and seven-loss hardware gates remain pending. Counter-elision T10 is excluded from integration. Root alone owns hardware; frozen baseline, candidate55, historical evidence and paper preserved. No push.

**Read first, in order:**
1. [`integration/INTEGRATION_CONTRACT.md`](integration/INTEGRATION_CONTRACT.md) — the decision record
   for the whole timing+size integration effort.
2. [`integration/size/SELECTED_PATTERN.md`](integration/size/SELECTED_PATTERN.md) — **Option B′
   (`framework/size/case4_pad58b.py`) is the active pattern, confirmed production-context compatible
   against the real pinned OpenDNP3 master/outstation in the mocked endpoint-gate harness (no TCP
   sockets).** Options A and B both failed the same gate first — see the document's history for why.
   CONTROL's 19-byte gap closes with one G41V3 object at qualifier `0x28`, 2 points; READ's 9-byte gap
   closes with three `ALL_OBJECTS`/qualifier-`0x06` headers, no point data. **An external review of the
   commit that first reported this found the original 62-assertion gate's own key checks did not
   actually require real data delivery** — the READ recovery assertion could pass even if the padded
   response delivered zero points, by the test file's own admission. The gate has since been
   strengthened and re-run to real completion: **165/165 assertions pass**, source-hashed at
   `framework/size/endpoint_gate/context_evidence_pad58b_01/`. CONTROL gets a real OPERATE and a
   software-counted actuation in the mock command handler (not a hardware measurement); READ delivers
   all 23 real points. **This clears the software model only, in the mocked (no-sockets) harness — Phase
   D's P4 realization is unstarted, no real-TCP-socket gate exists yet, and nothing here says it fits the
   ASIC's own constraints.** Standing lesson: no size candidate is done until it clears `endpoint_gate`
   with assertions that actually require what they claim — a passing summary count is not sufficient
   either, as this same gate just demonstrated.
3. [`integration/read/TIMING_QUEUE_MIGRATION_STATUS.md`](integration/read/TIMING_QUEUE_MIGRATION_STATUS.md)
   — T's queue-resident timing role (`read_queue_timing.p4`). **An external review of the same commit
   found three real gaps the original 18-test interpreter suite missed**: a missing `Mirror()` emission
   (the interpreter synthesizes clone/blocker behavior the P4 doesn't implement — still open, queued
   next), an OPERATE deadline that was reused across generations (**fixed**, one-line change, 133 tests
   now, 132 passing + 1 new expected failure for a separate, lower-severity RESET-near-clock-wrap defect
   found as a byproduct), and a `wgen` field parsed but never read (**investigated and found to need no
   fix** — N's real implementation already prevents a stale response from reaching T through the real
   path; this trust boundary is now pinned by an explicit test rather than assumed). The real `bf-p4c`
   compile (both local SDK 9.13.1 and the switch's installed 9.13.2, compile-only) still hits the same
   reproducible internal compiler crash in PHV allocation — five independent attempts now, including
   today's OPERATE fix, none changed the signature at all. Read the document before attempting a sixth.

**Separately, read [`integration/core/M_RECIRCULATION_VERDICT.md`](integration/core/M_RECIRCULATION_VERDICT.md).**
M's extended ACK/window mapper does not fit in 12 ingress stages. Eight compiler-verified attempts
(m13 through m23, `LEDGER.md`) narrowed this to a genuine four-register hardware placement limit;
the most promising fix (a second ingress pass via recirculation) was implemented in full and refuted
by the compiler itself, not just argued. The two remaining options (move the registers to egress, or
redesign M from scratch around this limit) are each a real project, not a quick follow-up, and the
verdict document asks Philip to choose before more engineering time goes into either. Everything
below this point continues to describe work that does NOT depend on that decision.

Continue directly from [PLAN.md](PLAN.md#execution-checklist--2026-10-07).
Core transport is the active step: ACK/window normalization, SELECT response,
then OPERATE padding/carving and replay. Full Case4 remains incomplete.

SDK constraint: use the switch's existing version; no updates. Read-only
inspection confirms `p4c9.13.2 (SHA:1baf055)` at
`/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf-p4c` on `decps@10.10.54.81`.
`installed_sdk_build.py` compiles in private temporary directories without chip
activation or software changes. Older local9.13.1 results remain development
evidence, not installed-version qualification.

## Accepted first SELECT milestone — existing switch SDK9.13.2

Normal100, zero0 and wrapped0xfffffff0 each pass6/6 in the isolated SDK9.13.2
software model on the switch CPU. External handshake and SELECT35 produce one
exact109-byte Ethernet frame with55-byte padded payload. Independent IPv4/TCP
checksums and every DNP3 CRC pass. Genuine packet-driven completion leaves
N9/M4/E4; no ownership/cache/register proof presets. This covers first SELECT only.
[Current verification](integration/core/ordinary/evidence/installed_select_verification_01/verification.json)
binds saved raw logs, driver, source copies, configuration and compiler artifacts.

| Device0 role | Exact source SHA prefix | Installed-SDK build | Ingress / egress | Critical path |
| --- | --- | --- | --- | --- |
| N + final emitter, pipe0 | `ca695e97ea67` | `installed_nf_05` |12 /4 |11 |
| M preparation/activation, pipe1 | `c8820a1f7f14` | `installed_m_baseline_01` |10 /0 |9 |
| E cache + typed bridge, pipe3 | `dae2efee6c5e` | `installed_e_01` |1 /10 |7 |

Each pipe has its own12 ingress stages: N has none spare, baseline M has two,
and E's ingress bridge has11. E's cache consumes10 egress stages. Pipe2 remains
reserved for T. Recirculation reuses stages and adds passes; it does not add stage
capacity. These counts do not establish extended mapper fit.
Fresh SDK model traces confirm19 SELECT ingress visits and18 private TX records
totaling2346 Ethernet bytes, excluding4-byte model trailers; the internal24-byte
completion header and unmeasured physical costs remain separate. Fresh source
suite71/71 and static-scanner3/3 pass. No SDK updates or chip activation.

## Historical first SELECT milestone — local SDK9.13.1

External SYN/SYNACK/ACK then SELECT35 produce one exact109-byte Ethernet frame
with55-byte padded payload in the isolated local model. Genuine completion leaves
N Work9, M4 and E4; no ownership/cache/register proof presets were configured.
Normal100, zero0 and wrapped0xfffffff0 coordinates each pass6/6 checks:
[verification and packet identities](integration/core/ordinary/evidence/split_verification_01/verification.json).
Lead freshly reran52 source/config tests successfully. IP/TCP checksums and DNP3
CRCs independently pass for all three retained endpoint frames.

| Same modeled device0 role | Exact source SHA prefix | Build | Ingress / egress | Critical path |
| --- | --- | --- | --- | --- |
| N + final emitter, pipe0 | `610d129d7446` | `nf_02` |12 /4 |11 |
| M preparation/activation, pipe1 | `c8820a1f7f14` | `m3_01` |10 /0 |9 |
| E cache + typed bridge, pipe3 | `dae2efee6c5e` | `e3_02` |1 /10 |7 |

All three programs loaded together using
[the source-bound split configuration](integration/core/ordinary/evidence/model_config_split_01/bindings.json).
Pipe2 is reserved for the T join. N still uses all12 ingress stages; M now has two
spare stages. NF's normal32 PHV is62/64, SALUs4/4 at7–9 and table IDs16/16
at1 and10. M peaks at2/4 SALUs and5/16 table IDs. E image SALUs occupy4/4
at4–6; retain the full image instead of narrowing identity checks for capacity. Failed coupled N/E14-stage compositions are retained, not fit claims.
The split retains all14 image banks, full owner/epoch/generation checks, actual
publication/completion returns and a full32 current-generation emission receipt.
Component sources and rendering are in [ordinary/README.md](integration/core/ordinary/README.md).

Observed first-SELECT model accounting:19 ingress visits,6 service egress visits,
18 private TX records totaling2346 Ethernet bytes excluding model trailers,
plus an internal24-byte completion header. This is functional model accounting;
TM/fabric and physical wire service are not measured. Successful runs omit the
model's `--int-port-loop` flag; front ports remain cold-added with loopback NONE.
Failed front-loop attempts and the SYN-only controlled comparison are preserved.

## Installed-SDK transport checkpoint

The switch's existing9.13.2 compiler now builds the extended N/F source
`ca695e97…b950c` in `installed_nf_05`:12 ingress/4 egress, critical11.
Source/snapshot/compiler/artifact checks pass. This reduces the failed15-stage
extension to12 by fusing dependent writers and mutually exclusive result tables,
then moving private-admission refusal before Work/state access. Full identity,
FIN quarantine and malformed-return checks remain. N still has no spare stage.
The exact E cache also builds in `installed_e_01`:1 ingress/10 egress, critical7.
All compiler pipeline contexts, including `p0`, pass the corrected static-entry
capacity scanner; its3 CLI regression tests pass after2 witnessed failures.
The first-SELECT-only model result above now covers this exact N, baseline M
and E on9.13.2. It does not qualify reverse normalization or the full transport.

Fresh source regression passes71/71, including19 focused transport methods and
168 independent ACK/window pairs. The readonly M path snapshots actual generation
and owner plus actual full32 boundary/position in a20-byte typed record, then
independently rereads full generation/epoch/owner/phase and BOTH coordinates in a
second visit before external release. The source-only paired-coordinate forgery
witness rejects even when boundary-position remains35; removing the two reread
comparisons makes its retained negative canary fail. M10/M11 failed bank placement.
M12 (`deceea36…94cd`, next14) still fails PHV allocation with36 unallocated slices;
it has no fit/model claim. Preserve failed logs and freeze each replacement.
The baseline10-stage M in the first-SELECT table has no ACK/window mapper.
Latest source next15 (`081b4122…fea25`) moves both full32 coordinate comparisons
inside readonly scalar actions and requires both genuine grants. Reviewer approves
source only; fresh71/71 tests pass. Installed M13 resolves the PHV failure but
still fails table placement with no more placeable tables. Inspect that dependency
before another change; unused M egress arithmetic is a possible bounded alternative,
not an implemented or accepted layout.

2026-10-07 continuation: both diagnosed stage-fit fixes (role-dispatch flattening, then
register co-location hoist of the read-only `inspect_reservation`/`context_check` halves) are
now implemented in the real generator (`transport_candidate_next17/m3.p4`, sha
`6788aa92…93a6`), not a scratch copy, and still do not fit. Fresh regression across every suite
this session has used (`ordinary` 71/71, root `tests` 33/33, `connection/binding` 84/84,
`controller` 17/17, `core/harness` 42/42, `core/m` 33/33, `read` 103/103) stays green. Local
9.13.1 compile (`evidence/stage_fit_m17_01`) improves the dependency-graph critical path 9 -> 8
but still FAILS table placement; the compiler's own placement log now names the exact
remaining constraint ("dependency between inspect_reservation_t_0 and activation_reservation_t_0
requiring more than one stage") -- `Ingress.reservation`'s single-stage pinning is not resolved
by hoisting only the role==1 read, because `activation_reservation_t` (role==2's
`retire_reservation`) and `reserve_t` (role==0, deep in the native path) still touch the same
register far later. A parallel, now-explicit conflict exists on `Ingress.ledger_position`
(`mapping_position_t` vs `activate_position_t`) and a further one on `Ingress.ledger_tag`
(`activate_geometry_t` vs `activate_ledger_t`). `ledger_position`'s write side has no read-only
half to extract, unlike `reservation`'s. See `LEDGER.md`'s 2026-10-07 "Both diagnosed fixes
implemented" entry for the full compiler quotes and unplaced-table list. No mapper fit, model,
SDK update, hardware action or push.

2026-10-07 continuation 2: merged `inspect_reservation_t`/`activation_reservation_t` into one
table (`transport_candidate_next18/m3.p4`, sha `fccac9016d…905a4`), keyed on
`(role,enabled,profile)` so `Ingress.reservation` has exactly one apply() site instead of two --
this removes m17's named wall (`inspect_reservation_t`/`activation_reservation_t` no longer
conflict; confirmed 0 occurrences in the placement log). Needed hoisting
`reference_differences_t`/`activation_identity_t` to the same early call site (pure header math,
no new dependency); `qualify_context_t`/`claim_once_t`/`activate_geometry_t`/`activate_position_t`/
`activate_ledger_t`/`dirty_return_t`/`terminal_result_t` are unchanged from m17. Fresh regression
(same 7 suites as m17's entry) stays green. Compile
(`evidence/stage_fit_m18_01`, local 9.13.1, exit 2, FAILS): critical path **10** (worse than m17's
8 -- `activation_reservation_t` now carries a real dependency it didn't have before). The sole
repeated, final "requiring more than one stage" conflict across every retry log is now
`dependency between activate_geometry_t_0 and activate_ledger_t_0` -- the task's named
`Ingress.ledger_tag` conflict. `Ingress.ledger_position` does not appear as an active blocker in
this attempt. A broader variant that also hoisted `claim_once_t`/`activate_geometry_t`/
`activate_position_t`/`activate_ledger_t`/`dirty_return_t`/`terminal_result_t` the same way was
tried, tests passed, but compiled to critical path **14** with a NEW conflict against `construct_t`
(role==0's native admission chain, out of scope) -- reverted, not in `transport.py`. Resolving
`ledger_position`/`ledger_tag` properly needs hoisting `claim_once_t`'s own MUTATION
(`activation_receipt`) ahead of its validation gate, which this task's gating-preservation
constraint rules out without a larger restructuring of role==0's admission chain (already deferred
above); not attempted further. See `LEDGER.md`'s 2026-10-07 "Applied the same merge technique to
the m17 wall itself" entry for the full compiler quotes, unplaced-table list and the reverted
variant's evidence. No mapper fit, model, SDK update, hardware action or push.

Source-counted ACK mapping uses N5+M2 ingress visits and408 private Ethernet bytes;
response57 uses the same7 visits and750 bytes. Endpoint54/111 bytes are separate.
These counts remain unmeasured until the exact installed-SDK model runs.
Source parser consumption is bounded by153 bytes across roles; the20-byte snapshot
with111-byte response consumes147 including intrinsic/port metadata. No compiled
parse-depth claim. Next: obtain extended M fit, load that exact9.13.2 N/M/E split,
compare external
normal/zero/wrap ACK/window and uncarved57 response frames, then continue OPERATE.

## Remaining core work, in execution order

1. ACK/window inverse before N association, including inside-insertion clamps,
   both edges, zero-window and full32 wrap; completed SELECT owner18 and its57-byte
   matching response. Avoid the older N response's second20-byte subtraction.
2. **SUPERSEDED 2026-10-08 by `integration/size/SELECTED_PATTERN.md`**: this item originally read
   "OPERATE 35→55, matching 57-byte response carved into exactly ordered 28/29, both insertions, every
   subsequent packet mapped, sender-driven cached-tail repair." The selected pattern instead targets a
   shared 49-byte pre-carve payload split `[28,21]` for both SELECT and OPERATE, via a request-side
   qualifier-rewrite codec (`0x28`→`0x17`, count 1→2) rather than the separate-header insertion this item
   described — the old 55/57 separate-header codec (`case4_padding.expand_control()`) is kept as a
   working reference and as the documented fallback (Option B, 58-byte uniform pad) if the qualifier-
   rewrite codec fails endpoint-compliance validation, but it is not the current target.
3. Actual READ/T timing join and current-association OPERATE deadlines; finite
   fallback, independent heartbeat and genuine credits.
4. Post-M cancellation, duplicate/stale emission model witnesses, loss/lifecycle,
   fragments/resegmentation, reset/FIN/reconnect/exhaustion and complete retirement.
5. Complete exact9.13.2 offline build/model/schema/controller inventory and rollback
   package. The qualification registry stays empty until the complete target passes.

Full transport, timing and hardware gates in [PLAN.md](PLAN.md) remain unchecked.
The current18 model checks qualify first SELECT only; the71 source tests do not
qualify the mapper on the SDK model. Earlier
590,976-case results include no-leak-only branches and are not that many full
state/packet equivalences. Original N/T prerequisite model evidence is retained
with its own exact sources; it does not qualify the new full target.

## Continuation boundaries

Use one continuing implementer and one bounded reviewer. Lead integrates and
commits on `main` as `akekulip <akekulip@gmail.com>` for author AND committer,
without contributor trailers. No push. Preserve unrelated `CLAUDE.md`, frozen
sources/evidence and the paper. Local isolated model/source work is authorized;
live loading and physical port/TM/PRE/mirror/pktgen changes or traffic retain their
separate gates. Physical OPERATE is attended-only. No hardware action occurred.

## Historical continuation notes

The following notes retain earlier identities and limits. Their old words
"current" and "not yet" describe those checkpoints; the accepted split milestone
above and [PLAN.md](PLAN.md) define the present execution state.

The following continuation details retain pre-review historical identities;
the current facts above and the linked PLAN supersede their role and completion claims.

**Resume from the [core functionality and testing plan](PLAN.md).** This checkpoint replaces the
2026-10-06 one in full: historical step1/2 prerequisite results below do not close
the current connection/timing acceptance gates; step3 remains unfinished.
The complete target is still absent (no 9.13.2 build, no hardware run); everything here is
source-fragment, whole-program-harness or local-Tofino-model evidence, never hardware-measured.

Historical base: `388f78a33`; current base is stated above, branch `main`, unpushed. Work directly on `main`; preserve frozen sources,
evidence, the paper and unrelated local changes. Lead alone commits, `akekulip <akekulip@gmail.com>`
as author AND committer, no contributor trailers. This checkpoint does not authorize a push or any
hardware action (physical OPERATE is attended-only per repo `CLAUDE.md`).

## What changed since 2026-10-06

- **A restricted N source packet harness exists**: `integration/core/harness/` runs the parser,
  ingress control and deparser of a generated TNA source, with recirculation through the private
  return port, up to 8 passes. It is source-level (a restricted interpreter), not the target; its
  README says so. It does not implement the composed M/T/egress/TM path. Tests: `integration/core/harness/tests` (`python3 -m unittest discover -s
  integration/core/harness/tests -p 'test_*.py'`, 42 tests).
- **The local Tofino-1 model runs** inside `unshare -Urn` with an LD_PRELOAD pagemap shim (DMA
  physical addresses are otherwise unavailable to an unprivileged process). Setup, the shim, and a
  reusable launcher/driver are in `integration/core/launch_model.sh`, `integration/core/
  model_driver.py`, `integration/evidence/model_02/RESULT.md`. This is **functional** evidence
  only: the model's clock is not wall time, and it is not hardware. It has independently verified:
  validator, forward/reverse mapping, the selected-wire composition, cross-pipe forwarding
  (4-pipe probe, `model_28`), the e2e mirror, and the packet generator.
- **Native connection binding (`integration/connection/binding/`)** was restructured (a merged
  guard table, banks keyed directly, folded event rows) to fit stage limits. The
  historical590,976-case grid reports zero failures, but includes guard-miss
  branches that check only private-header refusal; it is not590,976 full state/
  packet equivalences. READ is outside that grid and has separate invariant and
  direct tests. The frozen oracle is `tests/oracle_35bf9aa3_native_binding.p4`.
  The baseline also carries the step-1 retry/ACK forwarding fix,
  READ kinds 9 (request), 10 (ACK), 11 (response) with a `tev` handoff, the step-3 OPERATE-response
  exchange with per-exchange ACK offset, busy-WorkRecord drop-and-count, whole-segment-resend
  counting, and fixes for three real bugs the model/review found: an epoch-0 endless-recirculation
  wedge, a guard-miss private-envelope leak, and a flow-miss WorkRecord pin. **Previous baseline: `native_18`,
  source sha `642dfe54…`, 12 of 12 ingress stages, no spare stage.**
  **Correction (found by the 2026-10-07 acceptance audit): the 68/71-step model agreement
  (`model_24`–`model_27`) ran against `native_11` (sha `c2352572…`), one commit before the
  flow-miss fix and two before the port renumbering. `native_18` itself carries only a bare
  `primitive_compiled` manifest — it has NOT been loaded on the model or diffed against the
  harness. Do not read "model-verified" as applying to the committed `native_18` source until
  that rerun exists.**
- **A separate READ timing role** `integration/read/read_timing.p4` (copy-evolved from the
  `held_timing_expected_probe.p4`; the probe itself is untouched) implements D_A-parametrized
  ADMIT/hold/release/fallback/policy-off/reset, checked against an independent schedule oracle
  `integration/read/join_reference.py`. **Previous baseline: `read_timing_05`, 12 of 12 ingress stages.**
  **Correction (same audit): the one passing held-path model run (`read_timing_model_05`) was
  launched against `read_timing_04` (sha `01b93f01…`), not `read_timing_05` (sha `d2b35563…`,
  the port-renumbered current source, different hash). `read_timing_05` has not been run on the
  model either.**
- **A step-3 design note** `integration/core/STEP3_DESIGN.md` places roles across Tofino-1's four
  pipes: N (connection) pipe 0 ingress, M (padding/mapping/carve, not yet built) pipe 1, T (timing)
  pipe 2, pipe 3 reserved for step 4. The model's cross-pipe probe confirms the placement is
  physically possible; it does not confirm the pipe-0/pipe-1/pipe-2 port numbers until gate
  G-PORTS runs on the switch (`integration/evidence/model_28/PORTS_PROPOSAL.md` has the current
  device-port table; `ports.p4` and `read_timing.p4`/`native_binding.p4` already use it).
- **A resource canary for role M** (`integration/core/m/m_skeleton.p4`) compiles the mapping,
  geometry and ledger core at exactly 12 of 12 ingress stages in pipe 1, with sequence translation
  checked against the independent transport oracle (`framework/size/case4_transport.py`). The full
  M (padding construct, descriptor build, carve decision, exact-byte replay) is **not yet built** —
  see "Open / stopped" below.

## Open / stopped

- **Role M beyond the canary is unfinished (plan step3).** Task1 only normalizes
  parser/apply receiving ports196/197. The historical canary occupies12 stages;
  current admission/replay repairs fail15 stages and require protected staged integration;
  actual35→55 production, descriptor/carve decisions and exact replay must be
  integrated and measured before any complete-target claim. Earlier planning
  interruptions remain historical evidence, not a qualification result.
- **The supported-tuple catch-all** (an unparsed-but-matched IP length forwarded natively) needs
  M's mapping-only path and is a documented gap in N until M exists.
- **Foreign-epoch client/server stores and terminal leakage are repaired in Task1.**
  The exact current build stays within12 stages; see the current evidence index above.
- **Step 4 (loss/lifecycle, fragment assembly)** is not started; the old assembly layouts
  (`integration/assembly_passes/REPORT.md`) still fail PHV and were not revisited this session.
- **Step 5 (qualification: 9.13.2 build, schema/inventory, hardware package)** is not started.
  `candidate_bringup.py`'s SDE path (`SETUP_DIR`) and controller registry are from the earlier
  framework track and have not been re-verified against the Case 4 sources.
- **No hardware action of any kind occurred.** Every verified claim above is source-fragment,
  whole-program-harness, or local-model evidence; the model's own clock is explicitly not timing
  evidence (`read_timing_model_07`, `model_02/RESULT.md`).

## Reproduce

From this directory:
```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s integration/connection/binding/tests -p 'test_*.py'
python3 -m unittest discover -s integration/controller/tests -p 'test_*.py'
python3 -m unittest discover -s integration/core/harness/tests -p 'test_*.py'
python3 -m unittest discover -s integration/core/m/tests -p 'test_*.py'
python3 -m unittest discover -s integration/read/tests -p 'test_*.py'
```
Compile a changed candidate to a NEW evidence directory with `build.py`; never overwrite retained
evidence. `build.verify_evidence` checks source/compiler/schema identity. `python3 integration/
core/scan_static_entries.py <out>` catches a table whose const entries exceed its declared size
(the defect that stopped `native_04`/retained `handshake_14` loading on the model). The local
model is driven via `integration/core/launch_model.sh` (see `model_17/RESULT.md` and
`model_28/RESULT.md` for usage and what each prior run proved); it needs `unshare -Urn` and the
pagemap shim built once (`integration/evidence/model_02/shim/`).

See `LEDGER.md` for the full dated history of this session's findings and fixes.

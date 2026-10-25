## Active override — 2026-10-25, response-ready timing v2

Follow root plan.md and WORKING_NOTES.md. Philip removed the exchange deadline. ACK waits for matching
whole response, ACK releases once, response follows after D=5/10/15/20 ms. J remains 2.4 ms. Drop validated
request retries only while their original request or response is retained; otherwise allow TCP recovery
without new admission/growth/J. FIN/RST/epoch cleanup; no timing fallback. Candidate c67 compiles within all resource bounds; its runtime gate is in progress.
c62 v1 strict model passed 694/694; its 500 ms deadline is superseded. No successor hardware run yet.

# Active code map: the two-READ size and timing candidate

Claude continuation: repository-root [plan.md](../../../plan.md) and
[CLAUDE_HANDOVER_20261024.md](../../../CLAUDE_HANDOVER_20261024.md). c52 is the selected candidate (model gate passed; physical set 23-31 ran; reference 772/772; timing fails 100 us; J unproven; FIN recovery open).

One page for finding the code that is in use now. Status as of 2026-10-24. The single
status file for the current run is `STAGE/read_complete_01/CURRENT.md`; the dated history is `STATUS.md` in
the same directory and the full record is `COMPLETION_RECORD.md`.

Abbreviations used below (all paths from the repository root):

```sh
ARCH=defense4/timing/case4_architecture
STAGE=$ARCH/integration/core/response_only_rearm/stage_experiments
HW=$ARCH/integration/evidence/rearm_01/hw
PY312=${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}   # Python 3.12; system python3 is 3.8
```

## Candidates

| build | what it is | state |
|---|---|---|
| `m12p_c52_sdk9132` | c51 plus relay FIN+PSH+ACK accepted as FIN (FIN flag terms 8w17&&&8w0xf7, parser row, short_shapes twins) | model_gate_passed (16 drivers); physical 23-31: reference 772/772 (blocks 24+31, ledger), smoke/loss_mixed/graceful/held OPERATE pass; loss_full t0 target miss; RST/reconnect fail switch gate on late-first-READ fallbacks; timing fails 100 us; J unproven |
| `m12p_c51_sdk9132` | c50 plus 8 qualified half-closed RST first_event rows | model_gate_passed (16 drivers); physical smoke rc0, reference 772/772 rc0, loss_full rc0, loss_mixed 4/7, persistence aborted (Vision outage); timing fails 100 us |
| `m12p_c50_sdk9132` | c49 plus guarded bounded FIN owner-phase restart | compiled/reviewed within limits; exact fin_busy193/193 across3connections; final16-driver gate and all padded physical runs pending |
| `m12p_c49_sdk9132` | timestamp relay45/49 control profile with canonical constant keys | installed-row readback exact; diagnostic30/30; relay_sbo1085/1085; busy-FIN62/70 failure retained |
| `m12p_c51_sdk9132` | proposed qualified half-closed RST admission | DOES NOT EXIST; root plan.md gives counterexample, eight-row proposal, alternatives and tests |
| `m12p_c30_sdk9132` | relay READ91/134→141/158; legacy software SBO37→61 | READ compiled-model1332/1332; corrected control_timing415/415; no padded physical relay qualification |
| `m12p_c31_sdk9132` through `m12p_c48_sdk9132` | integrated whole49→60 relay SBO, timestamp successor attempts | failed compile/static attempts through46;47/48 compiled then exposed provenance/constant-key runtime defects, retained |
| `m12p_c25` | two-READ build: mixed READ 91 -> 141, full integrity READ 247 -> 271, SELECT/OPERATE 37 -> 61 | model gate passed; on hardware the padding was byte-exact (campaign 02) and timing precision FAILED; recovery blocks not run |
| `m12p_c26` | c25 plus a behavior-preserving resource reduction (`--reduce`; pipe-1 egress 7 -> 4 stages; N/E/T 12/12/11; both SDKs) | model gate passed (counts equal to c25's); not frozen; no hardware. See COMPLETION_RECORD section 0a |
| `m11_09` | the four-arm build behind the manuscript evaluation `eval_m11_09_20261018_02` | frozen; the paper's evidence |

The timing failure's cause is not located. The earlier "receive-idle-dependent delay into Vision" localization
was withdrawn in 4a0b0fc56 because its metric was circular (it counted the transit it was meant to explain);
see `STAGE/read_complete_01/evidence/timing_reanalysis_20261022/README.md`. IEEE 1815 conformance was not
audited in this run.

## The path, stage by stage

| stage | code | notes |
|---|---|---|
| 1. generator | `STAGE/m12_fullsize/make_m12.py` (entry) -> `m12_fullsize/m12gen/{build,common,mapper,read_policy,segmented,two_read,relay_sbo,relay_ts}.py` | legacy identities preserved; actual relay selected by --relay-sbo --relay-ts |
| 2. P4 source and profile | `STAGE/ctl_timing_01/evidence/m12p_<id>/{response_only.p4, response_only.inputs.json, supported_profile.json}` | constants from `STAGE/read_complete_01/vectors/` (`derive.py`, `derive_two_read.py`, `make_two_read_templates.py`) |
| 3. compile | `$ARCH/build.py` (local SDK 9.13.2 at `~/bf-sde-9.13.2`, a copy of the switch's install; one compile since 2026-10-23) | output `compile_local/`: the model tests it and the switch loads it (`freeze_gate.loaded_compile`). Builds before m12p_c29_sdk9132 used local 9.13.1 plus `compile_switch_orchestrator.py` (`compile_switch_9132/`, the loaded one) |
| 4. model gate | `STAGE/ctl_timing_01/run_model.py` (drivers in `ctl_timing_01/model_*.py` and `STAGE/seg61_02/model_*.py`), verdict `ctl_timing_01/model_summary.py --v3` | dependency closure recorded by `ctl_timing_01/record_closure.py` |
| 5. block configs and freeze | `STAGE/read_complete_01/hw/make_sel751_configs.py` (physical relay) / `make_two_read_configs.py` (historical software) -> `hw/config/rc01_m12p_*.json`; `$HW/freeze_gate.py` -> `freeze_v3.json`; `read_complete_01/hw/make_hw_manifest.py` -> campaign manifest | a block runs only through `$HW/run_block_frozen.sh`, which checks the freeze first |
| 6. hardware supervisor | `$HW/evaluation_campaign.py` (init/start/status/resume/stop-after-current/reconcile); per block `run_block_frozen.sh` -> `run_block.sh`; restore check `restore_verify.py` | physical endpoint: SEL-751 `.7:20000`; guarded master: `$ARCH/protocol/hw_vepa/relay_master.py` and `active_harness`; historical software endpoints: `$ARCH/integration/evidence/rearm_01/repeat_sbo_endpoint`; library: `$ARCH/protocol/hw_vepa` (`campaign.py`, `wire_check.py`, `clrt_check.py`, `standards.py`); live testbed ownership state in `~/.local/state/dnp3-evaluation/tofino1-testbed/ownership.json` (never hand-edited) |
| 7. readout | `STAGE/read_complete_01/analysis/hw_read_readout.py` | independent, fail-closed, built from the frozen config rather than the run's own records |
| 8. reproduce | `STAGE/read_complete_01/reproduce.sh` | offline only; never loads the switch |

Software endpoint and policy code: `STAGE/read_complete_01/{software,policy}`. Evidence per run lives under
`STAGE/read_complete_01/evidence/` (`hw_campaigns/`, `hw_blocks/`, `timing_reanalysis_20261022/`).

## Commands

Every command below is taken from the script's own argparse or usage text. None of them touch the switch
except the hardware supervisor, which needs Philip's recorded authorization for each campaign. The current assessment and “Implement the plan” authorize guarded physical SEL-751 runs after the same-artifact gates. No software outstation is permitted in this execution.

Generate a candidate into a scratch directory (created if missing):

```sh
python3 $STAGE/m12_fullsize/make_m12.py /tmp/m12p --policy --c3 cimg --shapes passthrough --two-read            # c25
python3 $STAGE/m12_fullsize/make_m12.py /tmp/m12p --policy --c3 cimg --shapes passthrough --two-read --reduce   # c26
python3 $STAGE/m12_fullsize/check_generator_identity.py      # exit 1 if any live mode changed
```

Compile locally (never loads a device). c25's recorded manifest used a 1200 s timeout:

```sh
python3 $ARCH/build.py BUILD/response_only.p4 BUILD/compile_local --timeout 1200   # SDK 9.13.2, the switch's
python3 $STAGE/ctl_timing_01/efficiency_candidates.py BUILD --record-artifacts      # pin the artifacts BEFORE the gate
```

Model gate (private local model, no hardware). Actual SEL-751 requires16 drivers including relay_sbo and fin_busy.
Drivers: `abandon abort contention control_timing dup fin_busy relay_sbo
egress_diag fullread fullread_boundary fullread_corrupt isolation_cleanup mixed mixedfull packets policy
policy_boundary prefix rearm repeat segmented select_lifecycle smoke smoke_sizeoff two_read_robust`; the v3
summary names the ones it requires:

```sh
cd $STAGE/ctl_timing_01
python3 run_model.py evidence/m12p_c26 smoke 1
python3 model_summary.py evidence/m12p_c26 --v3 --enforce   # exit 1 unless the gate passed
```

Freeze and check a block config:

```sh
python3 $HW/freeze_gate.py write BUILD -o BUILD/freeze_v3.json --configs CONFIG [CONFIG ...]
python3 $HW/freeze_gate.py check BUILD/freeze_v3.json --config CONFIG
```

Hardware supervisor (authorized campaigns only). `init` takes the manifest and creates
`MANIFEST.parent/<campaign_id>/`; the other commands take that campaign directory:

```sh
python3 $HW/evaluation_campaign.py init   $STAGE/read_complete_01/evidence/hw_campaigns/<ID>.manifest.json
python3 $HW/evaluation_campaign.py start  CAMPAIGN_DIR      # detaches immediately
python3 $HW/evaluation_campaign.py status CAMPAIGN_DIR      # read-only
python3 $HW/evaluation_campaign.py reconcile CAMPAIGN_DIR STEP_ID [--baseline-run-root DIR --baseline-terminal FILE]
```

Readout of one recorded block:

```sh
$PY312 $STAGE/read_complete_01/analysis/hw_read_readout.py BLOCK_DIR --config CONFIG [--arms a,b] --out readout.json
```

Offline reproduction (software tests, policy, constants, P4 regeneration, model-gate recomputation, freeze
binding). `CANDIDATE` is one of `c25` (default), `c24`, `c12`, `c20`, `b08`; c26 is not yet in the script:

```sh
bash $STAGE/read_complete_01/reproduce.sh
CANDIDATE=c12 bash $STAGE/read_complete_01/reproduce.sh
bash $STAGE/read_complete_01/reproduce.sh --readout BLOCK_DIR CONFIG [ARMS]
```

## Directories the active path depends on

Do not move or rename these. Generated configs and evidence records hold their absolute paths, and the
generators resolve siblings through `HERE.parent`.

- `STAGE/{m12_fullsize, ctl_timing_01, seg61_02, read_complete_01, seg61_01, read_reencode_01, full_read_01, combined_nt_01}`
- the P4 lineage these were derived from: `STAGE/{dup_hold_01, n_crc_residue, t_sealed_lifetime, combined_nt_diag_01, retx_passthrough_01}`
  (for example `seg61_02/generate.py` reads `dup_hold_01/evidence/full_02_strict/response_only.p4`, and every
  `rc01_m12p_c25_*.json` config pins that path)
- `$ARCH/integration/core/{response_only, model_driver.py, launch_model.sh, harness}`, `response_only_rearm/{cp.py, hw}`
- `$ARCH/integration/{read, connection/binding}/tests`, `$ARCH/protocol/{response_path_cp.py, hw_vepa}`
- `$ARCH/integration/evidence/rearm_01/{hw, repeat_sbo_endpoint}`
- `defense4/timing/framework/size`, `defense4/timing/evidence/campaign_v2/repro/leakage_campaign.py`

The manuscript cites `ctl_timing_01/evidence/{m11_09/DESIGN_FACTS.md, m10_03/PART2_DESIGN_20261018.md}`,
`seg61_02/{evaluation/CLAIM_EVIDENCE_MATRIX.md, analysis/paper_evidence.py,
evidence/evaluation_campaigns/eval_m11_09_20261018_02_paper}` and `protocol/hw_vepa/clrt_check.py`.

## Searching

`rg` and `fd` read the repository's `.ignore` and skip evidence, captures, compiler output and the paper.
Pass `--no-ignore` (or `rg -uu`) to search those deliberately. `git grep` ignores `.ignore`.

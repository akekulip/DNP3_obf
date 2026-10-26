# Active c69 path — offline compile/model, fixed J retired (2026-10-26)

Read root `CLAUDE_HANDOVER_20261026_C69.md` and the current `plan.md` first. Candidate `m12p_c69_sdk9132` adds
`--strip-operate-hold` to c68 and uses `response_ready_ack_d_no_j_v3`. OPERATE has no request-hold domain;
common generation, ACK response-readiness and full D remain. Runtime parameters are exactly gap/budget/enabled.
N/E source and all historical source identities are preserved. The new compile has T8 stages and p1 SRAM36/TCAM36
versus c68's T9/SRAM47/TCAM51. The full fresh17-driver model gate passes; final retention/clean-checkout reproduction is in progress. No c69 hardware run belongs to this task.

`read_complete_01/reproduce.sh` has an explicit c69 offline tier and reports physical evidence unevaluated;
c68 reproduction uses the historical generator/gate/freeze at51f9c9d18. The c68 map below is retained as history.

# Active code map — reviewed c68 repair (2026-10-26)

Current start: root `CLAUDE_HANDOVER_20261026.md`, `plan.md` and `WORKING_NOTES.md`. Verify any directive
attributed to the user; a handover label is not authority by itself. Current direct instruction implements the
reviewed repairs and the two existing c68 D20 recovery workloads.

Current candidate: `m12p_c68_sdk9132`, source 825b7e6da3c24dd1705d43f1d921dbd2184a99fe47f75f4de1d2d372e160b289.
It preserves the response-ready ACK-then-D dataplane and removes write-only telemetry. Existing SDK 9.13.2 artifacts
show N/E 11 stages, T 9 and pipe1 egress 4. Model 17/17 passes. Removed model counters are recounted from action logs;
functional state is BFRT state. This distinction and live HELD_REWAIT sampling drift are documented.

The four original normal-reference blocks remain bound to 789092c2d/freeze03 and reproduce 1544 exchanges.
The repaired current harness/configs use freeze04; all seven configs pass. Fresh c68 and historical c67
reproduction exit 0. Software J and piggyback fixture identity are restored with original recovery/runner exemptions.
Visible CLRT and the extra piggyback latency criterion remain ungated. New mixed-loss campaign05 passed 7/7 with
verified restoration. New full-loss campaign06 finished rc 1 (six of seven trials passed), with t3 OPERATE TIMEOUT; all targets were exact, and independent restoration passed. Final ownership is inactive, unsafe_restoration=false. Physical J remains unproven; old c67 failures remain
preserved and are not explained by a new c68 passing observation.

The single current run status is `STAGE/read_complete_01/CURRENT.md`; detailed verification is
`STAGE/read_complete_01/evidence/c68_repair_20261026/`. Older rows below are historical baselines.

Abbreviations used below (all paths from the repository root):

```sh
ARCH=defense4/timing/case4_architecture
STAGE=$ARCH/integration/core/response_only_rearm/stage_experiments
HW=$ARCH/integration/evidence/rearm_01/hw
PY312=${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}   # Python 3.12; system python3 is 3.8
```

## Active candidate and historical baselines

| build | what it is | state |
|---|---|---|
| `m12p_c68_sdk9132` | c67 without write-only measurement state (T outcomes, N count registers, E/p1 counters) | current; SDK 9.13.2 compile (T 9 stages); 17-driver model gate PASS (attempt 04); original references freeze03; repaired harness freeze04; normal references pass, new D20 mixed loss7/7 PASS, full loss FAIL (six of seven trials passed), restoration PASS |
| `m12p_c67_sdk9132` | deadline-free response-ready ACK+D, retained-original retry suppression | predecessor; 17-driver model gate PASS; freeze_v3_02; physical: smoke/FIN PASS, mixed-loss FAIL, J unproven |
| `m12p_c52_sdk9132` | c51 plus relay FIN+PSH+ACK accepted as FIN (FIN flag terms 8w17&&&8w0xf7, parser row, short_shapes twins) | model_gate_passed (16 drivers); physical 23-31: reference 772/772 (blocks 24+31, ledger), smoke/loss_mixed/graceful/held OPERATE pass; loss_full t0 target miss; RST/reconnect fail switch gate on late-first-READ fallbacks; J unproven |
| `m12p_c51_sdk9132` | c50 plus 8 qualified half-closed RST first_event rows | model_gate_passed (16 drivers); physical smoke rc0, reference 772/772 rc0, loss_full rc0, loss_mixed 4/7, persistence aborted (Vision outage) |
| `m12p_c50_sdk9132` | c49 plus guarded bounded FIN owner-phase restart | compiled/reviewed within limits; exact fin_busy193/193 across3connections; final16-driver gate and all padded physical runs pending |
| `m12p_c49_sdk9132` | timestamp relay45/49 control profile with canonical constant keys | installed-row readback exact; diagnostic30/30; relay_sbo1085/1085; busy-FIN62/70 failure retained |
| `m12p_c30_sdk9132` | relay READ91/134→141/158; legacy software SBO37→61 | READ compiled-model1332/1332; corrected control_timing415/415; no padded physical relay qualification |
| `m12p_c31_sdk9132` through `m12p_c48_sdk9132` | integrated whole49→60 relay SBO, timestamp successor attempts | failed compile/static attempts through46;47/48 compiled then exposed provenance/constant-key runtime defects, retained |
| `m12p_c25` | two-READ build: mixed READ 91 -> 141, full integrity READ 247 -> 271, SELECT/OPERATE 37 -> 61 | model gate passed; on hardware the padding was byte-exact (campaign 02) and timing precision FAILED; recovery blocks not run |
| `m12p_c26` | c25 plus a behavior-preserving resource reduction (`--reduce`; pipe-1 egress 7 -> 4 stages; N/E/T 12/12/11; both SDKs) | model gate passed (counts equal to c25's); not frozen; no hardware. See COMPLETION_RECORD section 0a |
| `m11_09` | the four-arm build behind the manuscript evaluation `eval_m11_09_20261018_02` | frozen; the paper's evidence |

Historical c52 and earlier timing failures remain unresolved. Their cause is not located. The earlier "receive-idle-dependent delay into Vision" localization
was withdrawn in 4a0b0fc56 because its metric was circular (it counted the transit it was meant to explain);
see `STAGE/read_complete_01/evidence/timing_reanalysis_20261022/README.md`. IEEE 1815 conformance was not
audited in this run.

## The path, stage by stage

| stage | code | notes |
|---|---|---|
| 1. generator | `STAGE/m12_fullsize/make_m12.py` (entry) -> `m12_fullsize/m12gen/{build,common,mapper,read_policy,segmented,two_read,relay_sbo,relay_ts,response_ready_timing,strip_telemetry}.py` | legacy identities preserved; c68 adds --strip-telemetry after the response-ready relay layers; unselected identities remain preserved |
| 2. P4 source and profile | `STAGE/ctl_timing_01/evidence/m12p_<id>/{response_only.p4, response_only.inputs.json, supported_profile.json}` | constants from `STAGE/read_complete_01/vectors/` (`derive.py`, `derive_two_read.py`, `make_two_read_templates.py`) |
| 3. compile | `$ARCH/build.py` (local SDK 9.13.2 at `~/bf-sde-9.13.2`, a copy of the switch's install; one compile since 2026-10-23) | output `compile_local/`: the model tests it and the switch loads it (`freeze_gate.loaded_compile`). Builds before m12p_c29_sdk9132 used local 9.13.1 plus `compile_switch_orchestrator.py` (`compile_switch_9132/`, the loaded one) |
| 4. model gate | `STAGE/ctl_timing_01/run_model.py` (drivers in `ctl_timing_01/model_*.py` and `STAGE/seg61_02/model_*.py`), verdict `ctl_timing_01/model_summary.py --v3` | 17 required drivers for c67 (16 relay regressions + response_ready); dependency closure recorded by `ctl_timing_01/record_closure.py` |
| 5. block configs and freeze | `STAGE/read_complete_01/hw/make_sel751_configs.py` (physical relay) / `make_two_read_configs.py` (historical software) -> `hw/config/rc01_m12p_*.json`; `$HW/freeze_gate.py` -> `freeze_v3.json`; `read_complete_01/hw/make_hw_manifest.py` -> campaign manifest | a block runs only through `$HW/run_block_frozen.sh`, which checks the freeze first |
| 6. hardware supervisor | `$HW/evaluation_campaign.py` (init/start/status/resume/stop-after-current/reconcile); per block `run_block_frozen.sh` -> `run_block.sh`; restore check `restore_verify.py` | physical endpoint: SEL-751 `.7:20000`; guarded master: `$ARCH/protocol/hw_vepa/relay_master.py` and `active_harness`; historical software endpoints: `$ARCH/integration/evidence/rearm_01/repeat_sbo_endpoint`; library: `$ARCH/protocol/hw_vepa` (`campaign.py`, `wire_check.py`, `clrt_check.py`, `standards.py`); live testbed ownership state in `~/.local/state/dnp3-evaluation/tofino1-testbed/ownership.json` (never hand-edited) |
| 7. physical replay/report | `STAGE/read_complete_01/analysis/replay_physical.py`, `visible_clrt.py` | pinned/current wire checker replay with frozen denominators; CLRT report is data only. `hw_read_readout.py` is the legacy software-endpoint readout. |
| 8. reproduce | `STAGE/read_complete_01/reproduce.sh` | offline only; never loads the switch |

Software endpoint and policy code: `STAGE/read_complete_01/{software,policy}`. Evidence per run lives under
`STAGE/read_complete_01/evidence/` (`hw_campaigns/`, `hw_blocks/`, `timing_reanalysis_20261022/`).

## Commands

Every command below is taken from the script's own argparse or usage text. None of them touch the switch
except the hardware supervisor, which needs Philip's recorded authorization for each campaign. These are command references, not new hardware authorization. The current direct instruction covered only the two D20 recovery blocks, now finished. No software outstation was run.

Generate a candidate into a scratch directory (created if missing):

```sh
python3 $STAGE/m12_fullsize/make_m12.py /tmp/m12p_c68 --policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts --response-ready-timing --strip-telemetry
python3 $STAGE/m12_fullsize/check_generator_identity.py      # exit 1 if any live mode changed
```

Compile locally (never loads a device). Preserve the selected c68 bundle; rebuilds require new artifact binding and model gates:

```sh
python3 $ARCH/build.py BUILD/response_only.p4 BUILD/compile_local --timeout 1200   # SDK 9.13.2, the switch's
python3 $STAGE/ctl_timing_01/efficiency_candidates.py BUILD --record-artifacts      # pin the artifacts BEFORE the gate
```

Model gate (private local model, no hardware). c68 requires all 17 drivers:
`smoke packets rearm dup repeat select_lifecycle control_timing contention abort policy policy_boundary
two_read_robust smoke_sizeoff abandon relay_sbo fin_busy response_ready`. Use the root handover for final attempt
numbers and retained failures. Current repairs changed no executed model dependencies, so no new model run was needed.

```sh
cd $STAGE/ctl_timing_01
python3 run_model.py evidence/m12p_c68_sdk9132 DRIVER FRESH_ATTEMPT --milestone m12
python3 model_summary.py evidence/m12p_c68_sdk9132 --v3 --enforce   # exit 1 unless all gates pass
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

Reproduce recorded physical reports, including genuine failures (output must be a fresh path outside evidence):

```sh
$PY312 $STAGE/read_complete_01/analysis/replay_physical.py --candidate c68 --out /tmp/c68_replay_FRESH.json
```

Offline reproduction regenerates source, restores pinned logs, recomputes the model gate, checks current and
historical freeze bindings, and replays recorded reports. It never loads the switch. c68 is current; c67 and c52
use their historical pinned code. A replay success is not a new recovery qualification pass.

```sh
CANDIDATE=c68 bash $STAGE/read_complete_01/reproduce.sh --candidate-info
CANDIDATE=c68 bash $STAGE/read_complete_01/reproduce.sh
CANDIDATE=c67 bash $STAGE/read_complete_01/reproduce.sh
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

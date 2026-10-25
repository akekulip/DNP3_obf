# c67 physical qualification preparation — read-only findings

Inspected 2026-10-25. No hardware connection, model run, supervisor launch, compile, pipeline change, or configuration edit was performed. Only this report was written. Root owns hardware. Current `plan.md` and the active override at the top of `CLAUDE.md` define scope; historical c52 records below are evidence of baseline state, not new authorization.

## Current admission verdict

**Do not launch yet.** Fresh read-only command:

```bash
python3 defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01/model_summary.py evidence/m12p_c67_sdk9132 --v3 --enforce
```

returned exit 1 / `blocked` during this inspection:

- `repeat_01`: 469/523, exit 1.
- `contention_01`: incomplete, no final results/closure/profile binding yet. Its apparent missing-provenance errors are consistent with an in-progress attempt; re-evaluate after it finishes.
- No attempt: `select_lifecycle`, `control_timing`, `abort`, `policy`, `policy_boundary`, `two_read_robust`, `smoke_sizeoff`, `abandon`, `relay_sbo`, `fin_busy`.
- Build has no `model_summary_v3.json` and no freeze file yet.

These findings are a snapshot while root continues model work. Recompute rather than borrowing this snapshot or any c52/c62 pass. The required 17 are `smoke packets rearm dup repeat select_lifecycle control_timing contention abort policy policy_boundary two_read_robust smoke_sizeoff abandon relay_sbo fin_busy response_ready`. Latest attempt per driver governs; retained failures need the summary's supported evidence-backed disposition; dependency closures, reset postchecks, exact profile/source, strict response-ready coverage, and compiled T-clock checks remain mandatory.

The existing runner form is `python3 "$CTL/run_model.py" evidence/m12p_c67_sdk9132 DRIVER ATTEMPT --milestone m12`; choose a fresh unused attempt number. The strict pass is `model_response_ready_m12p_c67_sdk9132_03`. Do not run concurrently with root's model owner.

## Source and exact deployable bundle

Use these shell variables from repository root for the commands below:

```bash
ARCH="$PWD/defense4/timing/case4_architecture"
STAGE="$ARCH/integration/core/response_only_rearm/stage_experiments"
CTL="$STAGE/ctl_timing_01"
BUILD="$CTL/evidence/m12p_c67_sdk9132"
RC="$STAGE/read_complete_01"
HW="$ARCH/integration/evidence/rearm_01/hw"
CFG="$RC/hw/config"
FREEZE="$BUILD/freeze_v3.json"
```

- Source SHA256 `e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1`.
- `compile_local/manifest.json`: exit 0, `p4c 9.13.2 (SHA: 1baf055)`, exact source hash. This one SDK9.13.2 bundle is both model-tested and hardware-loaded. Do not substitute local SDK9.13.1 output or a separate rebuild.
- Local compiler `/home/philip/bf-sde-9.13.2/install/bin/bf-p4c`; switch SDE `/home/decps/Downloads/bf-sde-9.13.2`.
- Prepared configs bind `compile_local/out`, BFRT SHA `7430330ad3f66e5789487a2e02cc147299b9c6fb8fab1c961d7d20dbeea8ab39`, p0 binary `4e031889951c77e20244fd1df05fde12d550e403e992cda07b425293e720a73a`, p1 binary `197189858d8dedae437a9e7f060e1ca45f499507942b4f4b5089b41ebb3d2b41`.
- `timing_contract=response_ready_ack_d_v2`; config nanosecond parameters are only `gap`, `op_j=2400000`, `budget=240000`, `enabled=1`. No exchange deadline/readiness fallback.
- Physical endpoint `.7:20000`, relay address0, master `.1` address1. Guarded points1,3, code1/count1/on200ms/off0. Physical J remains `unproven_by_user_choice`.
- Switch `decps@10.10.54.81`, Vision `decps@10.10.54.19`; master_dev9, relay_dev64, T180, hb181, held182, N-ACK48, recirc68. Held ACK/response queue contract remains qid6/qid4. Preset `shape_59570`.
- Restoration program `case4_response_path`; launch `/home/decps/Philip_repo/logs/bringup_20261005/launch_case4_response_path.sh`, replay freshly captured pre-run $PORT state, relay slot, Vision state, then ping through switch.

## Ten existing configs and exact block coverage

All filenames start `rc01_m12p_c67_sdk9132_sel751_` and end `.json`:

| Suffix | Arms / D | Planned exchanges or recovery arguments |
|---|---|---|
| `d5_smoke` | combined / 5ms | 2 READ + successful SELECT + OPERATE =4; tool candidate_campaign |
| `d5_reference` | off,timing_only,size_only,combined / 5ms | 4×193=772; manifest supplies all arms and physical_relay |
| `d10_reference_rest` | timing_only,combined / 10ms | 386 |
| `d15_reference_rest` | timing_only,combined / 15ms | 386 |
| `d20_reference_rest` | timing_only,combined / 20ms | 386 |
| `d20_loss_mixed_950` | combined / 20ms | `--loss core_mixed` |
| `d20_loss_full_950` | combined / 20ms | `--loss core_full` |
| `d20_persistence_graceful_950` | combined / 20ms | `--close-mode graceful` |
| `d20_persistence_rst_950` | combined / 20ms | `--close-mode rst --rst-grace-ms 1000` |
| `d20_reconnect_950` | combined / 20ms | `--scenario reconnect --reconnect-policy protected` |

Each reference arm has 65 READ (33 mixed,32 integrity),64 SELECT,64 OPERATE=193. References total 772+386+386+386=1930. Off and size_only run exactly once. Recovery configs use the existing candidate tools named by `evaluation.campaign_block.tool`; preserve those identifiers when assembling the manifest. Reconnect is the existing three-connection whole block, one cold bring-up, no register clearing/reseeding between connections.

Both loss presets contain seven identity targets: request_mixed/request_full #3, ack_sep #3, read_resp_padded #3, select_resp_padded #1, operate_req #1, operate_resp_padded #1, master_ack_of_padded_data #1. Every entry has `target=identity`. No 350ms stress block is included or allowed by the response-ready manifest generator.

**Config check:** instantiated each of these ten configs through `CandidateCampaign` with `DryRunner`, its recorded arms/loss/scenario/reconnect selection, and physical_relay; all ten `preflight()` lists were empty. This verifies local binding and generation workload budgets, not model admission, live reachability, or a freeze. No current configuration blocker was found.

## Ordered freeze and supervisor commands after the gate passes

These are future root-owned actions; they were not executed here.

```bash
python3 "$CTL/model_summary.py" evidence/m12p_c67_sdk9132 --v3 --write --enforce
python3 "$HW/freeze_gate.py" write "$BUILD" -o "$FREEZE" --configs "$CFG"/rc01_m12p_c67_sdk9132_sel751_*.json
python3 "$HW/freeze_gate.py" check "$FREEZE" --config "$CFG/rc01_m12p_c67_sdk9132_sel751_d5_smoke.json"
bash "$HW/run_block_frozen.sh" "$FREEZE" candidate_campaign "$CFG/rc01_m12p_c67_sdk9132_sel751_d5_smoke.json" UNIQUE_DRYRUN_ID --arms combined --fixtures physical_relay --dry-run
```

Use no diagnostic exception for qualification. Freeze pins the source, loaded compile, configs, model summary/closures, harness, acceptance and restoration machinery. Any later edit to pinned files requires re-evaluation and a new valid freeze; preserve old evidence.

`make_hw_manifest.py` accepts only one config tag at a time. Therefore invoke it separately for d5/d10/d15/d20 or assemble one durable manifest from the exact recorded block commands before initialization; do not accidentally omit the other tags. Safe existing form:

```bash
python3 "$RC/hw/make_hw_manifest.py" --build m12p_c67_sdk9132 --endpoint-profile sel751 --config-tag d5 "$FREEZE" UNIQUE_D5_ID smoke reference
python3 "$RC/hw/make_hw_manifest.py" --build m12p_c67_sdk9132 --endpoint-profile sel751 --config-tag d10 "$FREEZE" UNIQUE_D10_ID reference_rest
python3 "$RC/hw/make_hw_manifest.py" --build m12p_c67_sdk9132 --endpoint-profile sel751 --config-tag d15 "$FREEZE" UNIQUE_D15_ID reference_rest
python3 "$RC/hw/make_hw_manifest.py" --build m12p_c67_sdk9132 --endpoint-profile sel751 --config-tag d20 "$FREEZE" UNIQUE_D20_ID reference_rest loss_mixed_950 loss_full_950 persistence_graceful_950 persistence_rst_950 reconnect_950
python3 "$HW/evaluation_campaign.py" init MANIFEST
python3 "$HW/evaluation_campaign.py" start CAMPAIGN_DIR
python3 "$HW/evaluation_campaign.py" status CAMPAIGN_DIR
```

Start the next phase only after reviewing the preceding result. Use the existing run-specific authorization record naming the current assessment and Philip's “Implement the plan”; no repeated permission request is needed under the active plan. Wrapper owns `--apply`, `--config`, `--run-id` and `DEFENSE4_HW_AUTHORIZED=1`; do not bypass it. Dry-run uses a unique nonretained ID. Existing wrapper returns0 block+restore pass,1 block failure with verified restore,2 restoration unverified (stop all hardware),3 freeze refusal. Supervisor requires systemd user `Linger=yes` and detaches with an immutable manifest; do not relaunch a retained run root or retry a terminal step in place.

Reference acceptance remains planned=eligible, n≥20 for mixed READ/integrity READ/SELECT/OPERATE, nearest-rank p99 absolute complete-CLRT error≤100us, all D, no successful bypass. Retain first/complete CLRT, maxima, drops/retransmissions, padding/application/SEQ/ACK/switch counters, and failed planned denominators. FIN closes only on successful complete graceful/RST/reconnect blocks including all three connections.

## Ownership, generation, and exact restoration observations

Read-only local observations available to root:

```bash
cat ~/.local/state/dnp3-evaluation/tofino1-testbed/ownership.json
systemctl --user list-units 'dnp3-eval-*' --all
python3 "$HW/evaluation_campaign.py" status CAMPAIGN_DIR
cat CAMPAIGN_DIR/state.json
cat CAMPAIGN_DIR/steps/STEP_ID/terminal.json
cat RUN_ROOT/restore_verify.json
```

Ownership at inspection: `active=false`, `unsafe_restoration=false`, latest step `rc01_hw_c52_20261025_35_idt_loss_full_950`; this is a local state observation, not a new live health check. Never hand-edit ownership. Root should inspect fresh controller/block units and production process during its authorized preflight.

Generation headroom is built into `candidate_campaign.py` before traffic. It reads the exact installed BFRT `p1.t_Ingress.gen_alloc_reg` and `p1.t_Ingress.op_gen_alloc_reg`, requires full valid hardware reads with no software fallback, and checks usable maximum65534 against derived reserves. Reference T-on reserve for one connection: read211, operate82 (65READ+2×64SBO +2lifecycle+16margin; 64OPERATE+2+16). T-off reserve18/18. Smoke reserve22/19. Preserve recorded `snap/*_generation_headroom.json` and budget evidence; do not reset allocator state to evade admission. Helper's existing CLI is `generation_headroom.py --build-out OUT --switch-tools SWITCH_TOOLS --reserve-read N --reserve-operate N --output JSON`, called only by authorized runner environment.

Historical latest retained exact offload baseline (`rc01_hw_c52_20261025_35_idt_loss_full_950/vision_offload_baseline.json`) is interface `enp59s0f0np0`, gro=true,lro=false,rx-gro-hw=false,rx-gro-list=false. Root must take a fresh per-run baseline and restore those exact recorded effective booleans; “all disabled” is not the baseline. Existing capture context temporarily disables receive aggregation for qualification and restores it. `restore_verify.py` checks fresh `ethtool -k` against SHA-bound `vision_offload_baseline.json`, including owned firewall/loss cleanup. Existing other baseline contracts are adaptive RX on,rx-usecs50; CPU latency2000000000,no helper. No new OS/network/firmware changes are authorized.

Independent restore command (future root action; contacts hardware): `python3 "$HW/restore_verify.py" --config CONFIG --run-root RUN_ROOT`. Never treat runner exit alone as restoration proof.

## Reproduction and documentation remaining

- `CANDIDATE=c67 bash "$RC/reproduce.sh" --candidate-info` and c67 source/generator flags already exist; integrated relay regression branch includes c67. Full reproduction already recomputes v3 and checks all matching tagged configs against named freezes.
- Still required: successful complete17-driver v3 summary, final model dependency/log retention pins and archives, resource review/compile bytes retained, new c67 freeze naming all ten configs, all physical block evidence and readouts, clean-checkout source/artifact/model/config reproduction. Reproduction currently cannot pass c67 gate; no freeze exists. Compiler output is git-ignored, so clean checkout must reconstruct/restore exact artifacts and explicitly distinguish missing-byte freeze checks.
- Full reproduction presently reports “no freeze yet ... skipping” when none exists; do not count that as deployment reproducibility. Parent should retain a successful actual freeze check after gates.
- Ten configs were already prepared; generator uses exclusive writes. For regeneration comparison, use a fresh output directory with d5(smoke/reference),d10/d15(reference arms timing_only combined),d20(reference arms plus explicit recovery blocks). Do not overwrite or regenerate c52 evidence.
- `ACTIVE_CODE_MAP.md` and lower `CLAUDE.md` still contain c52/current and even obsolete c51-table entries; top active override is newer. Final scoped updates remain required to WORKING_NOTES,CURRENT,STATUS,COMPLETION_RECORD,ACTIVE_CODE_MAP,CLAUDE checkpoints/reproduction entry. Preserve stated limits: J physical unproven, no new tap/software outstation/attacker campaign, no threshold relaxation.

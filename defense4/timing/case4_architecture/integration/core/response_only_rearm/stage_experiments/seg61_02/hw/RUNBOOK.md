# candidate61 hardware preparation

> **Four-arm smoke PASSED on silicon on 2026-10-14 (`candidate61_fourarm_smoke_03`).** Off/timing_only READ 49 and SBO 37; size_only/combined READ, SELECT and OPERATE 61, each one received TCP segment. Earlier attempts `_01` and `_02` failed closed on harness defects (fixed, retained). The commands below for persistence, loss, reconnect, isolation, held-OPERATE and timing have not been run.

This directory is a staging surface for the `seg61_02` candidate61 silicon campaigns. It does not change production defaults, shared campaign entry points, or `response_only_rearm/hw/sealed_profile.py`.

Candidate61 configs bind to `full_04` and point at the completed switch SDK 9.13.2 build. Strict comparison configs are separately labelled and pinned to the strict `dup_hold_01/full_02_strict` switch build.

- source: `integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/full_04/response_only.p4`
- source SHA256: `1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa`
- switch build manifest: `integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/full_04/compile_switch_9132/manifest.json`
- switch build out: `integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/full_04/compile_switch_9132/out`
- switch SDK 9.13.2 bfrt SHA256: `e32df20459c0dc15b9a64cabc7f64d43e53f90434c51698d5b8a58aa43de0311`
- switch SDK 9.13.2 `response_only.p4pp` SHA256: `3306c394ef3f447cb48e62f25e2df609acc72e02085f83f6096ccbb9d7287a43`
- local SDK 9.13.1 bfrt SHA256: `c39432cddeab754c1579a182221196d03180bbff7f8ee919f69af8e036c32b05`
- local SDK 9.13.1 `response_only.p4pp` SHA256: `db35b1b3a90fe307e4554b44289e20eff41ceb3bf12c4f57c1b5033c58acb4c8`

Strict comparison build identity:

- source SHA256: `2ad71761399e023b0d3b6b72f9fb71257da012499ffe30ac4758b395fc1bd97c`
- switch build manifest: `integration/core/response_only_rearm/stage_experiments/dup_hold_01/evidence/full_02_strict/compile_switch_9132/manifest.json`
- switch build out: `integration/core/response_only_rearm/stage_experiments/dup_hold_01/evidence/full_02_strict/compile_switch_9132/out`
- switch SDK 9.13.2 bfrt SHA256: `22d666b23d2d63bf76d62b7d2b6643a5aac6e303abe9ac6b4f1392ed38f437f6`
- switch SDK 9.13.2 `response_only.p4pp` SHA256: `2052c564cc77938f3b13001ed94abe089b93e0cdb040c0b259161270dcf3c0d9`

Every generated config pins `build.profile`, `build.source_sha256`, and `build.hashes` from the matching `compile_switch_9132/manifest.json`. Candidate61 expected sizes are READ49/SBO37 for off and timing-only, READ61/SBO61 for size-only and combined. Strict comparison expected sizes are READ49/SBO37 for off and timing-only, READ58/SBO37 for size-only and combined. Regenerate with `build_candidate61_configs.py` if either switch compile is replaced.

## Required shared sealed_profile registration

Do not edit the shared file from this staging directory. Before hardware execution, add candidate61 to `integration/core/response_only_rearm/hw/sealed_profile.py` after the switch build is complete:

```python
# candidate61 seg61_02 full_04, SDK 9.13.2.
'e32df20459c0dc15b9a64cabc7f64d43e53f90434c51698d5b8a58aa43de0311': {
    '3306c394ef3f447cb48e62f25e2df609acc72e02085f83f6096ccbb9d7287a43',
},
```

This registration is required because `sealed_profile.select()` rejects unknown bfrt/profile pairs before silicon qualification.

## Campaign order and exact commands

Run `plan` first for every entry and review the emitted command list. Run commands require `DEFENSE4_HW_AUTHORIZED=1` and are intentionally omitted here unless they are the same command with `plan` changed to `run --apply`.

Smoke and bounded ordinary four-arm gate:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_fourarm_smoke.json --run-id candidate61_fourarm_smoke_01 --arms off,timing_only,size_only,combined --fixtures separate_ack
```

Persistence, graceful and RST, through the same-tuple series harness:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_series.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_persistence_graceful_950.json --run-id candidate61_persistence_graceful_950_01 --arms combined --fixtures separate_ack --close-mode graceful
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_series.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_persistence_rst_950.json --run-id candidate61_persistence_rst_950_01 --arms combined --fixtures separate_ack --close-mode rst --rst-grace-ms 1000
```

Loss and reconnect gates:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_loss_core_950.json --run-id candidate61_loss_core_950_01 --arms combined --fixtures separate_ack --loss core
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_reconnect_950.json --run-id candidate61_reconnect_950_01 --arms combined --fixtures separate_ack --scenario reconnect --reconnect-policy protected
```

Stale traffic and retained external old-packet diagnostics:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_isolation.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_stale_tokens_950.json --run-id candidate61_stale_tokens_950_01
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_external.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_old_external_950.json --run-id candidate61_old_external_950_01 --old-graceful <retained-old-graceful-archive-dir> --old-rst <retained-old-rst-archive-dir>
```

Held-OPERATE duplicate gate:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_series.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_held_operate_350.json --run-id candidate61_held_operate_350_01 --arms combined --fixtures separate_ack --close-mode graceful
```

Repeated four-arm evaluation and strict comparison at 59,570 PPS / 950 us:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_eval_59570_950_b1.json --run-id candidate61_eval_59570_950_b1 --arms off,timing_only,size_only,combined --fixtures separate_ack
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_eval_59570_950_b2.json --run-id candidate61_eval_59570_950_b2 --arms combined,off,timing_only,size_only --fixtures separate_ack
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_eval_59570_950_b3.json --run-id candidate61_eval_59570_950_b3 --arms size_only,combined,off,timing_only --fixtures separate_ack
```


Strict baseline comparison, separately labelled at 59,570 PPS / 950 us, pinned to `strict_dup_hold_full02`:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/strict_comparison_59570_950_b1.json --run-id strict_comparison_59570_950_b1 --arms off,timing_only,size_only,combined --fixtures separate_ack
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/strict_comparison_59570_950_b2.json --run-id strict_comparison_59570_950_b2 --arms combined,off,timing_only,size_only --fixtures separate_ack
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/strict_comparison_59570_950_b3.json --run-id strict_comparison_59570_950_b3 --arms size_only,combined,off,timing_only --fixtures separate_ack
```

Piggyback is separate and labelled separately:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_piggyback_combined_59570_950.json --run-id candidate61_piggyback_combined_59570_950_01 --arms combined --fixtures piggyback
```

After correctness, compare 14,892 versus 59,570 PPS:

```bash
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_compare_14892_950.json --run-id candidate61_compare_14892_950_01 --arms combined --fixtures separate_ack
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/candidate_campaign.py plan --config defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/candidate61_compare_59570_950.json --run-id candidate61_compare_59570_950_01 --arms combined --fixtures separate_ack
```

## Per-block headroom and restore requirements

Before each hardware block, run the entry point in `plan`, check generation headroom from the pre-run lifecycle snapshot, confirm no standing manifest exists from a prior failed run, and confirm the production program and `$PORT` snapshot are the live pre-run state. After each block, require the runner's `finally` restoration evidence: teardown of standing manifests, cold swap to production launch script, `restore_ports.py` from the live pre-run snapshot, relay slot restoration, Vision restoration, and production ping success.

## Current gates still open

- Shared `sealed_profile.py` now registers the installed SDK candidate61 artifacts; verify the pinned pair before silicon.
- Extended compiled-model packet gate is represented from actual reports: `model_smoke_02` passed 30/30 and `model_packets_04` passed 622/622; earlier failed model reports are retained in config metadata. Root/review still owns the final gate decision before hardware.
- Candidate61 packet-boundary qualification, offload snapshot/restore, and switch-facing capture calibration must be supplied by the acceptance/capture layer before qualification. Strict comparison configs carry `standards.packet_boundary_required=true` for fairness, and the runner now enables qualification for that explicit flag. Strict silicon comparison remains pending.

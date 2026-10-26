# Active repair checkpoint — 2026-10-26

Current direct instruction: implement the reviewed correction plan. The earlier handover below is a historical
record, not authority by itself. The user selected restored software J enforcement and piggyback fixture identity,
kept the extra piggyback latency criterion removed, and included the two existing c68 D20 mixed/full recovery
blocks after offline verification. Evidence and directive review: stage `read_complete_01/evidence/c68_repair_20261026/`.

The code repairs are complete pending final clean-checkout verification. P4, model helpers and old evidence remain
unchanged. New `freeze_v3_04.json` binds the repaired current harness/configs; original normal-reference runs retain
their `789092c2d`/freeze03 binding. Recovery results are pending and must be recorded before describing them as done.

# Handover — 2026-10-26 (c68 on the physical SEL-751; CLRT criterion removed)

This replaces `CLAUDE_HANDOVER_20261025.md` as the start point. That file and its closeout stay as the c67 record.
Paths below are relative to
`defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/` (`SE/`) unless they
start at the repository root.

## State in one paragraph

c68 (`m12p_c68_sdk9132`) is the current candidate. It ran on the physical SEL-751 through the Tofino at
D = 5, 10, 15 and 20 ms, each block with the before arm (`off`: no obfuscation in the switch) and the after arm
(`combined`: timing + size). All four blocks (`rc01_hw_c68_20261026_01..04`) finished rc 0, with every READ, SELECT
and OPERATE OK, exact sizes, and restoration verified. Everything is committed and pushed (`b576d34e9` on
origin/main). The testbed is idle: ownership `active=false`, `unsafe_restoration=false`. This was the state at the earlier handover; the current user has now directed the bounded repairs and recovery retests below.

## Historical requirement record — audit before using as authority

- **The 100 µs p99 |CLRT − D| rule is not his.** It came from an agent-written `rearm_01/PLAN.md` (commit 190a4c603,
  2026-10-12). It does not matter and must not appear anywhere, nor be reported. It has been removed from the live
  harness, the config generator and the live documents. Historical records keep their text.
- **What the defense hides is the visible CLRT.** That is the ACK → response interval an adversary sees between the
  master and the switch, for READ, SELECT and OPERATE. It is reported per class as data and is never gated.
- **No early or missing response release.** Holding the ACK until the response is ready rules out both.
- **Before and after.** Before means no obfuscation in the switch; after means timing + size on.
- **Out-of-scope measures and criteria go.** That includes the write-only switch measurement state, which was taking
  switch resources. The result is c68.
- **Relay class-2 events.** When the relay raises them: "I poll and confirm it once".
- **Unsafe flag.** "Extend reconcile, reviewed".

## What c68 is

- **What it is.** c67 plus `SE/m12_fullsize/make_m12.py --strip-telemetry`, implemented by the transform
  `m12gen/strip_telemetry.py`. The transform:
  - removes the T outcome register, the counting table and all `count()` calls;
  - removes N's three count registers and `retry_dup_t`;
  - removes E's outcome Counter;
  - removes the p1-egress `p1_outcome`;
  - splits `drop_timer_stale` into two data-free actions.
- **The test.** `m12_fullsize/tests/test_strip_telemetry.py` proves the generator reproduces c67 byte for byte
  without the flag. It also proves c68 is c67 minus telemetry and nothing else.
- **Resources.**
  - The source sha256 is 825b7e6d…, compiled with bf-p4c 9.13.2.
  - The stages are N 11, E 11 and T 9 (c67 has T 10).
  - SRAM falls from 179 to 170 on p0 and from 52 to 47 on p1.
- **Model gate.** It passes 17/17 (attempt 04, `model_gate_passed`).
  - The removed counters are recounted from the model log by `integration/core/telemetry_from_log.py`.
  - `model_driver.Model.register_read` applies it when the profile says `switch_telemetry: false`.
  - The recount was verified against real c67 registers in the `diag_shim_*` runs.
- **Freeze.** `SE/ctl_timing_01/evidence/m12p_c68_sdk9132/freeze_v3_03.json`.
  - Freezes v3_01 and v3_02 are stale.
  - Any edit to the harness closure stales the freeze again. Re-freeze before the next hardware run.

## Results (visible CLRT at the master NIC, median ms, before → after; 193 exchanges per arm)

| D | mixed READ | integrity READ | SELECT | OPERATE |
|---|---|---|---|---|
| 5 | 2.325 → 4.851 | 2.961 → 5.085 | 2.219 → 4.920 | 3.098 → 5.000 |
| 10 | 2.758 → 10.197 | 2.526 → 10.046 | 2.277 → 9.977 | 2.808 → 9.883 |
| 15 | 2.453 → 14.774 | 3.923 → 15.216 | 2.296 → 14.957 | 2.841 → 14.778 |
| 20 | 2.502 → 20.049 | 2.942 → 19.944 | 2.188 → 20.105 | 2.740 → 20.086 |

- **Sizes.**
  - Before: 91, 134, 49 and 49 bytes.
  - After: 141, 158, 60 and 60 bytes.
- **Spread.** The full minimum, median and maximum per class are in `SE/read_complete_01/CURRENT.md`.
  The data is in `SE/read_complete_01/evidence/c68_visible_clrt_20261026.json`, produced by
  `SE/read_complete_01/analysis/visible_clrt.py`.
- **Pcaps.** The before and after captures are under
  `SE/read_complete_01/evidence/hw_blocks/rc01_hw_c68_20261026_0N_reference_rest/physical_relay/{off,combined}/`.
- **Campaign records** are in `SE/read_complete_01/evidence/hw_campaigns/rc01_hw_c68_20261026_0N/`, including the
  authorization `.md` files.

## Things the next agent must know

1. **The relay can break the integrity READ on its own.**
   - Normal responses carry IIN `80 00`. With `84 00` (IIN1.2, class-2 events pending), the integrity READ
     (g60v2/v3/v4 + g60v1) returns event data. It then no longer matches the 134-octet shape, and every build
     loses it. This happened between 16:10 and 22:25 on 2026-10-25 with no traffic.
   - Check the IIN first when an integrity READ times out after an OPERATE.
   - The cure is `defense4/timing/active_harness/event_clear.py`, run through `vision_run.py --event-clear`. It sends
     READ and CONFIRM only.
   - Config: `protocol/hw_vepa/config/sel751_event_clear_20261026.json`. Do not use the `_20261025` config, which
     names the dead Vision host.
   - Last clear: `relay_event_clear_20261025_03`, final IIN `80 00`.
2. **Vision's management address is `decps@10.10.54.19`.** `.166` is dead. A config naming `.166` fails at its first
   Vision step and sets `unsafe_restoration`. That is how campaign `relay_event_clear_20261025_02` set the flag.
3. **New reconcile class `vision_never_reached`** (in `integration/evidence/rearm_01/hw/evaluation_campaign.py`,
   tests `tests/test_vision_never_reached.py`).
   - It clears the flag only for a block that ran nothing but pre-contact steps and failed to connect to the
     configured Vision.
   - It requires a Vision identity re-proof, a named latest baseline, and a full fresh `restore_verify` with Vision
     remapped.
   - It was reviewed twice before use. The record of its one live use is under
     `hw_campaigns/relay_event_clear_20261025_02/steps/…/reconcile_20261026T052057Z/`.
4. **Hardware path, unchanged.** Run these in order:
   - `freeze_gate.py write` and `check`;
   - an authorization record;
   - `run_block_frozen.sh … --dry-run` with the exact manifest argv;
   - `make_hw_manifest.py`;
   - `evaluation_campaign.py init`/`start`/`status`;
   - `restore_verify`.
   An unverified restoration stops all hardware work.
5. **Large logs live on disk only.** Three raw model logs of about 4.6 GB each are on disk, uncommitted, in
   `SE/ctl_timing_01/evidence/diag_shim_contention_m12p_c67_sdk9132_0{1,2,3}/model_*.log`. Their hashes are in each
   directory's committed `RAW_SHA256SUMS`. Other model logs are committed as `.xz`.

## Open items for Philip (none started)

1. **Two non-relay checks to decide.** The precision cleanup also removed two checks on the software-outstation
   path: the "OPERATE transit ≥ op_j" gate in `hold_check`, and the piggyback-fraction range check (with the standards
   `_recompute_hold` and the piggyback latency bound). Neither affects the SEL-751 runs. Restore them only if Philip
   says so.
2. **c67's mixed-loss SBO recovery failure** (handover 2026-10-25 closeout) was not retested on c68. c68 changes no
   forwarding logic, so the failure is expected to persist. Any retest needs a direction from Philip.
3. **Pre-existing test failures**, also failing on HEAD before this work: `test_candidate_series[response_ready_ack_d_v1]`
   and `test_profile_contract…mixed_timing_or_source_abi` (rearm_01). `test_readiness_configs.py` is an untracked
   leftover and was not committed.

## Standing constraints (from repository CLAUDE.md)

- **Commits.** Author and committer are `akekulip <akekulip@gmail.com>`. Use explicit paths, never `git add -A`.
- **Do not stage** `BRANCH_PRUNE_20260915.txt` or `DNP3_Implementation_Directive_492013014.md`. Their deletions
  pre-date this work.
- **Pushing.** Push only on instruction. No force push and no history rewrite.
- **Never modify** `defense4/timing/implementation/` or the listed raw_pcaps directories. c52 evidence is immutable.
  Do not touch `paper/`.
- **Testbed.** No Vision reboot, no OS, kernel or firmware change, no keepalive, no manual ownership edits, and no
  weakened restoration checks. Guarded points are {1,3}.
- **No CLRT threshold anywhere.** The visible CLRT is data, not a gate.

# Claude handover — c67 response-ready timing, 2026-10-25

Philip requested this handover and explicitly required that Claude **not expand the scope**. This file,
`plan.md`, and the current section of `WORKING_NOTES.md` supersede the October 24 handover's next actions.
Work is on `main`, HEAD `68fcec059`; the reviewed changes described below are still uncommitted.

## Scope limits — read before acting

Finish the existing c67 milestone. Do not restart design, sizing, native-relay characterization, compiler
investigation, or historical tooling cleanup. The generated P4 and its SDK 9.13.2 artifacts are already built
and verified. The immediate work is one narrowly identified abort-fixture repair, the remaining model gates,
then only the physical blocks already listed in `plan.md`.

Allowed next changes are limited to defects reproduced by a named required gate. Keep the current architecture,
packet queues, profile, workload, and acceptance thresholds. A broad refactor, new candidate design, or new
research question needs a separate instruction from Philip. Do not turn a difficult gate into added scope.

Do not add or revisit:

- A relay tap/mirror, timestamp recorder, switch-anchor image, synthetic ACK, new packet buffer, or TCP reassembly.
- Exchange deadlines, readiness/fallback success, keepalive traffic, raw-TCP master, new relay/control profiles,
  or changed production defaults. Physical SEL-751 testing of the existing profile is already authorized;
  general relay compatibility is outside this milestone.
- New D/J sweeps, 350 ms stress, attacker experiments, IEEE audit, manuscript work, or additional campaigns.
  The approved D values are 5/10/15/20 ms; J stays 2.4 ms. Physical J is explicitly **unproven by user choice**.
- OS/TCP/kernel/firmware changes, package upgrades, reboot, hand-edited ownership, weakened restoration,
  or a relaxed 100 us timing threshold. Use the installed Python 3.8 SDK runtime instead of changing packages.
- Rewriting retained results, borrowing an earlier passing attempt, bypassing source/profile/capture hashes,
  or weakening the surviving-response assertion to make abort01 pass.

If an authorized physical timing gate fails, retain all planned denominators and failed evidence. Diagnose only
the failing release/queue/capture path using the existing apparatus. If the remedy requires an excluded change,
report that concrete blocker to Philip; do not silently enlarge the work. Safely restorable recovery blocks
remain in the approved plan even if a reference timing criterion fails.

## Current implementation and candidate

```sh
ARCH="$PWD/defense4/timing/case4_architecture"
STAGE="$ARCH/integration/core/response_only_rearm/stage_experiments"
CTL="$STAGE/ctl_timing_01"
SEG="$STAGE/seg61_02"
RC="$STAGE/read_complete_01"
HW="$ARCH/integration/evidence/rearm_01/hw"
BUILD="$CTL/evidence/m12p_c67_sdk9132"
EVID="$RC/evidence/timing_response_ready_20261025"
```

- Source SHA-256: `e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1`.
- `compile_local/manifest.json`: p4c 9.13.2, exit 0, 101.867 s. The source, retained compile input and all nine
  manifest artifact hashes were reverified. Actual allocation: N/E stages 0..10, T 0..9, pipe-1 egress 0..3;
  all 11 T state objects have one physical bank. The same compiled bundle is used for model and hardware.
- Fresh regeneration is byte-identical, including normalized profile identity; record
  `EVID/c67_takeover_source_regeneration_01.json`. Do not re-record artifact pins or change inputs now: launches
  bind them. The generic compile wrapper's `full_target:false` label does not describe the actual two-pipe
  source; use the source, inputs, contexts and resource reports already reviewed.
- Contract `response_ready_ack_d_v2`: retain the genuine relay ACK until its matching complete response arrives,
  release ACK once, then release response after D. Keep OPERATE request hold J independently. No exchange expiry.
  Suppress validated request retries only while an original request or response is actually retained; otherwise
  permit TCP recovery without new admission/growth/J. FIN/RST/epoch clean up ownership.
- Existing physical shapes stay fixed: READ 91→141 `[50,91]`, integrity READ 134→158 `[24,134]`, control 49→60
  `[28,32]`. Timing-off/size-off arms use their selected profile's native sizes. Preserve application bytes,
  SEQ/ACK mapping, checksums and one growth commit per logical response. Faithful error delivery is transport
  correctness, not successful SELECT authorization or OPERATE. Retain the shared acceptance validators.

## Reviewed source changes to preserve

Five runtime drivers differ from HEAD:

| File under STAGE | Change |
| --- | --- |
| `seg61_02/model_repeat.py` | Genuine v2 ACK/response pair, actual T-clock D proof, exact destination checks, stop on failed prerequisites, planned/completed/unexecuted diagnostics |
| `ctl_timing_01/model_select_lifecycle.py` | Same v2 pair/endpoint/failure handling, without losing cancellation/replacement/retry/stale-authority scenarios |
| `seg61_02/model_abandon.py` | Install the source-bound v2 parameter ABI; retain original untimed default |
| `seg61_02/model_dup.py` | Correct obsolete replay-marker expectation; prove cached replay leaves generation/frontiers/growth unchanged |
| `ctl_timing_01/model_contention.py` | Fold each v2 timing proof into its existing committed-case verdict, preserving the finite reset-case schema |

The repeat and lifecycle repairs prevent exact bytes on the wrong port from passing, and prevent a failed
request from causing manufactured relay replies or dependent OPERATE traffic. Tests execute the actual driver
control flow. Current hashes:

```text
model_repeat.py           4d259036e3bd0e74a812b67c7fd8d770a52d95c436090c77bca685bc14a773bb
model_select_lifecycle.py 35e0d4444dfc12dec9a674f7ccb6a81099c5e5f6b7749f6b27d1049c6b1752d8
```

Focused tests `seg61_02/tests/test_repeat_response_ready.py` (11 cases) and
`test_abandon_response_ready.py` (3 cases) are new/untracked. Independent repeat/lifecycle review: PASS,
64 targeted tests plus 24 additional timed-function probes. Duplicate and contention reviews also PASS.
Reports and the abort diagnosis are preserved in `EVID/claude_handover/`; they are supplementary snapshots,
not replacements for the current gate. Do not depend on the gitignored `.superpowers` copies.

## Model inventory and actual blocker

Latest completed attempts on c67, all with launch exit 0. A behavioral PASS does not override stale provenance
or missing required coverage:

| Driver | Attempt | Behavioral cases | Current qualification |
| --- | --- | --- | --- |
| smoke | 01 | 30/30 | current |
| packets | 01 | 763/763 | current |
| response_ready | 03 | 826/826 | current |
| rearm | 02 | 800/800 | current |
| dup | 02 | 117/117 | current |
| repeat | 03 | 530/530 | current; completed READ73/SELECT68/OPERATE67 equals plan |
| select_lifecycle | 02 | 138/138 | current; completed READ9/SELECT18/OPERATE6 equals plan |
| control_timing | 02 | 390/390 | current; four D settings |
| fin_busy | 01 | 193/193 | current |
| two_read_robust | 01 | 181/181 | current |
| relay_sbo | 01 | 1085/1085 | current |
| policy | 01 | 281/281 | current |
| policy_boundary | 01 | 206/206 | current |
| smoke_sizeoff | 01 | 30/30 | current |
| abort | 01 | 80/80 | BLOCKED: four absent survivor proofs and stale repeat dependency |
| contention | 02 | 453/453 | BLOCKED: stale repeat dependency |
| abandon | none | — | required, not run |

The enforced v3 gate therefore remains **BLOCKED**. There is no c67 freeze or physical result. *(Superseded: see the Closeout section at the end; the gate passed and all planned physical blocks ran.)* Earlier failed
attempts remain intact. Contention01's 493/493 still exited 1 because its postcheck rejected four extra timing
case names; contention02's 453/453 embeds those 40 timing proofs in the original cases and passed its postcheck.

**First next repair: abort stimulus, not the checker.** In `model_contention.py`'s held negative controls,
the fixture sends only a response, tests an invalid RST, then cleans up without ever sending the genuine ACK.
Under v2 the response must stay retained. All four rows have zero responses, master frames, ACK commits and
response releases. `_abort_negatives` correctly rejects them. Details and exact tags are in
`EVID/claude_handover/abort-gate-diagnosis.md`.

Repair only the v2 negative controls: after proving the invalid RST did not reset the connection, send the
matching genuine ACK and observe that the **already-held original** response survives and releases once after
full D. Require exact master-port ACK/response bytes and T-clock proof. Preserve the held positive abort cases,
strict survivor gate, cleanup and legacy behavior. Do not resend the response or create a new request as proof
of survival. Add the focused regression, review the change, then run the affected drivers.

At this checkpoint the next unused attempts are:

```sh
python3 "$CTL/run_model.py" "$BUILD" abort 2 --milestone m12
python3 "$CTL/run_model.py" "$BUILD" contention 3 --milestone m12
python3 "$CTL/run_model.py" "$BUILD" abandon 1 --milestone m12
python3 "$CTL/model_summary.py" "$BUILD" --v3 --enforce
```

Check for existing directories before launch and use the next unused number. Never rerun in place. At most
two isolated model instances: the host has 196 hugepages and each model reserves 72. Recompute the exact stale
dependency set after the fixture edit; rerun additional drivers only if their executed closures actually change.

## Verification and runtime notes

- Generator suite: 182 passed, 1 skipped, 163 subtests passed; ten legacy generator identities unchanged.
- Full CTL suite was accidentally invoked with research Python 3.12: 994 passed, 3 failed and 6 setup errors,
  all nine due to importing the SDK's Python 3.8 `grpc._cython.cygrpc`. The three relay-observation tests and six
  timeline-wrapper tests pass when rerun with system Python 3.8. Retain both the failed invocation and corrected
  results; do not describe the original full command as passing. Logs: `EVID/c67_takeover_ctl_offline_01.log`,
  `c67_takeover_relay_sbo_py38_01.log`, `c67_takeover_timeline_py38_01.log`.
- Use system `python3` (3.8) for SDK/model/CTL tests. Use `~/.venvs/research/bin/python` (3.12) for generator
  tests and modern software encoder annotations. No package changes are needed.
- The other Codex task acknowledged handover and stopped edits/launches. Its superseded coordinator was
  stopped, not resumed; its last model child finished. New scheduling stopped when Philip requested Claude
  takeover. At the final check, no model, test, archive process or hardware campaign remained running.
  `EVID/claude_handover/final-state.json` records the enforced gate, source hashes, process and ownership state.

## Hardware continuation — only after the complete model gate

No c67 pipeline load, traffic, or physical control action occurred. Read-only checks found the expected
`case4_response_path` program on `decps@10.10.54.81`, Vision `decps@10.10.54.19` data interface
`enp59s0f0np0` UP at `192.168.10.1`, no running `dnp3-eval-*` unit, and local ownership inactive with
`unsafe_restoration=false`. Recheck live state through the existing preflight before any run.

The existing ten configs `RC/hw/config/rc01_m12p_c67_sdk9132_sel751_d*.json` passed local dry preflight.
Only these blocks are approved:

1. D5 combined smoke: both READ workloads and one successful SELECT/OPERATE pair (4 exchanges).
2. D5 reference with four arms; D10/D15/D20 reference with timing_only and combined. Each arm has 65 READ,
   64 SELECT and 64 OPERATE. Total: **1,930 planned reference exchanges**, with off/size_only only once.
3. D20 combined mixed/full identity-loss presets, graceful close, RST, and all three reconnect connections.

Use only the existing frozen supervisor: `freeze_gate.py`, `run_block_frozen.sh`, `evaluation_campaign.py`,
and independent `restore_verify.py`. After the final passing summary, write the first c67 freeze against
all ten configs, check it, and dry-run the exact block argv before initializing the campaign. The manifest
generator takes `--config-tag d5` (or d10/d15/d20), with block tokens `smoke`, `reference`, `reference_rest`,
etc.; do not pass invented `d5_smoke` tokens. Exact commands are in `EVID/claude_handover/hardware-prep-report.md`.

Existing standing authorization covers only these guarded physical SEL-751 blocks. Record it per run;
do not ask again merely to execute the already-approved block. Keep guarded points {1,3}, code1/count1/
on200ms/off0. Restore baseline program, ports, slot, offloads and owned network state through the runner.
An unverified restoration stops all hardware work. Never change ownership by hand.

Reference acceptance remains planned=eligible, n≥20 per mixed READ/integrity READ/SELECT/OPERATE,
nearest-rank p99 absolute complete-CLRT error≤100 us. Preserve maxima, first/complete timing, drops,
retransmissions, byte/application/SEQ/ACK evidence and switch counts. No successful fallback. Use the existing
capture/offload evidence before claiming switch-emitted packet boundaries. FIN remains open until all complete
recovery blocks pass; physical J remains unproven.

## Retention, Git, and completion

Preserve immutable c52 source/evidence and earlier failed candidates. Preserve the unrelated pre-existing
deletions `BRANCH_PRUNE_20260915.txt` and `DNP3_Implementation_Directive_492013014.md`; do not stage them.
The old October 14 61-octet directive is not the current task. No new commit or push was made during this takeover.

Model evidence and several archives/configs remain untracked. Use explicit paths, never `git add -A`.
`EVID/claude_handover/evidence-retention-plan.md` gives the existing restoration manifest format, metadata
set and eleven still-untracked compile resource reports. `archive_c67_completed.py` in that directory archives
only finished attempts and verifies raw/archive hashes. Raw logs stay local; `.xz` plus pins are retained in Git.
The completed archive pass pinned 44 logs across 22 attempts. The six logs for repeat03, lifecycle02 and
control_timing02 remain intact locally but still need archives/pins; the snapshot names them exactly. Do not
archive live logs or alter
launches/closures/results. `RC/restore_retained_logs.py` restores pinned bytes without overwriting originals.

After the three remaining model gates and authorized hardware blocks, finish clean-checkout reproduction,
final readouts, documentation and the already-authorized task commits/push. Use Philip's author and committer
identity `akekulip <akekulip@gmail.com>`, no attribution trailers, no history rewrite. Include updated
`WORKING_NOTES.md` in a push. Keep c52's historical pins unchanged. Do not call a checkout reproducible merely
because `reproduce.sh` skipped a missing freeze. The final source/evidence commit must actually reconstruct
the current gate and check the real c67 freeze/configs.

## Closeout (2026-10-25, Claude; Philip's disposition)

**c67 outcome (2026-10-25 closeout; Philip's disposition).** The planned c67 hardware testing is complete, and c67 has
**not** passed hardware qualification.

| dimension | result | evidence |
|---|---|---|
| model gate | PASS | 17/17 drivers; `model_summary.py --v3 --enforce` = model_gate_passed (`model_summary_v3.json` 4dbd5710...) |
| smoke (D5) | PASS | campaign `rc01_hw_c67_20261025_02` |
| FIN recovery | PASS for the planned scope (plan.md FIN criterion) | campaign `_07`: graceful, RST and reconnect, each with all three connections, restoration verified |
| timing | FAIL, cause unresolved | campaigns `_03` (D5, four arms), `_04`/`_05`/`_06` reference_rest (D10/D15/D20) |
| mixed-loss SBO recovery | FAIL | campaign `_06` loss_mixed_950, trial t3 |
| physical OPERATE J | unproven | no relay-side observation |

- **Freeze:** every block ran under `freeze_v3_02.json` (b82acb00...). `freeze_v3.json` (bd8852a2...) predates the
  v2-only installer fix and is retained. Campaign 01 was refused by the installer dry-run before any pipeline write,
  because the installer expected a T register (t0_reg) that the v2 build does not compile. Every block's
  restoration was verified, and ownership ended inactive with unsafe_restoration=false.
- **Timing:**
  - All 1,930 planned reference exchanges were observed and eligible.
  - Every timed class at every D fails the unchanged 100 us criterion (0 of 32 timed cells pass).
  - The nearest-rank p99 absolute errors range from 1.722 to 44.104 ms.
  - The worst case is D10 timing_only mixed READ (n=33). Its observed complete CLRT is 54.104 ms, an absolute error of
    44.104 ms at D=10; with 33 samples, that error is also the p99.
  - The other timed classes lie roughly within D +/- 2-3 ms. The spread does not change with D, which does not locate
    its source. No cause is attributed (Vision included).
  - `evidence/c67_reference_replay_20261025.json` (5010adec...) is an offline replay with the campaign checker
    (relay_check.py), not an independent checker validation. It reproduces the recorded per-class precision exactly.
- **Mixed loss:**
  - In trial t3, the padded SELECT response was dropped by identity-targeted loss. SELECT recovered after 1024.2 ms,
    and the relay then answered OPERATE with CROB status TIMEOUT on points 1 and 3.
  - This is recorded as an application failure, separate from transport correctness.
  - The other SELECT recovery times (c67 loss_full t3 1007.5 ms with OPERATE OK; c52 loss_mixed t3 1001.7 ms with
    OPERATE OK) neither measure the relay's select window nor show that D caused the expiry.
- **Debugging scope:** further work is limited to bounded, hypothesis-specific debugging and retesting of these two
  failures, on the existing testbed, profiles, guarded operations and restoration (Philip, 2026-10-25). Failed
  evidence and the original thresholds are preserved. It must not become a new feature, production default, relay
  profile or instrumentation project.

Model repairs and attempts:
- the abort v2 held-negative fixture now injects the genuine ACK after the no-reset proof and requires the
  original response to survive exactly once after the full D (`model_contention.py` `abort_survivor_verdict`;
  `ctl_timing_01/tests/test_abort_response_ready.py`);
- abort02 84/84, contention03 457/457, abandon01 12/12, then the enforced v3 gate PASS;
- hardware installer: `response_only_rearm/hw/bringup_composite.py` drops `t0_reg` from the sealed T readback only
  for `response_ready_ack_d_v2`, with a test tying it to the compiled registers.

Retention:
- every completed c67 attempt, failed and passing, is archived and pinned in
  `read_complete_01/evidence/c67_dependency_retention_20261025/manifest.json` (56 logs), and
  `restore_retained_logs.py` passes;
- the four `test_sealed_profile.py` snapshot fixtures were repaired (test-only).

Two `rearm_01/hw` tests fail identically at committed HEAD `68fcec059`, because they exercise the superseded v1
contract (`test_candidate_series` switch gate [v1] and the `test_profile_contract` mixed-ABI test). They are
recorded, not changed.

Next (revised scope): bounded, hypothesis-specific debugging and retesting of the timing and mixed-loss failures,
offline discrimination first. A concrete lead is D10 block 04, timing_only exchange 162: the ACK arrived 2.908 ms
after the request and the response at 57.012 ms, with normal switch counters. This is not yet explained. Any new
config, freeze or campaign follows the existing guarded path, with its own authorization record.

## Addendum 2026-10-26 — c68, criterion removed, hardware before vs after at every D

This addendum supersedes the timing statements above; the closeout text above is kept as written.

- Philip (2026-10-25): the 100 us p99 |CLRT − D| criterion was agent-written (rearm_01/PLAN.md, 2026-10-12), not his;
  it does not matter and is not reported. It is removed from the live harness (protocol/hw_vepa, rearm_01/hw), the
  config generator and the live documents. The CLRT an adversary between master and switch sees (ACK -> response per
  class) is reported as data only; correctness gates are unchanged.
- c68 (`m12p_c68_sdk9132`) = c67 with write-only switch measurement state removed (generator
  `m12gen/strip_telemetry.py`). Model gate 17/17 (attempt 04) with the removed counters recounted from the model log
  (`integration/core/telemetry_from_log.py`, verified against real c67 registers in `diag_shim_*`).
- Physical SEL-751: `rc01_hw_c68_20261026_01..04` (D=5/10/15/20), off (before) and combined (after), every block rc 0,
  restoration verified. Table: `read_complete_01/CURRENT.md`; data `read_complete_01/evidence/c68_visible_clrt_20261026.json`.
- Found on the way: the relay's spontaneous class-2 event (IIN1.2) broke the integrity READ for every build; cleared
  once by Philip's choice (`relay_event_clear_20261025_03`). A wrong Vision host in my event-clear config set
  unsafe_restoration; cleared through a new reviewed reconcile class (`vision_never_reached` in
  `evaluation_campaign.py`), fresh restore_verify passed in full. Details: WORKING_NOTES 2026-10-25/26.

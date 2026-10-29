# c73: c72 with proven dead and no-op P4 removed

**Parked (Philip, 2026-10-29).** c73 frees no stage and its integration is unfinished; the current priority is a
c72-derived packet-loss fix. **c73 is MODEL-QUALIFIED ONLY.** It has not run on the switch, Vision or the SEL-751. A
hardware matrix for a new candidate needs Philip's go-ahead (CLAUDE.md). Every hardware result in this repository was
taken with c72 (`results/builds/c72`, source SHA-256
`97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e`). None of it transfers to c73.

- c73 source SHA-256: `3e7dbb38c0bbd03f7cb0946c4621b043172a6eab3b839be0c1ed6389b4e77b2c`
- **Not canonical yet.** In the repository, `p4/response_only.p4` is still c72, so c72 remains runnable and every
  c72 test stays green. `canonical_switch.patch` holds the tracked-file changes that make c73 canonical:
  `p4/response_only.p4`, `scripts/model/action_observations.json`, `scripts/model/cp_base.py`,
  `results/analysis/stage_cut/current_build.json` and `tests/p4/test_e_wend_equivalence.py`. Apply it with
  `git apply results/builds/c73/canonical_switch.patch` only after the integration below is finished and Philip
  approves. Until
  then `summarize_v3(results/builds/c73)` reports blocked, because the model evidence binds the c73 versions of
  those files. After the patch it recomputes `model_gate_passed`, and the c72-premise tests listed under "Tests"
  below must be retired at tag `c72-validation-final` or re-targeted.
- Size: 2,256 lines and 286,584 bytes in c72; 2,100 lines and 270,814 bytes in c73. 156 c72 lines were deleted, 70
  were edited, and nothing was added.

## How c73 was made

`derive_c73.py` turns `results/builds/c72/response_only.p4` into the c73 source byte for byte:
`python3 results/builds/c73/derive_c73.py results/builds/c72/response_only.p4 OUT.p4 MANIFEST.json`.

- **Edit set.** It is the read-only inventory's cumulative variant D2, without the kind-12 replay domain, plus a
  "tidy" group of direct consequences.
- **Checked edits.** Each edit asserts its exact match count.
- **Real deletion.** The edits first run in blank-line mode, then every line they emptied is deleted.
- **Records.** `c73_removals.json` lists every edit by group, the deleted c72 line ranges and the edited c72 lines.
  `c72_to_c73.diff` is the unified diff.

**Real deletion changes only generated names.** bf-p4c names synthesized tables and actions after source lines
(`tbl_response_onlyNNN`), so real deletion renames them. No script, test or JSON under `scripts/` or `tests/` names a
specific one. `scripts/diag_mirror_checks.py` and `scripts/hardware/check_mirror_select.py` match them only by
pattern.

`real_deletion_check.json` holds the proof. The same edits in blank-line mode (line numbers equal to c72's) were
compiled with the same command. After normalisation, the twin's `.bfa` equals c73's: 0 differing lines in p0
(53,806 lines) and p1 (6,540). Blank-line preservation is therefore not kept anywhere.

## What was removed (c72 line numbers)

**A2: the certain set.** The inventory measured a 0-line normalised `.bfa` diff for this set.

- **13 tables that no control applies**, with their actions:
  - N: `syn_shapes` 244, `short_shapes` 248, `available_t` 276, `epoch_guard` 340, `read_request_profile` 445,
    `rd_second_crc_t` 455, `rd_request_crc_t` 458, `rd_tail_crc_t` 468.
  - E: `in_rb0_t` 878, `in_rb1_t` 881, `in_rt_t` 884, `crc_read_tail_t` 1154, `crc_read_b_t` 1157.
  - 14 actions go with them. So do 8 Hash instances and the `tcp_read` Checksum at 1293.
- **8 uncallable T actions:** `peek_gen`, `admit_gen` and `reset_bump_gen` 1628-1630; `bypass_request` 1776;
  `stop_blocking_off` 1833; `flush_ack_off` 1900; `flush_response_off` 1932; `unmatched` 1943.
- **36 metadata fields that nothing reads**, with every write to them:
  - N: 26 fields (lines 110 and 113), among them the decoy and frozen-decoy fields, `emit_loop`, `cache_mode`,
    `changed`, `tcp_length` and `counter`. The writes in `configure` (250) go too, but its parameters stay.
  - E: `result` (19 writes), `rtcrc`, `rtcrc_b`, `in_rb0` and `in_rb1`.
  - T: `cur_epoch_val`, `quarantined_epoch`, `seen1_diff` and `seen2_diff`.
  - x: `p1_res`.
- **Unused headers:**
  - N instances `second`, `response_tail`, `rd_tail` and `rb`, and the types `n_response_tail_h`, `n_read_tail_h`
    and `n_replay_h`.
  - E types `r_ctl_tail_p1_h`, `r_ctl_tail_p2_h` and `r_read_d56_h`.
- **20 unreachable parser states:** 19 in `n_IgParser` (129-198) and `mss` in `r_EgParser` (788).
- **Uninstantiated shells:** `n_EgParser`, `n_Egress` and `n_EgDeparser` (576-578); `t_EmptyEgress*` (2093-2108).
- **The constant `r_SH_NONE`** (609).

**B2: E read headers that are never valid.** `read_b0` (796-797) is the only state that extracts `p03`..`c2`, and no
state transitions to it.

- Removed: that state, 15 header instances (`ra p03 ca rbh p45 c0 p69 p1012 cb rc p1321 c1 p22 c2 cd3`) and 8
  header types.
- Removed: their 9 fields plus one `8w0` pad from both incremental TCP checksum lists (1307-1309 and 1321-1323).
  The removed fields total 30 bytes, an even count, so the byte parity of the remaining fields is unchanged.
- Removed: 10 `emit` calls (1332-1335) and their 9 `@pa_no_overlay` pins (703-711). Those pins sit in the block
  before `r_IgParser`, which bf-p4c already drops.

**C2, without kind 12:**

- `read_input_t` row `(8w9,false,false,_)` and its action `read_request_input` (469). After A2, `packet_kind` 9 is
  set only in `read_request_full` and `read_request_mx`, so one of those two headers is always valid.
- With that row gone, `hdr.rd_req`, its type and two `@pa_mutually_exclusive` pins (209-210).
- Five actions that no row can select. Each is listed in a const-entries table with a const default but appears in
  no entry: `close_pending` and `close_free` (348-349), `first_close_ack` (380), `close_forward` (402) and
  `rev_withhold_zero` (1176).
- `m.rbad0`, `m.rbad1` and `m.rbadt`. Each is set to 0 in the parser and written nowhere else, so their key columns
  in `acct_t` and `classify_fwd` held only `0` or `_`. The fields, the key columns, the parser writes and the pins in
  the dropped block are removed.

**D2:**

- `n_ExpectedWorkRecord` operation 3: the `inspect` RegisterAction (45-50), `inspect_work`, four `dispatch` rows
  (size 9 to 5) and the comment describing operation 3 (23). `m.work_op` is only ever assigned 0, 1 or 2.
- `r_Egress.odd_ip_t` and `odd_conn` (830-834). `odd_conn` wrote `m.dir` and `m.idx`, and then the same branch
  called `drop_lifetime()`. Nothing read them afterwards, so that branch now calls `drop_lifetime()` directly.

**tidy:**

- 13 `r_OUT_*` constants (612-617) whose only use was a removed `m.result` write.
- The `settle_t` comments about `m.result` (1222-1223, 1250). The comment now says that `native`, `armed_map` and
  `armed_nat` are empty actions kept as model telemetry markers.
- The stale rbad/`read_b0` comment (1257).
- The emptied `CASE4_PROBE_SHELL_P4` include guard (2090-2109).
- Whitespace left inside edited lines.

**Kept on purpose:**

- **The kind-12 replay domain**, every row and action of it: `committed_t`, `network`, the origin transitions
  `0x010c`/`0x020c`/`0x030c`, `first_replay` and `count_replay_refused` with their `first_event` rows, the two
  `continuation_t` `next_stage` rows, `busy_t` and `guard`. Philip must confirm it is retired before it goes.
- **E3** (the N `t0` header).
- **The inventory KEEP list:**
  - empty telemetry markers counted by the model gate;
  - `t_N_RETURN`, `r_IMAGE_LEN` and `t_MODEL_PKTGEN_IN`;
  - the 61-byte sentinel rows and the T outer guard;
  - the `configure` parameters;
  - the `r_IgParser`/`r_Ingress`/`r_IgDeparser` shells. Deleting them would re-attach the 50-line pin block in
    front of them.
- **`out_drop(bit<8> why)` and the three constants it receives** (`r_OUT_DROP_OVERLAP/AHEAD/MERGED`). `why` became
  unused with `m.result`, but removing it changes an action signature and the const entries. That is a follow-up,
  not part of the measured D2 set.

## Tooling bound to the canonical source (changed by `canonical_switch.patch`, not yet applied)

- `scripts/model/action_observations.json`:
  - `source_sha256` is c73's.
  - The four removed actions are unmapped: `t_Ingress.bypass_request`, `stop_blocking_off`, `unmatched` and
    `r_Egress.rev_withhold_zero`. None of them could ever execute.
  - 18 retained action-body hashes were recomputed. Each body equals its c72 body with only `m.result` or
    `m.emit_loop` writes removed, after whitespace normalisation, and the update script asserts that.
  - Every retained numeric observation cell is unchanged.
  - Review record: `action_map_review.json`.
- `scripts/model/cp_base.py`, `e_conn_rows`: stops passing on `response_path_cp`'s two `Egress.odd_ip_t` rows, the same
  way it already dropped that module's `Ingress.forwarding` rows. The model drivers and the hardware installer
  (`scripts/hardware/rows.py`) both build their E rows here.
  - `response_path_cp.py` is deliberately unchanged. The inventory suggested editing it at lines 78-79, but it is
    also the control plane of the production program `case4_response_path`. `campaign_base` restoration reinstalls
    that program's relay slot through `switch_slot.py relay` (lab.json `relay_slot: true`), so editing it would
    change production restoration.
  - `installer_plan_vs_c72.json`: the offline installer plan for the c72 campaign argv was 36 operations; it is
    now 34. Exactly the two `p0.r_Egress.odd_ip_t` rows are gone and the order of the rest is preserved. c73's plan
    equals c72's plan under the new tooling.
- `results/analysis/stage_cut/current_build.json` names c73. It is the only build `tests/p4/test_stage_target.py`
  reads.
- `tests/p4/test_e_wend_equivalence.py`: `classify_fwd` has 13 key columns instead of 16 (the three constant-0
  rbad columns are gone), so the all-zero tail of the probe vector is 11 long instead of 14. The assertion is
  unchanged.

## Resources (SDK 9.13.2, c72's command and flags, no defines)

`resource_comparison.json` uses baseline c72. `resource_review.json` uses baseline c69, the same layout as c72's
own review.

| | c72 | c73 | delta |
|---|---|---|---|
| p0 ingress / egress stages | 10 / 10 | 10 / 10 | 0 / 0 |
| p1 ingress / egress stages | 8 / 4 | 8 / 4 | 0 / 0 |
| p0 PHV containers (all) | 174 | 174 | 0 |
| p0 PHV bits used | 3,381 | 3,372 | -9 (egress) |
| p0 8b / 16b / 32b containers | 39 / 71 / 64 | 41 / 69 / 64 | +2 / -2 / 0 |
| p0 egress tagalong containers | 48 | 35 | -13 (-5 8b, -8 32b) |
| p0 VLIW instructions | 119 | 115 | -4 |
| p0 SRAM blocks | 158 | 154 | -4 |
| p0 hash bits | 1,017 | 977 | -40 |
| p0 exact / ternary xbar bytes | 436 / 363 | 430 / 362 | -6 / -1 |
| p0 action data bus bytes | 238 | 234 | -4 |
| p0 logical table IDs | 112 | 111 | -1 |
| p1 MAU and PHV | | | none |

**Deviation from inventory variant D2.** All deltas match D2 except VLIW, which is -4 here against -5 in D2. The
missing instruction is in stage 9 (first_event: D2 has 27, c73 28). It is `first_replay`, which c73 keeps because
the kind-12 domain is excluded.

**PHV.** The total container count is unchanged. Two 16-bit containers became two 8-bit ones, a re-pack of the
same fields.

## Model gate

**`model_summary_v3.json`: `model_gate_passed`, 17 of 17 drivers, no blocked reasons.** The drivers ran
unchanged through `scripts/model/run_model.py` on SDK 9.13.2 tofino-model. That is functional output, not hardware
and not timing.

| driver | c73 run | cases | c72 run |
|---|---|---|---|
| abandon | model_abandon_c73_01 | 12/12 | model_abandon_c72_02 |
| abort | model_abort_c73_02 | 84/84 | model_abort_c72_01 |
| contention | model_contention_c73_01 | 457/457 | model_contention_c72_01 |
| control_timing | model_control_timing_c73_01 | 417/417 | model_control_timing_c72_01 |
| dup | model_dup_c73_01 | 308/308 | model_dup_c72_01 |
| fin_busy | model_fin_busy_c73_01 | 193/193 | model_fin_busy_c72_01 |
| packets | model_packets_c73_01 | 763/763 | model_packets_c72_01 |
| policy | model_policy_c73_01 | 281/281 | model_policy_c72_01 |
| policy_boundary | model_policy_boundary_c73_01 | 206/206 | model_policy_boundary_c72_01 |
| rearm | model_rearm_c73_02 | 798/798 | model_rearm_c72_01 |
| relay_sbo | model_relay_sbo_c73_01 | 1069/1069 | model_relay_sbo_c72_01 |
| repeat | model_repeat_c73_01 | 526/526 | model_repeat_c72_01 |
| response_ready | model_response_ready_c73_01 | 838/838 | model_response_ready_c72_01 |
| select_lifecycle | model_select_lifecycle_c73_01 | 146/146 | model_select_lifecycle_c72_01 |
| smoke | model_smoke_c73_01 | 30/30 | model_smoke_c72_03 |
| smoke_sizeoff | model_smoke_sizeoff_c73_01 | 30/30 | model_smoke_sizeoff_c72_01 |
| two_read_robust | model_two_read_robust_c73_01 | 181/181 | model_two_read_robust_c72_01 |

Two earlier attempts stay on disk, disclosed:

- **`model_abort_c73_01`.** The driver printed 84/84 PASS. An interruption of the agent session then killed
  `run_model.py` before it wrote `launch_command.json`, so the attempt has no launch record. Attempt 02 passed 84/84.
- **`model_rearm_c73_01`.** 795 of 798 passed. `inverse_distance113_window0`, `_window112` and `_window113` failed.
  - In `_window113`'s exchange, the model delivered the normalizations of `_window0` and `_window112` late, after
    each case's 0.5 s exchange timeout.
  - Its 3 captured frames are byte-exact matches for the three expected frames from IP offset 34 on. The neighbouring
    distances 112 and 114 passed every window.
  - This is model wall-clock latency, like the c72 abort race. Attempt 02 passed 798/798.

**Comparison with c72** (`results/models/c73/gate_vs_c72.json`; the comparator source is embedded in the file):

- **Cases and exits.** All 17 c73 runs exit 0. Case names and verdicts are identical to c72's latest runs for every
  driver: 6,339 cases.
- **Observed values.** They are compared leaf by leaf. 14 drivers have no observed difference at all.
- **Timestamps.** 48 differences are T timestamps (`t_Ingress.ack_commit_at_reg`): 23 in control_timing, 23 in
  response_ready and 2 in rearm.
- **Re-waits.** 34 are the T hold re-wait count: cell 1 of the T outcome counts, in 17 control_timing and 17
  response_ready snapshots. It is 24 to 23 in control_timing and 25 to 24 in response_ready.
- **Old-epoch drops.** 34 are cell 14 of the same counts (`drop_old_epoch`, a held packet still looping when the
  epoch advances), in the same snapshots: 3 to 2 and 2 to 3.
  - This class is not in the stated allowed list, so `only_stated_allowed_differences` is false.
  - It is run-to-run hold-loop timing. Pipe 1 (T and x) of c73 equals c72 after name normalisation, except one hash
    seed line, and so does c72_diag_mirror's.
  - Runs of that identical T binary already disagree. In control_timing, (cell 1, cell 14) is (24, 3) in c72 and
    (25, 2) in c72_diag_mirror; in response_ready, it is (25, 2) and (24, 2).
  - `only_run_to_run_variation` is true.
- **Run closure.** The runs used this worktree's `scripts/`, which differs from commit ca0db02d1 in exactly two
  files: `scripts/model/action_observations.json` and `scripts/model/cp_base.py`, both described above. No driver
  differs from the commit.

## Not established, and follow-ups

- **No hardware.** c73's behaviour on silicon, its timing and its installer readback on the switch are untested.
- **Prior-candidate tests fail by design.** Making c73 canonical revokes the premise of every test that asserts
  "c72 (or its diagnostic derivative) is deployable from this tree". The freeze gate refuses any non-canonical
  candidate; the live model summary blocks once `action_observations.json` no longer binds c72's source; the
  diagnostic generator's anchors sit in deleted code (`n_EgParser`, `tcp_read`). Those tests were left as they are.
  Philip decides whether to retire them at tag `c72-validation-final` (plan step 10) or re-target them once c73 has a
  hardware configuration. Measured by the independent review on main at `c95d8266d` (after E4b), with the switch
  patch applied, `python3 -m pytest tests --ignore=tests/analysis` gives 425 passed, 27 failed and 19 errors; without
  it, 469 passed and 2 failed (the 2 are path-bound goldens that pass in the main checkout). In the original worktree
  (base `ca0db02d1`) it was 335 passed, 24 failed and 19 errors. The 3 extra failures on main are
  `tests/hardware/test_e4b_definition.py::test_every_existing_definition_prepares_byte_for_byte_unchanged[diag_d3_off|
  diag_d3_on|diag_e2_first]`: after the switch, the diagnostic definitions cannot be prepared, because
  `diag_mirror.json` names c72 as the canonical source. The failures in the worktree:
  - `tests/hardware/test_freeze_gate_diagnostic.py` (32) and `tests/hardware/test_diag_definitions.py` (4): the
    canonical source is no longer c72 and the diagnostic generator cannot regenerate its build.
  - `tests/model/test_abandon_timed.py::test_c72_gate_summary_has_no_blocked_abandon_closure`: c72's live closure
    names the old `action_observations.json`.
  - `tests/hardware/test_diag_runtime.py`, four tests (GOLDEN_PLAN_SHA x3 and the c72 dry-run stdout golden): the c72
    installer plan lost the two `odd_ip_t` rows (`installer_plan_vs_c72.json`).
  - `tests/hardware/test_diag_runtime.py::test_unit_commands_are_unchanged_without_diag_mirror` (2): an artifact of
    the worktree path, failing before the change too. With the main checkout path substituted, both hashes equal
    their goldens with the c73 changes.
  - `tests/build/` is not collected by that command (pytest skips directories named `build`). Run explicitly, it
    gives 40 passed and 8 errors, all `tests/build/test_diag_mirror.py` generator-anchor errors of the same kind.
- **Kind-12 replay domain**: needs Philip's confirmation that it is retired.
- **E3** (the N t0 header and lap format change): excluded, needs its own model gate.
- **Pragma trap.** The 50-line pin block before the uninstantiated `r_IgParser` is still dropped by bf-p4c. Moving
  or deleting it changes allocation (+3 8-bit containers and +1 TCAM, measured by the inventory).
- **Unused parameter.** `out_drop`'s `why` is a candidate for a later cleanup.
- **Compile manifest paths.** `compile_local/manifest.json` records the worktree's absolute paths. Every live
  verifier passes `source_root=results/builds/c73`, the same as for c72, whose manifest also records a different
  checkout path in the clean-clone reproduction.

## Independent review (2026-10-29)

A read-only P4 review found no CRITICAL or HIGH issue and recommends keeping c73 as the next candidate. Its checks:
- the A2 set compiles to c72's normalised `.bfa` exactly;
- the egress checksum entries are identical apart from the 13 removed never-valid entries (29 bytes plus the `8w0`
  pad, so byte parity holds);
- the const entries of all 59 tables are identical apart from the intended rows;
- the rbad key columns are provably zero where read;
- no tool hard-codes a generated table name.

It reran two drivers on c73, kept under `results/models/c73_review/`:
- `response_ready` attempt 09: 838/838. Its old-epoch drop count differs from c73 run 01, which confirms that count
  varies between runs of one binary.
- E4 (timing-on abandoned SELECT) attempt 10: 14/14, with no difference from c72's E4 run. Attempt 09 failed only
  because bf_switchd did not start within the default 15 s wait.

Open from the review: the 17-driver gate never sends an IPv4 packet with IHL ≠ 5. The `odd_ip_t` removal therefore
rests on a static proof (both hit and miss lead to `drop_lifetime()`, and nothing reads the fields it wrote). One
IHL = 6 packet through c73 on the model would close it.

# Phase 8 — bounded experiments: readiness, runbook and the exact blockers (2026-10-06)

**Status: NOT RUN.** No candidate was loaded, no traffic was sent to the relay, and the live switch was only read (processes and file
listings on the switch host). The assignment authorises bounded READ and non-actuating SELECT runs after the technical preconditions
pass; three of them do not yet pass. Physical OPERATE stays attended-only and was not prepared for hardware.

## Preconditions

| gate | status | evidence |
|---|---|---|
| response-ready tests, release and recovery | **pass** | 47 candidate tests; model-versus-P4 diff, 14+ scenarios; mutation tests |
| compile, SDE 9.13.1 and **9.13.2**, current source `6387c588…` | **pass** | 7 ingress / 0 egress, 88 tables, identical schema in both (`local_build_35`, `sde_9_13_2_build_02`) |
| control adapter against the real schema | **partial** | offline only; three parameter tables; `connect()` never run |
| experiment declarations | **pass** | `framework/declarations/{smoke,main}.json`, validated, build identity bound |
| live state identified, not inferred from a handover | **partial** | read-only: `bf_switchd` pid 10674, up about 24 h, `--conf-file …/bringup_20261005/frozen_abs.conf --init-mode=cold` |
| **restoration procedure rehearsed** | **pass** | `RESTORATION_REHEARSAL_20261006.md`: cold restart with no candidate; one benign configuration difference (port 17 scheduler speed) |
| **candidate bring-up (ports, TM queues, pktgen, mirror/PRE, session tables) written against the new schema** | **blocked** | nothing in the tree configures these for the candidate; the adapter does not read or verify them |
| relay-facing capture point | **unknown** | state it before the run and restrict conclusions to the master-facing view if absent |

## Live state, read this session (not inferred from a handover)

Read-only snapshot, 2026-10-06 (`framework/results/live_state_20261006/live_snapshot_20261006.json.gz`, sha256 `43dd7c64…`, 292 tables, 190
bulk-readable and 102 refused with the reason kept; produced by `framework/control/live_snapshot.py`, which only calls `entry_get` and
`default_entry_get` under its own client id). `bf_switchd` pid 10674 was unchanged afterwards (about 25 h).

- Loaded program `defense4_rrc_bor_unified12` (schema from `rrc_bor_build_v2`). Ports up: dev ports 9, 10, 11 (25G) and 64 (1G); no loopback mode is set on any port, so this is
  the fresh-bring-up state, before a configuration run has put dp8 and the others into loopback.
- `tbl_params` default: mode 3 (does not arm), `read_len` 18, budget 18,000, `shape_enable` 0. `tbl_bor_params`: a_ticks 20,000,000, r_ticks 24,000,000.
  `tbl_session`: `sess_none`. `pktgen.app_cfg`: 7 entries. Traffic-manager, PRE and port tables are captured.
- The live `tbl_params` **has `shape_enable`; the candidate's does not.** A restore must be written for the live program's schema, never taken from the candidate's.
- Whether the frozen setup scripts can bring up the candidate is **not established**: a static look for table names was inconclusive (they reach tables by a
  different access pattern), so blocker 2 stays open until a dry run against the 9.13.2 candidate schema says otherwise.

## Why loading the candidate is not safe to do unattended

The only way to run a different program is to stop the single `bf_switchd` (pid 10674) and cold-start another. That drops every link and every
table, including the relay leg that needs the SFP in cage E1/33 and the isolation applied on Vision. The restoration path exists as files
(`launch.sh`, `ports_up.py`, `up2.py`–`up4.py`, `frozen_abs.conf`, and `dnp3_latency_20260926/{configure.py,fixed_config.json,off_config.json}`)
but has never been run end to end in the reverse direction, and `bfrt_snapshot.py` tolerates read errors and does not capture all TM and PRE
state, so a snapshot alone is not a restoration. An untested way back from a cold restart of the lab's only switch daemon is the missing item.

## What would clear it (in order)

1. Rehearse the restoration with no candidate: stop and cold-restart `bf_switchd` with `frozen_abs.conf`, replay the bring-up scripts, apply
   `off_config.json`, and read back ports, queue ladder, pktgen state, mirror/PRE and the three parameter tables. Save the full readback.
2. Write the candidate bring-up against the 9.13.2 schema, reusing the bring-up scripts' port and TM steps, and read every one of them back.
3. Run `framework/runner/cli.py plan` then `verify` read-only on the switch host; extend the snapshot to TM, pktgen and PRE.
4. Smoke: `framework/declarations/smoke.json` — 30 READs per mode, check raw captures, response validation, readback, reason counters, state cleanup.
5. Main series only if the smoke is clean: `main.json` (3 × 1,000 attempted READs per arm per policy, seed 20261006, counterbalanced).
6. After every session restore and verify; keep the transcript.

Refused points (admission) are reported, not dropped. No SELECT run starts until the guarded profile and isolation are verified. Never
infer the loaded program from an old note.

# Restoration rehearsal — cold restart of the Tofino with no candidate, 2026-10-06

Authorised by Philip in this session ("go on with it", after the cold start was explained). The candidate was **not** loaded. The purpose was to
prove the way back before any program swap.

## Procedure, as run (UTC)

| time | step | result |
|---|---|---|
| 16:29, 16:3x | read-only snapshots of the loaded program (`framework/control/live_snapshot.py`) | two snapshots 30 min apart: zero configuration differences (noise control) |
| before | baseline from Vision: ping 192.168.10.7 through the switch | 3/3, 0.35–1.3 ms |
| 16:33:23 | `sudo pkill -TERM -P 10671; sudo kill -TERM 10671` (the `launch.sh` group, pid 10674 was `bf_switchd`) | exited in under a second; 50052, 7777, 9090 listeners gone |
| 16:33:2x | `sudo setsid nohup bash …/bringup_20261005/launch.sh` (unchanged; same `frozen_abs.conf`, `--init-mode=cold`) | system services at 16:33:29, server started at 16:33:36 |
| 16:37:38 | `framework/control/restore_ports.py … live_snapshot_20261006.json.gz --apply --wait 35` (20 `$PORT` entries, speed/FEC/auto-negotiation/enable) | dev ports 9, 10, 11 (25G) and 64 (1G) up; dp8 enabled, not up, as before |
| 16:38:23 | post-restore snapshot, compared with the pre-restart one (`framework/analysis/compare_snapshots.py`) | see below |
| after | ping from Vision through the switch | 5/5, 0.33–0.56 ms |

The daemon was serving about 13 s after the kill. The rest of the roughly five-minute wall time was the SSH session hanging on the daemon's file handles and the port
settle time; a scripted run needs about one minute.

## Result

All 292 tables compared. **No configuration difference except one:** `tm.port.sched_cfg`, dev port 17, `scheduling_speed` was `BF_SPEED_NONE` and is now
`BF_SPEED_10G`. Port 17 is a neighbouring lane of the 40G port 16; the value follows from the order in which the earlier exploratory scripts created port 16 and is unused by this design.
`tbl_params`, `tbl_bor_params`, `tbl_session`, `pktgen.app_cfg`, the replication, mirror and traffic-manager queue and pool tables are identical. Counters, port statistics and registers differ,
as expected after a restart, and are reported as state.

## What this establishes, and what it does not

- Established: the pre-test state of this lab **is** reproducible by `launch.sh` plus the port replay from a snapshot, in one minute, with links restored and the SEL reachable
  through the switch. Blocker 1 of the runbook is cleared.
- Not established: that the *candidate* can be brought up (ports are only part of it; see the runbook). Nothing about the candidate was exercised.
- The live program's `tbl_params` has `shape_enable`, the candidate's does not; a restore is always written for the live program's schema.
- Cost: every link drops and every TCP session through the switch is cut for the restart window.

## Re-run

```
ssh decps@<switch host> 'sudo pkill -TERM -P <launch.sh pid>; sudo kill -TERM <launch.sh pid>'
ssh decps@<switch host> 'sudo setsid nohup bash ~/Philip_repo/logs/bringup_20261005/launch.sh > restart.log 2>&1 < /dev/null &'
python3 restore_ports.py defense4_rrc_bor_unified12 live_snapshot_20261006.json.gz --apply --wait 35      # on the switch host
python3 live_snapshot.py defense4_rrc_bor_unified12 post.json && python3 compare_snapshots.py pre.json post.json
```

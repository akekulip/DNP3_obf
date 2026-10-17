# m10_03 model-gate failures: causes (2026-10-17)

Each failure is classed as a dataplane defect, a harness defect or unresolved, from its trace. A later passing run
resolves nothing.

Tools in this directory, run from `ctl_timing_01/`:
- `trace_case.py LOG HEXPATTERN OUT.json`: the ordered decisions of every record of one connection;
- `tstamp_at.py LOG WALL...`: T's clock (`global_tstamp[39:8]`) of given ingress records;
- `window_probe.py CT`: a source-interpreter sweep.

| failure | run | class | cause (evidence) |
|---|---|---|---|
| `restart_SELECT_no_response_to_master` | `model_contention_m10_03_02` | **dataplane defect (propagation window); present on m9_01 and m10_03 as tested; m6–m8 not tested** | In the failing run the restarted master RST ran *behind* a response N had already handed to T: `emit_tev` 20.783, N's cancelling owner CAS 20.822, T's release of the held response by its normal rule 20.858, T's reset application (`close_epoch`) 20.880. The window between N's cancellation and T's application (N's stage 2 plus the hand-off) is the defect. m10's restart is what routed this case into it, so m10's finding-1 fix does not close it here. `window_probe_output.txt` shows the same window on m9_01 and m10_03 in the source interpreter, for a different scenario: a master RST arriving 1–5 laps before a held response's scheduled release lets the response out; none did at 6–39 laps; the pinned test asserts 8–13. On the model the window is a few laps (about 60 ms of model time). No silicon duration has been measured. The failure is intermittent on m10: `diag_restart_case_on_m10_03_01` passed restart_SELECT; `diag_driver_import_02` leaked again (released 29.118, applied 29.141). `diag_restart_case_on_m9_01_01` fails `no_response_to_master` by another mechanism: its first RST is not relayed. |
| `abort_held_READ_master_reset_at_rcv_nxt` | `model_contention_m10_03_01` | **harness defect** | The driver checked "held" from the outcome counters, then sent the outstation RST. T released the response by its rule at 32.382 (`release_response_counted`; egress 32.391). The outstation RST arrived at 32.552 (raw log line 2003578, src 10.0.0.2:20000, RST+ACK), 170 ms after the release; the reads after the 0.3 s capture took about 0.45 s. The record at 34.610/34.617 is the driver's cleanup master RST (line 2007175), not the outstation RST. The trace files' hex filter misses the reversed tuple, so the outstation RSTs appear only in the raw log. On m9_01 the outstation RST (04.851) arrived before the drop (`drop_old_epoch` 04.926). |
| `sweep_OPERATE_030ms_delivered_once_committed` | `model_contention_m10_03_01` | **harness defect** | The model process logged nothing from 21.9695 to 22.6433 while this connection's ACK was recirculating: a stall. T's clock kept its normal rate (about 1.25 model ns per wall ns). T's own registers give a_commit at t0 + 2402.5 ms (`ack_commit_at_reg` 141406249984 ns against `t0_reg` 139003749888 ns), so a_commit + gap reached t0 + readiness (2000 ms) and T's fallback was the contract outcome. On m9_01 the response reached T at t0 + 1536.2 ms and was released normally. The driver judged by host time. |
| `sweep_SELECT_060ms_request_relayed` | `model_contention_m10_03_01` | **harness defect** | The model logged nothing from 36.5935 to 39.8795 (3.29 s) while the request was in N. It was relayed at 40.108, after the driver's fixed 1.0 s capture window had closed. Because the driver then sent the outstation ACK while the request was still in N, N recorded three busy retries (`count_busy_delta[2] = 3`). The exchange itself completed (`RESP_RELEASE`). |

## Harness corrections (contract-derived; `contention_rules.py`, `tests/test_contention_rules.py`)

- **Request relay:** the contract is "relayed exactly once". The driver now waits for the relay up to `WAIT_S`
  instead of 1.0 s of host time.
- **Abort, held branch** (corrected after code review). The order is decided only from T's release counters, read
  immediately before the RST is sent (`contention_rules.abort_branch_outcome`):
  - already released: the released-branch expectation applies;
  - not released before the send but released after it: **inconclusive**. Such a release may have come after T
    applied the reset (the outstation RST also crosses the N-to-T window: N cancels at 32.575, T applies at
    32.591), so the point fails and is never passed.

  The first version of this rule decided from outcomes after the send and could have excused exactly that leak.
- **Sweep commit:** when T's own registers show `a_commit + gap >= t0 + readiness` (sign-bit comparison, as T makes
  it), the fallback is the contract outcome. The point is then judged as "delivered once by readiness" and listed as
  `committed_path_not_measured`; the raw register values and the margin are kept in the row. Model summary v3
  treats a non-empty list as **incomplete** and blocks. A commit not after t0 (initial value, stale or foreign read)
  is an invalid read and fails the point.
- **Request relay:** a relay over 1 s is recorded (`request_relay_over_1s`).

## Decision

The reset-propagation window is a dataplane defect against m6's original contract. On 2026-10-17 Philip scoped the
contract to T's reset-application pass (next section). The original result is kept as recorded.

## Revised reset contract (Philip, 2026-10-17)

The original contract ("the held response is never released" after a valid reset) is kept, together with its
recorded failure (`model_contention_m10_03_02`, `restart_SELECT_no_response_to_master`). It is not overwritten.
The revised contract is scoped to T's reset-application point:

- **The state update.** The reset takes effect for T's held traffic on the T_IN pass of the reset hand-off (tev kind
  0x0d). That pass runs `close_epoch`, which seals `cur_epoch_reg` (bit 31; `response_only.p4` `epoch_close`), and
  `live_reset_gen`, which bumps `gen_alloc_reg`. After it, any held packet of the old incarnation fails `match_epoch`
  (`OLD_EPOCH_DROP`) or the lane-generation check (`HELD_STALE_FLUSH`). It is never released.
- **Requirement 1:** a response that reached the master was released by a T pass before that update.
- **Requirement 2:** no T pass releases a response of the connection after it.

Separately named check: `reset_application_check.py`, with tests in `tests/test_reset_application_check.py`.
`run_model.py` runs it after every m10 contention attempt and retains `reset_application.json`, and model summary v3
requires every restart point to PASS ("no reset applied" blocks). Reset delivery, closure, reconnect and isolation
stay separate driver checks. Restart coverage is now a run-level check, because the model's timing decides whether a
given point interleaves.

Applied to the retained runs (after the code review's attribution fix: actions are attributed to the current
ingress record of their pipe, not by packet id):
- `model_contention_m10_03_02` restart_SELECT: one release pass found (20.857867), before T applied the reset
  (20.880497), and none after.
- `diag_driver_import_02` restart_SELECT: release 29.117758, application 29.141112, none after.
- **Verdict on both: `unattributed`, not PASS.** Their restart points did not record T's release count, so the
  required cross-check (releases found = T's own count) cannot be made, and a lost attribution cannot be excluded.
  These runs are consistent with the revised contract but do not verify it. New runs record the count.

**Limitation recorded.** The propagation window, from N's cancellation to T's application, is about two passes (N's
stage 2 and the hand-off). In the source interpreter, a master RST 1–5 laps before a scheduled release lets the
response out. That is a lap count from the interpreter and the model. It does not establish a silicon duration; no
silicon measurement of the window exists.

**Driver crash (attempt 03).** `model_contention.py` loaded `t_config.py` by path, and t_config's own
`import build_ports` failed. The driver now reads the units it actually wrote from `$OUT/t_params_written.json`.

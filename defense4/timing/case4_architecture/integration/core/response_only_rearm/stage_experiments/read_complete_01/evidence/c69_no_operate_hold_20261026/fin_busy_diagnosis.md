# c69 busy FIN fixture diagnosis and bounded repair

The first c69 FIN attempt (`ctl_timing_01/evidence/model_fin_busy_m12p_c69_sdk9132_01`) failed 191/193 checks. All three connections were attempted; connection 0 failed `retry_not_exhausted` (expected 0, observed 1), which left only two connections qualified. The FIN itself and the final master ACK passed on all three connections.

## Executed evidence

Times below are the model log's local timestamps on 2026-10-26. Line numbers refer to the retained `model_20261026_132046.log` in that attempt.

| Connection 0 event | Time | Packet | Log line |
| --- | --- | --- | --- |
| Relay pure ACK enters port 64, flags `0x10`, SEQ `0x16136`, ACK `0x1125a` | 13:21:08.177097 | `0xad` | 172339 |
| ACK executes `n_Ingress.busy_retry_ack`, initializes budget 32 | 13:21:08.187831 | `0xad` | 172948 |
| Relay FIN enters port 64, flags `0x11`, same SEQ/ACK | 13:21:08.218148 | `0xb1` | 175217 |
| FIN executes `n_Ingress.busy_retry_rst`, initializes budget 32 | 13:21:08.225295 | `0xb1` | 175808 |
| Counter cell 2 reaches the anchor's recorded value 26; FIN has budget 22 | 13:21:08.441038 | `0xc7` | 191528 |
| Cell 2 next increments, so this action was not yet included in the anchor's cell-2 sample | 13:21:08.448403 | `0xc8` | 192238 |
| ACK with budget 1 still reads forced work `0x000000017ffffffe` (phase 1) | 13:21:08.718234 | `0xea` | 216191 |
| That ACK executes `n_Ingress.busy_exhausted` | 13:21:08.720415 | `0xea` | 216441 |
| FIN with budget 4 reads released work `0x000000047ffffffe` (phase 4) | 13:21:08.725007 | `0xeb` | 216852 |
| FIN executes `n_Ingress.reset_continue` | 13:21:08.740097 | `0xec` | 217954 |
| FIN executes `n_Ingress.emit_reset` | 13:21:08.749931 | `0xed` | 218664 |

The ACK executes 31 `busy_retry_rst_next` actions before exhaustion. The FIN executes 28 such actions and succeeds. Thus the fixture held its artificial lock through the ACK's complete finite retry allowance. This is an observed ACK drop, not a FIN drop or evidence that removing T's OPERATE hold broke N's close path.

Successful connections corroborate the narrow timing boundary: connection 1's first released-work observations are FIN budget 5 at 13:21:18.070198 and ACK budget 2 at 13:21:18.078347; connection 2's ACK first sees released work with budget 4 at 13:21:27.907095. Neither increments exhaustion.

## Cause and repair

The old critical loop called `snapshot()`: four actual BFRT reads followed by eight serial synthetic counter reads. Each removed-counter read calls `telemetry_from_log.register_value()`, which waits for 10 ms of log silence, capped at 50 ms, then parses incremental log output. After obtaining the useful cell-2 value, the snapshot still reads cells 3 through 7 before the caller unlocks. On this active model, those five waits plus parsing explain the approximately 270–284 ms of log progress between the anchor's cell-2 observation and the observed release. The retained run has no per-call host timestamps, so individual read durations are inferred from this serial code and the measured packet ordering.

Only `model_fin_busy.py` changes. Its critical sequence now reuses the unchanged `model_log_view.wait_for()` from an offset taken immediately before sending the same ACK and FIN. It requires an exact pipe-0 executed `n_Ingress.busy_retry_rst` action, reads only the actual work register, then immediately releases in `finally`. A qualified anchor requires observed generation `0x7ffffffe` and phase 1. Metadata records the matched action, log start/end offsets, wait duration, and actual pre-unlock work result. Full snapshots run outside the locked interval. Missing actions or wrong/missing work state fail qualification; read exceptions still release the fixture cell and fail the connection.

The existing 32 retry allowance, strict zero-exhaustion assertion, both peer packets, and all-three-connections completion check are unchanged. Aggregate `count_busy[2]` alone is intentionally insufficient: ACK retry-next actions also increment it before the FIN arrives. No shared telemetry helper, log helper, model summary, P4 source, or timing parameter changes are required.

## Validation

Focused regression tests were run against the original fixture first: 17 failed, including the real-main check that detects full snapshot reads under the forced lock. After the repair: 17 passed. Coverage includes exact action versus ACK/next actions, pipe selection, pre-pair offsets, partial lines, bounded timeouts, actual work qualification, exception cleanup, immediate read-to-unlock ordering, and all-three/zero-exhaustion behavior through `main()`.

The focused fixture, existing log observer, telemetry, and model-summary tests passed together: **104 passed** with `PYTHONPATH=defense4/timing/case4_architecture/integration/core/response_only/hw`. Without that path, four existing summary fixtures fail importing `t_config`; the same failure reproduces with the summary test alone. Python compilation and `git diff --check` also passed.

Repaired driver SHA-256: `4733172a27e6e1ee475852d0ffd6d6fcc975946a3aa1ac2771b805bd25a78772`. Original retained driver SHA-256: `1c9be518e5f7569013548a12a1838a61493da05fd1ec73b5a18460bfd94f8459`.

The parent owns the fresh `fin_busy_02` compiled-model validation. This repair does not reinterpret or replace the original failed evidence and does not by itself claim the compiled-model gate passed.

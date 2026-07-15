# Working Notes — Invalid-Index CommandStatus Refactor (DNP3_inval.md)

**Task:** stop the test harness manufacturing/assuming that an unconfigured CROB index
returns OUT_OF_RANGE. Use the most native OpenDNP3 mechanism; if none, move index
validity into a clean outstation control-point backend that returns the native status,
and make the test scripts observe-and-report only. Software-only, G12V1 only. Then
re-run the experiments.

## Key finding (verified, not assumed)
OpenDNP3 does **NOT** natively validate a CROB index. Probe: SuccessCommandHandler +
DB sized K=5 -> master SELECT/OPERATE index 5 returns SUCCESS on the wire; handler saw
numSelect/numOperate=2 (stack delivered the out-of-range index). So the application
ICommandHandler is the sole authority for the CommandStatus. (IEEE 1815 review: the
standard-aligned code for a nonexistent point is NOT_SUPPORTED(4)+IIN2.2, not
OUT_OF_RANGE(12) which is value-scoped; harness retains OUT_OF_RANGE for continuity as
an explicit application mapping choice — see NONEXISTENT_INDEX_COMMAND_STATUS.)

## What changed
- `run_outstation.py`: new `ControlPointBackend` (application authority; returns native
  opendnp3.CommandStatus; single-source encoding constants
  NONEXISTENT_INDEX_COMMAND_STATUS / UNSUPPORTED_CODE_COMMAND_STATUS). `ControlTestState`
  delegates existence to it (no hardcoded OUT_OF_RANGE). Handler dropped `_status_map`,
  returns the backend's native status, logs the status source. Startup log lists
  configured indexes + status source.
- `run_master.py`: log line — transmits plan verbatim, does not validate/infer status.
- `analyze_multicrob_pcap.py`: observe-vocabulary keys (observed_status_by_index,
  first_non_success_status/index); docstring reworded observe-not-assume. Pass logic
  already never required OUT_OF_RANGE.
- runners' report prose de-assumed ("Observation plan"; "observed, not assumed").
- NEW `tests/test_control_point_backend.py` — 8 tests, all pass.

## Status: COMPLETE + rig-re-validated (2026-07-14, Vision↔Hulk).
- Local: py_compile x6 OK; unit tests 8/8; loopback smoke (real outstation K5, idx 0..5)
  -> idx5 = 0x0C OUT_OF_RANGE on wire, operate_seen=0, no valid output changed.
- Rig padding suite: all 8 cases pass (valid_k5_n5 all_success+OPERATE; invalid
  end/begin/middle -> 5/OUT_OF_RANGE no-operate; decoy-only; K16N17 -> 16/TOO_MANY_OPS).
- Rig boundary: valid K5N5 all_success+OPERATE; invalid K5N6 -> 5/OUT_OF_RANGE no-operate.
- Behaviour byte-identical to prior week8/week8_next runs — only the decision *location*
  and attribution changed.
- Deliverables: `reports/invalid_index_status_refactor.md` (all 7 DNP3_inval.md outputs).

## Decisions
- Retain OUT_OF_RANGE(12) for a nonexistent index (byte-comparable to prior captures);
  it is now an explicit application constant, not a hidden decision. NOT_SUPPORTED(4) is
  the standard-aligned alternative — flip the one constant + re-baseline to adopt it.
- Status decision lives ONLY in run_outstation.py; runners/master/analyzer never
  reference the CommandStatus enum (guarded by a unit test).

## Verify env
- Local analyzer needs scapy (system python3.8 has 2.4.3). Rig hosts run Python 3.12.3.

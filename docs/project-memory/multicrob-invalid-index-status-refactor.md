---
name: multicrob-invalid-index-status-refactor
description: "DNP3 multi-CROB: OpenDNP3 does NOT validate a CROB index natively; status now from a ControlPointBackend (app authority), rig-re-validated 2026-07-14"
metadata: 
  node_type: memory
  type: project
  originSessionId: 1e96b6f9-dac8-4096-8f66-bfc4124385ee
---

Task DNP3_inval.md in `dnp3_multicrob_harness/`: stop the harness manufacturing/assuming
that an unconfigured CROB index returns OUT_OF_RANGE; make the outstation application (not
the test code) decide the CommandStatus, and make the runners/analyzer observe-and-report.

**Hard fact (empirically proven, do not re-derive):** OpenDNP3's protocol stack does NOT
validate a Group 12 Var 1 control index against the configured database. Probe:
`opendnp3.SuccessCommandHandler` (unconditional SUCCESS, no index check) + a DB sized to
K binary-output points; master SELECT/OPERATE to index K returns **SUCCESS on the wire**,
and the handler's numSelect/numOperate show the stack delivered the out-of-range index to
the application. So `ICommandHandler.Select()/Operate()` is the sole authority for the
status. (`DatabaseSizes.numBinaryOutputStatus` is for the reporting data model, not
control validation.)

**IEEE 1815 note:** the standard-aligned status for a *nonexistent* point is
`NOT_SUPPORTED` (4) + IIN2.2; `OUT_OF_RANGE` (12) is value-scoped (assumes the point
exists). The harness retains OUT_OF_RANGE(12) for byte-continuity with prior captures as
an explicit APPLICATION choice — see the module constant `NONEXISTENT_INDEX_COMMAND_STATUS`
in `run_outstation.py`. Flip that constant + re-baseline to adopt NOT_SUPPORTED.

**Refactor (run_outstation.py):** new `ControlPointBackend` (application authority;
`command_status(index, code)` returns native `opendnp3.CommandStatus`; `status_name` via
`opendnp3.CommandStatusToString`). `ControlTestState._validate` delegates to it (no
hardcoded literal). `ControlTestCommandHandler` dropped `_status_map` and returns the
backend's native status; startup log lists configured indexes + status source. Runners /
master / analyzer only observe-and-report — a unit test guards that they never reference
the `opendnp3.CommandStatus` enum (the decision lives ONLY in run_outstation.py).
Tests: `tests/test_control_point_backend.py` (8/8). Deliverables:
`reports/invalid_index_status_refactor.md`.

**Rig re-run 2026-07-14 (Vision↔Hulk), byte-identical to prior runs:** padding suite 8/8
(invalid end/begin/middle → 5/OUT_OF_RANGE no-OPERATE; decoy-only; K16N17 →
16/TOO_MANY_OPS); boundary valid K5N5 + invalid K5N6 pass. Only the decision *location*
and attribution changed, not the wire behaviour. [[multicrob-boundary-index-result]]
[[multicrob-invalid-index-padding]] [[dnp3-harness-verified]] [[lab-hosts-dnp3]]

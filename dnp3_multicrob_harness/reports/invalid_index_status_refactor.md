# Invalid-Index CommandStatus Refactor — Deliverables (DNP3_inval.md)

Software-only OpenDNP3 characterisation. Rig re-run 2026-07-14 on Vision
(`10.10.54.19`, master) / Hulk (`10.10.54.158`, outstation). No physical output is
operated; no DNP3 byte is rewritten; transmitted CROB order is unchanged.

---

## 1. Can OpenDNP3 natively detect an unconfigured CROB index?

**No.** OpenDNP3's protocol stack does **not** validate a Group 12 Var 1 (CROB)
control index against the configured database. This was verified empirically against
the installed build, not assumed:

- An outstation was configured with a database sized to exactly **K = 5** binary-output
  points and given the built-in `opendnp3.SuccessCommandHandler` (returns
  `CommandStatus.SUCCESS` for **every** Select/Operate, with **no** index check).
- A master issued a `SelectAndOperate` command set with index 0 (valid) **and index 5
  (out of range)**.
- On the wire, **both** index 0 and index 5 returned `Status: SUCCESS`, and the
  handler's counters showed `numSelect = 2 / numOperate = 2` — i.e. the stack delivered
  the out-of-range index straight to the application handler without filtering it.

Therefore the DNP3 stack cannot infer whether an application-level control point
exists. Per IEEE 1815-2012 the `ICommandHandler.Select()/Operate()` return value **is**
the CommandStatus: point existence is an application property of the device's
control-point data model, and the stack performs only *syntactic* validation (framing,
CRC, qualifiers, object sizes). This harness therefore places index validity in a
dedicated **`ControlPointBackend`** (the outstation application), which returns the
native `opendnp3.CommandStatus`.

**Where the status comes from (precise attribution):** the returned CommandStatus for a
CROB originates in the **outstation application control-point backend**. It is **not**
decided by the DNP3 protocol stack, and it is **not** manufactured or assumed by the
experiment/test code.

**Standards note (encoding choice).** IEEE 1815-2012 review found that the strictly
standard-aligned status for a control addressed to a *nonexistent* point is
`NOT_SUPPORTED` (4) — "control operation not supported for this point" — and the
response should also set IIN2.2 (PARAMETER_ERROR). `OUT_OF_RANGE` (12) is defined over
the requested *value* ("value outside the range permitted for this point") and
presupposes the point exists. This harness **deliberately retains `OUT_OF_RANGE` (12)**
for a nonexistent index to stay byte-comparable with the prior (week8) rig captures; it
is now an **explicit, single-source, attributable application mapping choice**
(`NONEXISTENT_INDEX_COMMAND_STATUS` in `run_outstation.py`), not a protocol mandate and
not a silent substitution. Flip that one constant (and re-baseline) to adopt the
standard-aligned `NOT_SUPPORTED`.

---

## 2. Changed files

| File | Change |
|------|--------|
| `run_outstation.py` | New `ControlPointBackend` (application authority, returns native `opendnp3.CommandStatus`); `ControlTestState` delegates existence to it; command handler drops the hardcoded `_status_map` and returns the backend's native status; explicit encoding constants; startup log of configured indexes + status source. |
| `run_master.py` | Added a startup log making explicit that the master transmits the plan verbatim and does **not** validate indexes or infer the response status. (No behavioural change — it already only transmitted + observed.) |
| `analyze_multicrob_pcap.py` | Docstring reworded to "observe and report"; added observe-vocabulary output keys `observed_status_by_index`, `first_non_success_status`, `first_non_success_index`. Pass logic already never required OUT_OF_RANGE. |
| `run_crob_boundary_index_test.py` | Report section "Expected comparison" → "Observation plan (observe and report — statuses are not assumed)"; removed "should return OUT_OF_RANGE" language. |
| `run_crob_padding_candidate_tests.py` | Report "Interpretation" reworded to observed-not-assumed; softened one case goal that led with an assumed status. |
| `tests/test_control_point_backend.py` | **New.** Unit / dry-run tests proving the status is decided by the backend and not hardcoded/assumed by the runners, master, or analyzer. |

---

## 3. Diffs (key sections)

### `run_outstation.py` — explicit, single-source encoding constants (new)

```python
# STANDARDS NOTE (IEEE 1815-2012): the standard-aligned status for a control to a
# *nonexistent* point is NOT_SUPPORTED (4) + IIN2.2; OUT_OF_RANGE (12) is value-scoped.
# This harness RETAINS OUT_OF_RANGE for continuity with prior rig captures as an explicit
# APPLICATION mapping choice. Flip the constant (and re-baseline) to switch.
NONEXISTENT_INDEX_COMMAND_STATUS = opendnp3.CommandStatus.OUT_OF_RANGE
UNSUPPORTED_CODE_COMMAND_STATUS  = opendnp3.CommandStatus.NOT_SUPPORTED
```

### `run_outstation.py` — control-point backend (new authority)

```python
class ControlPointBackend(object):
    """Outstation application control-point data model -- the AUTHORITY for the CROB
    command status. OpenDNP3 does not validate a control index natively; this backend
    returns the native opendnp3.CommandStatus for each requested (index, control_code)."""
    def has_point(self, index):
        return 0 <= index < self.control_point_count
    def command_status(self, index, control_code):
        if not self.has_point(index):
            return NONEXISTENT_INDEX_COMMAND_STATUS      # application decision
        if not self.supports_code(control_code):
            return UNSUPPORTED_CODE_COMMAND_STATUS
        return opendnp3.CommandStatus.SUCCESS
    @staticmethod
    def status_name(status):
        return opendnp3.CommandStatusToString(status)
```

### `run_outstation.py` — `ControlTestState._validate` now delegates (was hardcoded)

```diff
-    def _validate(self, index, control_code):
-        if index not in self.supported_indexes:
-            return 'OUT_OF_RANGE', 'index {} not in supported set 0..{}'.format(...)
-        if control_code not in self.supported_codes:
-            return 'NOT_SUPPORTED', 'control code {} not in {}'.format(...)
-        return 'SUCCESS', None
+    def _validate(self, index, control_code):
+        # Delegate the existence/support decision to the control-point backend, which
+        # returns the native opendnp3.CommandStatus. This state no longer decides
+        # OUT_OF_RANGE/NOT_SUPPORTED itself -- it reports the backend's status.
+        status = self.backend.command_status(index, control_code)
+        if status == opendnp3.CommandStatus.SUCCESS:
+            return status, None
+        if not self.backend.has_point(index):
+            reason = 'index {} is not a configured control point (backend indexes {})'.format(...)
+        else:
+            reason = 'control code {} not accepted by backend {}'.format(...)
+        return status, reason
```

### `run_outstation.py` — command handler drops the hardcoded string→enum map

```diff
-        self._status_map = {
-            'SUCCESS': opendnp3.CommandStatus.SUCCESS,
-            'NOT_SUPPORTED': opendnp3.CommandStatus.NOT_SUPPORTED,
-            'OUT_OF_RANGE': opendnp3.CommandStatus.OUT_OF_RANGE,
-            'NO_SELECT': opendnp3.CommandStatus.NO_SELECT,
-        }
+        self.backend = state.backend      # the application authority for command status
+        # No status-string -> CommandStatus map: Select/Operate return the native
+        # opendnp3.CommandStatus from the backend directly.
...
-        return self._status_map.get(status, opendnp3.CommandStatus.NOT_SUPPORTED)  # Select
-        return self._status_map.get(result['status'], opendnp3.CommandStatus.NOT_SUPPORTED)  # Operate
+        return status               # Select: native status from backend
+        return status               # Operate: native backend/SBO-lifecycle status
```

### `run_outstation.py` — startup log (status source made explicit)

```python
_log.info('CONTROL-TEST configured control indexes: %s (codes %s).',
          list(backend.configured_indexes), list(backend.supported_codes))
_log.info('CONTROL-TEST command-status source: %s. OpenDNP3 does NOT validate a CROB '
          'index natively; the returned CommandStatus (incl. OUT_OF_RANGE for a '
          'nonexistent index) is decided by the outstation application backend, not by '
          'the DNP3 stack and not assumed by the test code.', backend.describe())
```

### `run_master.py` — transmit-and-observe contract logged

```python
_log.info('Master transmits this CROB plan verbatim (indexes + order as given); it does NOT '
          'validate index existence and does NOT infer the response CommandStatus -- the status '
          'is decided by the outstation application and observed from the outstation JSON + PCAP.')
```

### `analyze_multicrob_pcap.py` — observe-and-report output keys (added, non-breaking)

```python
'observed_status_by_index': {idx: status_name(st) for idx, st in select_statuses_by_index.items()},
'first_non_success_status': first_rejected_status_name,
'first_non_success_index':  first_rejected_index,
```

---

## 4. Exact new control flow

```
master request           run_master.py builds a CommandSet of N CROBs from --crob-plan /
                         --crob-count and issues ONE SelectAndOperate. It transmits the
                         indexes and order verbatim; it does not validate indexes and does
                         not infer status.
        |
        v  (SELECT, then OPERATE only if SELECT fully succeeded — OpenDNP3 master SBO rule)
outstation handler       ControlTestCommandHandler.Select()/Operate() (run_outstation.py).
                         The DNP3 stack passes EVERY index to the handler (it does not
                         filter — proven in §1).
        |
        v
status source            ControlPointBackend.command_status(index, code)  <-- AUTHORITY
                         has_point(index)? -> SUCCESS ; else NONEXISTENT_INDEX_COMMAND_STATUS
                         (OUT_OF_RANGE by config) ; bad code -> NOT_SUPPORTED. Returns a
                         native opendnp3.CommandStatus. SBO lifecycle (pending SELECT,
                         timeout, param match) adds SUCCESS/NO_SELECT for valid points.
        |
        v
DNP3 response            The stack echoes each G12V1 object with the per-index status octet
                         the handler returned (e.g. index 5 -> 0x0C OUT_OF_RANGE). No byte is
                         rewritten. A partial SELECT failure suppresses OPERATE and arms no
                         valid control.
        |
        v
PCAP analyzer            analyze_multicrob_pcap.py reads the per-index CommandStatus from the
                         SELECT response bytes and REPORTS it (observed_status_by_index,
                         first_non_success_status). It classifies by the observed first
                         non-success status; it never assumes OUT_OF_RANGE and never fails a
                         test merely because the status is not OUT_OF_RANGE.
```

---

## 5. Run commands (rig, from the harness dir on the dev box)

Full suite (contains all five named cases + count-limit contrasts):

```bash
python3 run_crob_padding_candidate_tests.py --user decps
```

Individual cases (each starts a fresh K=5 `--control-test` outstation):

```bash
# valid K=5, N=5
python3 run_crob_padding_candidate_tests.py --user decps --only valid_k5_n5
# invalid-at-end        (indexes 0,1,2,3,4,5   -> index 5 invalid)
python3 run_crob_padding_candidate_tests.py --user decps --only invalid_end_k5_n6
# invalid-at-beginning  (indexes 5,0,1,2,3,4)
python3 run_crob_padding_candidate_tests.py --user decps --only invalid_begin_k5_n6
# invalid-in-middle     (indexes 0,1,5,2,3,4)
python3 run_crob_padding_candidate_tests.py --user decps --only invalid_middle_k5_n6
# invalid-only          (indexes 5,6,7 — all invalid, a decoy-only set)
python3 run_crob_padding_candidate_tests.py --user decps --only decoy_only_invalid_k5_n3
```

The boundary experiment (valid K5N5 vs invalid K5N6) is a separate script:

```bash
python3 run_crob_boundary_index_test.py --user decps
```

Under the hood each case runs, unchanged from before:

```bash
# Hulk (outstation): python3 run_outstation.py --control-test --control-point-count 5 --run-id <id>
# Vision (master):   python3 run_master.py --action multi-crob-sbo --crob-plan '<idx:CODE,...>' --run-id <id>
```

---

## 6. Sample report — observed status, no OUT_OF_RANGE assumption

Regenerated by the re-run: `reports/padding_candidates/padding_candidate_results.md`
(full) and `reports/boundary/boundary_index_results.md`. The status is read from the
wire and reported as observed. Rig results, 2026-07-14:

| case | K | N | transmitted order | classification | first non-success (observed) | OPERATE sent | valid output changed |
|------|---|---|-------------------|----------------|------------------------------|--------------|----------------------|
| valid_k5_n5 | 5 | 5 | [0,1,2,3,4] | `all_success` | – | True | yes |
| invalid_end_k5_n6 | 5 | 6 | [0,1,2,3,4,5] | `invalid_index_rejected_during_select_no_operate` | 5 / OUT_OF_RANGE | False | no |
| invalid_begin_k5_n6 | 5 | 6 | [5,0,1,2,3,4] | `invalid_index_rejected_during_select_no_operate` | 5 / OUT_OF_RANGE | False | no |
| invalid_middle_k5_n6 | 5 | 6 | [0,1,5,2,3,4] | `invalid_index_rejected_during_select_no_operate` | 5 / OUT_OF_RANGE | False | no |
| decoy_only_invalid_k5_n3 (invalid-only) | 5 | 3 | [5,6,7] | `decoy_only_invalid_rejected` | 5 / OUT_OF_RANGE | False | no |
| multiple_invalid_k5_n8 | 5 | 8 | [0..4,5,6,7] | `multiple_invalid_indexes_rejected` | 5 / OUT_OF_RANGE | False | no |
| count_limit_valid_k16_n17 | 16 | 17 | [0..16] | `too_many_ops_during_select` | 16 / TOO_MANY_OPS | False | no |

The "first non-success" column is the observed per-index status verbatim from the SELECT
response; the harness does not assume it. The K16N17 row shows the analyzer reporting a
different observed status (`TOO_MANY_OPS`, the operation-count limit) without being told
to expect it — a test is never failed for a status that is not OUT_OF_RANGE.

Per-index observed map for an invalid case (from `reports/padding_candidates/analyze_invalid_end_k5_n6.json`):

```json
"observed_status_by_index": {"0":"SUCCESS","1":"SUCCESS","2":"SUCCESS",
                             "3":"SUCCESS","4":"SUCCESS","5":"OUT_OF_RANGE"},
"first_non_success_status": "OUT_OF_RANGE", "first_non_success_index": 5,
"operate_sent": false
```

---

## 7. Unit / dry-run tests

`tests/test_control_point_backend.py` (standalone or pytest, no rig needed):

```
$ python3 tests/test_control_point_backend.py
PASS test_backend_configured_points
PASS test_backend_returns_native_command_status
PASS test_command_status_enum_decision_only_in_outstation
PASS test_handler_returns_backend_status_and_has_no_status_map
PASS test_invalid_index_status_is_explicit_single_source
PASS test_runners_do_not_reference_command_status_enum
PASS test_state_delegates_to_backend
PASS test_state_has_no_hardcoded_status_strings
8/8 passed
```

They prove: the invalid-index status is a native `opendnp3.CommandStatus` from the
backend; the handler's hardcoded `_status_map` is gone; the state delegates existence to
the backend; the invalid-index encoding is an explicit single-source constant; and the
runners / master / analyzer never reference the `opendnp3.CommandStatus` enum (they do
not decide or assume the status). A loopback end-to-end smoke (real `ExperimentOutstation`,
K=5, indexes 0..5) additionally confirms index 5 → `0x0C` OUT_OF_RANGE on the wire with
`operate_seen = 0` and no valid output changed — identical to the prior rig behaviour.

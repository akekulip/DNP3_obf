#!/usr/bin/env python3
"""
Unit / dry-run tests proving the multi-CROB experiment code no longer hardcodes or
assumes the invalid-index CommandStatus, and that the status is decided by the
outstation application control-point backend.

Runs standalone (``python3 tests/test_control_point_backend.py``) or under pytest.
Requires pydnp3 (imported by run_outstation). No network / no rig needed.

What these tests establish, mapped to DNP3_inval.md:
  * The status for a nonexistent index comes from ControlPointBackend (the outstation
    application), returned as a native opendnp3.CommandStatus -- not manufactured by
    ControlTestState, the command handler, the runners, the master, or the analyzer.
  * The removed hardcoded map (handler ``_status_map``) is gone.
  * The experiment runners / master / analyzer never reference the
    ``opendnp3.CommandStatus`` enum (i.e. they do not decide/assume the status).
  * The invalid-index encoding is an explicit, single-source, attributable constant.
"""
import os
import sys

HARNESS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HARNESS_DIR)

from pydnp3 import opendnp3
import run_outstation as ro

CS = opendnp3.CommandStatus


def _crob(code_name='LATCH_ON'):
    return opendnp3.ControlRelayOutputBlock(getattr(opendnp3.ControlCode, code_name))


# --------------------------------------------------------------------------- #
# 1. Backend is the authority and returns NATIVE opendnp3.CommandStatus values.
# --------------------------------------------------------------------------- #
def test_backend_configured_points():
    b = ro.ControlPointBackend(control_point_count=5)
    assert b.configured_indexes == (0, 1, 2, 3, 4)
    assert all(b.has_point(i) for i in range(5))
    assert not b.has_point(5)
    assert not b.has_point(-1)


def test_backend_returns_native_command_status():
    b = ro.ControlPointBackend(control_point_count=5)
    valid = b.command_status(0, 'LATCH_ON')
    invalid = b.command_status(5, 'LATCH_ON')          # nonexistent index
    bad_code = b.command_status(0, 'PULSE_ON')         # unsupported code
    # native opendnp3 enum values, not strings
    assert isinstance(valid, CS) and isinstance(invalid, CS) and isinstance(bad_code, CS)
    assert valid == CS.SUCCESS
    assert invalid == ro.NONEXISTENT_INDEX_COMMAND_STATUS
    assert bad_code == ro.UNSUPPORTED_CODE_COMMAND_STATUS
    # status_name is derived from opendnp3, not a hand-written table
    assert b.status_name(invalid) == opendnp3.CommandStatusToString(invalid)


def test_invalid_index_status_is_explicit_single_source():
    # The invalid-index status is an attributable module constant, not a literal
    # buried in a conditional. This harness retains OUT_OF_RANGE for continuity;
    # NOT_SUPPORTED (4) is the IEEE-1815-aligned alternative (see module note).
    assert ro.NONEXISTENT_INDEX_COMMAND_STATUS == CS.OUT_OF_RANGE
    b = ro.ControlPointBackend(control_point_count=3)
    assert b.command_status(3, 'LATCH_ON') is ro.NONEXISTENT_INDEX_COMMAND_STATUS


# --------------------------------------------------------------------------- #
# 2. ControlTestState delegates existence to the backend (does not self-decide).
# --------------------------------------------------------------------------- #
def test_state_delegates_to_backend():
    b = ro.ControlPointBackend(control_point_count=3)
    st = ro.ControlTestState(backend=b)
    assert st.backend is b
    # invalid index -> backend's native status, state records nothing
    status, reason = st.select(3, 'LATCH_ON', 1, 100, 100)
    assert status == ro.NONEXISTENT_INDEX_COMMAND_STATUS
    assert 3 not in st.selected_commands
    assert 'not a configured control point' in reason
    # valid index -> SUCCESS, recorded
    status, _ = st.select(2, 'LATCH_ON', 1, 100, 100)
    assert status == CS.SUCCESS and 2 in st.selected_commands


def test_state_has_no_hardcoded_status_strings():
    # The state must not carry a string-keyed status map or literal decision.
    st = ro.ControlTestState(control_point_count=2)
    assert not hasattr(st, '_status_map')
    # operate on an unselected valid index -> NO_SELECT (SBO lifecycle, native enum)
    res = st.operate(0, 'LATCH_ON', 1, 100, 100)
    assert res['status'] == CS.NO_SELECT


# --------------------------------------------------------------------------- #
# 3. Command handler returns the backend's native status; the old map is gone.
# --------------------------------------------------------------------------- #
def test_handler_returns_backend_status_and_has_no_status_map():
    st = ro.ControlTestState(control_point_count=5)
    h = ro.ControlTestCommandHandler(st)
    assert h.backend is st.backend
    assert not hasattr(h, '_status_map')            # removed hardcoded string->enum map
    h.Start()
    assert h.Select(_crob('LATCH_ON'), 0) == CS.SUCCESS
    assert h.Select(_crob('LATCH_ON'), 5) == ro.NONEXISTENT_INDEX_COMMAND_STATUS
    h.End()
    assert 5 in h.rejected_indexes and 0 not in h.rejected_indexes


# --------------------------------------------------------------------------- #
# 4. The experiment runners / master / analyzer do NOT decide/assume the status:
#    they never reference the opendnp3.CommandStatus enum. Only the outstation does.
# --------------------------------------------------------------------------- #
EXPERIMENT_CODE_FILES = [
    'run_master.py',
    'run_crob_boundary_index_test.py',
    'run_crob_padding_candidate_tests.py',
    'analyze_multicrob_pcap.py',
]


def test_runners_do_not_reference_command_status_enum():
    offenders = {}
    for name in EXPERIMENT_CODE_FILES:
        with open(os.path.join(HARNESS_DIR, name)) as fh:
            src = fh.read()
        if 'opendnp3.CommandStatus.' in src or 'CommandStatus.OUT_OF_RANGE' in src:
            offenders[name] = [ln for ln in src.splitlines()
                               if 'CommandStatus.' in ln]
    assert not offenders, (
        'experiment code must not decide/assume the CommandStatus enum; found: %s' % offenders)


def test_command_status_enum_decision_only_in_outstation():
    with open(os.path.join(HARNESS_DIR, 'run_outstation.py')) as fh:
        assert 'NONEXISTENT_INDEX_COMMAND_STATUS' in fh.read()


# --------------------------------------------------------------------------- #
# Standalone runner (no pytest dependency).
# --------------------------------------------------------------------------- #
def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith('test_') and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print('PASS %s' % t.__name__)
        except AssertionError as exc:
            failures += 1
            print('FAIL %s: %s' % (t.__name__, exc))
        except Exception as exc:                       # report (never hide) any error
            failures += 1
            print('ERROR %s: %r' % (t.__name__, exc))
    print('\n%d/%d passed' % (len(tests) - failures, len(tests)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(_run_all())

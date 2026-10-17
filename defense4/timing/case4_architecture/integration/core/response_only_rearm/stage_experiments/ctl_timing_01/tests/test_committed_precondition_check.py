"""committed_precondition_check.py: the committed-path precondition (response at T before t0 + readiness), read from
T's clock in the model log (option 1, 2026-10-17)."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

CT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CT))
spec = importlib.util.spec_from_file_location('committed_precondition_check', CT / 'committed_precondition_check.py')
cpc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpc)
EV = CT / 'evidence'
READINESS = 7812502                     # 2 s in 256 ns units, as written in the m10 model runs


def rec(t, *actions, pipe=1, port=180, frame=''):
    return dict(wall='w%d' % t, pipe=pipe, port=port, frame=frame, t_units=t if pipe == 1 else None,
                actions=['t_Ingress.%s' % a for a in actions])


SEQ, HEAD = '00045948', '0564112233445566'
# a wire frame from the outstation (sport 20000) carrying 8 payload octets, sequence SEQ
WIRE = ('001122334455aabbccddeeff0800' + '45000030000140004006000a0a0000020a000001' +
        '4e207531' + SEQ + '00000000' + '5018100000000000' + HEAD)


def window(ingress_at, t_arrival, fallback=True, admitted=True):
    """An OPERATE point: SELECT setup lane, OPERATE lane at t0=1000, ACK, response at the wire, then at T."""
    w = [rec(10, 'admit_t0', 'admit_request'), rec(20, 'admit_response'),
         rec(1000, 'live_admit_gen', 'admit_t0', 'hold_operate'), rec(1100, 'hold_ack')]
    if fallback:
        w.append(rec(ingress_at - 1, 'release_ack_fallback'))
    w += [rec(ingress_at - 1, 'read_t0'), rec(0, pipe=0, port=9, frame=WIRE), rec(ingress_at + 1, 'read_t0'),
          rec(t_arrival, *(['admit_response'] if admitted else []), frame='ff' + SEQ + HEAD)]
    return w


def run(ingress_at, t_arrival, case_ok=False, busy_ok=True, original_ok=True, **kw):
    w = window(ingress_at, t_arrival, **kw)
    m = cpc.measure(w, 0, len(w), READINESS)
    return m, cpc.classify(case_ok, m, busy_ok, original_ok)


def test_late_clock_comparison_wraps():
    assert not cpc.late(20, (1 << 32) - 10, READINESS)
    assert cpc.late(((1 << 32) - 10 + READINESS) % (1 << 32), (1 << 32) - 10, READINESS)


def test_the_judged_lane_is_the_last_admission():
    m, _ = run(1000 + READINESS + 10, 1000 + READINESS + 50)
    assert m['t0_units'] == 1000


def test_a_late_stimulus_is_not_measured():
    m, c = run(1000 + READINESS + 10, 1000 + READINESS + 50)
    assert m['ingress_late'] is True and c == 'committed_path_not_measured'


def test_in_time_at_the_switch_but_late_at_t_is_in_switch_delay_not_excused():
    """Code review M1 / attempt 05: the response entered the switch before readiness and reached T after it."""
    _m, c = run(1000 + READINESS - 100, 1000 + READINESS + 50)
    assert c == 'in_switch_delay'


def test_response_at_t_in_time_is_a_genuine_failure():
    _m, c = run(1000 + READINESS - 100, 1000 + READINESS - 50)
    assert c == 'genuine_failure'


def test_an_unproven_excuse_is_never_granted():
    """Code review H3: a busy drop, an undelivered original, no prior ACK fallback, or a non-admitting arrival."""
    late_in, late_t = 1000 + READINESS + 10, 1000 + READINESS + 50
    assert run(late_in, late_t, busy_ok=False)[1] == 'undetermined'
    assert run(late_in, late_t, original_ok=False)[1] == 'undetermined'
    assert run(late_in, late_t, fallback=False)[1] == 'undetermined'
    assert run(late_in, late_t, admitted=False)[1] == 'undetermined'


def test_a_bracket_straddling_readiness_is_undetermined():
    w = window(1000 + READINESS + 10, 1000 + READINESS + 50)
    w[w.index(next(r for r in w if r['pipe'] == 0)) - 1]['t_units'] = 1000 + READINESS - 5
    m = cpc.measure(w, 0, len(w), READINESS)
    assert m['ingress_late'] is None and cpc.classify(False, m, True, True) == 'undetermined'


def test_unattributed_and_missing_arrival():
    assert cpc.classify(False, dict(attributed=False), True, True) == 'unattributed'
    assert cpc.classify(False, dict(attributed=True), True, True) == 'undetermined'


def test_a_pass_with_a_late_arrival_is_flagged_inconsistent():
    assert cpc.classify(True, dict(attributed=True, t_arrival_late=True), True, True) == 'inconsistent'
    assert cpc.classify(True, dict(attributed=False), True, True) == 'measured_unverified'
    assert cpc.classify(True, dict(attributed=True, t_arrival_late=False), True, True) == 'measured'


def test_a_checker_error_is_a_json_record_with_its_own_exit_code(tmp_path, capsys):
    """Code review: an uncaught exception exited 1, which run_model saved as an empty 'classified' file."""
    assert cpc.main(['x', str(tmp_path)]) == 3
    assert json.loads(capsys.readouterr().out)['error'] is True


def test_outstation_payload_ignores_master_frames_and_bare_acks():
    assert cpc.outstation_payload(WIRE) == (SEQ, HEAD)
    assert cpc.outstation_payload(WIRE.replace('4e207531', '75314e20')) is None
    bare = WIRE[:32] + '0028' + WIRE[36:-len(HEAD)]
    assert cpc.outstation_payload(bare) is None


@pytest.mark.skipif(not list((EV / 'model_contention_m10_03_05').glob('model_*.log')),
                    reason='the model log is over 50 MiB and untracked (UNTRACKED_LARGE_LOGS.sha256)')
def test_attempt_05_operate_090_is_an_in_switch_delay():
    """The response entered the switch 1777.5-1807.5 ms after t0 and reached T at 2070 ms (readiness 2000 ms)."""
    out = cpc.check(EV / 'model_contention_m10_03_05')
    p = out['points']['sweep_OPERATE_090ms']
    assert p['classification'] == 'in_switch_delay' and p['t_arrival_ms_after_t0'] == 2070.0
    assert len(out['points']) == 38
    others = {q['classification'] for t, q in out['points'].items() if t != 'sweep_OPERATE_090ms'}
    assert others <= {'measured', 'measured_unverified'}

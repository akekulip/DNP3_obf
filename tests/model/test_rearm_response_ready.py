"""Profile-specific rearm stimulus preserves the successful timed OPERATE and reconnect proof."""
import ast
from pathlib import Path

import pytest

REARM = Path(__file__).resolve().parents[2] / 'scripts/model/model_rearm.py'


def function(name):
    import time
    node = next(node for node in ast.parse(REARM.read_text()).body
                if isinstance(node, ast.FunctionDef) and node.name == name)
    namespace = dict(time=time, same_frame=lambda got, want, original=None: got == want)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(REARM), 'exec'), namespace)
    return namespace[name]


def test_new_rearm_profile_uses_actual_d_j_without_deadline_or_legacy_keys():
    params = function('timing_params_for_profile')
    profile = dict(timing_contract='response_ready_ack_d_v2', timing_ns=dict(
        D_release_budget=5000000, J_operate_hold=2400000))
    assert params(profile) == dict(gap=5000000, op_j=2400000,
                                   budget=240000, enabled=0)
    assert params({}) == dict(da=50000000, readiness=400000000, cap=16000000,
                              gap=50000000, op_j=200000000, budget=240000, enabled=0)
    with pytest.raises(ValueError):
        params(dict(timing_contract='unchecked'))


def test_operate_waits_for_genuine_relay_then_sends_ack_and_whole_response_without_observer_work():
    run = function('response_ready_operate')
    events = []
    receives = iter([[(9, b'other')], [(64, b'relayed request')], [],
                     [(9, b'ACK')], [(9, b'whole response')]])
    def send(port, frame):
        events.append(('send', port, frame))
    def collect(_duration):
        events.append(('collect',))
        return next(receives, [])
    captured, relayed = run(send, collect, 9, 64, b'operate', b'relayed request',
                            b'ACK native', b'response native', b'whole response')
    assert relayed
    index = events.index(('send', 64, b'ACK native'))
    assert events[index - 1] == ('collect',)
    assert events[index + 1] == ('send', 64, b'response native')
    assert [item for item in events if item[0] == 'send'] == [
        ('send', 9, b'operate'), ('send', 64, b'ACK native'), ('send', 64, b'response native')]
    assert captured == [(9, b'other'), (64, b'relayed request'), (9, b'ACK'), (9, b'whole response')]



def test_unrelayed_operate_never_causes_fabricated_relay_ack_or_response():
    run = function('response_ready_operate')
    class Clock:
        value = 0
        @classmethod
        def monotonic(cls):
            cls.value += .1
            return cls.value
    run.__globals__['time'] = Clock
    sent = []
    captured, relayed = run(lambda port, frame: sent.append((port, frame)), lambda duration: [(9, b'other')],
        9, 64, b'operate', b'genuine relay request', b'ACK native', b'response native', b'whole response', timeout=.3)
    assert relayed is False
    assert sent == [(9, b'operate')]
    assert captured and all(frame == b'other' for port, frame in captured)


def test_no_j_rearm_profile_uses_only_D_and_common_timing_fields():
    params = function('timing_params_for_profile')
    profile = dict(timing_contract='response_ready_ack_d_no_j_v3', timing_ns=dict(D_release_budget=5000000))
    assert params(profile) == dict(gap=5000000, budget=240000, enabled=0)

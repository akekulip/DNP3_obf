"""A relay response must be injected before the driver analyzes its live exchange.

The actual exchange method runs with I/O spies. This regression reproduces the
c60 attempt-01 expiry: report/log parsing occurred before the SELECT ACK/response.
"""
import ast
import types
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1]


class EndAfterStimulus(Exception):
    pass


@pytest.mark.parametrize('order,no_ack,absent,duplicate,expected', [
    ('ack_first', False, False, False, ['ack', 'response']),
    ('response_first', False, False, False, ['response', 'ack']),
    ('ack_first', True, False, False, ['response']),
    ('ack_first', False, True, False, ['ack']),
    ('ack_first', False, False, True, ['ack', 'ack', 'response']),
])
def test_relay_stimulus_precedes_report_log_or_bfrt_work(order, no_ack, absent, duplicate, expected):
    import sys
    sys.path.insert(0, str(CTL))
    import model_response_ready as ready
    tree = ast.parse((CTL / 'model_response_ready.py').read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    cls = next(node for node in main.body if isinstance(node, ast.ClassDef) and node.name == 'ReadyGate')
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == 'exchange_ready')
    events = []
    in_flight = [False]
    response_frames = []
    resolved = [False]
    observed_polls = [0]

    def no_intervening_work(kind):
        if in_flight[0]:
            assert response_frames == expected, '%s occurred before relay stimulus: %r' % (kind, response_frames)
        events.append(kind)

    def packet(flags, seq, ack, reverse=False, payload=b''):
        return b'ack' if reverse and not payload else b'response' if reverse else b'request'

    class Socket:
        def __init__(self, relay):
            self.relay = relay

        def send(self, frame):
            if self.relay:
                response_frames.append(frame.decode())
            else:
                in_flight[0] = True
            events.append(('send', frame.decode()))

    class Model:
        def register_read(self, *args, **kwargs):
            no_intervening_work('bfrt')
            return 7

        def drain(self, *args):
            no_intervening_work('drain')

        def capture(self, *args, **kwargs):
            return {1: [], 2: []}

    class Gate:
        def __init__(self):
            self.master, self.relay = types.SimpleNamespace(dev_port=1), types.SimpleNamespace(dev_port=2)
            self.fast = {1: Socket(False), 2: Socket(True)}
            self.h = types.SimpleNamespace(scalar=lambda value: value, same_frame=lambda a, b, c: a == b)
            self.v = types.SimpleNamespace(packet=packet)
            self.m, self.ports, self.log = Model(), [1, 2], 'unused.log'
            self.calls = 0

        def frames(self, *args):
            return b'Q', b'A', b'B'

        def outcomes(self):
            no_intervening_work('bfrt')
            self.calls += 1
            if self.calls > 1:
                assert resolved[0], 'BFRT polling stalled an unresolved exchange'
                raise EndAfterStimulus()
            return {name: 0 for name in ready.NAMES}

        def encoding_state(self):
            no_intervening_work('bfrt')
            return dict(commit=0, replay=0, growth=0)

        def collect(self, *args):
            if response_frames == expected:
                observed_polls[0] += 1
                if observed_polls[0] >= 3 and not absent:
                    resolved[0] = True
                    return [(1, b'response')]
                return []
            return [(2, b'request')]

        def add(self, *args, **kwargs):
            no_intervening_work('report')

        def records(self, *args):
            no_intervening_work('log_parse')
            return [dict(t_units=10, actions=['t_Ingress.admit_t0'])]

    namespace = dict(ready.__dict__)
    namespace.update(mp=types.SimpleNamespace(rp=types.SimpleNamespace(
        advance_timestamp=lambda: None, preserve_options=lambda a, b: b)),
        view=types.SimpleNamespace(size=lambda path: 0))
    if hasattr(ready, 'LiveIngress'):
        class Live:
            expired = False
            latest_units = None

            def __init__(self, *args):
                pass

            def poll(self):
                if absent and observed_polls[0] >= 3:
                    self.expired = True
                    resolved[0] = True

            def action(self, name):
                return None
        namespace['LiveIngress'] = Live
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(CTL / 'model_response_ready.py'), 'exec'), namespace)
    gate = Gate()
    with pytest.raises(EndAfterStimulus):
        namespace['exchange_ready'](gate, 'SELECT', 'CONTROL', (100, 900, 900), order=order,
                                   no_ack=no_ack, absent=absent, duplicate=duplicate)
    assert response_frames == expected


def test_incremental_live_reader_matches_retained_parser_across_partial_lines(tmp_path):
    import sys
    sys.path.insert(0, str(CTL))
    import model_response_ready as ready
    import reset_application_check as rac
    def line(text, pipe=1):
        return ':10-25 12:00:00.000001: :0x1:-:<0,%d,5>:%s\n' % (pipe, text)
    text = ''.join([
        line('========== Ingress Pkt from port 180 =========='), line('Packet :'), line('aa bb cc dd '),
        line('global_tstamp[39:8] to value 0x1001'), line('Execute Action: t_Ingress.admit_t0'),
        line('========== Egress Pkt from TM to port 9 ==========', pipe=0),
        line('========== Ingress Pkt from port 182 =========='), line('Packet :'), line('0b 00 00 07 '),
        line('global_tstamp[39:8] to value 0x1011'), line('Execute Default Action: t_Ingress.hold_ack'),
    ])
    path = tmp_path / 'model.log'
    path.write_bytes(b'')
    reader = ready.LiveIngress(path, 0)
    payload = text.encode()
    cursor = 0
    for length in (1, 7, 31, 100, 211, len(payload)):
        with path.open('ab') as output:
            output.write(payload[cursor:cursor + length])
        cursor += length
        reader.poll()
    expected = rac.ingress_records(text.splitlines(True))
    for ordinal, record in enumerate(expected):
        record['ordinal'] = ordinal
        record['t_units'] &= ~1
    assert reader.records == expected
    assert reader.latest_units == 0x1010
    assert reader.action('admit_t0')['t_units'] == 0x1000
    assert reader.frame(182, bytes.fromhex('0b000007'))['ordinal'] == 1
    old = list(reader.records)
    reader.poll()
    assert reader.records == old
    assert reader.offset == len(payload)


def test_live_expiry_comes_from_actual_completion_salu_transition(tmp_path):
    import sys
    sys.path.insert(0, str(CTL))
    from model_response_ready import LiveIngress
    def line(text):
        return ':10-25 12:00:00.000001: :0x1:-:<0,1,5>:%s\n' % text
    path = tmp_path / 'model.log'
    path.write_text(''.join(map(line, ['========== Ingress Pkt from port 182 ==========',
        'global_tstamp[39:8] to value 0x1001', '----- register: t_Ingress.ack_done_reg -----',
        'Before stateful alu execution: 0x00000007', 'After stateful alu execution: 0x00020007'])))
    reader = LiveIngress(path, 0)
    assert reader.expired is False
    reader.poll()
    assert reader.expired is True
    assert reader.transitions == [dict(t_units=0x1000, before=7, after=0x20007)]
    reader.poll()
    assert len(reader.transitions) == 1


def test_full_gate_prioritizes_independent_edge_cases_and_keeps_all_matrix_planned():
    tree = ast.parse((CTL / 'model_response_ready.py').read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    cls = next(node for node in main.body if isinstance(node, ast.ClassDef) and node.name == 'ReadyGate')
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
    events = []
    class FirstEdgeObserved(Exception):
        pass
    class Gate:
        report = types.SimpleNamespace(record=dict(meta={}))
        def set_timing(self, *args):
            pass
        def new_connection(self, tag):
            events.append(tag)
            raise FirstEdgeObserved()
        def edge_case(self, mode):
            events.append(mode)
            raise FirstEdgeObserved()
    namespace = dict(control_only=False, D_VALUES=(5000000, 10000000, 15000000, 20000000))
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(CTL / 'model_response_ready.py'), 'exec'), namespace)
    gate = Gate()
    with pytest.raises(FirstEdgeObserved):
        namespace['run'](gate)
    assert events == ['duplicate_over_bound']
    planned = gate.report.record['meta']['planned_cases']
    assert planned[:2] == ['duplicate_over_bound', 'commit_across_expiry']
    assert len([case for case in planned if case.startswith('D')]) == 8
    assert planned.index('expired_A_token_isolation') < planned.index('D5_ack_first')
    assert 'generation_A_to_B_isolation' in planned
    assert 'invalid_child_ids' in planned
    assert 'disabled_and_exhaustion' in planned

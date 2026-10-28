"""The busy FIN fixture must observe the FIN and release before finite retries expire."""
import copy
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

CT = (Path(__file__).resolve().parents[2] / 'scripts/model')
sys.path.insert(0, str(CT))
import model_log_view as view
spec = importlib.util.spec_from_file_location('fin_busy_observation_driver', CT / 'model_fin_busy.py')
busy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(busy)

WORK = 'p0.n_Ingress.work.work'
GENERATION = 'n_Ingress.work.work.generation'
PHASE = 'n_Ingress.work.work.phase'
SEEDED = {GENERATION: [0x7ffffffe], PHASE: [1],
          'action_name': None, 'is_default_entry': False}
ACK = b'peer ACK'
FIN = b'peer FIN'


def action(name, prefix='Execute Action:', pipe=0):
    return (':10-26 13:21:08.225295:        :0xb1:-:<0,%d,8>:%s n_Ingress.%s\n'
            % (pipe, prefix, name))


class Clock:
    def __init__(self, on_sleep=None):
        self.now = 0.0
        self.on_sleep = on_sleep

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        if self.on_sleep:
            self.on_sleep()


class Model:
    """Only external BFRT and socket operations are replaced; the log observer is real."""
    def __init__(self, log, trace='', work=None):
        self.log, self.trace = log, trace
        self.work = copy.deepcopy(SEEDED if work is None else work)
        self.events = []
        self.locked = False

    def register_write(self, name, index, values, pipe):
        assert (name, index, pipe) == (WORK, 0, 0)
        assert values[GENERATION] == 0x7ffffffe
        self.locked = values[PHASE] == 1
        self.events.append('lock' if self.locked else 'unlock')

    def drain(self, ports):
        assert ports == [9, 64]
        self.events.append('drain')

    def send(self, port, frame):
        assert port == 64
        self.events.append(frame)
        if frame == FIN:
            with self.log.open('a') as out:
                out.write(self.trace)

    def register_read(self, name, index, pipe):
        # Any full snapshot or counter polling while locked breaks this contract.
        assert (name, index, pipe, self.locked) == (WORK, 0, 0, True)
        self.events.append('actual work read')
        return copy.deepcopy(self.work)


@pytest.fixture
def probe(tmp_path, monkeypatch):
    log = tmp_path / 'model_fixture.log'
    log.write_text('')
    monkeypatch.setenv('OUT', str(tmp_path))
    monkeypatch.setattr(view, 'time', Clock())

    def run(trace='', work=None):
        model = Model(log, trace, work)
        anchor = race(model, [9, 64], 64, ACK, FIN, timeout=.01)
        return anchor, model
    return log, run


def race(*args, **kwargs):
    assert hasattr(busy, 'busy_fin_race'), 'driver still polls a full snapshot while forced busy'
    return busy.busy_fin_race(*args, **kwargs)


@pytest.mark.parametrize('prefix', ['Execute Action:', 'Execute Default Action:'])
def test_exact_fin_retry_qualifies_actual_busy_work_and_unlocks_immediately(probe, prefix):
    log, run = probe
    exact = action('busy_retry_rst', prefix)
    anchor, model = run(action('busy_retry_ack') + action('busy_retry_rst_next') + exact)
    assert anchor['qualified'] is True
    assert anchor['retry_action'] == exact.rstrip('\n')
    assert anchor['retry_log_end'] == log.stat().st_size
    assert anchor['work.work'] == SEEDED
    assert model.events == ['lock', 'drain', ACK, FIN, 'actual work read', 'unlock']
    assert model.locked is False


@pytest.mark.parametrize('trace', [action('busy_retry_ack'), action('busy_retry_rst_next'),
                                  action('busy_retry_rst', pipe=1), 'unrecognized model output\n'])
def test_non_fin_actions_cannot_release_a_qualified_anchor(probe, trace):
    _log, run = probe
    anchor, model = run(trace)
    assert anchor['qualified'] is False and anchor['retry_action'] is None
    assert anchor['work.work'] is None
    assert .01 <= anchor['wait_seconds'] < .02
    assert model.events == ['lock', 'drain', ACK, FIN, 'unlock']


def test_pre_pair_fin_action_does_not_qualify_a_later_pair(probe):
    log, run = probe
    log.write_text(action('busy_retry_rst'))
    anchor, model = run(action('busy_retry_rst_next'))
    assert anchor['log_start'] == len(action('busy_retry_rst').encode())
    assert anchor['qualified'] is False
    assert model.events[-1] == 'unlock'


@pytest.mark.parametrize('complete', [False, True])
def test_fin_action_needs_a_complete_log_line(probe, monkeypatch, complete):
    log, run = probe
    partial = action('busy_retry_rst').rstrip('\n')

    def finish_line():
        if complete and not log.read_text().endswith('\n'):
            with log.open('a') as out:
                out.write('\n')
    monkeypatch.setattr(view, 'time', Clock(finish_line))
    anchor, model = run(partial)
    assert anchor['qualified'] is complete
    assert ('actual work read' in model.events) is complete
    assert model.events[-1] == 'unlock'


@pytest.mark.parametrize('work', [{GENERATION: [99], PHASE: [1]},
                                 {GENERATION: [0x7ffffffe], PHASE: [4]},
                                 {GENERATION: [0x7ffffffe]}, {}])
def test_wrong_or_missing_actual_work_never_qualifies(probe, work):
    _log, run = probe
    anchor, model = run(action('busy_retry_rst'), work)
    assert anchor['qualified'] is False
    assert anchor['work.work'] == work
    assert model.events[-2:] == ['actual work read', 'unlock']


def test_actual_read_error_still_releases_the_forced_cell(probe):
    log, _run = probe
    model = Model(log, action('busy_retry_rst'))

    def failed_read(*_args, **_kwargs):
        raise RuntimeError('BFRT read failed')
    model.register_read = failed_read
    with pytest.raises(RuntimeError, match='BFRT read failed'):
        race(model, [9, 64], 64, ACK, FIN, timeout=.01)
    assert model.events[-1] == 'unlock' and model.locked is False


def test_missing_unique_log_cannot_seed_or_qualify_the_fixture(probe):
    log, _run = probe
    log.unlink()
    model = Model(log)
    with pytest.raises(ValueError, match='one model log'):
        race(model, [9, 64], 64, ACK, FIN, timeout=.01)
    assert model.events == []


@pytest.mark.parametrize('exhaustions', [0, 1])
def test_main_uses_short_observation_and_keeps_strict_three_connection_checks(tmp_path, monkeypatch, exhaustions):
    """Reintroducing snapshot polling while locked fails the real main's close experiment."""
    log = tmp_path / 'model_fixture.log'
    log.write_text('')
    inputs = tmp_path / 'inputs.json'
    inputs.write_text('{}')
    for key, value in {'OUT': str(tmp_path), 'PORT_MAP': str(inputs), 'PROG': 'fixture'}.items():
        monkeypatch.setenv(key, value)

    class Report:
        def __init__(self, *_args, **meta):
            self.record = {'meta': meta, 'cases': []}

        def add(self, name, expected, observed, ok=None):
            self.record['cases'].append(dict(name=name, expected=expected, observed=observed,
                                             ok=expected == observed if ok is None else ok))

        def finish(self, _path):
            return all(row['ok'] for row in self.record['cases'])

    class FixtureModel(Model):
        def __init__(self):
            super().__init__(log)
            self.retries = self.exhausted = 0

        def send(self, port, frame):
            assert port == 64
            self.events.append(frame[0])
            if frame[0] == 17:
                self.retries += 1
                self.exhausted += exhaustions
                with log.open('a') as out:
                    out.write(action('busy_retry_rst'))

        def register_read(self, name, index, pipe):
            if self.locked:
                return super().register_read(name, index, pipe)
            self.events.append('snapshot ' + name)
            if name == WORK:
                return {GENERATION: [31], PHASE: [4]}
            if name.endswith('count_busy'):
                return {'n_Ingress.count_busy.f1': [self.retries if index == 2 else self.exhausted if index == 3 else 0]}
            return {name.split('.', 1)[1] + '.f1': [1]}

        def capture(self, ports, **_kwargs):
            assert not self.locked
            return {9: [bytes.fromhex('11000000dc0000006501')], 64: []}

    model = FixtureModel()
    reports = []

    class Gate:
        def __init__(self, report, instance, _h, _cp):
            reports.append(report)
            self.report, self.m, self.ports = report, instance, [9, 64]
            self.relay, self.master = SimpleNamespace(dev_port=64), SimpleNamespace(dev_port=9)
            self.v = SimpleNamespace(packet=lambda flag, seq, ack, reverse=False:
                                     bytes([flag]) + seq.to_bytes(4, 'big') + ack.to_bytes(4, 'big') + bytes([reverse]))

        def configure(self):
            pass

        def handshake(self, *_args):
            return 100, 200, 220

        def exchange(self, name, _frame, expected):
            assert not self.m.locked
            self.report.add(name, expected, expected)

    h = SimpleNamespace(Report=Report, Model=lambda **_kwargs: model,
                        scalar=lambda row: next(iter(row.values()))[0],
                        same_frame=lambda frame, expected, _sent: frame == expected)
    monkeypatch.setattr(busy.mp, 'load', lambda name, _path: h if name == '_fin_helpers' else None)
    monkeypatch.setattr(busy.mp, 'PacketGate', Gate)
    rc = busy.main()
    result = reports[0].record
    assert rc == (0 if exhaustions == 0 else 1), result['cases']
    assert result['meta']['attempted_connections'] == 3
    assert result['meta']['completed_connections'] == (3 if exhaustions == 0 else 0)
    rows = [row for row in result['cases'] if row['name'] == 'retry_not_exhausted']
    assert len(rows) == 3 and all(row['expected'] == 0 and row['observed'] == exhaustions for row in rows), result['cases']
    for point in result['meta']['connections']:
        assert point['busy_anchor_before_unlock']['qualified'] is True
        assert point['busy_anchor_before_unlock']['work.work'] == SEEDED
    assert model.events.count(16) == model.events.count(17) == 3

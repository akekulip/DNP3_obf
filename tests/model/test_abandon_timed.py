"""E4: the abandoned-SELECT T=1 scenario lives in its own driver; the gate's T=0 driver stays byte-identical.

Drivers run in a subprocess (the SDE client is Python 3.8) against a fake model that records every call. The T=0
reference is the exact driver that passed the c72 gate (its retained driver_source.py). Any edit of
model_abandon.py breaks the c72 gate's closure binding, so its bytes must equal that run's driver."""
import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / 'scripts/model'
DRIVER = MODEL / 'model_abandon.py'
TIMED_DRIVER = MODEL / 'model_abandon_t1.py'
BUILD = ROOT / 'results/builds/c72'
# the canonical candidate whose live model gate must stay unblocked (c74 since c74 became canonical)
CANON = ROOT / json.loads((ROOT / 'results/analysis/stage_cut/current_build.json').read_text())['build']
GATE_RUN = ROOT / 'results/models/c72/model_abandon_c72_02'
EXPECTATIONS = ROOT / 'results/models/c72_e4_abandon_t1/EXPECTATIONS.json'
MASTER, RELAY = 9, 64
sys.path[:0] = [str(MODEL), str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]

HARNESS = r'''
import json, os, sys, time, types
from pathlib import Path
root = Path.cwd(); MODEL = root / 'scripts/model'
sys.path[:0] = [str(MODEL), str(root / 'scripts/checks'), str(root / 'scripts/hardware')]
import model_driver
spec = json.loads(sys.stdin.read())
baseline = set(sys.modules)
results = []
for run in spec['runs']:
    for name in set(sys.modules) - baseline:
        del sys.modules[name]
    os.environ.update(run['env'])
    out = Path(run['env']['OUT']); out.mkdir(parents=True, exist_ok=True)
    calls, pending = [], []
    script, phases = list(run.get('script') or []), list(run.get('phases') or [])
    records = [list(r) for r in run.get('records') or []]
    behaviour = run['behaviour']

    def output(port, frame):
        if behaviour == 'drop':
            return {}
        if behaviour == 'echo':
            return {str(RELAY if port == MASTER else MASTER): [frame.hex()]}
        return script.pop(0) if script else {}

    def frames_for(entry, ports):
        got = {p: [] for p in ports}
        for port, hexes in (entry or {}).items():
            got.setdefault(int(port), []).extend(bytes.fromhex(h) for h in hexes)
        return got

    class FakeTable:
        def __init__(self, name): self.name = name
        def make_key(self, keys): return [str(k) for k in keys]
        def make_data(self, data, action): return [str(d) for d in data] + [action]
        def entry_add(self, target, keys, data): calls.append(['entry_add', self.name, str(target), keys, data])

    class FakeModel:
        def __init__(self, ports=None, enable=True): calls.append(['Model', ports, enable])
        def enable_ports(self, ports, speed=None, loopback=None): calls.append(['enable_ports', list(ports)])
        def add(self, table, keys, action=None, data=None, priority=None, pipe=None):
            calls.append(['add', table, repr(keys), action, repr(data), priority, pipe])
        def set_default(self, table, action, data=None):
            if action == 't_Ingress.set_params' and data is not None:
                data = model_driver.t_params_for_build(data)
            calls.append(['set_default', table, action, data])
        def table(self, name, raw=False):
            calls.append(['table', name, raw]); return FakeTable(name)
        def register_read(self, name, index, field=None, pipe=None):
            calls.append(['register_read', name, index, pipe])
            phase = phases.pop(0) if phases else 4
            return {'n_Ingress.work.work.generation': [7], 'n_Ingress.work.work.phase': [phase]}
        def exchange(self, in_port, frame, out_ports, timeout=1.0, quiet=0.3):
            calls.append(['exchange', in_port, frame.hex(), list(out_ports), timeout, quiet])
            return frames_for(output(in_port, frame), out_ports)
        def drain(self, ports=None): calls.append(['drain', list(ports or [])])
        def send(self, port, frame):
            calls.append(['send', port, frame.hex()]); pending.append(output(port, frame))
        def capture(self, ports, timeout=1.0, quiet=0.3):
            calls.append(['capture', list(ports), timeout, quiet])
            got = {p: [] for p in ports}
            while pending:
                for port, frames in frames_for(pending.pop(0), ports).items():
                    got.setdefault(port, []).extend(frames)
            return got

    class FakeView:
        offset = [0]
        @staticmethod
        def log_path(out_dir=None): return out / 'model_fake.log'
        @staticmethod
        def size(path):
            FakeView.offset[0] += 1; return FakeView.offset[0]
        @staticmethod
        def records_since(path, offset): return records.pop(0) if records else []

    module = types.ModuleType('abandon_under_test')
    module.__file__ = run['file']
    exec(compile(Path(run['source']).read_text(), module.__file__, 'exec'), module.__dict__)
    module.Model = FakeModel
    module.helpers.Reflector = lambda port: types.SimpleNamespace(start=lambda: calls.append(['Reflector', port]))
    module.gc = types.SimpleNamespace(Target=lambda **k: 'Target%r' % sorted(k.items()),
                                      KeyTuple=lambda *a, **k: 'Key%r' % ((a, sorted(k.items())),),
                                      DataTuple=lambda *a, **k: 'Data%r' % ((a, sorted(k.items())),))
    module.time = types.SimpleNamespace(sleep=lambda s: calls.append(['sleep', s]), monotonic=time.monotonic)
    if run['env']['ABANDON_T'] == '1':
        module.clock_view = lambda: FakeView
    for name, value in (run.get('patch') or {}).items():
        setattr(module, name, value)
    rc = module.main()
    found = [p for p in ('abandon_results.json', 'abandon_t1_results.json') if (out / p).is_file()]
    results.append(dict(rc=rc, files=found, calls=calls,
                        report=json.loads((out / found[0]).read_text()) if len(found) == 1 else None))
Path(spec['result']).write_text(json.dumps(results))
'''.replace('MASTER', str(MASTER)).replace('RELAY', str(RELAY))


def run_fake(tmp_path, runs):
    """Execute each run spec in one Python 3.8 process with fresh project modules; return their records."""
    result = tmp_path / 'harness_result.json'
    for index, run in enumerate(runs):
        run['env'] = dict(dict(MILESTONE='current', ABANDON_T='0'), **run.get('env', {}),
                          OUT=str(tmp_path / ('out%02d' % index)))
        run['source'] = str(run.get('source', TIMED_DRIVER if run['env']['ABANDON_T'] == '1' else DRIVER))
        run['file'] = str(TIMED_DRIVER if run['env']['ABANDON_T'] == '1' else DRIVER)
    done = subprocess.run(['/usr/bin/python3', '-c', HARNESS], cwd=ROOT, capture_output=True, text=True,
                          input=json.dumps(dict(runs=runs, result=str(result))),
                          env=dict(os.environ, PORT_MAP=str(BUILD / 'response_only.inputs.json'),
                                   PROG='response_only'))
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
    return json.loads(result.read_text())


def gate_reference():
    """The retained driver_source.py of the passing c72 abandon gate run, bound to its recorded hash."""
    recorded = json.loads((GATE_RUN / 'abandon_results.json').read_text())
    source = GATE_RUN / 'driver_source.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == recorded['meta']['driver_sha256']
    assert recorded['summary']['failed'] == [] and recorded['meta']['scope'].endswith(
        'T enabled=0; what N drops, whether it clears with time, RST or a new connection')
    return source, recorded


TO_MASTER = ('SYNACK', 'READ_server_ACK', 'READ_response_61', 'SELECT_response_61')


def scripted(report):
    """One model output per injected frame: every recorded want, so both drivers see an all-pass model."""
    script = []
    for row in report['cases']:
        if 'want' not in row:
            continue                                        # a check with no injected frame
        if not row['want']:
            script.append({})                               # an expected drop
            continue
        wants = row['want'] if isinstance(row['want'], list) else [row['want']]
        pair = '_ACK_and_response' in row['name']
        if pair:
            script.append({})                               # the genuine ACK: held, nothing leaves yet
        script.append({str(MASTER if pair or row['name'] in TO_MASTER else RELAY): wants})
    return script


# ---- the gate stays T=0 -------------------------------------------------------------------------------------

def test_gate_environment_keeps_abandon_t_zero_even_when_t1_is_inherited(tmp_path, monkeypatch):
    import run_model
    monkeypatch.setenv('ABANDON_T', '1')
    env = run_model.gate_environment(tmp_path / 'inputs.json', {'milestone': 'current'},
                                     run_model.DRIVERS['abandon'], tmp_path / 'out', '/sdk/9.13.2')
    assert env['ABANDON_T'] == '0'


def test_gate_driver_is_byte_identical_to_the_passing_gate_run():
    _source, recorded = gate_reference()
    assert hashlib.sha256(DRIVER.read_bytes()).hexdigest() == recorded['meta']['driver_sha256'] == \
        '00059dce369af4017eaf5a657f4476a86323765e1e23eb142419102da8ef919a'


def test_canonical_gate_summary_has_no_blocked_abandon_closure():
    sys.path.insert(0, str(ROOT / 'scripts/hardware'))
    import freeze_gate
    summary = freeze_gate.model_summary_module().summarize_v3(CANON)
    assert not [reason for reason in summary['blocked_reasons'] if reason.startswith('abandon')], summary


def test_t0_rows_equal_the_retained_gate_record(tmp_path):
    _source, recorded = gate_reference()
    [run] = run_fake(tmp_path, [dict(behaviour='drop')])
    assert run['files'] == ['abandon_results.json']
    shape = [(row['name'], row['expected'], row.get('want')) for row in run['report']['cases']]
    assert shape == [(row['name'], row['expected'], row.get('want')) for row in recorded['cases']]
    assert run['report']['meta']['scope'] == recorded['meta']['scope']


@pytest.mark.parametrize('milestone', ['current', 'm1'])
def test_t0_behaviour_is_identical_to_the_gate_driver(tmp_path, milestone):
    reference, _recorded = gate_reference()
    env = dict(MILESTONE=milestone)
    first = run_fake(tmp_path / 'wants', [dict(behaviour='drop', source=reference, env=env)])[0]
    script = scripted(first['report'])
    runs = []
    for behaviour in ('drop', 'echo', 'script'):
        for source in (reference, DRIVER):
            runs.append(dict(behaviour=behaviour, source=source, env=env, script=script))
    done = run_fake(tmp_path, runs)
    for ref, new in zip(done[0::2], done[1::2]):
        assert new == ref
    assert done[4]['rc'] == 0 and done[4]['report']['summary']['failed'] == []


@pytest.mark.parametrize('old,new', [
    ("'one exact frame'", "'one frame'"),
    ('timeout=3, quiet=.15', 'timeout=3, quiet=.2'),
    ("forwarded = send('READ_after_SELECT_cancels_selection_forwarded', sent, want)",
     "forwarded = send('READ_after_SELECT_cancels_selection_forwarded', sent, None)"),
])
def test_t0_comparison_detects_a_changed_expectation_or_call(tmp_path, old, new):
    reference, _recorded = gate_reference()
    text = reference.read_text()
    assert text.count(old) >= 1
    mutant = tmp_path / 'mutant.py'
    mutant.write_text(text.replace(old, new))
    first = run_fake(tmp_path / 'wants', [dict(behaviour='drop', source=reference)])[0]
    done = run_fake(tmp_path, [dict(behaviour='script', source=source, script=scripted(first['report']))
                               for source in (reference, mutant)])
    assert done[0] != done[1]


# ---- the T=1 scenario -----------------------------------------------------------------------------------------

def timed_table():
    tree = ast.parse(TIMED_DRIVER.read_text())
    values = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
              for target in node.targets if isinstance(target, ast.Name)}
    assert 'TIMED_STEPS' in values and 'TIMED_CONTRACT' in values, 'model_abandon_t1.py has no T=1 table'
    return ast.literal_eval(values['TIMED_CONTRACT']), ast.literal_eval(values['TIMED_STEPS'])


def test_timed_table_matches_the_contract_derivation_record():
    contract, steps = timed_table()
    record = json.loads(EXPECTATIONS.read_text())
    assert contract == record['timing_contract'] == 'response_ready_ack_d_no_j_v3'
    assert [list(map(lambda v: list(v) if isinstance(v, tuple) else v, step)) for step in steps] == [
        [row['row'], row['stimulus'], row['master'], row['relay'], row['release']] for row in record['rows']]
    for row in record['rows']:
        assert row['citations'] and all(':' in item for item in row['citations'])
        assert row['inject'] == ('master' if row['relay'] else 'relay')


def expected_rows():
    _contract, steps = timed_table()
    rows = ['timed_scenario_preconditions']
    for step in steps:
        rows.append(step[0])
        if step[4] == 'response_ready_D':
            rows.append(step[0].split('_')[0] + '_T_clock_response_ready_ACK_then_D')
    return rows + ['N_work_free_after_every_step']


def good_records(gap=19534):
    actions = [('hold_ack', 1000), ('admit_response', 1100), ('release_ack_commit', 1102),
               ('rewait_response', 1200), ('release_response_counted', 1102 + gap)]
    return [dict(pipe=1, port=182, actions=['t_Ingress.' + name], t_units=units) for name, units in actions]


def timed_runs(tmp_path, variants):
    """One drop pass collects the driver's own wants; each variant then perturbs an otherwise correct model."""
    first = run_fake(tmp_path / 'wants', [dict(behaviour='drop', env=dict(ABANDON_T='1'),
                                               records=[good_records(), good_records()])])[0]
    assert first['files'] == ['abandon_t1_results.json'], first['report']
    base = scripted(first['report'])
    runs = []
    for change in variants:
        run = dict(behaviour='script', env=dict(ABANDON_T='1'), script=json.loads(json.dumps(base)),
                   records=[good_records(), good_records()])
        change(run)
        runs.append(run)
    return first, run_fake(tmp_path, runs)


def test_timed_scenario_passes_on_contract_behaviour_and_follows_the_table(tmp_path):
    first, [run] = timed_runs(tmp_path, [lambda run: None])
    report = run['report']
    assert run['rc'] == 0 and report['summary']['failed'] == [], report['summary']
    assert [row['name'] for row in report['cases']] == expected_rows()
    assert all(row.get('characterization') is False for row in report['cases'])
    meta = report['meta']
    assert meta['model_gate'] is False and meta['scenario'] == 'E4_abandoned_SELECT_timing_enabled'
    assert 'not part of the model gate' in meta['scope'] and meta['timing_contract'] == 'response_ready_ack_d_no_j_v3'
    params = [call for call in run['calls'] if call[0] == 'set_default']
    assert params == [['set_default', 'p1.t_Ingress.params', 't_Ingress.set_params',
                       dict(gap=19534, budget=240000, enabled=1)]]
    # The shared stimulus prefix is byte-identical to the gate's T=0 stimulus (same builders and timestamp ticks).
    _source, recorded = gate_reference()
    gate = {row['name']: row.get('want') for row in recorded['cases']}
    timed = {row['name']: row.get('want') for row in report['cases']}
    for name in ('SYN', 'SYNACK', 'final_ACK', 'READ_request', 'SELECT_request'):
        assert timed[name] == gate[name]
    assert timed['READ_ACK_and_response_61'] == [gate['READ_server_ACK'], gate['READ_response_61']]
    sent = [call[2] for call in run['calls'] if call[0] in ('exchange', 'send')]
    assert len(sent) == 12


def stale_work(run):
    run['phases'] = [4, 4, 4, 4, 1]


def records_without_hold(run):
    run['records'][0] = [r for r in good_records() if 'hold_ack' not in r['actions'][0]] + [
        dict(pipe=1, port=180, actions=['t_Ingress.passthrough_tev_forward'], t_units=990)]


def short_d(run):
    run['records'][1] = good_records(gap=19532)


def stale_flush(run):
    run['records'][0] = good_records() + [dict(pipe=1, port=182, actions=['t_Ingress.flush_response_stale'],
                                               t_units=1300)]


def double_commit(run):
    run['records'][1] = good_records() + [dict(pipe=1, port=182, actions=['t_Ingress.release_ack_commit'],
                                               t_units=1104)]


def response_first(run):
    entry = run['script'][5]
    entry[str(MASTER)] = entry[str(MASTER)][::-1]


def response_missing(run):
    entry = run['script'][8]
    entry[str(MASTER)] = entry[str(MASTER)][:1]


def extra_relay_frame(run):
    run['script'][5][str(RELAY)] = [run['script'][3][str(RELAY)][0]]


def dropped(index):
    def change(run):
        run['script'][index] = {}
    return change


@pytest.mark.parametrize('change,row', [
    (records_without_hold, 'READ_T_clock_response_ready_ACK_then_D'),
    (short_d, 'SELECT_T_clock_response_ready_ACK_then_D'),
    (stale_flush, 'READ_T_clock_response_ready_ACK_then_D'),
    (double_commit, 'SELECT_T_clock_response_ready_ACK_then_D'),
    (response_first, 'READ_ACK_and_response_61'),
    (response_missing, 'SELECT_ACK_and_response_61'),
    (extra_relay_frame, 'READ_ACK_and_response_61'),
    (dropped(9), 'READ_after_SELECT_cancels_selection_forwarded'),
    (dropped(10), 'RST_after_abandoned_SELECT_forwarded'),
    (dropped(11), 'new_SYN_after_abandoned_SELECT_admitted'),
    (stale_work, 'N_work_free_after_every_step'),
])
def test_timed_scenario_failures_are_failures_never_characterizations(tmp_path, change, row):
    _first, [run] = timed_runs(tmp_path, [change])
    report = run['report']
    assert run['rc'] == 1 and row in report['summary']['failed'], report['summary']
    assert all(case.get('characterization') is False for case in report['cases'])


def test_timed_scenario_refuses_another_contract_before_any_stimulus(tmp_path):
    _first, [run] = timed_runs(tmp_path, [lambda run: run.update(patch=dict(TIMED_CONTRACT='other'))])
    assert run['rc'] == 1 and run['report']['summary']['failed'] == ['timed_scenario_preconditions']
    assert not [call for call in run['calls'] if call[0] in ('exchange', 'send')]


# ---- the separate runner --------------------------------------------------------------------------------------

def test_runner_sets_t1_only_in_its_own_environment_and_writes_outside_the_gate(tmp_path, monkeypatch):
    import model_summary
    import run_model
    import run_abandon_t1 as runner
    monkeypatch.setenv('ABANDON_T', '0')
    args = (tmp_path / 'inputs.json', {'milestone': 'current'})
    gate = run_model.gate_environment(*args, run_model.DRIVERS['abandon'], tmp_path / 'out', '/sdk')
    env = runner.scenario_environment(*args, tmp_path / 'out', '/sdk')
    assert (gate['ABANDON_T'], env['ABANDON_T']) == ('0', '1')
    assert (gate['CTL_CLOSURE_TARGET'], env['CTL_CLOSURE_TARGET']) == (str(DRIVER), str(TIMED_DRIVER))
    changed = ('ABANDON_T', 'CTL_CLOSURE_TARGET')
    assert {k: v for k, v in env.items() if k not in changed} == {k: v for k, v in gate.items() if k not in changed}
    assert runner.DRIVER == TIMED_DRIVER and TIMED_DRIVER not in run_model.DRIVERS.values()
    out = runner.evidence_dir(BUILD, 1)
    assert out == ROOT / 'results/models/c72_e4_abandon_t1/model_abandon_t1_c72_01'
    assert model_summary.model_root(BUILD) not in out.parents
    assert 'not part of' in runner.SCENARIO and 'model gate' in runner.SCENARIO

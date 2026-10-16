"""C3 diagnostic (C3_DIAGNOSTIC_PLAN_20261016): the read-only switch poller and the isolation/control modes.

No hardware. The poller runs against a fake BF Runtime `switch` module (in-process and as a real background
process for the wait-start/stop helpers); the campaign is planned with the DryRunner; the monitor reuses the W2
permit harness (retained m4 counters, synthetic Vision ticks, MODEL-ONLY); the verdict runs on the retained
candidate61 trial exactly as test_stale_isolation_s3 does.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

import pytest

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import diag_poll as dp
import token_window as tw
import test_stale_isolation_s3 as s3
import test_isolation_20s as w2

CONFIG = HW.parent / 'config'
ORIGINAL = CONFIG / 'ctl_m5_stale_iso20_950.json'
ORIGINAL_SHA256 = '2f46923e116fad37193c9630734f56a5d5fa0dc179fa270b26e1fbe4f23a3fe2'
DIAG = {'isolation': CONFIG / 'ctl_m5_c3diag_iso20_950.json', 'control': CONFIG / 'ctl_m5_c3diag_control_950.json'}
PORTS = {'isolation': 59870, 'control': 59871}


# ---------------------------------------------------------------- poller: sample format and read-only guarantee

class FakeSwitch:
    """register()/must_get() as switch.Switch returns them; owner and work carry the retained m5 shapes."""

    def __init__(self, fail=()):
        self.fail, self.calls = set(fail), []

    def register(self, name, pipe, index=0):
        self.calls.append(('register', name, pipe, index))
        if ('outcomes', index) in self.fail:
            raise RuntimeError('grpc read failed')
        return [index, 100 * index]                       # two pipes: the poller sums them

    def must_get(self, table, pipe, key):
        self.calls.append(('must_get', table, pipe, key))
        if table in self.fail:
            raise RuntimeError('grpc read failed: ' + table)
        if table == 'tf1.pktgen.app_cfg':
            app = key[0][1]
            return dict(trigger_counter=2 - app, batch_counter=2 - app, pkt_counter=8 - 4 * app, ipg=0,
                        action_name='trigger_recirc_pattern', is_default_entry=False)
        short = table.split('.', 1)[1]
        if table == 'p0.n_Ingress.work.work':
            return {short + '.generation': [17], short + '.phase': [4], 'action_name': None}
        value = {'p0.n_Ingress.epoch': 15, 'p0.n_Ingress.owner': 327682, 'p1.t_Ingress.cur_epoch_reg': 15,
                 'p1.t_Ingress.gen_alloc_reg': 6, 'p1.t_Ingress.op_gen_alloc_reg': 4}[table]
        return {short + '.f1': [value], 'action_name': None, 'is_default_entry': False}

    def close(self):
        self.calls.append(('close',))


def counter(start=1000, step=7):
    state = {'now': start}

    def clock():
        state['now'] += step
        return state['now']
    return clock


def test_sample_format_reads_every_named_cell_with_switch_monotonic_bounds():
    sw = FakeSwitch()
    sample = dp.sample(sw, 3, clock=counter(), wall=lambda: 1234.5)
    assert tuple(sorted(sample)) == tuple(sorted(dp.SAMPLE_KEYS))
    assert sample['seq'] == 3 and sample['wall_time'] == 1234.5 and sample['errors'] == {}
    assert sample['t_start_ns'] < sample['t_end_ns']
    assert sample['outcomes'] == [101 * i for i in range(25)]            # all 25 cells, summed over pipes
    assert sample['pktgen'] == {'READ': dict(trigger_counter=2, batch_counter=2, pkt_counter=8),
                                'OPERATE': dict(trigger_counter=1, batch_counter=1, pkt_counter=4)}
    assert (sample['n_epoch'], sample['n_owner'], sample['n_work_generation'], sample['n_work_phase'],
            sample['t_cur_epoch'], sample['t_gen_alloc'], sample['t_op_gen_alloc']) == (15, 327682, 17, 4, 15, 6, 4)
    # outcome cells over ALL_PIPES, as snapshot_counters.py; apps on pipe 1 (snapshot_lifecycle --read-app);
    # registers at index 0 on their own pipe (snapshot_lifecycle)
    registers = [c for c in sw.calls if c[0] == 'register']
    assert registers == [('register', 'p1.t_Ingress.outcomes', 0xffff, i) for i in range(25)]
    gets = {c[1]: c[2:] for c in sw.calls if c[0] == 'must_get'}
    assert gets['tf1.pktgen.app_cfg'][0] == 1
    names = {name for _, name, _ in dp.REGISTERS}
    assert names == {name for _, name, _ in tw.AUTHORITY} | {'p0.n_Ingress.work.work'}
    for name in names:
        assert gets[name] == (1 if name.startswith('p1.') else 0, [('$REGISTER_INDEX', 0, None)])
    work_reads = [c for c in sw.calls if c[0] == 'must_get' and c[1] == 'p0.n_Ingress.work.work']
    assert len(work_reads) == 1                                           # generation and phase from one read


def test_a_failed_read_is_recorded_in_its_sample_and_the_rest_is_still_read():
    sample = dp.sample(FakeSwitch(fail={('outcomes', 6), 'tf1.pktgen.app_cfg', 'p0.n_Ingress.work.work'}), 0,
                       clock=counter())
    assert sample['outcomes'][6] is None and sample['outcomes'][7] == 707
    assert sample['pktgen']['READ'] == dict(trigger_counter=None, batch_counter=None, pkt_counter=None)
    assert sample['n_work_generation'] is None and sample['n_work_phase'] is None and sample['n_epoch'] == 15
    assert set(sample['errors']) == {'outcomes[6]', 'pktgen.READ', 'pktgen.OPERATE', 'n_work_generation',
                                     'n_work_phase'}


def args(tmp_path, **change):
    values = dict(output=str(tmp_path / 'p.jsonl'), stop_file=str(tmp_path / 'p.stop'), pid_file=str(tmp_path / 'p.pid'),
                  switch_tools=str(tmp_path), program='response_only', client_id=218, period_s=0.1,
                  max_duration_s=600.0, timeout_s=2.0)
    values.update(change)
    return type('Args', (), values)


@pytest.fixture
def restore_sigterm():
    previous = signal.getsignal(signal.SIGTERM)
    yield
    signal.signal(signal.SIGTERM, previous)


def lines(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def test_poll_stops_on_the_stop_file_and_writes_a_summary(tmp_path, restore_sigterm):
    a = args(tmp_path)
    sw = FakeSwitch()
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 3:
            Path(a.stop_file).touch()
    assert dp.poll(a, connect=lambda *_: sw, clock=counter(step=1000), sleep=sleep) == 0
    out = lines(a.output)
    assert [line['seq'] for line in out[:-1]] == [0, 1, 2] and out[-1]['summary'] is True
    assert (out[-1]['stopped_by'], out[-1]['samples'], out[-1]['samples_with_errors']) == ('stop_file', 3, 0)
    assert all(0 < s <= 0.1 for s in sleeps) and sw.calls[-1] == ('close',)
    assert Path(a.pid_file).read_text().strip() == str(os.getpid())
    with pytest.raises(FileExistsError):                                    # never appends to an earlier run
        dp.poll(a, connect=lambda *_: FakeSwitch(), clock=counter(), sleep=sleep)


def test_poll_stops_on_sigterm_and_a_bind_failure_is_a_summary_not_a_sample(tmp_path, restore_sigterm):
    a = args(tmp_path)
    assert dp.poll(a, connect=lambda *_: FakeSwitch(), clock=counter(),
                   sleep=lambda _: os.kill(os.getpid(), signal.SIGTERM)) == 0
    assert lines(a.output)[-1]['stopped_by'] == 'sigterm' and lines(a.output)[-1]['samples'] == 1

    def refuse(*_):
        raise ValueError('requested program is not installed')
    b = args(tmp_path / 'b'); (tmp_path / 'b').mkdir()
    assert dp.poll(b, connect=refuse, clock=counter(), sleep=lambda _: None) == 1
    assert lines(b.output) == [dict(lines(b.output)[0], summary=True, samples=0, stopped_by='bind_failed')]


FORBIDDEN = {'entry_add', 'entry_mod', 'entry_del', 'default_entry_set', 'default_entry_reset',
             'bind_pipeline_config', 'set_app_enable', 'entry_mod_inc', 'clear', 'write_operation'}


def test_poller_source_has_no_table_or_register_write_call():
    source = (HW / 'diag_poll.py').read_text()
    tree = ast.parse(source)
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not attributes & FORBIDDEN, attributes & FORBIDDEN
    # the only .write() calls are the output file handle's, and the client's write() is defined only to refuse
    writes = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr == 'write']
    assert writes and all(isinstance(w.func.value, ast.Name) and w.func.value.id == 'handle' for w in writes)
    defs = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'write']
    assert len(defs) == 1 and isinstance(defs[0].body[0], ast.Raise)
    assert 'perform_subscribe=False' in source


FAKE_SWITCH = '''
import json, os
calls = []


class _Iface:
    def __init__(self, *args, **kwargs):
        calls.append(kwargs)
        self.channel = self

    def bfrt_info_get(self, program):
        return object()

    def close(self):
        pass


class gc:
    ClientInterface = _Iface


class _Data:
    def __init__(self, values):
        self.values = values


class _Table:
    def __init__(self, name):
        self.name = name

    def entry_get(self, target, keys, flags, p4_name=None):
        if self.name == 'tf1.pktgen.app_cfg':
            return [(_Data(dict(trigger_counter=1, batch_counter=1, pkt_counter=4)), None)]
        if self.name == 'p0.n_Ingress.work.work':
            return [(_Data({'x.generation': [3], 'x.phase': [1]}), None)]
        if self.name == 'p1.t_Ingress.outcomes':
            return [(_Data({'t_Ingress.outcomes.f1': [1, 2]}), None)]
        return [(_Data({'x.f1': [5]}), None)]


class Switch:
    def target(self, pipe):
        return pipe

    def table(self, name):
        return _Table(name)

    def key(self, table, key, priority=None):
        return key

    @staticmethod
    def as_dict(data):
        return dict(data.values)

    def must_get(self, table, pipe, key, priority=None):
        return self.get(table, pipe, key, priority)

    def register(self, name, pipe, index=0):
        return self.must_get(name, pipe, index)['t_Ingress.outcomes.f1']

    def write(self, op):
        raise AssertionError('base write reached')
'''


def fake_tools(tmp_path):
    tools = tmp_path / 'tools'; tools.mkdir()
    (tools / 'switch.py').write_text(FAKE_SWITCH)
    out = tmp_path / 'out'; out.mkdir()
    (out / 'bfrt.json').write_text(json.dumps(dict(tables=[dict(name='p1.t_Ingress.outcomes', size=25)])))
    return tools, out


def test_client_never_binds_or_subscribes_and_refuses_writes(tmp_path):
    tools, _ = fake_tools(tmp_path)
    sys.modules.pop('switch', None)
    try:
        sw = dp.read_only_switch(tools, 'response_only', 218)
        import switch
        assert switch.calls == [dict(client_id=218, device_id=0, perform_subscribe=False)]
        with pytest.raises(RuntimeError, match='read-only'):
            sw.write(dict(kind='pktgen_enable'))
        assert dp.sample(sw, 0)['errors'] == {}
    finally:
        sys.modules.pop('switch', None)
        sys.path.remove(str(tools.resolve()))


def test_background_poller_wait_start_and_stop_helpers_end_to_end(tmp_path):
    """Launched exactly as the harness launches it: a detached background subshell (no zombie parent here)."""
    import shlex
    tools, out = fake_tools(tmp_path)
    files = ['--output', str(tmp_path / 'p.jsonl'), '--stop-file', str(tmp_path / 'p.stop'),
             '--pid-file', str(tmp_path / 'p.pid')]
    tool = [sys.executable, str(HW / 'diag_poll.py')]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    poll = ' '.join(shlex.quote(x) for x in tool + ['poll', '--build-out', str(out), '--switch-tools', str(tools),
                                                     '--period-s', '0.05'] + files)
    subprocess.run(['bash', '-c', '(nohup %s > %s 2>&1 < /dev/null &)' % (poll, shlex.quote(str(tmp_path / 'p.log')))],
                   check=True, env=env, timeout=30)
    try:
        started = subprocess.run(tool + ['wait-start'] + files + ['--timeout-s', '10'], capture_output=True, text=True,
                                 env=env, timeout=30)
        assert started.returncode == 0, started.stdout + started.stderr
        report = json.loads(started.stdout)
        assert report['pid'] == int((tmp_path / 'p.pid').read_text()) and report['first_sample_ns'] > 0
        stopped = subprocess.run(tool + ['stop'] + files + ['--timeout-s', '5'], capture_output=True, text=True,
                                 env=env, timeout=30)
        assert stopped.returncode == 0, stopped.stdout + (tmp_path / 'p.log').read_text()
        report = json.loads(stopped.stdout)
        assert report['stopped'] and report['exited'] and report['ended_by'] == 'stop_file' and report['samples'] >= 1
        out_lines = lines(tmp_path / 'p.jsonl')
        assert out_lines[-1]['stopped_by'] == 'stop_file' and all(line['errors'] == {} for line in out_lines[:-1])
        assert out_lines[0]['outcomes'] == [3] * 25 and out_lines[0]['n_work_phase'] == 1
    finally:
        pid = dp._pid(tmp_path / 'p.pid')
        if pid is not None and dp._alive(pid):
            os.kill(pid, signal.SIGKILL)
    # a stop with no running poller and no summary is a failure, not a silent success
    assert subprocess.run(tool + ['stop', '--output', str(tmp_path / 'none.jsonl'), '--stop-file',
                                  str(tmp_path / 'none.stop'), '--pid-file', str(tmp_path / 'none.pid'),
                                  '--timeout-s', '0.2'], capture_output=True, env=env, timeout=30).returncode == 1


def test_poll_refuses_a_build_without_the_25_cell_outcome_layout(tmp_path):
    tools, out = fake_tools(tmp_path)
    (out / 'bfrt.json').write_text(json.dumps(dict(tables=[dict(name='p1.t_Ingress.outcomes', size=16)])))
    result = subprocess.run([sys.executable, str(HW / 'diag_poll.py'), 'poll', '--build-out', str(out), '--switch-tools',
                             str(tools), '--output', str(tmp_path / 'p.jsonl'), '--stop-file', str(tmp_path / 's'),
                             '--pid-file', str(tmp_path / 'pid')], capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and 'REFUSED' in result.stdout and not (tmp_path / 'p.jsonl').exists()


# ---------------------------------------------------------------- configs

def test_original_config_is_byte_identical():
    assert hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() == ORIGINAL_SHA256


@pytest.mark.parametrize('mode', ['isolation', 'control'])
def test_diagnostic_configs_differ_from_the_original_only_in_purpose_mode_port_and_note(mode):
    original, diag = json.loads(ORIGINAL.read_text()), json.loads(DIAG[mode].read_text())
    assert {k for k in set(original) | set(diag) if original.get(k) != diag.get(k)} == \
        {'_notes', 'traffic', 'purpose', 'diagnostic'}
    assert diag['_notes'][:-1] == original['_notes']
    assert {k for k in original['traffic'] if original['traffic'][k] != diag['traffic'][k]} == {'master_port_range'}
    assert diag['traffic']['master_port_range'] == dict(first=PORTS[mode], last=PORTS[mode])
    assert diag['purpose'] == 'diagnostic' and diag['diagnostic'] == dict(poller=True, period_s=0.1, mode=mode)
    assert diag['evaluation'] == original['evaluation'] == dict(purpose='stale_source_characterization',
                                                                read_precision=False)


def test_diagnostic_ports_are_not_used_by_any_other_config():
    used = {}
    for path in list(CONFIG.glob('*.json')) + list((s3.SEG / 'hw/config').glob('*.json')):
        try:
            span = json.loads(path.read_text()).get('traffic', {}).get('master_port_range')
        except ValueError:
            continue
        if span:
            for port in range(span['first'], span['last'] + 1):
                used.setdefault(port, []).append(path.name)
    for mode, port in PORTS.items():
        assert used[port] == [DIAG[mode].name]


# ---------------------------------------------------------------- purpose gate and settings

def load(mode=None):
    import candidate_isolation as ci
    return ci, ci.base.load_config(str(DIAG[mode] if mode else ORIGINAL))


def make(cfg, **kwargs):
    import candidate_isolation as ci
    return ci.TokenIsolationCampaign(cfg, ci.base.DryRunner(), 'c3', arms=['combined'], fixtures=['separate_ack'],
                                     **kwargs)


def test_diagnostic_modes_require_the_diagnostic_purpose_and_a_valid_section():
    ci, cfg = load('control')
    for change in (lambda c: c.pop('purpose'), lambda c: c.update(purpose='qualification'),
                   lambda c: c.update(purpose='stale_source_characterization'), lambda c: c.pop('diagnostic'),
                   lambda c: c['diagnostic'].update(mode='overlap'), lambda c: c['diagnostic'].update(poller='yes'),
                   lambda c: c['diagnostic'].update(period_s=0.01), lambda c: c['diagnostic'].update(period_s=True),
                   lambda c: c['diagnostic'].update(extra=1), lambda c: c['diagnostic'].pop('period_s'),
                   lambda c: c.update(evaluation=dict(purpose='diagnostic', read_precision=False))):
        bad = copy.deepcopy(cfg); change(bad)
        with pytest.raises(ValueError):
            make(bad)
    assert ci.diagnostic_settings({}) is None
    assert ci.diagnostic_settings(cfg) == dict(poller=True, period_s=0.1, mode='control', purpose='diagnostic')


def test_original_config_builds_the_unchanged_isolation_block():
    ci, cfg = load()
    run = make(cfg)
    assert run.diagnostic is None and run.control is False and 'c3_diagnostic' not in run.record
    assert str(HW / 'diag_poll.py') not in run.record['isolation_source_identity']
    assert (run.delay_ipg_ns, run.pause_ms) == (2_500_000_000, 20_000)


def test_isolation_diagnostic_keeps_the_derived_plan_and_control_uses_the_endpoint_maximum_without_a_plan():
    _, iso_cfg = load('isolation')
    _, ctl_cfg = load('control')
    _, original = load()
    iso, ctl, base_run = make(iso_cfg), make(ctl_cfg), make(original)
    assert iso.plan == base_run.plan and (iso.delay_ipg_ns, iso.pause_ms) == (2_500_000_000, 20_000)
    assert (ctl.plan['mode'], ctl.plan['bound'], ctl.delay_ipg_ns, ctl.pause_ms) == ('control', None, None, 20_000)
    assert ctl.capability == iso.capability == dict(max_pause_ms=20000, permit=True)
    for run in (iso, ctl):
        assert run.record['c3_diagnostic']['qualification'] is False
        assert run.record['c3_diagnostic']['counted_as_qualification'] is False
        assert str(HW / 'diag_poll.py') in run.record['isolation_source_identity']
    ctl.active_unit = (ctl.units()[0], 0, 'x'); ctl._series_padding = 1
    assert '--pre-read-grace-ms 20000 --endpoint isolation_20s' in ctl.series_vision_cmd('fixed', 59871, 1, 8, 0)


# ---------------------------------------------------------------- plan output: order of poller and delay steps

def plan_labels(mode):
    result = subprocess.run([sys.executable, str(HW / 'candidate_isolation.py'), 'plan', '--config', str(DIAG[mode]),
                             '--run-id', 'ctl_m5_c3diag_%s_test' % mode], capture_output=True, text=True, timeout=300,
                            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    assert result.returncode == 0, result.stderr[-2000:]
    return [line[14:].strip() for line in result.stdout.splitlines() if line.startswith('[')], result.stdout


def index(labels, text):
    found = [i for i, label in enumerate(labels) if text in label]
    assert len(found) == 1, (text, found)
    return found[0]


@pytest.mark.parametrize('mode', ['isolation', 'control'])
def test_plan_starts_the_poller_after_before_and_stops_it_after_vision_and_before_after(mode):
    labels, out = plan_labels(mode)
    deploy, verify = index(labels, 'copy diagnostic_switch_identity'), index(labels, 'verify diagnostic_switch_identity')
    before = index(labels, 'lifecycle snapshot ctl_m5_c3diag_%s_test_separate_ack_combined_t0_before' % mode)
    start = index(labels, 'C3 diagnostic: start the read-only poller')
    vision = index(labels, 'traffic + capture on master port %d' % PORTS[mode])
    stop = index(labels, 'C3 diagnostic: stop the poller (stop file')
    after = index(labels, 'counter snapshot ctl_m5_c3diag_%s_test_separate_ack_combined_t0_after' % mode)
    teardown = index(labels, 'teardown the composite')
    copy_samples = index(labels, 'collect C3 diagnostic poller samples')
    assert deploy < verify < before < start < vision < stop < after < teardown < copy_samples
    delays = [i for i, label in enumerate(labels) if label == 'delay fresh READ app only']
    if mode == 'isolation':
        assert delays and before < delays[0] < start
    else:
        assert delays == []                                  # control: no READ-IPG write (and so no restore)
    assert 'diag_poll.py poll --build-out' in out and '--period-s 0.1' in out and 'diag_poll.py stop' in out
    assert '_diag_poll.jsonl ' in out and '/diag_poll.jsonl' in out


def test_dry_snapshots_record_skipped_delay_and_restore_in_control_and_the_delay_in_isolation():
    for mode in ('isolation', 'control'):
        _, cfg = load(mode)
        run = make(cfg)
        run.active_unit = (run.units()[0], 0, 'lbl')
        run.snapshot('/r/out', 'lbl_before'); run.snapshot('/r/out', 'lbl_after')
        unit = run.record['c3_diagnostic']['units']['lbl']
        assert unit['started'] is True and unit['stopped'] is True
        commands = [cmd for _, cmd in run.rn.calls]
        assert sum('delay_read_tokens.py' in cmd for cmd in commands) == (1 if mode == 'isolation' else 0)
        if mode == 'control':
            assert run.window['delay']['skipped'] is True and run.window['restore_step']['skipped'] is True
        else:
            assert 'delay' not in run.window and 'restore_step' not in run.window
        start = next(i for i, c in enumerate(commands) if 'diag_poll.py poll' in c)
        stop = next(i for i, c in enumerate(commands) if 'diag_poll.py stop' in c)
        assert start < stop and stop < next(i for i, c in enumerate(commands) if 'snapshot_counters.py' in c and
                                            'lbl_after' in c)


class SwitchRunner:
    """Non-dry runner: every command succeeds except those the test scripts by substring -> (rc, out)."""
    dry = False

    def __init__(self, scripted=None, on_run=None):
        self.calls, self.scripted, self.on_run = [], dict(scripted or {}), on_run

    def run(self, where, cmd, cwd=None, timeout=None, label=None):
        import candidate_isolation as ci
        self.calls.append((where, label or '', cmd))
        if self.on_run:
            self.on_run(where, label or '', cmd)
        for key, (rc, out) in self.scripted.items():
            if key in cmd:
                return ci.base.Result(rc, out, '')
        if 'generation_headroom.py' in cmd:
            return ci.base.Result(0, json.dumps(dict(ok=True)), '')
        return ci.base.Result(0, '', '')


def live_run(tmp_path, runner, mode='control'):
    _, cfg = load(mode)
    run = make(cfg)
    run.rn, run.out, run.root = runner, (lambda *a, **k: None), str(tmp_path)
    run.bound = {name: {} for name in cfg['builds']}
    return run


NOT_STARTED = json.dumps(dict(started=False, pid=7, reason='first sample incomplete: outcomes incomplete',
                              first_sample_ns=41_000_000))


def test_a_poller_that_does_not_start_ends_the_block_before_traffic_and_still_tears_down_and_restores(tmp_path):
    import candidate_isolation as ci
    runner = SwitchRunner({' wait-start ': (1, NOT_STARTED),
                           'diag_poll.py stop': (1, json.dumps(dict(stopped=False, ended_by='sigterm')))})
    run = live_run(tmp_path, runner)
    unit, port = run.units()[0], run.ports()[0]
    with pytest.raises(ci.base.StepFailed, match='poller did not start .*block stopped before traffic'):
        run.run_unit(unit, port)
    run.restore()
    labels = [label for _, label, _ in runner.calls]
    pos = lambda text: next(i for i, label in enumerate(labels) if text in label)
    assert not any('traffic + capture' in label for label in labels)          # no Vision traffic at all
    assert pos('start the read-only poller') < pos('stop the poller') < pos('counter snapshot %s_after'
                                                                            % run.label(unit))
    assert pos('no poller may remain before teardown') < pos('teardown the composite (generator') < \
        pos('no poller may remain before the restore cold swap') < \
        pos('cold-swap bf_switchd back to the observed production')
    assert sum('diag_poll.py stop' in cmd for _, _, cmd in runner.calls) == 1
    state = run.record['c3_diagnostic']['units'][run.label(unit)]
    assert state['started'] is False and 'outcomes incomplete' in state['start_error']
    assert state['ended_by'] == 'sigterm' and state['diagnostic_incomplete'] is True
    assert state['first_sample_ns'] == 41_000_000
    trial = run.record['arms'][0]['trials'][0]
    assert trial['diagnostic_poller'] == dict(first_sample_ns=41_000_000, started=False)
    assert all(entry['ok'] for entry in run.record['restore'])


def test_start_command_bounds_the_poller_and_records_the_first_sample_duration(tmp_path):
    runner = SwitchRunner({' wait-start ': (0, json.dumps(dict(started=True, pid=7, first_sample_ns=38_000_000)))})
    run = live_run(tmp_path, runner)
    trial = {}
    run.start_poller('lbl', '/r/out', trial)
    start = next(cmd for _, label, cmd in runner.calls if 'start the read-only poller' in label)
    assert '--max-duration-s 180 ' in start and '--period-s 0.1 ' in start
    assert trial == {'diagnostic_poller': dict(first_sample_ns=38_000_000, started=True)}
    assert run.record['c3_diagnostic']['units']['lbl']['started'] is True


def test_keyboard_interrupt_in_the_unit_still_stops_the_poller(tmp_path, monkeypatch):
    import candidate_isolation as ci
    runner = SwitchRunner({' wait-start ': (0, json.dumps(dict(started=True, pid=7, first_sample_ns=1)))})
    run = live_run(tmp_path, runner)

    def interrupted(self, unit, port):
        self.start_poller(self.label(unit), '/r/out')
        raise KeyboardInterrupt
    monkeypatch.setattr(ci.cs.CandidateSeriesCampaign, 'run_unit', interrupted)
    with pytest.raises(KeyboardInterrupt):
        run.run_unit(run.units()[0], run.ports()[0])
    assert sum('diag_poll.py stop' in cmd for _, _, cmd in runner.calls) == 1


def test_a_leftover_poller_is_killed_and_fails_the_block_while_restore_proceeds(tmp_path):
    runner = SwitchRunner({"pgrep -f 'aux/diag_poll[.]py poll'": (3, 'LEFTOVER 4242')})
    run = live_run(tmp_path, runner)
    run.switch_touched = True                                         # the restore then cold-swaps production
    run.restore()
    labels = [label for _, label, _ in runner.calls]
    assert labels.index('C3 diagnostic: no poller may remain before the restore cold swap') < \
        next(i for i, label in enumerate(labels) if 'cold-swap bf_switchd back to the observed production' in label)
    assert run.soft_failures == ['diagnostic poller left running']
    assert run.record['c3_diagnostic']['poller_left_running'] is True
    assert 'kill -KILL $pids' in ci_check() and "pgrep -f 'aux/diag_poll[.]py poll'" in ci_check()
    # the pattern does not match the shell that runs it, and does match a running poll
    import re
    assert not re.search('aux/diag_poll[.]py poll', ci_check())
    assert re.search('aux/diag_poll[.]py poll', 'python3 /r/aux/diag_poll.py poll --build-out /r/out')


def ci_check():
    import candidate_isolation as ci
    return ci.LEFTOVER_POLLER_CHECK


def test_ordinary_isolation_runs_no_poller_or_leftover_steps(tmp_path):
    import candidate_isolation as ci
    _, cfg = load()
    run = make(cfg)
    run.rn, run.out = SwitchRunner(), (lambda *a, **k: None)
    run.check_leftover_poller('teardown'); run.stop_poller('x'); run.start_poller('x', '/r/out')
    assert run.rn.calls == [] and run.soft_failures == []
    assert ci.POLLER_MAX_DURATION_S == 180


def test_wait_start_refuses_an_incomplete_first_sample_and_terminates_the_poller(tmp_path):
    sleeper = subprocess.Popen(['sleep', '30'])
    try:
        (tmp_path / 'p.pid').write_text('%d\n' % sleeper.pid)
        first = dp.sample(FakeSwitch(fail={('outcomes', 3)}), 0, clock=counter())
        (tmp_path / 'p.jsonl').write_text(json.dumps(first) + '\n')
        assert dp.wait_start(args(tmp_path, timeout_s=2.0)) == 1
        assert sleeper.wait(timeout=10) == -signal.SIGTERM
    finally:
        if sleeper.poll() is None:
            sleeper.kill()


def test_sample_problems_names_every_missing_value():
    assert dp.sample_problems(dp.sample(FakeSwitch(), 0, clock=counter())) == []
    record = dp.sample(FakeSwitch(), 0, clock=counter())
    for change, problem in ((lambda r: r['outcomes'].__setitem__(4, None), 'outcomes incomplete'),
                            (lambda r: r['pktgen']['OPERATE'].update(pkt_counter=None), 'pktgen counters incomplete'),
                            (lambda r: r.update(t_gen_alloc=None), 'registers missing: t_gen_alloc'),
                            (lambda r: r['errors'].update(x='y'), "errors: ['x']")):
        bad = copy.deepcopy(record); change(bad)
        assert problem in dp.sample_problems(bad)


def detached(tmp_path, code):
    """A process reparented away from pytest (so it is reaped, never a zombie), as the harness launches the poller."""
    import shlex
    pid_file = tmp_path / 'p.pid'
    subprocess.run(['bash', '-c', '(%s -c %s > /dev/null 2>&1 < /dev/null & echo $! > %s)'
                    % (shlex.quote(sys.executable), shlex.quote(code), shlex.quote(str(pid_file)))], check=True,
                   timeout=30)
    return int(pid_file.read_text())


@pytest.mark.parametrize('code,ended_by', [
    ('import time\ntime.sleep(60)', 'sigterm'),                                                   # default SIGTERM
    ('import signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\ntime.sleep(60)', 'sigkill')])
def test_stop_escalates_from_the_stop_file_to_sigterm_to_sigkill_and_says_which_worked(tmp_path, code, ended_by,
                                                                                        capsys):
    pid = detached(tmp_path, code)
    try:
        import time
        time.sleep(0.3)                                               # let the ignoring handler install
        assert dp.stop_poller(args(tmp_path, timeout_s=0.4)) == 1     # no summary line: not a clean stop
        report = json.loads(capsys.readouterr().out)
        assert report['ended_by'] == ended_by and report['exited'] is True and report['stopped'] is False
        assert (tmp_path / 'p.stop').exists()
    finally:
        if dp._alive(pid):
            os.kill(pid, signal.SIGKILL)


def test_poller_never_samples_back_to_back(tmp_path, restore_sigterm):
    a = args(tmp_path)
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 3:
            Path(a.stop_file).touch()
    # each clock read advances 0.2 s: every sample overruns the 0.1 s period
    assert dp.poll(a, connect=lambda *_: FakeSwitch(), clock=counter(step=200_000_000), sleep=sleep) == 0
    assert sleeps == [dp.MIN_SLEEP_S] * 3 and dp.MIN_SLEEP_S == 0.05


# ---------------------------------------------------------------- control monitor and permit

def control_permit(m4, **change):
    import candidate_isolation as ci
    _, _, drain = w2.snapshots(m4)
    values = dict(before=copy.deepcopy(drain), polls=[drain], population=w2.m5_population(),
                  drained_tick_ns=w2.READY + 3_000_000_000, pause_deadline_ns=w2.READY + 20_000_000_000)
    values.update(change)
    return ci.control_permit_conditions(**values)


def test_control_permit_requires_drain_and_unchanged_authority_but_not_old_arrivals(m4):
    assert control_permit(m4) == []                       # drained at readiness: no arrival, no rejection needed
    _, mid, drain = w2.snapshots(m4)
    assert any('not drained' in f for f in control_permit(m4, polls=[mid]))
    moved = copy.deepcopy(drain); s3.set_register(moved, 'p1.t_Ingress.gen_alloc_reg', 99)
    assert any('authority changed at poll00' in f for f in control_permit(m4, polls=[moved]))
    owner = copy.deepcopy(drain); s3.set_register(owner, 'p0.n_Ingress.owner', (5 << 16) | 3)
    assert any('owner is not the current connection' in f for f in control_permit(m4, before=owner, polls=[owner]))
    assert any('before the c2 pause deadline' in f for f in
               control_permit(m4, drained_tick_ns=w2.READY + 20_000_000_000))
    assert control_permit(m4, polls=[]) == ['permit: no quiet poll observed']
    # the isolation conditions refuse the same drained-at-readiness state (no old arrival after readiness)
    _, _, drain = w2.snapshots(m4)
    assert any('no old READ token arrived' in f for f in tw.permit_conditions(
        copy.deepcopy(drain), [drain], w2.m5_population(), w2.READY + 3_000_000_000, w2.READY + 4_000_000_000,
        w2.READY + 20_000_000_000))


@pytest.fixture(scope='module')
def m4():
    return s3.run(s3.M4)


def monitor(mode, m4, tmp_path, polls, ticks, **vision_kwargs):
    _, cfg = load(mode)
    run = make(cfg)
    marker = dict(tcp_open=True, opens=1, pre_read_grace_ms=run.pause_ms, pre_read_ready_ns=w2.READY,
                  first_read_issued_ns=0)
    done = threading.Event()
    vision = w2.PermitVision(marker, w2.READY - tw.C1_TO_C2_READY_MIN_NS, [w2.READY + t for t in ticks],
                             tmp_path / 'proc', done, runs=tmp_path / 'runs', **vision_kwargs)
    run.rn, run.root, run.active_unit = vision, str(tmp_path), (run.units()[0], 0, w2.LABEL)
    if mode == 'isolation':
        run.window.update(delay_remote='/snap/delay.json', delay_time=1.0)
    queue = list(polls)

    def queued(label, suffix):
        vision.calls.append(('switch', 'quiet snapshot ' + suffix, '', 0))
        return queue.pop(0)
    run.quiet_snapshot = queued
    steps = []

    def step(where, label, cmd, cwd=None, check=True, timeout=3600):
        steps.append((where, label, cmd, timeout))
        return vision.run(where, cmd, label=label)
    run.step = step
    run.monitor(done)
    return run, vision, steps, tmp_path / 'runs' / w2.LABEL / 'c2' / 'pre_read_permit.json'


def test_control_monitor_grants_on_drain_without_restore_or_early_drain_abort(m4, tmp_path):
    _, _, drain = w2.snapshots(m4)
    run, vision, steps, permit = monitor('control', m4, tmp_path, [copy.deepcopy(drain), drain], [3_000_000_000],
                                         vision_clock=w2.vision_clock(3_500_000_000))
    assert run.window['monitor_ok'] is True, run.window.get('error')
    assert run.window['permit_conditions'] == dict(ok=True, failures=[])
    assert json.loads(permit.read_text())['granted_ns'] == w2.READY + 3_500_000_000
    labels = [s[1] for s in steps] + [c[1] for c in vision.calls]
    assert not any(label and ('restore' in label or label.startswith('collect token')) for label in labels)
    assert 'restored_vision_ns' not in run.window and vision.aborts == []
    assert run.window['runtime_slack_ns'] == 20_000_000_000 - tw.RESTORE_ALLOWANCE_NS - tw.ABORT_MARGIN_NS - \
        3_000_000_000
    marker = run.window['diagnostic_permit_marker']
    assert marker['granted_vision_ns'] == w2.READY + 3_500_000_000 and marker['poller'] is True


def test_isolation_mode_still_aborts_when_c2_is_ready_after_every_old_token(m4, tmp_path):
    _, _, drain = w2.snapshots(m4)
    run, vision, steps, permit = monitor('isolation', m4, tmp_path, [copy.deepcopy(drain), drain], [3_000_000_000])
    assert run.window['monitor_ok'] is False and 'c2 became ready after all old tokens' in run.window['error']
    assert not permit.exists() and run.window['c2_abort_confirmed'] is True


def test_control_monitor_withholds_the_permit_when_authority_moves(m4, tmp_path):
    _, _, drain = w2.snapshots(m4)
    moved = copy.deepcopy(drain); s3.set_register(moved, 'p1.t_Ingress.op_gen_alloc_reg', 99)
    run, vision, steps, permit = monitor('control', m4, tmp_path, [copy.deepcopy(drain), moved], [3_000_000_000],
                                         vision_clock=w2.vision_clock(3_500_000_000))
    assert run.window['monitor_ok'] is False and 'c2 permit withheld' in run.window['error']
    assert vision.grants == [] and not permit.exists() and run.window['c2_abort_confirmed'] is True


# ---------------------------------------------------------------- verdict: labelled diagnostic, never qualification

def _diag_verdict_inprocess(tmp_path, mode, incomplete):
    """The retained candidate61 verdict harness (test_stale_isolation_s3) with the diagnostic section added and the
    poller unit state injected immediately before verdict()."""
    import candidate_isolation as ci
    load_config = ci.base.load_config

    def diagnostic_config(path):
        cfg = load_config(path)
        cfg.update(purpose='diagnostic', diagnostic=dict(poller=True, period_s=0.1, mode=mode))
        return cfg
    ci.base.load_config = diagnostic_config
    verdict = ci.TokenIsolationCampaign.verdict

    def with_unit(self, trial, rec, label, *rest):
        self.record['c3_diagnostic']['units'][label] = dict(diagnostic_incomplete=incomplete,
                                                            incomplete_reasons=['test'] if incomplete else [])
        return verdict(self, trial, rec, label, *rest)
    ci.TokenIsolationCampaign.verdict = with_unit
    return s3._c61_verdict_inprocess(tmp_path)


def diag_verdict(tmp_path, mode, incomplete=False):
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    code = ('import json,sys; sys.path.insert(0,%r); import test_c3_diagnostic as t; from pathlib import Path; '
            'print(json.dumps(t._diag_verdict_inprocess(Path(%r),%r,%r)))'
            % (str(Path(__file__).parent), str(tmp_path), mode, incomplete))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), timeout=300)
    assert result.returncode == 0, result.stderr[-3000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize('mode', ['isolation', 'control'])
def test_diagnostic_verdict_is_labelled_and_never_qualification(tmp_path, mode):
    trial, isolation = diag_verdict(tmp_path, mode)
    assert isolation['ok'] is True, isolation['failures']
    assert isolation['purpose'] == 'diagnostic' and isolation['qualification'] is False
    assert isolation['precision_qualified'] is False and isolation['separate_from_precision'] is True
    assert isolation['diagnostic']['mode'] == mode and isolation['diagnostic']['counted_as_qualification'] is False
    assert trial['purpose'] == 'diagnostic' and trial['qualification'] is False
    assert trial['observed']['precision_qualified'] is False
    assert trial['scenario']['policy'] == 'c3_diagnostic_' + mode
    if mode == 'control':
        for key in ('cleanup', 'restore', 'old_token_window'):
            assert isolation[key]['not_applicable'] is True and isolation[key]['failures'] == []
        assert isolation['old_rejection_delta'] is None
        comparison = isolation['diagnostic']['control_rejection_comparison']
        assert comparison['gated'] is False and set(comparison['quiet_rejections']) == {'6', '14', '23', '24'}
        assert isolation['quiet_rejections'] == comparison['quiet_rejections']
    else:
        assert isolation['cleanup']['ok'] and isolation['restore']['ok'] and isolation['old_token_window']['ok']


def test_incomplete_poller_evidence_fails_the_diagnostic_verdict(tmp_path):
    trial, isolation = diag_verdict(tmp_path, 'isolation', incomplete=True)
    assert isolation['ok'] is False and 'diagnostic incomplete: test' in isolation['failures']
    assert trial['ok'] is False and isolation['qualification'] is False

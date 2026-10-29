"""E4b SELECT without OPERATE: guarded workload, endpoint plumbing and campaign controls (offline; no socket, SSH, BFRT
client or process is opened).

With traffic.sbo_select_only absent every command, argument, record and workload output stays byte-identical. The
golden values were recorded from commit ca0db02d1, before the select-only path existed, with the repository path
replaced by <ROOT>; the unit-call goldens are also checked against test_diag_runtime's own, which embed the main
checkout path.
"""
import contextlib
import copy
import hashlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]
import campaign  # noqa: E402
import campaign_base  # noqa: E402
import relay_master  # noqa: E402
import vision_run  # noqa: E402
import test_diag_runtime as diag  # noqa: E402  (shared offline fakes and the pre-existing goldens)
from dnp3_codec import FUNC_OPERATE, FUNC_SELECT, parse_frame  # noqa: E402
from session import Outcome, OUTCOME_NOT_ATTEMPTED  # noqa: E402

MAIN_CHECKOUT = '/home/philip/Projects/DNP3'
GOLDEN_WORKLOAD = {
    'sbo64_mixed_full': ('1ba362b89cd7a4c7a9f4c366e0265826d6f9053b6ee9a43d23821eb045348d0f',
                         'e568a93807c14fb363a2341f69003e9b06f4fdc12d5cd2213885caf04921e18a'),
    'sbo4_full': ('07b3c2732a64cd82ec24d687013336ab7b12402c5a34c08d5e54582e2b4cac59',
                  '7e3bb907b46c5c46ce675a12ad044f50da0c24f62c728a269af6709c00398f9e'),
    'run_sbo_end_full': ('1cb163bbdb09784139e9acfe8ddf5c874c3ea33857bc0048163c43fba61408e6',
                         'da4b5b1becd61e5e5222d45b449533eeebed395dffdfd96f3ce10b0d418dc97a'),
    'no_sbo': ('b2995ec22d24ac3d9585c31883068891a8f5db275c11eb219ebc7a859684ece6',
               'fd8e621b71367b27ce78b577d2035e2309d15a6eb46ee12877956e9efe1232d0')}
NORMAL_WORKLOADS = {'sbo64_mixed_full': dict(reads=65, schedule='mixed_full', sbo_cycles=64),
                    'sbo4_full': dict(reads=20, schedule='full', sbo_cycles=4),
                    'run_sbo_end_full': dict(reads=20, schedule='full'),
                    'no_sbo': dict(reads=8, schedule='mixed_full', run_sbo=False)}
GOLDEN_UNIT_CALLS = {'Campaign': '102dac9e1fbd355c5ca1942ab3e46e7a1bc468b7eaaed275dd754241bd74e986',
                     'CandidateCampaign': '142afa870cc9fbd9ccc452006328ccb6274114fedacb8843dc2ed0bf6005254d'}
GOLDEN_TRIAL_RECORD = {'Campaign': '818ca5dc7795580eea616de23b6a2aafb7c5eb0812cf4d60d969ee877e81655a',
                       'CandidateCampaign': 'bab1fc4ab166761b878d0211113fd66182b76c4f7d957932ecd6dcbbc6eaa134'}
GOLDEN_ENDPOINT_CONTROLS = dict(read_pause_ms=25, run_sbo=True, close_grace_ms=0, sbo_cycles=64,
                                read_schedule='mixed_full')
# vision_run.main -> run_connection keyword arguments at ca0db02d1
GOLDEN_RUN_CONNECTION_KWARGS = ['endpoint_binary_name', 'endpoint_profile', 'mirror_iface', 'pad_expect',
                                'qualify_capture', 'read_schedule', 'relay_close_mode', 'sbo_cycles', 'db']


def h(value):
    return hashlib.sha256(json.dumps(value, default=str).encode()).hexdigest()


def normalized(value, root=ROOT, to='<ROOT>'):
    return json.loads(json.dumps(value).replace(str(root), to))


# ----------------------------------------------------------------------------------------------- relay_master
class Fakes:
    """relay_master's process boundary: Session, socket options and sleeps, recorded. select/read outcomes and the
    OPERATE stub the SBO driver returns can be replaced to probe failure paths."""

    def __init__(self, monkeypatch, select_outcome='OK', select_status='SUCCESS', fail_read=None, operate_stub=None):
        self.log, fakes = [], self
        self.reads = 0

        class Sock:
            def setsockopt(self, *args):
                fakes.log.append(['setsockopt'] + list(args))

        class FakeSession:
            def __init__(self, host, port, source_address=None):
                fakes.log.append(['session', host, port, list(source_address)])
                self.sock = Sock()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                fakes.log.append(['close'])
                return False

            def transaction(self, **kw):
                fakes.log.append(['tx', kw['operation'], kw['function'], kw['app_seq'], kw['frame'].hex(), sorted(kw)])
                outcome, points = 'OK', []
                if kw['operation'] == 'READ':
                    fakes.reads += 1
                    if fail_read is not None and fakes.reads == fail_read:
                        outcome = 'TIMEOUT'
                else:
                    status = select_status if kw['operation'] == 'SELECT' else 'SUCCESS'
                    points = [(1, status), (3, status)]
                    outcome = select_outcome if kw['operation'] == 'SELECT' else 'OK'
                return Outcome(operation=kw['operation'], function=kw['function'], app_seq=kw['app_seq'] & 15,
                               outcome=outcome, request_wire_hex=kw['frame'].hex(), points=points)

        monkeypatch.setattr(relay_master, 'Session', FakeSession)
        monkeypatch.setattr(relay_master.time, 'sleep', lambda seconds: self.log.append(['sleep', seconds]))
        monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
        self.sbo_calls = []
        real = relay_master.one_sbo

        def one_sbo(*args):
            self.sbo_calls.append(args[-1])
            selected, operated = real(*args)
            return selected, (operate_stub if operate_stub is not None else operated)
        monkeypatch.setattr(relay_master, 'one_sbo', one_sbo)

    def functions(self):
        """DNP3 application function of every frame handed to a transaction, decoded from its bytes."""
        out = []
        for entry in self.log:
            if entry[0] == 'tx':
                frame, rest = parse_frame(bytes.fromhex(entry[4]))
                assert frame is not None and not rest
                out.append(frame.user_data[2])
        return out


E4B = dict(reads=20, schedule='full', sbo_cycles=4, select_only=True)


def test_select_only_workload_sends_no_operate_and_plans_operate_zero(monkeypatch):
    fakes = Fakes(monkeypatch)
    result = relay_master.workload(60000, **E4B)
    sent = [entry[1] for entry in fakes.log if entry[0] == 'tx']
    assert sent == ['READ', 'SELECT'] * 4 + ['READ'] * 16
    assert FUNC_OPERATE not in fakes.functions() and fakes.functions().count(FUNC_SELECT) == 4
    assert fakes.sbo_calls == [True] * 4                     # the existing sbo_driver select-only mode
    assert result['planned'] == result['counts'] == dict(READ=20, SELECT=4, OPERATE=0)
    assert result['ok'] is True and result['sbo_select_only'] is True and result['sbo_cycles'] == 4
    assert [r['operation'] for r in result['records']] == ['READ', 'SELECT'] * 4 + ['READ'] * 16
    selects = [entry for entry in fakes.log if entry[0] == 'tx' and entry[1] == 'SELECT']
    assert all('require_success' in entry[5] and 'expect_points' in entry[5] for entry in selects)


@pytest.mark.parametrize('probe', [dict(select_outcome='INVALID', select_status='TIMEOUT'),
                                   dict(select_outcome='TIMEOUT'), dict(fail_read=2)])
def test_a_failed_select_or_a_failed_read_after_it_fails_the_select_only_workload(monkeypatch, probe):
    fakes = Fakes(monkeypatch, **probe)
    result = relay_master.workload(60000, **E4B)
    assert result['ok'] is False and result['counts'] != result['planned']
    assert result['planned'] == dict(READ=20, SELECT=4, OPERATE=0)
    assert FUNC_OPERATE not in fakes.functions()


def test_an_operate_returned_as_sent_fails_the_select_only_workload_and_is_recorded(monkeypatch):
    sent = Outcome(operation='OPERATE', function=FUNC_OPERATE, app_seq=2, outcome='OK', request_wire_hex='0564')
    Fakes(monkeypatch, operate_stub=sent)
    result = relay_master.workload(60000, **E4B)
    assert result['ok'] is False
    assert [r['operation'] for r in result['records']].count('OPERATE') == 1


def test_select_only_stub_from_the_driver_is_not_attempted_and_unsent(monkeypatch):
    stubs = []
    real = relay_master.one_sbo
    Fakes(monkeypatch)

    def one_sbo(*args):
        pair = real(*args)
        stubs.append(pair[1])
        return pair
    monkeypatch.setattr(relay_master, 'one_sbo', one_sbo)
    assert relay_master.workload(60000, **E4B)['ok'] is True
    assert [(s.outcome, s.request_wire_hex, s.t_send) for s in stubs] == [(OUTCOME_NOT_ATTEMPTED, '', None)] * 4


@pytest.mark.parametrize('kwargs', [dict(sbo_cycles=0), dict(run_sbo=False), dict(select_only=1),
                                    dict(select_only='yes')])
def test_select_only_needs_an_explicit_true_with_sbo_cycles(monkeypatch, kwargs):
    fakes = Fakes(monkeypatch)
    with pytest.raises(ValueError, match='select-only'):
        relay_master.workload(60000, **dict(E4B, **kwargs))
    assert fakes.log == []                                   # refused before any session


@pytest.mark.parametrize('name', sorted(NORMAL_WORKLOADS))
@pytest.mark.parametrize('explicit', [False, True])
def test_normal_workload_output_and_requests_are_byte_identical(monkeypatch, name, explicit):
    fakes = Fakes(monkeypatch)
    kwargs = dict(NORMAL_WORKLOADS[name], **({'select_only': False} if explicit else {}))
    result = relay_master.workload(60000, **kwargs)
    assert (h(result), h(fakes.log)) == GOLDEN_WORKLOAD[name]
    assert 'sbo_select_only' not in result


# ------------------------------------------------------------------------------------------------- vision_run
def capture_workload(monkeypatch):
    seen = []

    def workload(*args, **kwargs):
        seen.append((args, kwargs))
        return dict(ok=True, records=[])
    monkeypatch.setattr(relay_master, 'workload', workload)
    return seen


def test_relay_connection_without_select_only_is_unchanged(monkeypatch, tmp_path):
    fakes = diag.VisionFakes(monkeypatch, tmp_path / 'run')
    result = vision_run.run_relay_connection(str(tmp_path / 'run'), 'fixture', 60000, 3, run_sbo=False,
                                             read_schedule='mixed_full')
    assert fakes.normalized() == diag.GOLDEN_VISION_LOG
    assert result['endpoint_controls'] == dict(read_pause_ms=25, run_sbo=False, close_grace_ms=0)


def test_relay_connection_passes_select_only_to_the_workload_and_records_it(monkeypatch, tmp_path):
    diag.VisionFakes(monkeypatch, tmp_path / 'run')
    seen = capture_workload(monkeypatch)
    result = vision_run.run_relay_connection(str(tmp_path / 'run'), 'fixture', 60000, 20, run_sbo=True, sbo_cycles=4,
                                             read_schedule='full', select_only=True)
    assert result['ok'] is True
    ((args, kwargs),) = seen
    assert args == (60000, 20) and kwargs['select_only'] is True and kwargs['sbo_cycles'] == 4
    assert sorted(kwargs) == sorted(diag.WORKLOAD_KWARGS + ['select_only'])
    assert result['endpoint_controls'] == dict(read_pause_ms=25, run_sbo=True, close_grace_ms=0, sbo_select_only=True)
    assert json.loads((tmp_path / 'run/result.json').read_text())['endpoint_controls']['sbo_select_only'] is True


def vision_main(monkeypatch, argv, authorize=None):
    seen = []
    if authorize is None:
        monkeypatch.setattr(vision_run, 'authorize_relay_run', lambda _a: None)
    monkeypatch.setattr(vision_run, 'run_connection', lambda *args, **kwargs: seen.append(kwargs) or dict(ok=True))
    monkeypatch.setattr(sys, 'argv', ['vision_run.py'] + argv)
    with contextlib.redirect_stdout(io.StringIO()), pytest.raises(SystemExit) as done:
        vision_run.main()
    return done.value.code, seen


def test_vision_main_without_the_flag_passes_exactly_todays_arguments(monkeypatch):
    for extra in ([], ['--sbo-select-only', '0']):
        code, seen = vision_main(monkeypatch, ['run', 'lbl', '--master-port', '60000'] + extra)
        assert code == 0 and sorted(seen[0]) == sorted(GOLDEN_RUN_CONNECTION_KWARGS)


def test_vision_main_passes_select_only_with_sbo_cycles(monkeypatch):
    code, seen = vision_main(monkeypatch, ['run', 'lbl', '--master-port', '60000', '--reads', '20',
                                           '--sbo-cycles', '4', '--sbo-select-only', '1'])
    assert code == 0 and seen[0]['sbo_select_only'] is True and seen[0]['sbo_cycles'] == 4


@pytest.mark.parametrize('argv', [
    ['setup', '--sbo-select-only', '1'],
    ['run', 'lbl', '--master-port', '60000', '--reads', '20', '--sbo-cycles', '4', '--sbo-select-only', '1',
     '--scenario', 'reconnect'],
    ['run', 'lbl', '--master-port', '60000', '--reads', '20', '--sbo-cycles', '4', '--sbo-select-only', '1',
     '--scenario', 'persistence'],
    ['run', 'lbl', '--master-port', '60000', '--reads', '20', '--sbo-cycles', '4', '--sbo-select-only', '1',
     '--drop', 'select_resp_padded:1'],
    ['run', 'lbl', '--master-port', '60000', '--reads', '20', '--sbo-cycles', '4', '--sbo-select-only', '1',
     '--event-clear'],
])
def test_vision_main_refuses_select_only_outside_one_plain_run(monkeypatch, argv):
    monkeypatch.setattr(vision_run, 'authorize_relay_run', lambda _a: pytest.fail('authorized before refusal'))
    monkeypatch.setattr(vision_run, 'run_connection', lambda *a, **k: pytest.fail('ran'))
    monkeypatch.setattr(sys, 'argv', ['vision_run.py'] + argv)
    with pytest.raises(SystemExit) as refused:
        vision_run.main()
    assert '--sbo-select-only' in str(refused.value.code)


@pytest.mark.parametrize('extra', [['--reads', '20'], ['--reads', '20', '--sbo-cycles', '4', '--run-sbo', '0'],
                                   ['--reads', '20', '--sbo-cycles', '4', '--sbo-select-only', '2']])
def test_authorization_refuses_select_only_without_guarded_sbo_cycles(monkeypatch, extra):
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    monkeypatch.setattr(vision_run, 'run_connection', lambda *a, **k: pytest.fail('ran'))
    monkeypatch.setattr(sys, 'argv', ['vision_run.py', 'run', 'lbl', '--master-port', '60000',
                                      '--sbo-select-only', '1'] + extra)
    with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as refused:
        vision_run.main()
    assert refused.value.code not in (0, None)


# --------------------------------------------------------------------------------------------------- campaign
def e4b_config(select_only=True):
    cfg = diag.c72_config()
    cfg['traffic']['sbo_cycles'] = 4
    cfg['trials']['reads_per_trial'] = 20
    if select_only:
        cfg['traffic']['sbo_select_only'] = True
    return cfg


@pytest.mark.parametrize('change', [
    lambda t: t.update(sbo_select_only=False), lambda t: t.update(sbo_select_only=1),
    lambda t: t.update(sbo_select_only='true'), lambda t: t.pop('sbo_cycles'),
])
def test_campaign_refuses_a_select_only_declaration_that_is_not_explicit_and_complete(change):
    cfg = e4b_config()
    change(cfg['traffic'])
    with pytest.raises(ValueError, match='sbo_select_only'):
        campaign_base.validate_profile(cfg)


def test_campaign_refuses_select_only_with_loss_or_scenarios():
    cfg = e4b_config()
    cfg['loss']['presets'] = {'x': [{'class': 'select_resp_padded', 'n': 1, 'target': 'identity'}]}
    with pytest.raises(ValueError, match='sbo_cycles'):
        campaign_base.validate_profile(cfg)
    cfg = e4b_config()
    cfg['scenarios'] = {'reconnect': {'arm': 'off', 'fixture': 'physical_relay', 'reconnect_port_offset': 1}}
    with pytest.raises(ValueError, match='sbo_cycles'):
        campaign_base.Campaign(cfg, campaign_base.DryRunner(), 'offline_fixture', scenario='reconnect')


@pytest.mark.parametrize('cls', [campaign_base.Campaign, campaign.CandidateCampaign])
def test_absent_select_only_unit_commands_and_records_are_byte_identical(cls):
    c, calls = diag.dry_unit(cls, diag.c72_config())
    assert h(normalized(calls)) == GOLDEN_UNIT_CALLS[cls.__name__]
    assert hashlib.sha256(json.dumps(normalized(calls, to=MAIN_CHECKOUT)).encode()).hexdigest() == \
        diag.GOLDEN_UNIT_CALLS_SHA[cls.__name__]
    assert h(normalized(c.record)) == GOLDEN_TRIAL_RECORD[cls.__name__]
    assert c.endpoint_controls() == GOLDEN_ENDPOINT_CONTROLS
    assert [cmd for where, cmd in calls if where == 'vision'] == [diag.GOLDEN_VISION_CMD]


@pytest.mark.parametrize('cls', [campaign_base.Campaign, campaign.CandidateCampaign])
def test_select_only_unit_adds_only_the_endpoint_flag(cls):
    _c, plain = diag.dry_unit(cls, e4b_config(select_only=False))
    c, select_only = diag.dry_unit(cls, e4b_config())
    assert len(plain) == len(select_only)
    for (where, before), (where_after, after) in zip(plain, select_only):
        assert where == where_after
        if 'vision_run.py run ' in before:
            assert ' --sbo-cycles 4 ' in before
            assert after == before.replace(' --sbo-cycles 4 ', ' --sbo-cycles 4 --sbo-select-only 1 ')
        else:
            assert after == before
    assert c.endpoint_controls()['sbo_select_only'] is True


def verdict_fixture(monkeypatch, tmp_path, cfg):
    c = campaign_base.Campaign(cfg, campaign_base.ShellRunner(cfg['hosts']), 'offline_fixture')
    dest = tmp_path / 'trial'
    (dest / 'snapshots').mkdir(parents=True)
    plan = dict(READ=20, **campaign_base.checks.planned_controls(cfg['traffic']))
    (dest / 'master.json').write_text(json.dumps(dict(ok=True, counts=plan, records=[])))
    seen = dict(analyze=[], switch=[])
    import relay_check
    monkeypatch.setattr(relay_check, 'analyze', lambda *args, **kwargs: seen['analyze'].append((args, kwargs)) or
                        dict(packets={}, failures=[], exchanges=[]))
    monkeypatch.setattr(relay_check, 'visible_clrt', lambda _report: {})
    monkeypatch.setattr(c, 'validate_standards_file', lambda *_args, **_kwargs: [])
    monkeypatch.setattr(campaign_base.checks, 'load_evidence_files', lambda **_kwargs: {})
    monkeypatch.setattr(campaign_base.checks, 'evaluate_switch',
                        lambda *args, **kwargs: seen['switch'].append((args, kwargs)) or ([], {}))
    trial = dict(label='t', master_port=60000, reads=20, failures=[], ok=False)
    c.relay_verdict(trial, {}, 't', str(dest), campaign_base.Result(0, '', ''), c.arms[-1], 'physical_relay')
    return trial, seen


def test_select_only_verdict_plans_zero_operate_for_wire_master_and_switch(monkeypatch, tmp_path):
    trial, seen = verdict_fixture(monkeypatch, tmp_path, e4b_config())
    ((args, kwargs),) = seen['analyze']
    assert args[2] == dict(READ=20, SELECT=4, OPERATE=0) and kwargs == dict(select_only=True)
    ((_args, switch),) = seen['switch']
    assert switch['sbo_count'] == 4 and switch['operate_count'] == 0
    assert trial['ok'] is True and trial['observed']['connections']['single']['master_acceptance'] is True


def test_normal_verdict_keeps_todays_relay_check_call(monkeypatch, tmp_path):
    trial, seen = verdict_fixture(monkeypatch, tmp_path, e4b_config(select_only=False))
    ((args, kwargs),) = seen['analyze']
    assert args[2] == dict(READ=20, SELECT=4, OPERATE=4) and kwargs == {}
    ((_args, switch),) = seen['switch']
    assert switch['sbo_count'] == 4 and switch['operate_count'] == 4
    assert trial['ok'] is True


def test_generation_reserve_for_select_only_stays_the_conservative_pair_budget():
    """The headroom reserve is a safety budget, not a checker denominator: it keeps reads + 2 x SELECT for a
    select-only plan, 4 generations per connection more than the reads + SELECT the switch will allocate."""
    c = campaign.CandidateCampaign(e4b_config(), campaign_base.DryRunner(), 'offline_fixture')
    reserve, budget = c._headroom_reserve({'reads': 20}, {'build': 'current', 'T': 1})
    assert budget['read_lane_per_connection'] == 20 + 2 * 4 >= 20 + 4
    assert reserve == {'read': 28 + 2 + 16}


def test_select_only_endpoint_controls_reach_the_effective_record():
    c = campaign_base.Campaign(copy.deepcopy(e4b_config()), campaign_base.DryRunner(), 'offline_fixture')
    assert dict(c.cfg['traffic'], **c.endpoint_controls())['sbo_select_only'] is True
    assert c.endpoint_control_args().endswith(' --sbo-cycles 4 --sbo-select-only 1 --read-schedule mixed_full')


def test_the_changed_workload_and_checkers_are_in_the_relay_checker_closure():
    """Their hashes bind every future standards verdict (a new checker identity); retained verdicts replay from git."""
    names = {os.path.relpath(path, ROOT) for path in campaign_base.relay_checker_files()}
    assert {'scripts/hardware/relay_master.py', 'scripts/checks/checks.py', 'scripts/checks/relay_check.py',
            'scripts/checks/standards.py'} <= names


def test_the_campaign_vision_command_reaches_the_workload_as_select_only(monkeypatch):
    """The exact command the campaign generates, parsed and authorized by vision_run.main (no capture or socket)."""
    import shlex
    _c, calls = diag.dry_unit(campaign.CandidateCampaign, e4b_config())
    (command,) = [cmd for where, cmd in calls if where == 'vision' and 'vision_run.py run ' in cmd]
    argv = shlex.split(command)
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')       # restored after; --apply sets it during main()
    code, seen = vision_main(monkeypatch, argv[argv.index('run'):], authorize='real')
    assert code == 0 and seen[0]['sbo_select_only'] is True and seen[0]['sbo_cycles'] == 4
    assert seen[0]['read_schedule'] == 'mixed_full' and argv[argv.index('--reads') + 1] == '20'


@pytest.mark.parametrize('select_only', [True, False])
def test_run_connection_passes_select_only_to_the_relay_connection(monkeypatch, select_only):
    # review M1: the hop run_connection -> run_relay_connection carries the flag (and nothing when it is off)
    seen = {}
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    monkeypatch.setattr(vision_run, 'run_relay_connection', lambda *args, **kwargs: seen.update(kwargs) or {})
    vision_run.run_connection('/nonexistent', 'label', 60160, 20, None, 0, 0, 0, sbo_cycles=4,
                              sbo_select_only=select_only)
    assert seen.get('select_only') is (True if select_only else None)
    assert seen['sbo_cycles'] == 4

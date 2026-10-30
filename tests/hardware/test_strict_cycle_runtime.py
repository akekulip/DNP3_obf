"""Strict-cycle workload ([READ mixed, SELECT, OPERATE, READ integrity] x N), endpoint plumbing and campaign controls
(offline; no socket, SSH, BFRT client or process is opened).

With traffic.sbo_strict_cycle absent every command, argument, record and workload output stays byte-identical: the
goldens are test_e4b_select_only_runtime's and test_diag_runtime's, recorded before the strict path existed.
"""
import contextlib
import copy
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]
import campaign  # noqa: E402
import campaign_base  # noqa: E402
import relay_check  # noqa: E402
import relay_master  # noqa: E402
import standards  # noqa: E402
import vision_run  # noqa: E402
import test_diag_runtime as diag  # noqa: E402
import test_e4b_select_only_runtime as e4b  # noqa: E402
from dnp3_codec import FUNC_OPERATE, FUNC_READ, FUNC_SELECT  # noqa: E402

STRICT = dict(reads=8, schedule='mixed_full', sbo_cycles=4, strict_cycle=True)
CYCLE = [('READ', 'mixed'), ('SELECT', None), ('OPERATE', None), ('READ', 'integrity')]


def sent(fakes):
    return [entry[1] for entry in fakes.log if entry[0] == 'tx']


# ----------------------------------------------------------------------------------------------- relay_master
def test_strict_workload_sends_read_select_operate_read_per_cycle(monkeypatch):
    fakes = e4b.Fakes(monkeypatch)
    result = relay_master.workload(60000, **STRICT)
    assert sent(fakes) == ['READ', 'SELECT', 'OPERATE', 'READ'] * 4
    assert fakes.functions() == [FUNC_READ, FUNC_SELECT, FUNC_OPERATE, FUNC_READ] * 4
    assert [(r['operation'], r.get('workload')) for r in result['records']] == CYCLE * 4
    assert [entry[3] for entry in fakes.log if entry[0] == 'tx'] == list(range(16))     # app_seq = index & 15
    assert fakes.sbo_calls == [False] * 4                       # the normal SELECT -> OPERATE driver
    assert result['planned'] == result['counts'] == dict(READ=8, SELECT=4, OPERATE=4)
    assert result['ok'] is True and result['sbo_strict_cycle'] is True and result['sbo_cycles'] == 4


def test_strict_workload_of_the_registered_size_wraps_the_sequence_in_order(monkeypatch):
    fakes = e4b.Fakes(monkeypatch)
    result = relay_master.workload(60000, reads=64, schedule='mixed_full', sbo_cycles=32, strict_cycle=True)
    assert sent(fakes) == ['READ', 'SELECT', 'OPERATE', 'READ'] * 32
    assert [entry[3] for entry in fakes.log if entry[0] == 'tx'] == [i & 15 for i in range(128)]
    assert result['ok'] is True and result['counts'] == dict(READ=64, SELECT=32, OPERATE=32)


def test_philips_stub_reproduction_passes_counts_and_fails_the_strict_plan(monkeypatch):
    """Today's workload with reads 2N and sbo_cycles N: mixed,S,O,integrity,S,O,mixed,integrity, ok=True."""
    fakes = e4b.Fakes(monkeypatch)
    result = relay_master.workload(60000, reads=4, schedule='mixed_full', sbo_cycles=2)
    assert [(r['operation'], r.get('workload')) for r in result['records']] == \
        CYCLE + [('SELECT', None), ('OPERATE', None), ('READ', 'mixed'), ('READ', 'integrity')]
    assert result['ok'] is True and sent(fakes).count('SELECT') == 2       # counts alone pass
    findings = relay_check.master_checks(result, 60000, dict(READ=4, SELECT=2, OPERATE=2), 'mixed_full',
                                         strict_cycle=True)
    assert relay_check.STRICT_CYCLE + 'the master did not run the strict-cycle workload' in findings
    assert any(f.startswith(relay_check.STRICT_CYCLE + 'master record sequence') for f in findings), findings
    flagged = dict(result, sbo_strict_cycle=True)                 # the order fails even with the flag
    assert any(f.startswith(relay_check.STRICT_CYCLE + 'master record sequence') for f in
               relay_check.master_checks(flagged, 60000, dict(READ=4, SELECT=2, OPERATE=2), 'mixed_full',
                                         strict_cycle=True))


@pytest.mark.parametrize('probe,stop', [(dict(select_outcome='INVALID', select_status='TIMEOUT'), 2),
                                        (dict(fail_read=2), 4)])
def test_a_failure_stops_the_strict_workload(monkeypatch, probe, stop):
    fakes = e4b.Fakes(monkeypatch, **probe)
    result = relay_master.workload(60000, **STRICT)
    assert result['ok'] is False and len(sent(fakes)) == stop


@pytest.mark.parametrize('kwargs', [dict(strict_cycle=1), dict(strict_cycle='yes'), dict(schedule='full'),
                                    dict(schedule='mixed'), dict(run_sbo=False), dict(reads=7), dict(reads=9),
                                    dict(sbo_cycles=0), dict(select_only=True)])
def test_strict_workload_refuses_bad_arguments_before_any_session(monkeypatch, kwargs):
    fakes = e4b.Fakes(monkeypatch)
    with pytest.raises(ValueError, match='strict'):
        relay_master.workload(60000, **dict(STRICT, **kwargs))
    assert fakes.log == []


@pytest.mark.parametrize('name', sorted(e4b.NORMAL_WORKLOADS))
def test_normal_workload_with_an_explicit_false_is_byte_identical(monkeypatch, name):
    fakes = e4b.Fakes(monkeypatch)
    result = relay_master.workload(60000, **dict(e4b.NORMAL_WORKLOADS[name], strict_cycle=False))
    assert (e4b.h(result), e4b.h(fakes.log)) == e4b.GOLDEN_WORKLOAD[name]
    assert 'sbo_strict_cycle' not in result


# ------------------------------------------------------------------------------------------------- vision_run
def test_relay_connection_passes_strict_cycle_to_the_workload_and_records_it(monkeypatch, tmp_path):
    diag.VisionFakes(monkeypatch, tmp_path / 'run')
    seen = e4b.capture_workload(monkeypatch)
    result = vision_run.run_relay_connection(str(tmp_path / 'run'), 'fixture', 60000, 64, run_sbo=True,
                                             sbo_cycles=32, read_schedule='mixed_full', strict_cycle=True)
    ((args, kwargs),) = seen
    assert args == (60000, 64) and kwargs['strict_cycle'] is True and kwargs['sbo_cycles'] == 32
    assert sorted(kwargs) == sorted(diag.WORKLOAD_KWARGS + ['strict_cycle'])
    assert result['endpoint_controls'] == dict(read_pause_ms=25, run_sbo=True, close_grace_ms=0,
                                               sbo_strict_cycle=True)
    assert json.loads((tmp_path / 'run/result.json').read_text())['endpoint_controls']['sbo_strict_cycle'] is True


def test_relay_connection_without_strict_cycle_is_unchanged(monkeypatch, tmp_path):
    diag.VisionFakes(monkeypatch, tmp_path / 'run')
    seen = e4b.capture_workload(monkeypatch)
    result = vision_run.run_relay_connection(str(tmp_path / 'run'), 'fixture', 60000, 64, run_sbo=True,
                                             sbo_cycles=32, read_schedule='mixed_full')
    ((_args, kwargs),) = seen
    assert sorted(kwargs) == sorted(diag.WORKLOAD_KWARGS) and 'sbo_strict_cycle' not in result['endpoint_controls']


@pytest.mark.parametrize('strict', [True, False])
def test_run_connection_passes_strict_cycle_to_the_relay_connection(monkeypatch, strict):
    seen = {}
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    monkeypatch.setattr(vision_run, 'run_relay_connection', lambda *args, **kwargs: seen.update(kwargs) or {})
    vision_run.run_connection('/nonexistent', 'label', 60170, 64, None, 0, 0, 0, sbo_cycles=32,
                              sbo_strict_cycle=strict)
    assert seen.get('strict_cycle') is (True if strict else None) and seen['sbo_cycles'] == 32


STRICT_ARGV = ['run', 'lbl', '--master-port', '60000', '--reads', '64', '--sbo-cycles', '32', '--read-schedule',
               'mixed_full']


def test_vision_main_without_the_flag_passes_exactly_todays_arguments(monkeypatch):
    for extra in ([], ['--sbo-strict-cycle', '0']):
        code, seen = e4b.vision_main(monkeypatch, ['run', 'lbl', '--master-port', '60000'] + extra)
        assert code == 0 and sorted(seen[0]) == sorted(e4b.GOLDEN_RUN_CONNECTION_KWARGS)


def test_vision_main_passes_strict_cycle_only_when_set(monkeypatch):
    code, seen = e4b.vision_main(monkeypatch, STRICT_ARGV + ['--sbo-strict-cycle', '1'])
    assert code == 0 and seen[0]['sbo_strict_cycle'] is True and seen[0]['sbo_cycles'] == 32


@pytest.mark.parametrize('extra', [['--scenario', 'reconnect'], ['--scenario', 'persistence'],
                                   ['--drop', 'select_resp_padded:1'], ['--event-clear']])
def test_vision_main_refuses_strict_cycle_outside_one_plain_run(monkeypatch, extra):
    monkeypatch.setattr(vision_run, 'authorize_relay_run', lambda _a: pytest.fail('authorized before refusal'))
    monkeypatch.setattr(vision_run, 'run_connection', lambda *a, **k: pytest.fail('ran'))
    for argv in (STRICT_ARGV + ['--sbo-strict-cycle', '1'] + extra, ['setup', '--sbo-strict-cycle', '1']):
        monkeypatch.setattr(sys, 'argv', ['vision_run.py'] + argv)
        with pytest.raises(SystemExit) as refused:
            vision_run.main()
        assert '--sbo-strict-cycle' in str(refused.value.code)


@pytest.mark.parametrize('change', [
    lambda a: a.__setitem__(a.index('64'), '63'), lambda a: a.__setitem__(a.index('mixed_full'), 'full'),
    lambda a: a.extend(['--run-sbo', '0']), lambda a: a.extend(['--sbo-select-only', '1']),
    lambda a: a.__delitem__(slice(a.index('--read-schedule'), a.index('--read-schedule') + 2)),
])
def test_authorization_refuses_strict_cycle_without_its_complete_shape(monkeypatch, change):
    argv = list(STRICT_ARGV) + ['--sbo-strict-cycle', '1']
    change(argv)
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    monkeypatch.setattr(vision_run, 'run_connection', lambda *a, **k: pytest.fail('ran'))
    monkeypatch.setattr(sys, 'argv', ['vision_run.py'] + argv)
    with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as refused:
        vision_run.main()
    code = refused.value.code                     # an authorization refusal (a message), not an argparse error
    assert isinstance(code, str) and ('strict' in code or 'invalid guarded SBO controls' in code), code


def test_authorization_accepts_the_registered_strict_shape(monkeypatch):
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    code, seen = e4b.vision_main(monkeypatch, STRICT_ARGV + ['--sbo-strict-cycle', '1'], authorize='real')
    assert code == 0 and seen[0]['sbo_strict_cycle'] is True


# --------------------------------------------------------------------------------------------------- campaign
def strict_config(strict=True):
    cfg = diag.c72_config()
    cfg['traffic']['sbo_cycles'] = 32
    cfg['trials']['reads_per_trial'] = 64
    if strict:
        cfg['traffic']['sbo_strict_cycle'] = True
    return cfg


@pytest.mark.parametrize('change', [
    lambda c: c['traffic'].update(sbo_strict_cycle=False), lambda c: c['traffic'].update(sbo_strict_cycle=1),
    lambda c: c['traffic'].update(sbo_strict_cycle='true'), lambda c: c['traffic'].pop('sbo_cycles'),
    lambda c: c['traffic'].update(read_schedule='full'), lambda c: c['traffic'].update(sbo_select_only=True),
    lambda c: c['trials'].update(reads_per_trial=65),
])
def test_campaign_refuses_a_strict_declaration_that_is_not_explicit_and_complete(change):
    cfg = strict_config()
    change(cfg)
    with pytest.raises(ValueError, match='sbo_strict_cycle'):
        campaign_base.validate_profile(cfg)


def test_campaign_accepts_the_registered_strict_shape():
    campaign_base.validate_profile(strict_config())


@pytest.mark.parametrize('cls', [campaign_base.Campaign, campaign.CandidateCampaign])
def test_strict_unit_adds_only_the_endpoint_flag(cls):
    _c, plain = diag.dry_unit(cls, strict_config(strict=False))
    c, strict = diag.dry_unit(cls, strict_config())
    assert len(plain) == len(strict)
    for (where, before), (where_after, after) in zip(plain, strict):
        assert where == where_after
        if 'vision_run.py run ' in before:
            assert after == before.replace(' --sbo-cycles 32 ', ' --sbo-cycles 32 --sbo-strict-cycle 1 ')
        else:
            assert after == before
    assert c.endpoint_controls()['sbo_strict_cycle'] is True
    assert c.endpoint_control_args().endswith(' --sbo-cycles 32 --sbo-strict-cycle 1 --read-schedule mixed_full')


def test_absent_strict_cycle_keeps_the_endpoint_controls():
    c = campaign_base.Campaign(diag.c72_config(), campaign_base.DryRunner(), 'offline_fixture')
    assert c.endpoint_controls() == e4b.GOLDEN_ENDPOINT_CONTROLS


@pytest.mark.parametrize('padding', [1, 0])
def test_strict_verdict_passes_the_strict_plan_and_the_arm_image_to_relay_check(monkeypatch, tmp_path, padding):
    cfg = strict_config()
    cfg['arms'][-1]['padding'] = padding
    trial, seen = e4b.verdict_fixture(monkeypatch, tmp_path, cfg)
    ((args, kwargs),) = seen['analyze']
    assert args[2] == dict(READ=20, SELECT=32, OPERATE=32)
    assert kwargs == dict(strict_cycle=True, images=standards.SEL751_IMAGES[bool(padding)])


def test_normal_verdict_keeps_todays_relay_check_call(monkeypatch, tmp_path):
    _trial, seen = e4b.verdict_fixture(monkeypatch, tmp_path, strict_config(strict=False))
    ((_args, kwargs),) = seen['analyze']
    assert kwargs == {}


def test_the_campaign_vision_command_reaches_the_workload_as_strict(monkeypatch):
    import shlex
    _c, calls = diag.dry_unit(campaign.CandidateCampaign, strict_config())
    (command,) = [cmd for where, cmd in calls if where == 'vision' and 'vision_run.py run ' in cmd]
    argv = shlex.split(command)
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    code, seen = e4b.vision_main(monkeypatch, argv[argv.index('run'):], authorize='real')
    assert code == 0 and seen[0]['sbo_strict_cycle'] is True and seen[0]['sbo_cycles'] == 32
    assert seen[0]['read_schedule'] == 'mixed_full' and argv[argv.index('--reads') + 1] == '64'


def test_strict_endpoint_controls_reach_the_effective_record():
    c = campaign_base.Campaign(copy.deepcopy(strict_config()), campaign_base.DryRunner(), 'offline_fixture')
    assert c.endpoint_controls()['sbo_strict_cycle'] is True
    assert dict(c.cfg['traffic'], **c.endpoint_controls())['sbo_strict_cycle'] is True

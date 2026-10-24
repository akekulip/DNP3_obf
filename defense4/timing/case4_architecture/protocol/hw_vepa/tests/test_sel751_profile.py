import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import campaign as cp


def config():
    cfg = json.loads((HERE / 'campaign.json').read_text())
    cfg.update(endpoint_profile='sel751')
    cfg['endpoints'] = dict(master_ip='192.168.10.1', outstation_ip='192.168.10.7',
                            outstation_port=20000, read_src=1, read_dst=0)
    cfg['ports_map'].update(master_dev=9, relay_dev=64)
    cfg['endpoint'] = dict(master='active_harness', points=[1, 3], code=1, count=1, on_ms=200, off_ms=0)
    return cfg


def test_sel751_has_no_software_binary_identity_requirement():
    cfg = config()
    cfg['builds'] = {}
    cfg['arms'] = []
    assert cp.check_bindings(cfg) == []


@pytest.mark.parametrize('section,key,value', [('endpoints', 'outstation_ip', '192.168.10.62'),
    ('endpoints', 'master_ip', '192.168.10.61'), ('endpoints', 'read_src', 9),
    ('ports_map', 'relay_dev', 9), ('endpoint', 'points', [1, 2]), ('endpoint', 'on_ms', 1)])
def test_relay_binding_rejects_arbitrary_destinations_and_commands(section, key, value):
    cfg = config()
    cfg[section][key] = value
    with pytest.raises(ValueError):
        cp.validate_endpoint_profile(cfg)


def test_relay_control_args_select_explicit_runner_branch():
    campaign = cp.Campaign(config(), cp.DryRunner(), 'offline_relay')
    assert '--endpoint-profile sel751' in campaign.endpoint_control_args()
    assert campaign.endpoint_binary_arg() == ''


def test_relay_master_failed_select_never_sends_operate(monkeypatch):
    import relay_master
    from session import Outcome
    calls = []
    class FakeSession:
        def __init__(self, *args, **kwargs):
            assert args == ('192.168.10.7', 20000)
            assert kwargs['source_address'] == ('192.168.10.1', 59410)
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def transaction(self, **kwargs):
            calls.append(kwargs['operation'])
            return Outcome(operation=kwargs['operation'], function=kwargs['function'],
                           app_seq=kwargs['app_seq'], outcome='INVALID' if kwargs['operation'] == 'SELECT' else 'OK')
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    monkeypatch.setattr(relay_master, 'Session', FakeSession)
    rec = relay_master.workload(59410, 1, read_pause_ms=0)
    assert not rec['ok']
    assert calls == ['READ', 'SELECT']


def test_vision_runner_has_physical_branch_without_server_or_sysctl(monkeypatch, tmp_path):
    import vision_run as vr
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED', '1')
    sentinel = {'ok': True}
    monkeypatch.setattr(vr, 'run_relay_connection', lambda *a, **kw: sentinel)
    assert vr.run_connection(str(tmp_path / 'fresh'), 'fresh', 59410, 1, 8, 0, 0, 1,
                             endpoint_profile='sel751') is sentinel


def test_relay_profile_accepts_actual_49_byte_control_shape_and_rejects_software_shape():
    sys.path.insert(0, str(HERE.parents[1] / 'integration/evidence/rearm_01/hw'))
    import candidate_campaign as cc
    encoding = dict(native_input_octets=dict(READ=[91, 134], SELECT=49, OPERATE=49),
                    read_images={'91': 141, '134': 158}, read_output_octets=[141, 158])
    assert cc._native_inputs_supported(encoding, endpoint_profile='sel751')
    encoding['native_input_octets']['SELECT'] = 37
    assert not cc._native_inputs_supported(encoding, endpoint_profile='sel751')


def test_failed_capture_restore_requires_independent_feature_match_and_can_recover(monkeypatch, tmp_path):
    import vision_run as vr
    import capture_observation as co
    import types
    sys.path.insert(0, str(HERE.parents[1] / 'integration/evidence/rearm_01/hw'))
    import restore_verify as rv
    state = dict(gro=True, fail_restore=False)
    def run(command):
        if command[1] == '-k':
            return types.SimpleNamespace(returncode=0, stdout='generic-receive-offload: %s\n' %
                                         ('on' if state['gro'] else 'off'), stderr='')
        if command[-1] == 'on' and state['fail_restore']:
            return types.SimpleNamespace(returncode=1, stdout='', stderr='restore rejected')
        state['gro'] = command[-1] == 'on'
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')
    baseline_path = tmp_path / 'baseline.json'
    baseline = vr.relay_offload_lifecycle('setup', baseline_path, run=run)
    state['fail_restore'] = True
    with pytest.raises(RuntimeError, match='restore'):
        with co.offload_capture_context(tmp_path / 'capture', run=run):
            pass
    assert baseline_path.exists()
    assert rv.offload_failures(run(['ethtool', '-k']).stdout, baseline)
    failed = vr.relay_offload_lifecycle('restore', baseline_path, run=run)
    assert failed['errors']
    assert baseline_path.exists()
    state['fail_restore'] = False
    restored = vr.relay_offload_lifecycle('restore', baseline_path, run=run)
    assert restored['errors'] == []
    assert rv.offload_failures(run(['ethtool', '-k']).stdout, baseline) == []


def test_relay_preflight_validates_frozen_frames_without_opening_socket(monkeypatch):
    import relay_master
    import socket
    def forbidden(*args, **kwargs):
        raise AssertionError('preflight must not create a socket')
    monkeypatch.setattr(socket, 'socket', forbidden)
    result = relay_master.preflight()
    assert result['ok']
    assert result['control_request_lengths'] == [45, 45]


def test_reconnect_preserves_physical_profile_on_all_three_connections(monkeypatch, tmp_path):
    import vision_run as vr
    monkeypatch.setattr(vr, 'RUNS', str(tmp_path))
    monkeypatch.setattr(vr, 'state', lambda: 'unchanged state')
    calls = []
    def connection(*args, **kwargs):
        calls.append(kwargs)
        return dict(ok=True, master_rc=0)
    monkeypatch.setattr(vr, 'run_connection', connection)
    result = vr.run_reconnect('physical_reconnect', 59410, 59411, 20, 8, 0, 0, 1,
                              read_schedule='mixed_full', endpoint_profile='sel751')
    assert result['ok']
    assert len(calls) == 3
    assert all(call['endpoint_profile'] == 'sel751' for call in calls)


def test_physical_reconnect_runs_all_planned_connections_after_application_failures(monkeypatch, tmp_path):
    import vision_run as vr
    monkeypatch.setattr(vr, 'RUNS', str(tmp_path))
    monkeypatch.setattr(vr, 'state', lambda: 'original state')
    calls = []
    def connection(*args, **kwargs):
        calls.append(kwargs['endpoint_profile'])
        return dict(ok=False, master_rc=1, error='application timeout')
    monkeypatch.setattr(vr, 'run_connection', connection)
    result = vr.run_reconnect('all_attempted', 59410, 59411, 20, 8, 0, 0, 1,
                             read_schedule='mixed_full', endpoint_profile='sel751')
    assert calls == ['sel751', 'sel751', 'sel751']
    assert result['planned_connections'] == result['attempted_connections'] == 3
    assert result['completed_connections'] == 0
    assert not result['ok']


def test_no_apply_or_environment_refuses_before_capture_or_socket(monkeypatch, tmp_path):
    import vision_run as vr
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED', raising=False)
    def forbidden(*args, **kwargs):
        raise AssertionError('unauthorized physical entry must not reach capture/socket')
    monkeypatch.setattr(vr, 'run_relay_connection', forbidden)
    with pytest.raises(ValueError, match='authorization'):
        vr.run_connection(str(tmp_path / 'refused'), 'refused', 59410, 2, 8, 0, 0, 1,
                          endpoint_profile='sel751')
    assert not (tmp_path / 'refused').exists()


def test_explicit_apply_authorizes_only_validated_physical_application_entry(monkeypatch):
    import vision_run as vr
    from types import SimpleNamespace
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED', raising=False)
    args = SimpleNamespace(endpoint_profile='sel751', mode='run', apply=False, label='guarded', master_port=59410,
           reads=2, sbo_cycles=0, read_schedule='mixed_full', run_sbo=1, gap_ms=0, read_pause_ms=25,
           close_grace_ms=0, endpoint_binary=None, pad_expect=None, drop=None)
    with pytest.raises(ValueError, match='authorization'):
        vr.authorize_relay_run(args)
    args.apply = True
    vr.authorize_relay_run(args)
    assert __import__('os').environ['DEFENSE4_HW_AUTHORIZED'] == '1'
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED')
    args.endpoint_profile = 'software'
    with pytest.raises(ValueError):
        vr.authorize_relay_run(args)
    assert 'DEFENSE4_HW_AUTHORIZED' not in __import__('os').environ


def test_physical_persistence_executes_three_same_tuple_connections(monkeypatch, tmp_path):
    import vision_run as vr
    monkeypatch.setattr(vr, 'RUNS', str(tmp_path))
    monkeypatch.setattr(vr, 'state', lambda: 'original state')
    calls = []
    def connection(*args, **kwargs):
        calls.append((args, kwargs))
        return dict(ok=True, master_rc=0)
    monkeypatch.setattr(vr, 'run_connection', connection)
    result = vr.run_relay_series('physical_persistence', 59410, 20, 'rst', 1000, 'mixed_full')
    assert result['ok']
    assert len(calls) == 3
    assert all(args[2] == 59410 and kwargs['endpoint_profile'] == 'sel751' and
               kwargs['relay_close_mode'] == 'rst' for args, kwargs in calls)


def test_passive_close_capture_waits_for_final_ack_without_sending(monkeypatch, tmp_path):
    import vision_run as vr
    import wire_check as wc
    polls = [0]
    def segment(src, dst, sport, dport, flags, seq, ack):
        return dict(src=src, dst=dst, sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, len=0)
    def parse(path):
        if str(path).endswith('out.pcap'):
            polls[0] += 1
            packets = [segment('192.168.10.1', '192.168.10.7', 59410, 20000, 17, 100, 200)]
            if polls[0] > 1:
                packets.append(segment('192.168.10.1', '192.168.10.7', 59410, 20000, 16, 101, 201))
            return packets, 'us'
        return [segment('192.168.10.7', '192.168.10.1', 20000, 59410, 17, 200, 101)], 'us'
    monkeypatch.setattr(wc, 'parse', parse)
    monkeypatch.setattr(vr.time, 'sleep', lambda seconds: None)
    monkeypatch.setattr(vr.subprocess, 'Popen', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('no send/process allowed')))
    result = vr.wait_relay_close(tmp_path, 59410, 'graceful')
    assert result['complete'] and result['polls'] == 2


@pytest.mark.parametrize('scenario', ['persistence', 'reconnect'])
def test_capture_error_with_failed_structured_restore_stops_further_connections(monkeypatch, tmp_path, scenario):
    import vision_run as vr
    monkeypatch.setattr(vr, 'RUNS', str(tmp_path))
    monkeypatch.setattr(vr, 'state', lambda: 'original state')
    calls = []
    def connection(*args, **kwargs):
        calls.append(args[0])
        directory = Path(args[0])
        directory.mkdir()
        (directory / 'capture_offloads.json').write_text(json.dumps(dict(restore_ok=False)))
        raise RuntimeError('capture command failed')
    monkeypatch.setattr(vr, 'run_connection', connection)
    if scenario == 'persistence':
        result = vr.run_relay_series('unsafe_capture', 59410, 20, 'graceful', 0, 'mixed_full')
    else:
        result = vr.run_reconnect('unsafe_capture', 59410, 59411, 20, 8, 0, 0, 1,
                                  endpoint_profile='sel751', qualify_capture=True)
    assert len(calls) == 1
    assert result['planned_connections'] == 3 and result['attempted_connections'] == 1
    assert result['connections']['c2']['ran'] is False

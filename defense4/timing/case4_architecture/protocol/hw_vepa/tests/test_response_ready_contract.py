"""Offline installer and qualification contracts for response-ready timing."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest
import relay_check

ARCH = Path(__file__).resolve().parents[3]
BASE_HW = ARCH / 'integration/core/response_only/hw'
sys.path.insert(0, str(BASE_HW))
import t_config as tc


def test_response_wait_timeout_has_exactly_one_units_conversion():
    values = dict(gap=5_000_000, op_j=2_400_000, response_wait_timeout=500_000_000, budget=240000, enabled=1)
    assert tc.t_units(values, unit_ns=256, grid_ns=512)['response_wait_timeout'] == 1953127
    op = tc.params_op(values)
    assert dict(op['data']) == values
    assert tc.check_params(values) == []


@pytest.mark.parametrize('obsolete', ['da', 'readiness', 'cap', 'pb'])
def test_response_ready_rejects_mixed_parameter_contract(obsolete):
    values = dict(gap=5_000_000, op_j=2_400_000, response_wait_timeout=500_000_000, budget=240000, enabled=1)
    values[obsolete] = 10_000_000
    assert tc.check_params(values)
    with pytest.raises(ValueError):
        tc.params_op(values)


def test_response_ready_precision_qualifies_read_workloads_separately():
    rows = [dict(operation=op, workload=workload, piggyback=False, complete_clrt_us=5001)
            for op, workload, n in [('READ', 'mixed', 33), ('READ', 'integrity', 32),
                                    ('SELECT', None, 64), ('OPERATE', None, 64)] for _ in range(n)]
    result = relay_check.precision(dict(exchanges=rows), 5_000_000, split_reads=True)
    assert set(result) == {'READ mixed', 'READ integrity', 'SELECT', 'OPERATE'}
    assert all(v['pass_'] for v in result.values())
    assert result['READ integrity']['planned'] == 32
    # Combining READ classes must never hide an undersampled class.
    rows = [row for row in rows if row['workload'] != 'integrity'] + [
        dict(operation='READ', workload='integrity', piggyback=False, complete_clrt_us=5001)]
    assert not relay_check.precision(dict(exchanges=rows), 5_000_000, split_reads=True)['READ integrity']['pass_']


def test_response_ready_load_config_and_installer_command(tmp_path):
    import campaign
    path = ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/config/rc01_m12p_c52_sdk9132_sel751_reference.json'
    cfg = json.loads(path.read_text())
    cfg['timing_contract'] = 'response_ready_ack_d_v1'
    cfg['timing_params_ns'] = dict(gap=5_000_000, op_j=2_400_000, response_wait_timeout=500_000_000,
                                   budget=240000, enabled=1)
    for build in cfg['builds'].values():
        build['timing_contract'] = cfg['timing_contract']
        build['piggyback_bound'] = False
    dest = tmp_path / 'config.json'
    dest.write_text(json.dumps(cfg))
    loaded = campaign.load_config(dest)
    runner = campaign.Campaign(loaded, campaign.DryRunner(), 'response_ready_offline')
    name = next(iter(cfg['builds']))
    runner.bound = {name: {}}
    command = runner.installer_cmd(name, 1, '/offline/out', 59410)
    assert '--t-response-wait-timeout 500000000' in command
    assert '--t-gap 5000000' in command
    assert all(flag not in command for flag in ('--t-da ', '--t-readiness ', '--t-cap ', '--t-pb '))


def load_installer():
    spec = importlib.util.spec_from_file_location('response_ready_installer_test', BASE_HW / 'bringup_composite.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_installer_selects_compiled_contract_and_rejects_obsolete_explicit_args(tmp_path):
    installer = load_installer()
    source = '// timing_contract: response_ready_ack_d_v1\n' \
             'action set_params(bit<32> gap, bit<32> op_j, bit<32> response_wait_timeout, bit<32> budget, bit<8> enabled) {}\n' \
             'md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe;'
    (tmp_path / 'response_only.p4pp').write_text(source)
    args = ['--build-out', str(tmp_path), '--master-port', '59410', '--t-response-wait-timeout', '500000000']
    a = installer.parse(args)
    op = installer.dataplane_params_op(a)
    assert op['values_ns'] == tc.RESPONSE_READY_DEFAULTS
    assert dict(op['data']) == tc.t_units(tc.RESPONSE_READY_DEFAULTS, unit_ns=256, grid_ns=512)
    for flag in ('--t-da', '--t-readiness', '--t-cap', '--t-pb'):
        with pytest.raises(ValueError, match='obsolete'):
            installer.dataplane_params_op(installer.parse(args + [flag, '10000000']))
    (tmp_path / 'response_only.p4pp').write_text('action set_params(bit<32> da) {}')
    with pytest.raises(ValueError, match='contract'):
        installer.dataplane_params_op(installer.parse(args))


def test_response_ready_configs_preserve_references_smoke_and_identity_loss():
    spec = importlib.util.spec_from_file_location('ready_config_test', ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/make_sel751_configs.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for block in ('smoke', 'reference', 'loss_mixed_950', 'loss_full_950', 'persistence_graceful_950',
                  'persistence_rst_950', 'reconnect_950'):
        template = 'reference' if block == 'smoke' else block
        cfg = mod.relay_config(json.loads((mod.HERE / ('config/rc01_m12p_c29_sdk9132_%s.json' % template)).read_text()))
        mod.response_ready_config(cfg, block, 20 if block != 'smoke' else 5)
        assert cfg['timing_contract'] == 'response_ready_ack_d_v1'
        assert set(cfg['timing_params_ns']) == set(tc.RESPONSE_READY_KEYS)
        assert cfg['evaluation']['host_precision_gated'] is True
        assert cfg['qualification_dimensions']['operate_j'] == 'unproven_by_user_choice'
        if block == 'smoke':
            assert [a['name'] for a in cfg['arms']] == ['combined']
            assert cfg['traffic']['sbo_cycles'] == 1
            assert cfg['evaluation']['campaign_block']['expected_exchanges'] == 4
        elif block == 'reference':
            assert cfg['evaluation']['campaign_block']['expected_exchanges'] == 772
            assert cfg['trials']['reads_per_trial'] == 65
            assert cfg['traffic']['sbo_cycles'] == 64
        else:
            assert [a['name'] for a in cfg['arms']] == ['combined']
            if block.startswith('loss_'):
                assert sum(map(len, cfg['loss']['presets'].values())) == 7
                assert all(e['target'] == 'identity' for entries in cfg['loss']['presets'].values() for e in entries)


def test_response_ready_snapshot_expiry_names_are_mandatory_and_fail_qualification():
    import copy
    import checks
    from test_checks import EXP, evidence
    ev = evidence()
    for snapshot in (ev['before'], ev['after']):
        snapshot['outcomes']['OUT_WAIT_EXPIRED'] = snapshot['outcomes'].pop('OUT_ACK_FALLBACK')
        snapshot['outcomes']['OUT_EXPIRED_DROP'] = snapshot['outcomes'].pop('OUT_RESP_FALLBACK')
        snapshot['outcomes']['OUT_REQ_BYPASS'] = 0
    fails, observed = checks.evaluate_switch(EXP, dict(T=1, padding=1), 10, ev,
                                             timing_contract='response_ready_ack_d_v1')
    assert not fails
    assert observed['waiting_expired'] == 0
    ev['after']['outcomes']['OUT_WAIT_EXPIRED'] = 1
    fails, observed = checks.evaluate_switch(EXP, dict(T=1, padding=1), 10, ev,
                                             timing_contract='response_ready_ack_d_v1')
    assert any('OUT_WAIT_EXPIRED' in failure for failure in fails)
    del ev['after']['outcomes']['OUT_EXPIRED_DROP']
    fails, _ = checks.evaluate_switch(EXP, dict(T=1, padding=1), 10, ev,
                                     timing_contract='response_ready_ack_d_v1')
    assert fails


def test_response_ready_manifest_defaults_exclude_superseded_stress(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('ready_manifest_test', ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/make_hw_manifest.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    root = tmp_path / 'hw'
    configs = root / 'config'
    configs.mkdir(parents=True)
    expected = ['smoke', 'reference', 'persistence_graceful_950', 'persistence_rst_950',
                'loss_mixed_950', 'loss_full_950', 'reconnect_950']
    for name in expected:
        cfg = dict(endpoint_profile='sel751', timing_contract='response_ready_ack_d_v1', evidence_dir=str(tmp_path),
                   evaluation=dict(arm_order=['combined'], campaign_block=dict(tool='candidate_campaign', arguments=[])))
        (configs / ('rc01_c53_sel751_d20_%s.json' % name)).write_text(json.dumps(cfg))
    frozen = tmp_path / 'freeze.json'
    frozen.write_text('{}')
    monkeypatch.setattr(mod, 'HERE', root)
    monkeypatch.chdir(tmp_path)
    mod.main(['--build', 'c53', '--endpoint-profile', 'sel751', '--config-tag', 'd20',
              '--config-dir', 'hw/config', str(frozen), 'ready'])
    result = json.loads((tmp_path / 'evidence/hw_campaigns/ready.manifest.json').read_text())
    assert [s['id'] for s in result['steps']] == ['ready_' + name for name in expected]
    assert all('held_operate_350' not in str(s) for s in result['steps'])
    assert all(Path(s['argv'][4]).is_absolute() for s in result['steps'])


def test_precision_retains_frozen_plan_and_both_response_boundaries():
    rows = [dict(operation='READ', workload='mixed', piggyback=False, first_clrt_us=4999,
                 complete_clrt_us=5001) for _ in range(32)]
    result = relay_check.precision(dict(exchanges=rows), 5000000, split_reads=True,
                                   planned={'READ mixed': 33, 'READ integrity': 32, 'SELECT': 64, 'OPERATE': 64})
    assert result['READ mixed']['planned'] == 33
    assert result['READ mixed']['eligible'] == 32
    assert not result['READ mixed']['pass_']
    assert result['READ mixed']['first_clrt_us']['max'] == 4999
    assert result['READ mixed']['complete_clrt_us']['max'] == 5001


@pytest.mark.parametrize('reference', [True, False])
def test_physical_verdict_keeps_j_unproven_and_limits_sample_gate_to_reference(tmp_path, monkeypatch, reference):
    import campaign
    import checks
    cfg = json.loads((ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/config/rc01_m12p_c52_sdk9132_sel751_reference.json').read_text())
    cfg['timing_contract'] = 'response_ready_ack_d_v1'
    cfg['qualification_dimensions'] = dict(operate_j='unproven_by_user_choice')
    cfg['evaluation']['campaign_block']['precision_reference'] = reference
    cfg['timing_params_ns'] = dict(tc.RESPONSE_READY_DEFAULTS)
    reads, sbo = (65, 64) if reference else (2, 1)
    cfg['traffic']['sbo_cycles'] = sbo
    rows, records = [], []
    for operation, n in [('READ', reads), ('SELECT', sbo), ('OPERATE', sbo)]:
        for i in range(n):
            workload = ('mixed' if i % 2 == 0 else 'integrity') if operation == 'READ' else None
            rows.append(dict(operation=operation, workload=workload, piggyback=False, first_clrt_us=5050,
                             complete_clrt_us=5050))
            size = (141 if workload == 'mixed' else 158) if operation == 'READ' else 60
            records.append(dict(operation=operation, workload=workload, response_wire_hex='00' * size))
    (tmp_path / 'master.json').write_text(json.dumps(dict(ok=True, records=records,
                            counts=dict(READ=reads, SELECT=sbo, OPERATE=sbo))))
    report = dict(ok=True, failures=[], exchanges=rows, packets={})
    monkeypatch.setattr(relay_check, 'analyze', lambda *args: report)
    monkeypatch.setattr(checks, 'load_evidence_files', lambda **kwargs: {})
    monkeypatch.setattr(checks, 'evaluate_switch', lambda *args, **kwargs: ([], {}))
    runner = campaign.Campaign(cfg, campaign.DryRunner(), 'offline_dimensions')
    runner.rn.dry = False
    arm = next(a for a in cfg['arms'] if a['name'] == 'combined')
    trial = dict(reads=reads, master_port=59410)
    from types import SimpleNamespace
    runner.relay_verdict(trial, {}, 'offline', str(tmp_path), SimpleNamespace(rc=0), arm, 'physical_relay')
    assert trial['ok'] and not trial['failures']
    assert trial['dimension_verdicts']['operate_j'] == 'unproven'
    assert trial['observed']['connections']['single']['timing_gated'] is reference
    if reference:
        assert trial['dimension_verdicts']['timing'] is True
    else:
        assert trial['dimension_verdicts']['timing'] == 'not_qualified_recovery_or_smoke'
        assert not trial['observed']['connections']['single']['precision']['OPERATE']['pass_']


@pytest.mark.parametrize('bad_snapshot,bad_value', [('before', None), ('after', None), ('after', True),
                                                  ('after', -1), ('after', 'missing'), ('after', 8)])
def test_response_ready_installed_timing_requires_readable_zero_request_bypass(bad_snapshot, bad_value):
    import checks
    from test_checks import EXP, evidence
    ev = evidence()
    for snapshot in (ev['before'], ev['after']):
        snapshot['outcomes']['OUT_WAIT_EXPIRED'] = snapshot['outcomes'].pop('OUT_ACK_FALLBACK')
        snapshot['outcomes']['OUT_EXPIRED_DROP'] = snapshot['outcomes'].pop('OUT_RESP_FALLBACK')
        snapshot['outcomes']['OUT_REQ_BYPASS'] = 7
    if bad_value == 'missing':
        del ev[bad_snapshot]['outcomes']['OUT_REQ_BYPASS']
    else:
        ev[bad_snapshot]['outcomes']['OUT_REQ_BYPASS'] = bad_value
    failures, _ = checks.evaluate_switch(EXP, dict(T=1, padding=1), 10, ev,
                                         timing_contract='response_ready_ack_d_v1')
    assert any('OUT_REQ_BYPASS' in failure for failure in failures)


@pytest.mark.parametrize('timed,installed_reads', [(False, 10), (True, 0)])
def test_response_ready_request_bypass_gate_preserves_off_and_native_only(timed, installed_reads):
    import checks
    from test_checks import EXP, evidence
    # An unknown-port-only connection contributes no installed READ/SBO timing events.
    ev = evidence(T=0)
    for snapshot in (ev['before'], ev['after']):
        snapshot['outcomes']['OUT_WAIT_EXPIRED'] = snapshot['outcomes'].pop('OUT_ACK_FALLBACK')
        snapshot['outcomes']['OUT_EXPIRED_DROP'] = snapshot['outcomes'].pop('OUT_RESP_FALLBACK')
    ev['after']['outcomes']['OUT_REQ_BYPASS'] = 1
    failures, _ = checks.evaluate_switch(EXP, dict(T=int(timed), padding=1), installed_reads, ev,
                                         sbo_count=0 if timed else 1, timing_contract='response_ready_ack_d_v1')
    assert not failures


@pytest.mark.parametrize('flag', ['--t-g', '--t-read'])
def test_installer_rejects_abbreviated_timing_flags(tmp_path, flag):
    installer = load_installer()
    with pytest.raises(SystemExit) as error:
        installer.parse(['--build-out', str(tmp_path), '--master-port', '59410', flag, '20000000'])
    assert error.value.code == 2


@pytest.mark.parametrize('references,selected', [(['reference_rest'], 'reference_rest'),
                                                (['reference', 'reference_rest'], 'reference')])
def test_manifest_tagged_reference_defaults_resolve_relative_config_paths(tmp_path, monkeypatch, references, selected):
    spec = importlib.util.spec_from_file_location('ready_split_manifest_test', ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/make_hw_manifest.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    root = tmp_path / 'hw'
    configs = root / 'config'
    configs.mkdir(parents=True)
    for name in references:
        cfg = dict(endpoint_profile='sel751', timing_contract='response_ready_ack_d_v1', evidence_dir=str(tmp_path),
                   evaluation=dict(arm_order=['timing_only', 'combined'],
                                   campaign_block=dict(tool='candidate_campaign', arguments=[])))
        (configs / ('rc01_selected_sel751_d10_%s.json' % name)).write_text(json.dumps(cfg))
    frozen = tmp_path / 'freeze.json'
    frozen.write_text('{}')
    monkeypatch.setattr(mod, 'HERE', root)
    monkeypatch.chdir(tmp_path)
    mod.main(['--build', 'selected', '--config-tag', 'd10', '--config-dir', 'hw/config',
              str(frozen), 'split_default'])
    result = json.loads((tmp_path / 'evidence/hw_campaigns/split_default.manifest.json').read_text())
    assert [s['id'] for s in result['steps']] == ['split_default_' + selected]
    step = result['steps'][0]
    assert Path(step['argv'][4]).is_absolute()
    assert Path(step['argv'][4]).is_file()
    assert step['argv'][-4:] == ['--arms', 'timing_only,combined', '--fixtures', 'physical_relay']

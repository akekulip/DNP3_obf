"""Offline installer and evidence contracts for response-ready timing (timing reported, never gated)."""
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


def test_response_ready_d_has_exactly_one_units_conversion_and_no_wait_deadline():
    values = dict(gap=5_000_000, op_j=2_400_000, budget=240000, enabled=1)
    assert tc.t_units(values, unit_ns=256, grid_ns=512)['gap'] == 19534
    assert 'response_wait_timeout' not in tc.RESPONSE_READY_KEYS
    op = tc.params_op(values)
    assert dict(op['data']) == values
    assert tc.check_params(values) == []


@pytest.mark.parametrize('obsolete', ['da', 'readiness', 'cap', 'pb', 'response_wait_timeout'])
def test_response_ready_rejects_mixed_parameter_contract(obsolete):
    values = dict(gap=5_000_000, op_j=2_400_000, budget=240000, enabled=1)
    values[obsolete] = 10_000_000
    assert tc.check_params(values)
    with pytest.raises(ValueError):
        tc.params_op(values)


def test_visible_clrt_reports_each_class_as_data_without_a_verdict():
    rows = [dict(operation=op, workload=workload, piggyback=False, complete_clrt_us=5000 + i)
            for op, workload, n in [('READ', 'mixed', 33), ('READ', 'integrity', 32),
                                    ('SELECT', None, 64), ('OPERATE', None, 64)] for i in range(n)]
    rows.append(dict(operation='SELECT', workload=None, piggyback=True, complete_clrt_us=None))
    rows.append(dict(operation='OPERATE', workload=None, piggyback=False, complete_clrt_us=None))
    result = relay_check.visible_clrt(dict(exchanges=rows))
    assert set(result) == {'READ mixed', 'READ integrity', 'SELECT', 'OPERATE'}
    for name, n in (('READ mixed', 33), ('READ integrity', 32), ('SELECT', 64), ('OPERATE', 64)):
        v = result[name]
        assert set(v) == {'n', 'piggyback', 'min_us', 'median_us', 'max_us', 'values_us'}
        assert v['n'] == n == len(v['values_us'])
        assert v['values_us'] == sorted(v['values_us']) == [5000 + i for i in range(n)]
        assert (v['min_us'], v['max_us']) == (5000, 5000 + n - 1)
        assert v['median_us'] == 5000 + (n - 1) / 2
    assert result['SELECT']['piggyback'] == 1 and result['OPERATE']['piggyback'] == 0
    empty = relay_check.visible_clrt(dict(exchanges=[]))['READ mixed']
    assert empty == dict(n=0, piggyback=0, min_us=None, median_us=None, max_us=None, values_us=[])


def test_response_ready_load_config_and_installer_command(tmp_path):
    import campaign
    path = ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/config/rc01_m12p_c52_sdk9132_sel751_reference.json'
    cfg = json.loads(path.read_text())
    cfg['timing_contract'] = 'response_ready_ack_d_v2'
    cfg['timing_params_ns'] = dict(gap=5_000_000, op_j=2_400_000,
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
    assert '--t-response-wait-timeout' not in command
    assert '--t-gap 5000000' in command
    assert all(flag not in command for flag in ('--t-da ', '--t-readiness ', '--t-cap ', '--t-pb '))


def load_installer():
    spec = importlib.util.spec_from_file_location('response_ready_installer_test', BASE_HW / 'bringup_composite.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_installer_selects_compiled_contract_and_rejects_obsolete_explicit_args(tmp_path):
    installer = load_installer()
    source = '// timing_contract: response_ready_ack_d_v2\n' \
             'action set_params(bit<32> gap, bit<32> op_j, bit<32> budget, bit<8> enabled) {}\n' \
             'md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe;'
    (tmp_path / 'response_only.p4pp').write_text(source)
    args = ['--build-out', str(tmp_path), '--master-port', '59410']
    a = installer.parse(args)
    op = installer.dataplane_params_op(a)
    assert op['values_ns'] == tc.RESPONSE_READY_DEFAULTS
    assert dict(op['data']) == tc.t_units(tc.RESPONSE_READY_DEFAULTS, unit_ns=256, grid_ns=512)
    for flag in ('--t-da', '--t-readiness', '--t-cap', '--t-pb'):
        with pytest.raises(ValueError, match='obsolete'):
            installer.dataplane_params_op(installer.parse(args + [flag, '10000000']))
    with pytest.raises(SystemExit):
        installer.parse(args + ['--t-response-wait-timeout', '500000000'])


def test_response_ready_configs_preserve_references_smoke_and_identity_loss():
    spec = importlib.util.spec_from_file_location('ready_config_test', ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/make_sel751_configs.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for block in ('smoke', 'reference', 'loss_mixed_950', 'loss_full_950', 'persistence_graceful_950',
                  'persistence_rst_950', 'reconnect_950'):
        template = 'reference' if block == 'smoke' else block
        cfg = mod.relay_config(json.loads((mod.HERE / ('config/rc01_m12p_c29_sdk9132_%s.json' % template)).read_text()))
        mod.response_ready_config(cfg, block, 20 if block != 'smoke' else 5)
        assert cfg['timing_contract'] == 'response_ready_ack_d_v2'
        assert set(cfg['timing_params_ns']) == set(tc.RESPONSE_READY_KEYS)
        assert not {'purpose', 'read_precision', 'host_precision_gated'} & set(cfg['evaluation'])
        assert 'precision_reference' not in cfg['evaluation'].get('campaign_block', {})
        assert 'qualification_dimensions' not in cfg
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


def test_response_ready_snapshot_duplicate_names_are_mandatory_and_allow_recovery():
    import checks
    from test_checks import EXP, evidence
    ev = evidence()
    for snapshot in (ev['before'], ev['after']):
        snapshot['outcomes']['OUT_REQ_DUP_DROP'] = snapshot['outcomes'].pop('OUT_ACK_FALLBACK')
        snapshot['outcomes']['OUT_REQ_DUP_FORWARD'] = snapshot['outcomes'].pop('OUT_RESP_FALLBACK')
        snapshot['outcomes']['OUT_REQ_BYPASS'] = 0
    ev['after']['outcomes']['OUT_REQ_DUP_DROP'] = 2
    ev['after']['outcomes']['OUT_REQ_DUP_FORWARD'] = 1
    fails, observed = checks.evaluate_switch(EXP, dict(T=1, padding=1), 10, ev,
                                             timing_contract='response_ready_ack_d_v2')
    assert not fails
    assert observed['request_duplicates_dropped'] == 2
    assert observed['request_duplicates_forwarded'] == 1
    del ev['after']['outcomes']['OUT_REQ_DUP_FORWARD']
    fails, _ = checks.evaluate_switch(EXP, dict(T=1, padding=1), 10, ev,
                                     timing_contract='response_ready_ack_d_v2')
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
        cfg = dict(endpoint_profile='sel751', timing_contract='response_ready_ack_d_v2', evidence_dir=str(tmp_path),
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


@pytest.mark.parametrize('reference', [True, False])
@pytest.mark.parametrize('clrt_us', [5050, 54104])
def test_physical_verdict_reports_visible_clrt_and_never_fails_on_timing(tmp_path, monkeypatch, reference, clrt_us):
    """CLRT far from D (54.104 ms against D=5 ms) is reported per class and never becomes a failure; a config that
    still carries the retired precision_reference key is tolerated and ignored."""
    import campaign
    import checks
    cfg = json.loads((ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/config/rc01_m12p_c52_sdk9132_sel751_reference.json').read_text())
    cfg['timing_contract'] = 'response_ready_ack_d_v2'
    cfg['evaluation']['campaign_block']['precision_reference'] = reference
    cfg['timing_params_ns'] = dict(tc.RESPONSE_READY_DEFAULTS)
    reads, sbo = (65, 64) if reference else (2, 1)
    cfg['traffic']['sbo_cycles'] = sbo
    rows, records = [], []
    for operation, n in [('READ', reads), ('SELECT', sbo), ('OPERATE', sbo)]:
        for i in range(n):
            workload = ('mixed' if i % 2 == 0 else 'integrity') if operation == 'READ' else None
            rows.append(dict(operation=operation, workload=workload, piggyback=False, complete_clrt_us=clrt_us))
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
    # synthetic records without captures: the SEL-751 standards branch is exercised in test_relay_standards.py
    monkeypatch.setattr(runner, 'validate_standards_file', lambda *args, **kwargs: [])
    arm = next(a for a in cfg['arms'] if a['name'] == 'combined')
    trial = dict(reads=reads, master_port=59410)
    from types import SimpleNamespace
    runner.relay_verdict(trial, {}, 'offline', str(tmp_path), SimpleNamespace(rc=0), arm, 'physical_relay')
    assert trial['ok'] and trial['failures'] == []
    assert trial['dimension_verdicts'] == dict(application=True, switch=True, standards=True)
    single = trial['observed']['connections']['single']
    assert not {'timing_gated', 'precision'} & set(single)
    clrt = single['visible_clrt']
    assert clrt['READ mixed']['n'] + clrt['READ integrity']['n'] == reads
    assert clrt['SELECT']['n'] == clrt['OPERATE']['n'] == sbo
    assert all(v['min_us'] == v['max_us'] == clrt_us for v in clrt.values())
    saved = json.loads((tmp_path / 'trial.json').read_text())
    assert saved['observed']['connections']['single']['visible_clrt'] == clrt


@pytest.mark.parametrize('bad_snapshot,bad_value', [('before', None), ('after', None), ('after', True),
                                                  ('after', -1), ('after', 'missing'), ('after', 8)])
def test_response_ready_installed_timing_requires_readable_zero_request_bypass(bad_snapshot, bad_value):
    import checks
    from test_checks import EXP, evidence
    ev = evidence()
    for snapshot in (ev['before'], ev['after']):
        snapshot['outcomes']['OUT_REQ_DUP_DROP'] = snapshot['outcomes'].pop('OUT_ACK_FALLBACK')
        snapshot['outcomes']['OUT_REQ_DUP_FORWARD'] = snapshot['outcomes'].pop('OUT_RESP_FALLBACK')
        snapshot['outcomes']['OUT_REQ_BYPASS'] = 7
    if bad_value == 'missing':
        del ev[bad_snapshot]['outcomes']['OUT_REQ_BYPASS']
    else:
        ev[bad_snapshot]['outcomes']['OUT_REQ_BYPASS'] = bad_value
    failures, _ = checks.evaluate_switch(EXP, dict(T=1, padding=1), 10, ev,
                                         timing_contract='response_ready_ack_d_v2')
    assert any('OUT_REQ_BYPASS' in failure for failure in failures)


@pytest.mark.parametrize('timed,installed_reads', [(False, 10), (True, 0)])
def test_response_ready_request_bypass_gate_preserves_off_and_native_only(timed, installed_reads):
    import checks
    from test_checks import EXP, evidence
    # An unknown-port-only connection contributes no installed READ/SBO timing events.
    ev = evidence(T=0)
    for snapshot in (ev['before'], ev['after']):
        snapshot['outcomes']['OUT_REQ_DUP_DROP'] = snapshot['outcomes'].pop('OUT_ACK_FALLBACK')
        snapshot['outcomes']['OUT_REQ_DUP_FORWARD'] = snapshot['outcomes'].pop('OUT_RESP_FALLBACK')
    ev['after']['outcomes']['OUT_REQ_BYPASS'] = 1
    failures, _ = checks.evaluate_switch(EXP, dict(T=int(timed), padding=1), installed_reads, ev,
                                         sbo_count=0 if timed else 1, timing_contract='response_ready_ack_d_v2')
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
        cfg = dict(endpoint_profile='sel751', timing_contract='response_ready_ack_d_v2', evidence_dir=str(tmp_path),
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


def test_response_ready_profile_binds_four_field_source_and_no_deadline():
    path = ARCH / 'integration/core/response_only_rearm/hw/sealed_profile.py'
    spec = importlib.util.spec_from_file_location('ready_v2_sealed_profile', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    source = ('action set_params(bit<32> gap, bit<32> op_j, bit<32> budget, bit<32> enabled) {}\n'
              'md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe;')
    profile = dict(timing_contract='response_ready_ack_d_v2',
                   timing_ns=dict(D_release_budget=5000000, J_operate_hold=2400000))
    assert mod.validate_timing_contract(profile, source) == 'response_ready_ack_d_v2'
    assert tc.timing_contract_of_source(source) == 'response_ready_ack_d_v2'
    profile['timing_ns']['response_wait_timeout'] = 500000000
    with pytest.raises(ValueError, match='only D and J'):
        mod.validate_timing_contract(profile, source)
    profile['timing_ns'].pop('response_wait_timeout')
    with pytest.raises(ValueError, match='ABI'):
        mod.validate_timing_contract(profile, source.replace('bit<32> budget',
                  'bit<32> response_wait_timeout, bit<32> budget'))


@pytest.mark.parametrize('name', ['OUT_REQ_DUP_DROP', 'OUT_REQ_DUP_FORWARD'])
@pytest.mark.parametrize('value', [None, True, -1, 'unreadable'])
def test_response_ready_duplicate_counters_require_readable_integers(name, value):
    import checks
    from test_checks import EXP, evidence
    ev = evidence()
    for snapshot in (ev['before'], ev['after']):
        snapshot['outcomes']['OUT_REQ_DUP_DROP'] = snapshot['outcomes'].pop('OUT_ACK_FALLBACK')
        snapshot['outcomes']['OUT_REQ_DUP_FORWARD'] = snapshot['outcomes'].pop('OUT_RESP_FALLBACK')
        snapshot['outcomes']['OUT_REQ_BYPASS'] = 0
    ev['after']['outcomes'][name] = value
    fails, _ = checks.evaluate_switch(EXP, dict(T=1, padding=1), 10, ev,
                                     timing_contract='response_ready_ack_d_v2')
    assert any(name in failure for failure in fails)

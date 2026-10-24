import importlib.util
import json
import hashlib
from pathlib import Path

import pytest

ARCH = Path(__file__).resolve().parents[3]
PATH = ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/make_sel751_configs.py'
spec = importlib.util.spec_from_file_location('sel751_configs_test', PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_all_four_arm_and_recovery_templates_convert_without_software_endpoint():
    config_dir = PATH.parent / 'config'
    for block in ('reference', 'loss_mixed_950', 'loss_full_950', 'persistence_graceful_950',
                  'persistence_rst_950', 'reconnect_950', 'held_operate_350'):
        old = json.loads((config_dir / ('rc01_m12p_c29_sdk9132_' + block + '.json')).read_text())
        cfg = mod.relay_config(old)
        import campaign
        campaign.validate_profile(cfg)
        assert cfg['endpoint_profile'] == 'sel751'
        assert cfg['hosts']['vision'] == 'decps@10.10.54.166'
        assert cfg['endpoints']['outstation_ip'] == '192.168.10.7'
        assert cfg['ports_map']['relay_dev'] == 64
        assert 'binary_sha256' not in cfg['endpoint']
        assert cfg['fixture']['modes'] == ['physical_relay']
        assert cfg['expectations']['padding']['0']['sbo_resp_len'] == [49]
        assert cfg['expectations']['padding']['1']['sbo_resp_len'] == [60]
        assert cfg['expectations']['padding']['0']['read_resp_len'] == ([91] if block == 'loss_mixed_950' else [134] if block == 'loss_full_950' else [91, 134])
        if block == 'reference':
            assert len(cfg['arms']) == 4
            assert cfg['trials']['reads_per_trial'] == 65
            assert cfg['traffic']['sbo_cycles'] == 64


def test_generator_refuses_unbound_source_and_pins_selected_compile(tmp_path, monkeypatch):
    fake_arch = tmp_path / 'defense4/timing/case4_architecture'
    monkeypatch.setattr(mod, 'ARCH', fake_arch)
    build = fake_arch / 'integration/evidence/selected_relay'
    compile_dir = build / 'compile_local'
    compile_dir.mkdir(parents=True)
    source = b'offline generator binding fixture\n'
    (build / 'response_only.p4').write_bytes(source)
    digest = hashlib.sha256(source).hexdigest()
    profile = dict(endpoint_profile='sel751', tcp_profile='sel751_ts', candidate=dict(source_sha256=digest),
                   encoding=dict(native_input_octets=dict(READ=[91, 134], SELECT=49, OPERATE=49),
                                 output_octets=60, tcp_header_octets=32, syn_tcp_header_octets=40,
                                 synack_tcp_header_octets=44, ipv4_ihl=5, timestamp_option_prefix='0101080a'), ports=dict(relay_dev=64))
    (build / 'supported_profile.json').write_text(json.dumps(profile))
    hashes = {name: hashlib.sha256(name.encode()).hexdigest() for name in
              ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa')}
    manifest = dict(exit_code=0, source_sha256=digest, compiler='p4c 9.13.2 fixture', artifact_sha256=hashes)
    (compile_dir / 'manifest.json').write_text(json.dumps(manifest))
    output = tmp_path / 'configs'
    native = tmp_path / 'native.json'
    artifacts = {}
    for name in ('out.pcap', 'in.pcap', 'master.json', 'result.json'):
        raw = ('offline source-binding fixture ' + name).encode()
        (tmp_path / name).write_bytes(raw)
        artifacts[name] = hashlib.sha256(raw).hexdigest()
    observation = native_tcp_fixture()
    observation.update(exchanges=[dict(operation=operation, response=dict(actual_payload_lengths=[49]))
                                 for operation in ('SELECT', 'OPERATE')], artifacts=artifacts)
    native.write_text(json.dumps(observation))
    assert mod.main(['--build', str(build), '--output', str(output), '--native-observation', str(native)]) == 0
    configs = list(output.glob('*.json'))
    assert len(configs) == 7
    for path in configs:
        cfg = json.loads(path.read_text())
        selected = cfg['builds']['selected_relay']
        assert selected['source_sha256'] == digest
        assert selected['hashes'] == hashes
        assert selected['out_dir'] == str((compile_dir / 'out').relative_to(fake_arch))
        assert {arm['build'] for arm in cfg['arms']} == {'selected_relay'}
    import sys
    sys.path.insert(0, str(ARCH / 'integration/evidence/rearm_01/hw'))
    import freeze_gate as fg
    from types import SimpleNamespace
    monkeypatch.setattr(fg, 'REPO', tmp_path)
    model = dict(qualification='model_gate_passed', latest_by_driver={})
    monkeypatch.setattr(fg, 'compile_problems', lambda *args: [])
    monkeypatch.setattr(fg, 'model_summary_module', lambda: SimpleNamespace(summarize_v3=lambda build: model))
    for path in configs:
        candidate = dict(configs={fg.rel(path): fg.sha(fg.rel(path))}, source_sha256=digest,
                         loaded_compile=dict(manifest=fg.rel(compile_dir / 'manifest.json'), out_dir=fg.rel(compile_dir / 'out')),
                         artifacts=dict(compile_local={'out/' + key: value for key, value in hashes.items()}),
                         model=model, build=fg.rel(build))
        assert fg.candidate_binding(dict(freeze_version=fg.FREEZE_V3, candidate=candidate), path) == []
    (build / 'response_only.p4').write_bytes(b'changed after profile was pinned')
    with pytest.raises(ValueError, match='source-bound'):
        mod.main(['--build', str(build), '--output', str(tmp_path / 'bad_configs'), '--native-observation', str(native)])


def test_persistence_runner_selects_physical_master_for_all_connections():
    import sys
    sys.path.insert(0, str(ARCH / 'integration/evidence/rearm_01/hw'))
    import candidate_series
    template = PATH.parent / 'config/rc01_m12p_c29_sdk9132_persistence_graceful_950.json'
    cfg = mod.relay_config(json.loads(template.read_text()))
    campaign = candidate_series.CandidateSeriesCampaign(cfg, candidate_series.base.DryRunner(), 'physical_persistence')
    command = campaign.series_vision_cmd('physical', 59410, 20, 8, 0)
    assert 'vision_run.py run ' in command
    assert 'vision_candidate.py' not in command
    assert '--endpoint-profile sel751 --apply' in command
    assert '--scenario persistence' in command


def native_tcp_fixture():
    return dict(ok=True, packets=dict(out=[dict(flags=2, payload_len=0, tcp_header_bytes=40, ipv4_header_bytes=20,
                    tcp_options_hex='020405b40402080a010203040000000001030307'),
                    dict(flags=24, payload_len=45, tcp_header_bytes=32, ipv4_header_bytes=20,
                    tcp_options_hex='0101080a0102030411223344')],
                    **{'in': [dict(flags=18, payload_len=0, tcp_header_bytes=44, ipv4_header_bytes=20,
                    tcp_options_hex='020405b401030300010104020101080a1122334401020304')]}))


@pytest.mark.parametrize('change', ['master_ws', 'relay_ws', 'mss', 'missing_syn'])
def test_native_tcp_profile_refuses_unsupported_handshake(change):
    report = native_tcp_fixture()
    if change == 'master_ws':
        report['packets']['out'][0]['tcp_options_hex'] = report['packets']['out'][0]['tcp_options_hex'][:-2] + '08'
    elif change == 'relay_ws':
        report['packets']['in'][0]['tcp_options_hex'] = report['packets']['in'][0]['tcp_options_hex'].replace('01030300', '01030301')
    elif change == 'mss':
        report['packets']['out'][0]['tcp_options_hex'] = report['packets']['out'][0]['tcp_options_hex'].replace('020405b4', '02040578')
    else:
        report['packets']['out'].pop(0)
    with pytest.raises(ValueError):
        mod.endpoint_profiles.validate_tcp_observation(report)


def test_native_tcp_profile_accepts_exact_observed_layout_and_scale():
    mod.endpoint_profiles.validate_tcp_observation(native_tcp_fixture())


def test_existing_manifest_generator_selects_physical_configs_and_fixture(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('sel751_manifest_test', PATH.parent / 'make_hw_manifest.py')
    manifest_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manifest_module)
    root = tmp_path / 'hw'
    (root / 'config').mkdir(parents=True)
    template = json.loads((PATH.parent / 'config/rc01_m12p_c29_sdk9132_reference.json').read_text())
    cfg = mod.relay_config(template)
    cfg['evidence_dir'] = 'integration/evidence/physical_runs'
    (root / 'config/rc01_selected_sel751_reference.json').write_text(json.dumps(cfg))
    frozen = tmp_path / 'freeze.json'
    frozen.write_text('{}')
    monkeypatch.setattr(manifest_module, 'HERE', root)
    manifest_module.main(['--build', 'selected', str(frozen), 'physical_manifest', 'reference'])
    result = json.loads((tmp_path / 'evidence/hw_campaigns/physical_manifest.manifest.json').read_text())
    step = result['steps'][0]
    assert step['argv'][4].endswith('rc01_selected_sel751_reference.json')
    assert step['argv'][-2:] == ['--fixtures', 'physical_relay']
    assert Path(step['run_root']).is_absolute()

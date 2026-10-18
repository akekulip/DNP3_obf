import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / 'hw/evaluation_prepare.py'


def module():
    spec = importlib.util.spec_from_file_location('evaluation_prepare', PATH)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def test_fixed_cohort_order_and_budget():
    m = module()
    blocks = m.collection_order('test_campaign')
    assert len(blocks) == 154
    main = [b for b in blocks if b['phase'] == 'main']
    assert len(main) == 128
    assert sum(b['expected_exchanges'] for b in main) == 98816
    assert [b['split'] for b in main[:64]] == ['training'] * 64
    assert [b['split'] for b in main[64:]] == ['testing'] * 64
    assert len({b['id'] for b in blocks}) == 154
    assert [b['condition_id'] for b in main[:8]] == [c[0] for c in m.CONDITIONS]
    assert main[8]['condition_id'] == m.CONDITIONS[1][0]
    assert main[8]['arms'] == ['combined', 'off', 'timing_only', 'size_only']
    assert main[24]['arms'] == ['timing_only', 'size_only', 'combined', 'off']


def test_common_envelope_uses_largest_native_pilot_and_j():
    m = module()
    result = m.derive_envelope([5_000_001, 8_000_001], [200_000_000])
    assert result['response_availability_max_ns'] == 8_000_001
    assert result['requested_ns'] == dict(da=34_000_000, pb=59_000_000,
                                         readiness=64_000_000, cap=69_000_000)
    assert all(v % 1_000_000 == 0 for v in result['requested_ns'].values())
    assert result['guards_are_worst_case_bounds'] is False
    for field, ns in result['requested_ns'].items():
        assert result['effective_ns'][field] == m.grid.t_units(ns) * 256
    with pytest.raises(ValueError, match='TCP'):
        m.derive_envelope([8_000_001], [])
    with pytest.raises(ValueError, match='headroom'):
        m.derive_envelope([8_000_001], [60_000_000])
    with pytest.raises(ValueError):
        m.derive_envelope([], [200_000_000])


def test_configs_rotate_actual_arms_and_keep_source_bindings():
    m = module()
    base = m.load(m.BUILD / 'configs/part2_m11_09_ref_r30_b1.json')
    block = m.collection_order('test_campaign')[10 + 16 + 8]
    env = m.derive_envelope([6_000_000], [200_000_000])
    cfg = m.evaluation_config(base, block, env, 'order-hash')
    assert [a['name'] for a in cfg['arms']] == block['arms']
    assert cfg['fixture']['delay_ms'] == 5
    assert cfg['traffic']['sbo_cycles'] == 64
    assert cfg['trials']['reads_per_trial'] == 65
    assert cfg['builds'] == base['builds']
    assert cfg['endpoint'] == base['endpoint']
    assert cfg['ctl_timing_identity'] == base['ctl_timing_identity']
    assert cfg['evaluation']['collection_order_sha256'] == 'order-hash'
    assert cfg['timing_params_ns']['op_j'] == 2_400_000
    assert cfg['timing_params_ns']['gap'] == 10_000_000
    assert m.grid.check_config(cfg) == []


def test_no_clobber_json(tmp_path):
    m = module()
    p = tmp_path / 'locked.json'
    m.write_new(p, {'a': 1})
    with pytest.raises(FileExistsError):
        m.write_new(p, {'a': 2})


def test_prepared_manifest_pins_all_future_blocks_and_offline_gates(tmp_path):
    m = module()
    root = m.prepare(tmp_path / 'campaign', 'test_campaign')
    manifest = m.load(root / 'controller_manifest.json')
    blocks = [s for s in manifest['steps'] if s['kind'] == 'block']
    assert len(blocks) == 154
    assert [s['id'] for s in blocks] == [b['id'] for b in m.collection_order('test_campaign')]
    assert len(list((root / 'configs').glob('*.json'))) == 10
    hooks = [(i, s['id']) for i, s in enumerate(manifest['steps']) if s['kind'] == 'hook']
    assert hooks == [(10, 'derive'), (27, 'qualify'), (92, 'fit'), (157, 'export')]
    controller = m.module('evaluation_controller_for_config_test', m.HW / 'evaluation_campaign.py')
    controller.validate_manifest(manifest)
    config_loader = m.module('evaluation_config_validation', m.ARCH / 'protocol/hw_vepa/campaign.py')
    for block in m.collection_order('test_campaign')[:10]:
        cfg = config_loader.load_config(str(m.config_path(root, block)))
        assert cfg['evidence_dir'] == str(root / 'blocks')
    # A changed collection order is refused before any hook derives new configs.
    (root / 'collection_order.json').write_text('[]')
    with pytest.raises(ValueError, match='order'):
        m.frozen_order(root)


def test_missing_measurements_and_fallbacks_cannot_qualify(tmp_path):
    m = module()
    block = m.collection_order('test_campaign')[10]
    base = m.load(m.BUILD / 'configs/part2_m11_09_ref_r30_b1.json')
    cfg = m.evaluation_config(base, block, m.derive_envelope([5_000_000], [200_000_000]), 'order')
    errors = m.check_observations(block, cfg, {'ok': True, 'arms': [], 'effective': {}}, {'records': []})
    assert any('source identity' in e for e in errors)
    assert any('execution order' in e for e in errors)
    assert any('class counts' in e for e in errors)
    assert any('precision' in e for e in errors)
    assert any('trial gate' in e for e in errors)


def test_every_future_config_passes_existing_validation_and_headroom_inputs(tmp_path):
    m = module()
    base = m.load(m.BUILD / 'configs/part2_m11_09_ref_r30_b1.json')
    env = m.derive_envelope([8_123_456], [200_000_000])
    loader = m.module('evaluation_future_config_loader', m.ARCH / 'protocol/hw_vepa/campaign.py')
    for block in m.collection_order('test_campaign')[10:]:
        cfg = m.evaluation_config(base, block, env, 'order')
        assert cfg['timing_params_ns']['gap'] == block['D_ns']
        assert cfg['timing_params_ns']['op_j'] == block['J_ns']
        assert {k: cfg['timing_params_ns'][k] for k in env['requested_ns']} == env['requested_ns']
        assert [a['name'] for a in cfg['arms']] == block['arms']
        assert cfg['trials']['reads_per_trial'] == block['reads']
        assert cfg['traffic'].get('sbo_cycles', 0) == block['sbo']
        assert cfg['trial_mode'] == 'per_trial_cold'
        assert cfg['traffic']['master_port_range'] == base['traffic']['master_port_range']
        path = tmp_path / (block['id'] + '.json')
        m.write_new(path, cfg)
        loader.load_config(str(path))


def test_timeout_evidence_requires_both_observed_endpoint_rtos():
    m = module()
    doc = dict(schema_version='vision-tcp-rto-v2', status='ok', samples=[
        dict(endpoint='master', status='ok', units='ms', rto_ms=[200.0]),
        dict(endpoint='outstation', status='ok', units='ms', rto_ms=[240.0])])
    assert m.observed_rtos(doc) == [200_000_000, 240_000_000]
    for bad in ({}, dict(doc, samples=doc['samples'][:1]),
                dict(doc, samples=[dict(s, rto_ms=[]) for s in doc['samples']])):
        with pytest.raises(ValueError, match='endpoint TCP'):
            m.observed_rtos(bad)

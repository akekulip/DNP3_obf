"""Offline packaging contracts only: these incomplete fixtures are not hardware evidence.

The physical qualification boundary is stubbed solely to exercise artifact copying.
No estimator, hardware command, or main-result validation runs in these tests.
"""
import csv
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


@pytest.mark.parametrize('outstation_rto_ms, passes', [(200.0, True), (20.0, False), (None, False)])
def test_postcheck_requires_both_endpoint_rtos_and_headroom(tmp_path, monkeypatch, outstation_rto_ms, passes):
    path = Path(__file__).resolve().parents[1] / 'hw/evaluation_prepare.py'
    spec = importlib.util.spec_from_file_location('rto_integration_review', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    block = m.collection_order('rto_fixture')[10]
    root = tmp_path / 'postcheck_only'
    monkeypatch.setattr(m, 'frozen_order', lambda unused: ({}, [block]))
    monkeypatch.setattr(m, 'extract_ledger', lambda *unused: {'records': []})
    monkeypatch.setattr(m, 'check_observations', lambda *unused: [])
    monkeypatch.setattr(m, 'write_new', write)
    cfg = dict(timing_params_ns=dict(op_j=20_000_000, da=30_000_000, gap=20_000_000, cap=80_000_000))
    write(m.config_path(root, block), cfg)
    directory = m.run_root(root, block)
    write(directory / 'campaign_run.json', {'config_file_sha256': m.sha(m.config_path(root, block)),
                                            'pre_run_program': 'case4_response_path'})
    write(directory / 'restore_verify.json', {'ok': True})
    samples = [dict(endpoint='master', status='ok', units='ms', rto_ms=[200.0])]
    if outstation_rto_ms is not None:
        samples.append(dict(endpoint='outstation', status='ok', units='ms', rto_ms=[outstation_rto_ms]))
    write(directory / 'separate_ack/combined/trial/tcp_rto.json',
          dict(schema_version='vision-tcp-rto-v2', samples=samples))
    if passes:
        m.postcheck(root, block['id'])
    else:
        with pytest.raises(ValueError, match='TCP'):
            m.postcheck(root, block['id'])
    assert m.load(directory / 'evaluation_postcheck.json')['ok'] is passes


@pytest.mark.parametrize('training', [True, False])
def test_release_preserves_preliminary_controller_and_endpoint_evidence(tmp_path, monkeypatch, training):
    path = Path(__file__).resolve().parents[1] / 'hw/evaluation_prepare.py'
    spec = importlib.util.spec_from_file_location('release_integration_review', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = tmp_path / 'packaging_only'
    order = m.collection_order('packaging_only')
    definition = dict(campaign_id='packaging_only')
    monkeypatch.setattr(m, 'frozen_order', lambda unused: (definition, order))
    monkeypatch.setattr(m, 'qualified', lambda *unused: None)
    monkeypatch.setattr(m, 'write_new', write)

    monkeypatch.setattr(m, 'analysis_environment', lambda: dict(
        evidence_kind='analysis_environment', python='fixture', packages={'numpy': 'fixture'}))
    # Keep the production serializer/copy logic; replace unrelated cost/legacy analysis.
    def legacy_export(argv):
        table = Path(argv[1])
        table.write_text('packaging_fixture_only\n')
        write(Path(str(table) + '.counts.json'), {'packaging_fixture_only': True})
    monkeypatch.setattr(m, 'module', lambda name, path: SimpleNamespace(main=legacy_export))

    for block in order:
        directory = m.run_root(root, block)
        row = dict(record_type='captured_exchange', arm='baseline', exchange_id=block['id'],
                   txn_class='READ', trial=block['id'], clrt_ns=2_000_000,
                   ack_latency_ns=1_000_000, response_latency_ns=3_000_000)
        write(directory / 'publication_ledger.json', {'records': [row]})
        write(directory / 'campaign_run.json', {'arms': []})
        write(directory / 'evaluation_postcheck.json', {'packaging_fixture_only': True})
        for name in ('out.pcap', 'in.pcap', 'master.stdout', 'master.stderr',
                     'outstation.stdout', 'outstation.stderr'):
            (directory / name).write_bytes(('packaging fixture: ' + name).encode())
    for name in ('definition.json', 'collection_order.json', 'common_envelope.json',
                 'pilot_competence.json', 'feasibility_qualification.json',
                 'freeze_pilot.json', 'freeze_main.json', 'controller_manifest.json'):
        write(root / name, {'packaging_fixture_only': True})
    for name in ('manifest.json', 'identity.json', 'state.json', 'steps/fit/claimed.json',
                 'steps/fit/terminal.json'):
        write(root / 'packaging_only' / name, {'packaging_fixture_only': True})
    (root / 'packaging_only/steps/fit/command.log').write_text('fixture hook log')
    if not training:
        write(root / 'release_training/model_lock.json', {'packaging_fixture_only': True})
        write(root / 'fit_attestation.json', {'packaging_fixture_only': True})
    build = tmp_path / 'candidate'
    for name in ('supported_profile.json', 'response_only.inputs.json', 'compiler_comparison.json',
                 'resource_review.json', 'model_summary_v3.json',
                 'compile_local/manifest.json', 'compile_switch_9132/manifest.json'):
        write(build / name, {'packaging_fixture_only': True})
    monkeypatch.setattr(m, 'BUILD', build)

    destination = m.release(root, training)
    # review C1: every main artifact of the REAL release carries an explicit hardware label, since
    # publication_analysis.validate_release refuses unlabelled ones (validation records keep their own kinds)
    released = m.load(destination / 'release_manifest.json')
    unlabelled = [a['path'] for a in released['artifacts']
                  if a['kind'] != 'validation' and a.get('evidence_kind') != 'hardware']
    assert unlabelled == []
    manifest = m.load(destination / 'release_manifest.json')
    artifacts = {record['path']: record for record in manifest['artifacts']}
    assert manifest['environment_lock_file'] == 'environment_lock.json'
    assert m.load(destination / 'environment_lock.json')['packages'] == {'numpy': 'fixture'}
    assert (destination / 'requirements-analysis.txt').read_text() == 'numpy==fixture\n'
    for relative, record in artifacts.items():
        assert record['sha256'] == m.sha(destination / relative)
    for block in order[:26]:
        for name in ('out.pcap', 'in.pcap', 'publication_ledger.json',
                     'evaluation_postcheck.json', 'master.stdout', 'master.stderr',
                     'outstation.stdout', 'outstation.stderr'):
            relative = 'preliminary/' + block['id'] + '/' + name
            assert relative in artifacts
            assert artifacts[relative]['kind'] == 'audit'
    for relative in ('audit/controller_manifest.json', 'supervision/manifest.json',
                     'supervision/identity.json', 'supervision/state.json',
                     'supervision/steps/fit/claimed.json', 'supervision/steps/fit/terminal.json',
                     'supervision/steps/fit/command.log'):
        assert relative in artifacts
    for block in order[26:]:
        if training and block['split'] != 'training':
            assert not any(p.startswith('hardware/' + block['id'] + '/') for p in artifacts)
            continue
        for name in ('master.stdout', 'master.stderr', 'outstation.stdout', 'outstation.stderr'):
            assert 'hardware/' + block['id'] + '/' + name in artifacts
    with (destination / 'rows.csv').open() as handle:
        rows = list(csv.DictReader(handle))
    expected = {b['id'] for b in order[26:] if not training or b['split'] == 'training'}
    assert {row['example_id'] for row in rows} == expected
    assert all(not b['complete'] for b in m.load(destination / 'cohort.json')['blocks'])
    for relative, evidence_kind in (
            ('candidate/model_summary_v3.json', 'model_validation'),
            ('candidate/supported_profile.json', 'profile_metadata'),
            ('candidate/compile_local/manifest.json', 'compiler_validation')):
        assert artifacts[relative]['kind'] == 'validation'
        assert artifacts[relative]['evidence_kind'] == evidence_kind


def _postcheck_fixture(tmp_path, monkeypatch, *, cap=80_000_000, observed=None, attested=True):
    path = Path(__file__).resolve().parents[1] / 'hw/evaluation_prepare.py'
    spec = importlib.util.spec_from_file_location('postcheck_review', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    block = m.collection_order('pc_fixture')[10]
    root = tmp_path / 'postcheck_review'
    monkeypatch.setattr(m, 'frozen_order', lambda unused: ({}, [block]))
    monkeypatch.setattr(m, 'extract_ledger', lambda *unused: {'records': [dict(response_latency_ns=observed)]})
    monkeypatch.setattr(m, 'check_observations', lambda *unused: [])
    monkeypatch.setattr(m, 'write_new', write)
    write(m.config_path(root, block), dict(timing_params_ns=dict(op_j=2_400_000, da=30_000_000, gap=10_000_000, cap=cap)))
    directory = m.run_root(root, block)
    record = {'config_file_sha256': m.sha(m.config_path(root, block))}
    if attested:
        record['pre_run_program'] = 'case4_response_path'
        write(directory / 'restore_verify.json', {'ok': True})
    write(directory / 'campaign_run.json', record)
    write(directory / 'separate_ack/combined/trial/tcp_rto.json', dict(schema_version='vision-tcp-rto-v2', samples=[
        dict(endpoint='master', status='ok', units='ms', rto_ms=[200.0]),
        dict(endpoint='outstation', status='ok', units='ms', rto_ms=[200.0])]))
    return m, root, block, directory


def test_postcheck_budget_includes_cap_and_observed_latency(tmp_path, monkeypatch):
    """Review R8: the configured fallback release (cap) and the observed latency both count against the timeout."""
    m, root, block, _d = _postcheck_fixture(tmp_path, monkeypatch, cap=250_000_000)
    with pytest.raises(ValueError, match='TCP'):
        m.postcheck(root, block['id'])
    m, root, block, _d = _postcheck_fixture(tmp_path / 'b', monkeypatch, observed=210_000_000)
    with pytest.raises(ValueError, match='TCP'):
        m.postcheck(root, block['id'])


def test_postcheck_derives_hardware_and_refuses_unattested_evidence(tmp_path, monkeypatch):
    """Review A6: evidence_kind comes from the run (pre-run switch program and verified restore), never a stamp."""
    m, root, block, directory = _postcheck_fixture(tmp_path, monkeypatch, attested=False)
    with pytest.raises(ValueError, match='not attested hardware'):
        m.postcheck(root, block['id'])
    assert m.load(directory / 'evaluation_postcheck.json')['evidence_kind'] == 'unattested'
    m, root, block, directory = _postcheck_fixture(tmp_path / 'ok', monkeypatch)
    m.postcheck(root, block['id'])
    assert m.load(directory / 'evaluation_postcheck.json')['evidence_kind'] == 'hardware'

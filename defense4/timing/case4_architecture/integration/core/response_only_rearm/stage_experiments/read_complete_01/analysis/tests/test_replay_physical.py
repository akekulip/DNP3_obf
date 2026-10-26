"""Replay checks use copies for every mutation; retained artifacts are read only."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ANALYSIS = Path(__file__).resolve().parents[1]
EVIDENCE = ANALYSIS.parent / 'evidence/hw_blocks'
NORMAL = 'rc01_hw_c68_20261026_01_reference_rest'


def load_tool():
    spec = importlib.util.spec_from_file_location('replay_physical_test', ANALYSIS / 'replay_physical.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def copy_block(tmp_path, name=NORMAL):
    block = tmp_path / name
    block.mkdir()
    for name in ('campaign_run.json', 'freeze_check.json'):
        shutil.copy(EVIDENCE / block.name / name, block / name)
    shutil.copytree(EVIDENCE / block.name / 'physical_relay', block / 'physical_relay')
    return block


def test_c68_retained_complete_blocks_reproduce_1544_exchanges_and_failures_stay_failures():
    result = load_tool().replay('c68')
    assert result['ok'] is True
    assert result['completed']['trials'] == 8
    assert result['completed']['exchanges'] == 1544
    failed = [b for b in result['blocks'] if b['recorded_run_ok'] is False]
    assert len(failed) == 3
    assert all(t['recorded_ok'] is False for b in failed for t in b['trials'])
    assert all(c['wire_ok'] is False for b in failed for t in b['trials'] for c in t['connections'])
    assert any(b['never_attempted_trials'] for b in failed)


def test_c67_recovery_and_pretraffic_refusal_reproduce():
    result = load_tool().replay('c67')
    assert result['ok'] is True
    loss = next(b for b in result['blocks'] if b['block'].endswith('_06_loss_mixed_950'))
    assert len(loss['trials']) == 7
    assert any(not t['recorded_ok'] for t in loss['trials'])
    assert any(not c['wire_ok'] for t in loss['trials'] for c in t['connections'])
    refused = next(b for b in result['blocks'] if b['block'].endswith('_01_smoke'))
    assert refused['trials'] == []
    assert len(refused['pre_traffic_refusals']) == 1
    assert refused['completed'] is False


@pytest.mark.parametrize('name', ['trial.json', 'in.pcap', 'master.json', 'result.json', 'relay_wire.json'])
def test_missing_attempted_trial_evidence_fails(tmp_path, name):
    block = copy_block(tmp_path)
    next(block.glob('physical_relay/*/*/' + name)).unlink()
    with pytest.raises(ValueError, match=name):
        load_tool().replay_block(block, 'c68')


def test_frozen_denominators_are_not_derived_from_master_records(tmp_path):
    block = copy_block(tmp_path)
    path = block / 'campaign_run.json'
    run = json.loads(path.read_text())
    run['arms'][0]['trials'][0]['reads'] = 1
    path.write_text(json.dumps(run))
    with pytest.raises(ValueError, match='frozen'):
        load_tool().replay_block(block, 'c68')


def test_missing_expected_trial_directory_fails(tmp_path):
    block = copy_block(tmp_path)
    shutil.rmtree(next(block.glob('physical_relay/*/*')))
    with pytest.raises(ValueError, match='trial directories'):
        load_tool().replay_block(block, 'c68')


def test_missing_trial_in_successful_campaign_record_fails(tmp_path):
    block = copy_block(tmp_path)
    path = block / 'campaign_run.json'
    run = json.loads(path.read_text())
    run['arms'].pop()
    path.write_text(json.dumps(run))
    with pytest.raises(ValueError, match='missing expected trials'):
        load_tool().replay_block(block, 'c68')


def test_frozen_config_hash_mismatch_fails(tmp_path):
    block = copy_block(tmp_path)
    path = block / 'freeze_check.json'
    frozen = json.loads(path.read_text())
    frozen['config_sha256'] = '0' * 64
    path.write_text(json.dumps(frozen))
    with pytest.raises(ValueError, match='frozen config identity'):
        load_tool().replay_block(block, 'c68')


def test_exact_report_difference_fails(tmp_path):
    block = copy_block(tmp_path)
    path = next(block.glob('physical_relay/*/*/relay_wire.json'))
    report = json.loads(path.read_text())
    report['ok'] = False
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match='differs from retained'):
        load_tool().replay_block(block, 'c68')


def test_v2_reports_use_current_checker(tmp_path):
    block = copy_block(tmp_path)
    for path in block.glob('physical_relay/*/*/relay_wire.json'):
        report = json.loads(path.read_text())
        report['schema'] = 'sel751-wire-v2'
        path.write_text(json.dumps(report))
    result = load_tool().replay_block(block, 'c68')
    assert all(c['checker_revision'] == 'working-tree' for t in result['trials'] for c in t['connections'])


def test_cli_refuses_to_overwrite(tmp_path):
    out = tmp_path / 'replay.json'
    out.write_text('retained output\n')
    result = subprocess.run([sys.executable, str(ANALYSIS / 'replay_physical.py'), '--candidate', 'c68',
                             '--out', str(out)], text=True, capture_output=True)
    assert result.returncode == 2
    assert 'exists' in result.stderr
    assert out.read_text() == 'retained output\n'


def test_cli_rejects_output_under_retained_evidence():
    out = EVIDENCE / 'unwritten-replay-output.json'
    assert not out.exists()
    result = subprocess.run([sys.executable, str(ANALYSIS / 'replay_physical.py'), '--candidate', 'c68',
                             '--out', str(out)], text=True, capture_output=True)
    assert result.returncode == 2
    assert 'outside retained evidence' in result.stderr
    assert not out.exists()

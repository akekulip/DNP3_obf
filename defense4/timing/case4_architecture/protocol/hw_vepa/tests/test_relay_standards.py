"""SEL-751 receiver-visible branch of the shared standards validator.

Every case goes through the one entry point the campaigns use (Campaign.validate_standards_file ->
standards.build_standards_artifact / standards.validate_standards) on copies of retained physical-relay trials in
a temporary directory; the retained evidence itself is only read.
"""
import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import campaign  # noqa: E402
import standards

ARCH = Path(__file__).resolve().parents[3]
RC = ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01'
CONFIGS = RC / 'hw/config'
BLOCKS = RC / 'evidence/hw_blocks'
C68_REF = 'rc01_m12p_c68_sdk9132_sel751_d5oc_reference_rest.json'
C68_LOSS_MIXED = 'rc01_m12p_c68_sdk9132_sel751_d20repair_loss_mixed_950.json'
C68_LOSS_FULL = 'rc01_m12p_c68_sdk9132_sel751_d20repair_loss_full_950.json'
C67_RECONNECT = 'rc01_m12p_c67_sdk9132_sel751_d20_reconnect_950.json'

# every case reads retained physical-relay captures (pcaps are not part of a tracked-source export)
pytestmark = [pytest.mark.evidence_tree, pytest.mark.skipif(
    not next((BLOCKS / 'rc01_hw_c68_20261026_05_loss_mixed_950').glob('physical_relay/combined/*_t0/out.pcap'), None),
    reason='retained SEL-751 trial captures absent (tracked-source export)')]


def _trial_dir(block, arm, suffix):
    return next((BLOCKS / block / 'physical_relay' / arm).glob('*_' + suffix))


def _runner(config_name, run_id):
    cfg = json.loads((CONFIGS / config_name).read_text())
    runner = campaign.Campaign(cfg, campaign.DryRunner(), run_id)
    runner.rn.dry = False
    runner.bound = {name: build.get('hashes') for name, build in cfg['builds'].items()}
    return runner


def _copy(source, tmp_path, name='trial'):
    dest = tmp_path / name
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns('snapshots', '*.log', 'standards*.json'))
    return dest


def _captures(dest):
    return {'out': {'path': str(dest / 'out.pcap')}, 'in': {'path': str(dest / 'in.pcap')},
            'master': {'path': str(dest / 'master.json')}, 'relay_wire': {'path': str(dest / 'relay_wire.json')}}


def _validate(runner, dest, arm_name, connection_id=None, unbound_native=False, trial=None):
    trial = trial or json.loads((dest / 'trial.json').read_text())
    arm = next(a for a in runner.cfg['arms'] if a['name'] == arm_name)
    failures = runner.validate_standards_file(str(dest), trial, arm, _captures(dest), None,
                                              connection_id=connection_id, unbound_native=unbound_native,
                                              master_port=trial['master_port'])
    verdict = json.loads((dest / 'standards_verdict.json').read_text())
    return failures, verdict, trial, arm


def _revalidate(runner, dest, trial, arm, connection_id=None, unbound_native=False, artifact=None, **overrides):
    context = runner.standards_context(trial, arm, connection_id, unbound_native)
    context['master_port'] = trial['master_port']
    context.update(overrides)
    captures = runner.standards_captures(str(dest), _captures(dest))
    return standards.validate_standards(artifact or str(dest / 'standards.json'), context, captures)


@pytest.fixture
def mixed_loss(tmp_path):
    runner = _runner(C68_LOSS_MIXED, 'rc01_hw_c68_20261026_05_loss_mixed_950')
    dest = _copy(_trial_dir('rc01_hw_c68_20261026_05_loss_mixed_950', 'combined', 't0'), tmp_path)
    return runner, dest


def test_retained_passing_trial_passes_through_the_shared_entry_point(mixed_loss):
    runner, dest = mixed_loss
    failures, verdict, _, _ = _validate(runner, dest, 'combined')
    assert failures == [] and verdict['ok'] is True
    artifact = json.loads((dest / 'standards.json').read_text())
    assert artifact['schema_version'] == standards.SCHEMA_VERSION_SEL751
    assert artifact['scope'] == standards.SEL751_SCOPE
    observed = artifact['observed']
    assert observed['transport_ok'] and observed['select_authorizes_operate'] and observed['operate_success']
    assert observed['size_ok'] and observed['aggregate_verdict']
    assert observed['not_evaluated'] == {name: 'NOT EVALUATED' for name in standards.SEL751_NOT_EVALUATED}
    assert artifact['expected']['planned_exchanges'] == 22
    assert set(artifact['captures']) >= set(standards.SEL751_CAPTURES)
    # the build keeps its own label; the receiver-visible scope is stated beside it, never substituted for it
    assert artifact['identity']['profile'] == 'candidate61'
    assert not (dest / 'profile_verdict.json').exists()


def test_artifact_copied_from_another_run_is_rejected(mixed_loss, tmp_path):
    runner, dest = mixed_loss
    other = _copy(_trial_dir('rc01_hw_c68_20261026_05_loss_mixed_950', 'combined', 't1'), tmp_path, 'other')
    _validate(runner, other, 'combined')
    shutil.copy(other / 'standards.json', dest / 'standards.json')
    trial = json.loads((dest / 'trial.json').read_text())
    arm = next(a for a in runner.cfg['arms'] if a['name'] == 'combined')
    result = _revalidate(runner, dest, trial, arm)
    assert not result['ok']
    assert any(f.startswith('run.trial mismatch') for f in result['failures'])
    assert any(f.startswith('captures.') for f in result['failures'])


@pytest.mark.parametrize('field,mutate', [
    ('identity.candidate_source_sha256', lambda r, c, t: c.update(candidate_source_sha256='0' * 64)),
    ('identity.profile_hash', lambda r, c, t: r.cfg['builds']['m12p_c68_sdk9132'].update(profile='strict_comparison')),
    ('identity.effective_config_sha256', lambda r, c, t: r.cfg['traffic'].update(read_pause_ms=26)),
    ('checker.version', lambda r, c, t: c.update(checker_files=c['checker_files'][:-1])),
    ('run.run_id', lambda r, c, t: c['run_record'].update(run_id='rc01_hw_other')),
    ('run.connection', lambda r, c, t: c.update(connection_id='c3')),
])
def test_wrong_identity_is_rejected(mixed_loss, field, mutate):
    runner, dest = mixed_loss
    _, _, trial, arm = _validate(runner, dest, 'combined')
    context = runner.standards_context(trial, arm)
    context['master_port'] = trial['master_port']
    mutate(runner, context, trial)
    result = standards.validate_standards(str(dest / 'standards.json'), context,
                                          runner.standards_captures(str(dest), _captures(dest)))
    assert not result['ok']
    assert any(f.startswith(field) for f in result['failures']), result['failures']


@pytest.mark.parametrize('name', ['out', 'in', 'master', 'run_result', 'capture_offloads', 'relay_wire'])
def test_tampered_capture_is_rehashed_and_rejected(mixed_loss, name):
    runner, dest = mixed_loss
    _, _, trial, arm = _validate(runner, dest, 'combined')
    path = runner.standards_captures(str(dest), _captures(dest))[name]['path']
    with open(path, 'ab') as f:
        f.write(b'\n')
    result = _revalidate(runner, dest, trial, arm)
    assert not result['ok']
    assert any(f.startswith('captures.%s.sha256' % name) for f in result['failures'])


def test_missing_capture_is_rejected(mixed_loss):
    runner, dest = mixed_loss
    (dest / 'capture_offloads.json').unlink()
    failures, verdict, _, _ = _validate(runner, dest, 'combined')
    assert failures and not verdict['ok']
    assert any('capture_offloads' in f for f in verdict['failures'])


def test_wrong_arm_sizes_are_rejected(mixed_loss):
    """The same combined (padded) captures validated as the off arm: native 91/49 are expected, 141/60 seen."""
    runner, dest = mixed_loss
    off = dict(next(a for a in runner.cfg['arms'] if a['name'] == 'combined'), name='off', padding=0)
    runner.cfg['arms'].append(off)
    failures, verdict, _, _ = _validate(runner, dest, 'off')
    assert failures and not verdict['ok']
    observed = json.loads((dest / 'standards.json').read_text())['observed']
    assert observed['size_ok'] is False and observed['transport_ok'] is True
    assert any('141 octets, expected 91' in f for f in observed['size_failures'])
    assert any('60 octets, expected 49' in f for f in observed['size_failures'])


def test_wrong_class_size_is_rejected(mixed_loss):
    runner, dest = mixed_loss
    master = json.loads((dest / 'master.json').read_text())
    read = next(r for r in master['records'] if r['operation'] == 'READ')
    read['workload'] = 'integrity'          # a 141-octet mixed response claimed as the 158-octet class
    (dest / 'master.json').write_text(json.dumps(master))
    failures, verdict, _, _ = _validate(runner, dest, 'combined')
    assert failures and not verdict['ok']
    observed = json.loads((dest / 'standards.json').read_text())['observed']
    assert any('READ:integrity response 141 octets, expected 158' in f for f in observed['size_failures'])


def test_missing_exchange_is_rejected(mixed_loss):
    runner, dest = mixed_loss
    trial = json.loads((dest / 'trial.json').read_text())
    trial['reads'] += 1                     # the frozen plan expects one more READ than the run produced
    failures, verdict, _, _ = _validate(runner, dest, 'combined', trial=trial)
    assert failures and not verdict['ok']
    observed = json.loads((dest / 'standards.json').read_text())['observed']
    assert observed['aggregate_verdict'] is False
    assert any('missing exchange' in f for f in observed['application_failures'])


def test_crob_timeout_is_an_application_failure_not_successful_sbo(tmp_path):
    """c68 full-loss t3: the OPERATE response arrives intact (transport and size pass) with CROB status TIMEOUT."""
    runner = _runner(C68_LOSS_FULL, 'rc01_hw_c68_20261026_06_loss_full_950')
    dest = _copy(_trial_dir('rc01_hw_c68_20261026_06_loss_full_950', 'combined', 't3'), tmp_path)
    failures, verdict, _, _ = _validate(runner, dest, 'combined')
    assert failures and not verdict['ok']
    observed = json.loads((dest / 'standards.json').read_text())['observed']
    assert observed['transport_ok'] is True and observed['size_ok'] is True
    assert observed['select_authorizes_operate'] is True
    assert observed['operate_success'] is False and observed['aggregate_verdict'] is False
    assert any('TIMEOUT' in f for f in observed['application_failures'])


def test_timeout_cannot_be_relabelled_as_success(mixed_loss):
    """Stated observations are recomputed from the bound captures; an artifact claiming success is rejected."""
    runner, dest = mixed_loss
    master = json.loads((dest / 'master.json').read_text())
    operate = next(r for r in master['records'] if r['operation'] == 'OPERATE')
    operate['points'] = [[point, 'TIMEOUT'] for point, _ in operate['points']]
    (dest / 'master.json').write_text(json.dumps(master))
    _, _, trial, arm = _validate(runner, dest, 'combined')
    artifact = json.loads((dest / 'standards.json').read_text())
    assert artifact['observed']['operate_success'] is False
    artifact['observed'].update(operate_success=True, aggregate_verdict=True, application_failures=[])
    result = _revalidate(runner, dest, trial, arm, artifact=artifact)
    assert not result['ok']
    assert any('differ from the bound captures' in f for f in result['failures'])


def test_receiver_only_evidence_cannot_satisfy_an_emission_proof_requirement(mixed_loss):
    runner, dest = mixed_loss
    runner.cfg.setdefault('standards', {})['packet_boundary_required'] = True
    failures, verdict, _, _ = _validate(runner, dest, 'combined')
    assert failures and not verdict['ok']
    assert any('emission proof' in f for f in verdict['failures'])


def test_candidate61_label_alone_does_not_demand_emission_proof_in_sel751_scope(mixed_loss):
    runner, dest = mixed_loss
    trial = json.loads((dest / 'trial.json').read_text())
    arm = next(a for a in runner.cfg['arms'] if a['name'] == 'combined')
    assert runner.cfg['builds'][arm['build']]['profile'] == 'candidate61'
    assert runner.standards_context(trial, arm)['packet_boundary_required'] is False
    # the software rule is untouched: the same label still demands boundary proof outside the SEL-751 scope
    runner.cfg['endpoint_profile'] = 'software'
    assert runner.standards_context(trial, arm)['packet_boundary_required'] is True


def test_software_artifact_schema_is_rejected_in_sel751_scope(mixed_loss):
    runner, dest = mixed_loss
    _, _, trial, arm = _validate(runner, dest, 'combined')
    artifact = json.loads((dest / 'standards.json').read_text())
    artifact['schema_version'] = standards.SCHEMA_VERSION_V4
    result = _revalidate(runner, dest, trial, arm, artifact=artifact)
    assert not result['ok'] and any(f.startswith('schema_version') for f in result['failures'])


def test_relay_checker_identity_covers_the_relay_dependencies():
    names = {Path(p).name for p in campaign.relay_checker_files()}
    assert {'standards.py', 'relay_check.py', 'wire_check.py', 'endpoint_profiles.py', 'relay_master.py',
            'relay_loss.py', 'session.py', 'dnp3_codec.py', 'sbo_driver.py'} <= names
    assert all(Path(p).is_file() for p in campaign.relay_checker_files())


# ---- retained physical-relay captures reproduce their recorded outcomes ------------------------------------

RETAINED = [
    # (block, config, arm, trial suffix, connection dirs, native connection, expected ok)
    ('rc01_hw_c68_20261026_01_reference_rest', C68_REF, 'off', 't0', None, None, True),
    ('rc01_hw_c68_20261026_01_reference_rest', C68_REF, 'combined', 't0', None, None, True),
    ('rc01_hw_c68_20261026_04_reference_rest', 'rc01_m12p_c68_sdk9132_sel751_d20oc_reference_rest.json',
     'combined', 't0', None, None, True),
    ('rc01_hw_c68_20261026_06_loss_full_950', C68_LOSS_FULL, 'combined', 't2', None, None, True),
    ('rc01_hw_c68_20261026_06_loss_full_950', C68_LOSS_FULL, 'combined', 't3', None, None, False),
    ('rc01_hw_c67_20261025_07_persistence_graceful_950',
     'rc01_m12p_c67_sdk9132_sel751_d20_persistence_graceful_950.json', 'combined', 't0', ('c1', 'c2', 'c3'), None, True),
    ('rc01_hw_c67_20261025_07_persistence_rst_950',
     'rc01_m12p_c67_sdk9132_sel751_d20_persistence_rst_950.json', 'combined', 't0', ('c1', 'c2', 'c3'), None, True),
    ('rc01_hw_c67_20261025_07_reconnect_950',
     'rc01_m12p_c67_sdk9132_sel751_d20_reconnect_950.json', 'combined', 't0', ('c1', 'c2', 'c3'), 'c2', True),
    ('rc01_hw_c68_20261025_01_reference_rest', C68_REF, 'off', 't0', None, None, False),
]


@pytest.mark.parametrize('block,config,arm,suffix,connections,native,expected', RETAINED,
                         ids=['%s-%s-%s' % (r[0].split('_20261')[1], r[2], r[3]) for r in RETAINED])
def test_retained_captures_reproduce_their_original_outcome(tmp_path, block, config, arm, suffix, connections,
                                                           native, expected):
    source = _trial_dir(block, arm, suffix)
    recorded = json.loads((source / 'trial.json').read_text())
    assert recorded['ok'] is expected            # the retained record's own verdict
    before = {p: p.stat().st_mtime_ns for p in source.rglob('*') if p.is_file()}
    run_id = block
    runner = _runner(config, run_id)
    dest = _copy(source, tmp_path)
    outcomes = []
    for name in connections or (None,):
        directory = dest / name if name else dest
        trial = dict(recorded, master_port=recorded['master_port'] + (
            runner.cfg['scenarios']['reconnect']['reconnect_port_offset'] if name is not None and name == native else 0))
        failures, verdict, _, _ = _validate(runner, directory, arm, connection_id=name,
                                            unbound_native=(name is not None and name == native), trial=trial)
        outcomes.append(verdict['ok'])
        assert (failures == []) is verdict["ok"], verdict["failures"][:5]
    assert all(outcomes) is expected, failures[:5]
    assert {p: p.stat().st_mtime_ns for p in source.rglob('*') if p.is_file()} == before


def test_relay_verdict_records_a_standards_dimension(mixed_loss, monkeypatch):
    runner, dest = mixed_loss
    import checks
    monkeypatch.setattr(checks, 'evaluate_switch', lambda *args, **kwargs: ([], {}))
    arm = next(a for a in runner.cfg['arms'] if a['name'] == 'combined')
    trial = json.loads((dest / 'trial.json').read_text())
    trial = {k: trial[k] for k in ('fixture', 'label', 'master_port', 'reads')}
    runner.relay_verdict(trial, {}, trial['label'], str(dest), SimpleNamespace(rc=0), arm, 'physical_relay',
                         raise_on_failure=False)
    assert trial['dimension_verdicts']['standards'] is True
    assert json.loads((dest / 'standards_verdict.json').read_text())['ok'] is True


def _relay_trial(dest):
    trial = json.loads((dest / 'trial.json').read_text())
    return {k: trial[k] for k in ('fixture', 'label', 'master_port', 'reads')}


@pytest.mark.parametrize('break_it', ['result_json_missing', 'unsupported_schedule'])
def test_relay_verdict_standards_dimension_fails_closed_when_it_cannot_run(mixed_loss, monkeypatch, break_it):
    runner, dest = mixed_loss
    import checks
    monkeypatch.setattr(checks, 'evaluate_switch', lambda *args, **kwargs: ([], {}))
    if break_it == 'result_json_missing':
        (dest / 'result.json').unlink()
    else:
        runner.cfg['traffic']['read_schedule'] = 'unsupported'
    arm = next(a for a in runner.cfg['arms'] if a['name'] == 'combined')
    trial = _relay_trial(dest)
    runner.relay_verdict(trial, {}, trial['label'], str(dest), SimpleNamespace(rc=0), arm, 'physical_relay',
                         raise_on_failure=False)
    assert trial['dimension_verdicts']['standards'] is False
    assert trial['ok'] is False and any(': standards' in f or 'single: ' in f for f in trial['failures'])


def test_ordinary_relay_verdict_raises_on_a_standards_only_failure(mixed_loss, monkeypatch):
    runner, dest = mixed_loss
    import checks
    monkeypatch.setattr(checks, 'evaluate_switch', lambda *args, **kwargs: ([], {}))
    runner.cfg.setdefault('standards', {})['packet_boundary_required'] = True     # stronger than receiver-only
    arm = next(a for a in runner.cfg['arms'] if a['name'] == 'combined')
    trial = _relay_trial(dest)
    with pytest.raises(campaign.StepFailed):
        runner.relay_verdict(trial, {}, trial['label'], str(dest), SimpleNamespace(rc=0), arm, 'physical_relay')
    assert trial['dimension_verdicts'] == dict(application=True, switch=True, standards=False)


def test_reconnect_scenario_drives_native_c2_and_its_port_through_the_production_wiring(tmp_path, monkeypatch):
    import checks
    monkeypatch.setattr(checks, 'evaluate_switch', lambda *args, **kwargs: ([], {}))
    cfg = json.loads((CONFIGS / C67_RECONNECT).read_text())
    runner = campaign.Campaign(cfg, campaign.DryRunner(), 'rc01_hw_c67_20261025_07_reconnect_950',
                               arms=['combined'], scenario='reconnect', reconnect_policy='protected')
    runner.rn.dry = False
    runner.bound = {name: build.get('hashes') for name, build in cfg['builds'].items()}
    dest = _copy(_trial_dir('rc01_hw_c67_20261025_07_reconnect_950', 'combined', 't0'), tmp_path)
    arm = next(a for a in cfg['arms'] if a['name'] == 'combined')
    trial = _relay_trial(dest)
    runner.verdict_scenario(trial, trial['label'], str(dest), SimpleNamespace(rc=0), arm)
    assert trial['dimension_verdicts']['standards'] is True, trial['failures']
    expected = {name: json.loads((dest / name / 'standards.json').read_text())['expected'] for name in ('c1', 'c2', 'c3')}
    assert expected['c2']['padded'] is False and expected['c1']['padded'] is expected['c3']['padded'] is True

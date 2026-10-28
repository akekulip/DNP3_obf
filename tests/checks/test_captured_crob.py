"""Wire/application regression checks for the current SEL-751 receiver validator."""
import json

import pytest

from scripts.checks import relay_check, standards
from fixtures import control, conversation


def expected(padded):
    return dict(counts=dict(READ=0, SELECT=1, OPERATE=1), read_schedule='full', read_classes={}, padded=padded)


@pytest.mark.parametrize('padded', [False, True])
@pytest.mark.parametrize('split_tcp', [False, True])
def test_success_and_exact_control_images(tmp_path, padded, split_tcp):
    captures = conversation(tmp_path, padded=padded, split_tcp=split_tcp)
    observed = standards._sel751_observed({'master_port': 59410}, captures, expected(padded))
    assert observed['aggregate_verdict'], observed
    size = 60 if padded else 49
    assert observed['exchanges']['SELECT']['resp_len'] == [size]
    assert observed['exchanges']['OPERATE']['resp_len'] == [size]


@pytest.mark.parametrize('padded', [False, True])
@pytest.mark.parametrize('forge_success', [False, True])
def test_delivered_timeout_is_transport_success_and_application_failure(tmp_path, padded, forge_success):
    captures = conversation(tmp_path, status=1, padded=padded, forge_success=forge_success)
    observed = standards._sel751_observed({'master_port': 59410}, captures, expected(padded))
    assert observed['transport_ok'] and observed['size_ok'], observed
    assert observed['select_authorizes_operate'] is True
    assert observed['operate_success'] is False and observed['aggregate_verdict'] is False
    assert any('TIMEOUT' in error for error in observed['application_failures'])
    report = relay_check.analyze(tmp_path, 59410, expected(padded)['counts'], 'full')
    assert report['exchanges'][1]['application']['points'] == [[1, 'TIMEOUT'], [3, 'TIMEOUT']]


def test_metadata_application_cannot_hide_wire_timeout(tmp_path):
    captures = conversation(tmp_path, status=1, forge_success=True)
    path = tmp_path / 'master.json'
    master = json.loads(path.read_text())
    master['records'][1]['response_app_hex'] = control('OPERATE', 1, 0, True)[3].hex()
    path.write_text(json.dumps(master))
    observed = standards._sel751_observed({'master_port': 59410}, captures, expected(True))
    assert not observed['aggregate_verdict']
    assert any('metadata differs' in error for error in observed['application_failures'])


def test_crob_guarded_parameters_and_echo_are_checked_from_wire(tmp_path):
    captures = conversation(tmp_path, on_ms=201)
    observed = standards._sel751_observed({'master_port': 59410}, captures, expected(True))
    assert observed['transport_ok'] and not observed['operate_success']
    assert any('guarded request' in error for error in observed['application_failures'])


def test_wire_echo_must_match_captured_request():
    request, _, app, _ = control('OPERATE', 0, 0, True)
    _, response, _, response_app = control('OPERATE', 0, 0, True, on_ms=201)
    record = dict(operation='OPERATE', request_app_hex=app.hex(), response_app_hex=response_app.hex(),
                  points=[[1, 'SUCCESS'], [3, 'SUCCESS']])
    observation = relay_check.application_observation(request, b''.join(response), record)
    assert not observation['ok']
    assert any('echo differs' in error for error in observation['failures'])


def test_current_endpoint_scope_is_explicit():
    with pytest.raises(ValueError, match='endpoint_profile sel751'):
        standards.expected_identity({'config': {'endpoint_profile': 'software'}})


def context():
    arm = dict(name='combined', build='current', padding=True, timing=True)
    return dict(config=dict(endpoint_profile='sel751', arms=[arm], traffic=dict(run_sbo=True, sbo_cycles=1,
                    read_schedule='full'), builds={'current': dict(profile='current_sel751',
                    hashes={'p0/tofino.bin': 'a' * 64})}), arm=arm,
                run_id='synthetic_current', connection_id='single', master_port=59410,
                trial=dict(label='controls', reads=0), candidate_source_sha256='b' * 64,
                checker_files=[standards.__file__, relay_check.__file__])


def test_public_artifact_is_run_and_capture_bound(tmp_path):
    captures = conversation(tmp_path)
    ctx = context()
    artifact = standards.build_standards_artifact(ctx, captures)
    assert standards.validate_standards(artifact, ctx, captures)['ok']
    ctx['run_id'] = 'another_run'
    assert not standards.validate_standards(artifact, ctx, captures)['ok']
    ctx['run_id'] = 'synthetic_current'
    (tmp_path / 'in.pcap').write_bytes((tmp_path / 'in.pcap').read_bytes()[:-1])
    assert not standards.validate_standards(artifact, ctx, captures)['ok']


@pytest.mark.parametrize('missing', list(standards.SEL751_CAPTURE_FILES))
def test_public_validator_never_passes_an_unevaluated_check(tmp_path, missing):
    captures = conversation(tmp_path)
    ctx = context()
    artifact = standards.build_standards_artifact(ctx, captures)
    (tmp_path / standards.SEL751_CAPTURE_FILES[missing]).unlink()
    assert not standards.validate_standards(artifact, ctx, captures)['ok']


def test_forged_master_and_new_artifact_still_fail_public_validator(tmp_path):
    captures = conversation(tmp_path, status=1, forge_success=True)
    ctx = context()
    artifact = standards.build_standards_artifact(ctx, captures)
    verdict = standards.validate_standards(artifact, ctx, captures)
    assert not verdict['ok']
    assert verdict['verdicts'] == dict(transport=True, application=False, size=True)


def test_receiver_capture_cannot_claim_switch_emission_proof(tmp_path):
    captures = conversation(tmp_path)
    ctx = context()
    ctx['packet_boundary_required'] = True
    artifact = standards.build_standards_artifact(ctx, captures)
    verdict = standards.validate_standards(artifact, ctx, captures)
    assert not verdict['ok']
    assert any('emission proof required' in error for error in verdict['failures'])


def test_current_clrt_is_reported_per_class_without_a_precision_gate(tmp_path):
    captures=conversation(tmp_path)
    report=relay_check.analyze(tmp_path,59410,dict(READ=0,SELECT=1,OPERATE=1),'full')
    visible=relay_check.visible_clrt(report)
    assert set(visible)=={'READ mixed','READ integrity','SELECT','OPERATE'}
    assert visible['SELECT']['values_us']==[1.0]
    ctx=context()
    ctx['config']['timing_params_ns']=dict(gap=5000000,budget=240000,enabled=1)
    artifact=standards.build_standards_artifact(ctx,captures)
    assert standards.validate_standards(artifact,ctx,captures)['ok']

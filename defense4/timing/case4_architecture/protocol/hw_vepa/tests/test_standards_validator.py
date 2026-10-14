import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import pcaptk as tk  # noqa: E402
import standards  # noqa: E402


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value))


def tcp_frame(payload, sport=20000, dport=24000):
    return tk.frame('192.168.10.62', '192.168.10.61', sport, dport, 1000, 2000, tk.PSH | tk.ACK, payload)


def add_boundary_captures(tmp_path, captures, *, segment_count=5, payload_len=61):
    in_path = Path(captures['in']['path'])
    tk.write_pcap(str(in_path), [
        (100 + i, tcp_frame(tk.read_response(app_seq=i % 16, body_len=40)[:payload_len]))
        for i in range(segment_count)
    ])
    calibration_frames = [bytes([0x11]) * 256, bytes([0x22]) * 256]
    calibration_in = tmp_path / 'calibration_in.pcap'
    calibration_out = tmp_path / 'calibration_out.pcap'
    tk.write_pcap(str(calibration_out), [(100, tcp_frame(calibration_frames[0], 24000, 20000)),
                                         (101, tcp_frame(calibration_frames[1], 24000, 20000))])
    tk.write_pcap(str(calibration_in), [(200, tcp_frame(calibration_frames[0])),
                                        (201, tcp_frame(calibration_frames[1]))])
    capture_offloads = tmp_path / 'capture_offloads.json'
    calibration_expected = tmp_path / 'calibration_expected.json'
    calibration_result = tmp_path / 'calibration_result.json'
    run_result = tmp_path / 'result.json'
    before = {'gro': True, 'lro': False, 'rx-gro-hw': False, 'rx-gro-list': False}
    write_json(capture_offloads, {
        'interface': 'enp1s0',
        'before': {'features': before, 'raw': 'before', 'command': 'ethtool -k enp1s0'},
        'during': {'features': {'gro': False, 'lro': False, 'rx-gro-hw': False, 'rx-gro-list': False},
                   'raw': 'during', 'command': 'ethtool -K enp1s0 gro off'},
        'after': {'features': before, 'raw': 'after', 'command': 'ethtool -K enp1s0 gro on'},
        'restore_ok': True,
        'commands': ['ethtool -k enp1s0', 'ethtool -K enp1s0 gro off'],
    })
    write_json(calibration_expected, {
        'interface': 'enp1s0',
        'source_namespace': 'vision-test',
        'send_command': 'afpacket-calibrate --payload 256',
        'direction': 'in',
        'tuple': {'src': '192.168.10.62', 'dst': '192.168.10.61', 'sport': 20000, 'dport': 24000},
        'frames': [payload.hex() for payload in calibration_frames],
    })
    write_json(calibration_result, {'capture_commands': ['tcpdump -i enp1s0 -Q in'],
                                    'tcpdump_stats': {'captured': 2, 'dropped_kernel': 0,
                                                      'dropped_interface': 0}})
    write_json(run_result, {'capture_commands': {'in': 'tcpdump -i enp1s0 -Q in -w in.pcap'},
                            'tcpdump_stats': {'captured': segment_count, 'dropped_kernel': 0,
                                              'dropped_interface': 0}})
    captures.update({
        'capture_offloads': {'path': str(capture_offloads)},
        'calibration_expected': {'path': str(calibration_expected)},
        'calibration_in': {'path': str(calibration_in)},
        'calibration_out': {'path': str(calibration_out)},
        'calibration_result': {'path': str(calibration_result)},
        'run_result': {'path': str(run_result)},
    })
    return captures


def base_context(tmp_path, *, arm_name='combined', padding=1, image_len=61, control_padding=True):
    capture = tmp_path / 'in.pcap'
    capture.write_bytes(b'capture bytes for this run')
    out_capture = tmp_path / 'out.pcap'
    out_capture.write_bytes(b'out capture bytes for this run')
    checker = tmp_path / 'checker.py'
    checker.write_text('checker-version-1\n')
    cfg = {
        'arms': [{'name': arm_name, 'padding': padding, 'T': 1, 'build': 'candidate61'}],
        'builds': {
            'candidate61': {
                'image_len': image_len,
                'control_padding': control_padding,
                'profile': 'candidate61',
                'hashes': {'bfrt.json': 'b' * 64},
            }
        },
        'traffic': {'run_sbo': True},
    }
    run_record = {
        'run_id': 'run-a',
        'config_sha256': standards.effective_config_hash(cfg),
        'source_identity': {'runner_files': {'campaign.py': 'c' * 64}},
        'builds': {'candidate61': {'bfrt.json': 'b' * 64}},
    }
    context = {
        'config': cfg,
        'run_record': run_record,
        'trial': {'label': 'trial-a', 'reads': 3},
        'connection_id': 'c1',
        'arm': cfg['arms'][0],
        'checker_files': [checker],
        'candidate_source_sha256': 'a' * 64,
        'profile_identity': 'candidate61',
        'packet_boundary_required': True,
    }
    captures = {'in': {'path': str(capture)}, 'out': {'path': str(out_capture)}}
    add_boundary_captures(tmp_path, captures)
    return context, captures


def valid_artifact(tmp_path, context, captures):
    capture_path = Path(captures['in']['path'])
    return {
        'schema_version': standards.SCHEMA_VERSION,
        'run': {
            'run_id': 'run-a',
            'trial': 'trial-a',
            'connection': 'c1',
            'arm': context['arm']['name'],
        },
        'identity': {
            'candidate_source_sha256': 'a' * 64,
            'build': 'candidate61',
            'build_hashes': {'bfrt.json': 'b' * 64},
            'profile': 'candidate61',
            'profile_hash': standards.profile_hash(context['config']['builds']['candidate61']),
            'effective_config_sha256': standards.effective_config_hash(context['config']),
        },
        'checker': {
            'version': standards.checker_version(context['checker_files']),
            'dependency_closure_sha256': standards.dependency_closure_hash(context['checker_files']),
        },
        'captures': standards._capture_hashes(captures),
        'expected': {
            'counts': {'READ': 3, 'SELECT': 1, 'OPERATE': 1},
            'lengths': {'READ': [61], 'SELECT': [61], 'OPERATE': [61]},
        },
        'observed': {
            'checker_result': {
                'conformant': True,
                'require_handshake': True,
                'expected_lengths': {'READ': [61], 'SELECT': [61], 'OPERATE': [61]},
                'expected_counts': {'READ': 3, 'SELECT': 1, 'OPERATE': 1},
                'outstation_port': 20000,
                'master_port': 24000,
                'raw_result': {'verdicts': [
                    {'index': 0, 'kind': 'READ', 'wire_len': 61, 'app_seq': 0, 'ok': True},
                    {'index': 1, 'kind': 'READ', 'wire_len': 61, 'app_seq': 1, 'ok': True},
                    {'index': 2, 'kind': 'READ', 'wire_len': 61, 'app_seq': 2, 'ok': True},
                    {'index': 3, 'kind': 'SELECT', 'wire_len': 61, 'app_seq': 3, 'ok': True},
                    {'index': 4, 'kind': 'OPERATE', 'wire_len': 61, 'app_seq': 4, 'ok': True},
                ]},
                'result_sha256': 'f' * 64,
            },
            'exchanges': [
                {'kind': 'READ', 'count': 3, 'resp_len': [61], 'complete': 3, 'failures': []},
                {'kind': 'SELECT', 'count': 1, 'resp_len': [61], 'complete': 1, 'failures': []},
                {'kind': 'OPERATE', 'count': 1, 'resp_len': [61], 'complete': 1, 'failures': []},
            ],
            'failures': [],
            'transport_ok': True,
            'select_authorizes_operate': True,
            'operate_success': True,
            'aggregate_verdict': True,
            'precision': standards.precision_block(True, PASSING_PRECISION),
        },
    }


PASSING_PRECISION = {'pass': True, 'eligible': 500, 'gated': True, 'absolute_error_us': {'p99': 51.0}}
FAILING_PRECISION = {'pass': False, 'eligible': 50, 'gated': True, 'minimum_eligible': 20,
                     'maximum_p99_absolute_error_us': 100, 'absolute_error_us': {'p99': 144.0}}


def test_valid_artifact_passes_with_identity_bound_to_context(tmp_path):
    context, captures = base_context(tmp_path)
    result = standards.validate_standards(valid_artifact(tmp_path, context, captures), context, captures)
    assert result['ok'] is True
    assert result['expected']['lengths']['READ'] == [61]


def test_copied_artifact_from_another_run_is_rejected(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    artifact['run']['run_id'] = 'run-b'
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('run.run_id' in failure for failure in result['failures'])


def test_mutated_capture_hash_is_rejected_even_when_artifact_claims_pass(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    Path(captures['in']['path']).write_bytes(b'altered capture bytes')
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('captures.in.sha256' in failure for failure in result['failures'])


def test_incomplete_context_is_rejected_even_if_artifact_matches_missing_values(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    context['candidate_source_sha256'] = None
    context['checker_files'] = []
    context['run_record']['run_id'] = None
    artifact['run']['run_id'] = None
    artifact['identity']['candidate_source_sha256'] = None
    artifact['checker']['version'] = standards.checker_version([])
    artifact['checker']['dependency_closure_sha256'] = standards.dependency_closure_hash([])
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('context.run.run_id' in failure for failure in result['failures'])
    assert any('context.identity.candidate_source_sha256' in failure for failure in result['failures'])
    assert any('context.checker_files' in failure for failure in result['failures'])


def test_required_in_out_captures_are_context_requirements(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    result = standards.validate_standards(artifact, context, {})
    assert result['ok'] is False
    assert any('context.captures.out' in failure for failure in result['failures'])
    assert any('context.captures.in' in failure for failure in result['failures'])


def test_filtered_capture_must_bind_sources_and_filter_procedure(tmp_path):
    context, captures = base_context(tmp_path)
    source = tmp_path / 'source.pcap'
    filtered = tmp_path / 'filtered.pcap'
    source.write_bytes(b'source')
    filtered.write_bytes(b'filtered')
    captures = dict(captures)
    captures['filtered'] = {'path': str(filtered), 'filtered_from': {'source': str(source)},
                            'filter_procedure': 'remove declared replayed old frames by seq interval'}
    artifact = valid_artifact(tmp_path, context, captures)
    artifact['captures'] = standards._capture_hashes(captures)
    artifact['captures']['filtered'].pop('filter_procedure', None)
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('filter_procedure' in failure for failure in result['failures'])
    artifact['captures']['filtered']['filter_procedure'] = 'wrong filter'
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('filter_procedure mismatch' in failure for failure in result['failures'])
    artifact['captures']['filtered']['filter_procedure'] = captures['filtered']['filter_procedure']
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is True


def test_build_artifact_preserves_filtered_capture_procedure(tmp_path):
    context, captures = base_context(tmp_path)
    source = tmp_path / 'raw-out.pcap'
    filtered = tmp_path / 'current-out.pcap'
    source.write_bytes(b'raw source bytes')
    filtered.write_bytes(b'filtered current bytes')
    captures = dict(captures)
    captures['out'] = {'path': str(filtered), 'filtered_from': {'raw_out': str(source)},
                       'filter_procedure': {'removed': 2, 'method': 'seq-window'}}
    artifact = standards.build_standards_artifact(
        context, captures,
        {'checker_result': {'conformant': True, 'failures': [], 'verdicts': []},
         'transport_ok': True, 'select_authorizes_operate': True,
         'operate_success': True, 'aggregate_verdict': True})
    assert artifact['captures']['out']['filter_procedure'] == captures['out']['filter_procedure']
    result = standards.validate_standards(artifact, context, captures)
    assert not any('filter_procedure' in failure for failure in result['failures'])


def test_packet_boundary_required_gate_fails_closed_without_real_evidence(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    artifact['packet_boundary'] = {'qualified': True, 'segment_evidence': []}
    captures = dict(captures)
    captures.pop('capture_offloads')
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('packet_boundary' in failure or 'context.captures.capture_offloads' in failure
               for failure in result['failures'])


@pytest.mark.parametrize(
    'profile,arm,padding,image_len,control_padding,want_read,want_sbo',
    [
        ('candidate61', 'off', 0, 61, True, 49, 37),
        ('candidate61', 'timing_only', 0, 61, True, 49, 37),
        ('candidate61', 'size_only', 1, 61, True, 61, 61),
        ('candidate61', 'combined', 1, 61, True, 61, 61),
        ('strict_comparison', 'combined', 1, 58, False, 58, 37),
        ('strict_comparison', 'off', 0, 58, False, 49, 37),
        ('unbound_native', 'combined', 1, 58, True, 49, 37),
    ],
)
def test_profile_arm_length_table(tmp_path, profile, arm, padding, image_len, control_padding, want_read, want_sbo):
    context, captures = base_context(
        tmp_path, arm_name=arm, padding=padding, image_len=image_len, control_padding=control_padding
    )
    context['config']['builds']['candidate61']['profile'] = profile
    artifact = valid_artifact(tmp_path, context, captures)
    artifact['identity']['profile'] = profile
    artifact['identity']['profile_hash'] = standards.profile_hash(context['config']['builds']['candidate61'])
    artifact['expected']['lengths'] = {'READ': [want_read], 'SELECT': [want_sbo], 'OPERATE': [want_sbo]}
    artifact['observed']['checker_result']['expected_lengths'] = artifact['expected']['lengths']
    for exchange in artifact['observed']['exchanges']:
        exchange['resp_len'] = artifact['expected']['lengths'][exchange['kind']]
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is True


def test_transport_ok_does_not_imply_successful_sbo(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    artifact['observed']['transport_ok'] = True
    artifact['observed']['select_authorizes_operate'] = False
    artifact['observed']['operate_success'] = False
    artifact['observed']['aggregate_verdict'] = False
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('select_authorizes_operate' in failure for failure in result['failures'])
    assert any('operate_success' in failure for failure in result['failures'])


def test_checker_result_must_bind_handshake_lengths_and_counts(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    artifact['observed']['checker_result']['require_handshake'] = False
    artifact['observed']['checker_result']['expected_lengths']['READ'] = [49]
    artifact['observed']['checker_result']['expected_counts']['READ'] = 2
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('checker_result.require_handshake' in failure for failure in result['failures'])
    assert any('checker_result.expected_lengths' in failure for failure in result['failures'])
    assert any('checker_result.expected_counts' in failure for failure in result['failures'])


def test_build_standards_artifact_uses_observed_failures_and_writes_exact_lengths(tmp_path):
    context, captures = base_context(tmp_path)
    observed = {
        'exchanges': [{'kind': 'READ', 'count': 3, 'resp_len': [60], 'complete': 3, 'failures': []}],
        'failures': ['READ response length wrong'],
        'transport_ok': True,
        'select_authorizes_operate': True,
        'operate_success': True,
        'aggregate_verdict': False,
    }
    artifact = standards.build_standards_artifact(context, captures, observed)
    assert artifact['expected']['lengths'] == {'READ': [61], 'SELECT': [61], 'OPERATE': [61]}
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('observed.failures' in failure for failure in result['failures'])



def test_malformed_context_is_rejected_without_crashing(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    context['trial']['reads'] = 'not-an-int'
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False
    assert any('context malformed' in failure for failure in result['failures'])


# ---- precision status: serialized, reloaded, and kept apart from standards conformance -------------------

def _write_and_validate(tmp_path, context, captures, precision_block):
    artifact = valid_artifact(tmp_path, context, captures)
    artifact['observed']['precision'] = precision_block
    path = tmp_path / 'standards.json'
    path.write_text(json.dumps(artifact))
    return json.loads(path.read_text()), standards.validate_standards(str(path), context, captures)


def test_precision_pass_round_trips_and_qualifies(tmp_path):
    context, captures = base_context(tmp_path)
    reloaded, result = _write_and_validate(tmp_path, context, captures,
                                           standards.precision_block(True, PASSING_PRECISION))
    assert reloaded['observed']['precision']['status'] == 'pass'
    assert result['ok'] is True and result['qualification'] == 'qualified'
    assert result['precision']['status'] == 'pass'


def test_missing_precision_block_is_rejected(tmp_path):
    context, captures = base_context(tmp_path)
    artifact = valid_artifact(tmp_path, context, captures)
    del artifact['observed']['precision']
    result = standards.validate_standards(artifact, context, captures)
    assert result['ok'] is False and result['qualification'] == 'rejected'
    assert any('observed.precision missing' in f for f in result['failures'])


def test_timed_arm_without_precision_evidence_is_rejected(tmp_path):
    context, captures = base_context(tmp_path)
    block = standards.precision_block(True, None)
    assert block['status'] == 'fail' and block['reasons'] == ['READ precision evidence missing']
    _, result = _write_and_validate(tmp_path, context, captures, block)
    assert result['ok'] is True                       # conformance is separate
    assert result['qualification'] == 'rejected'


def test_precision_failure_in_qualification_purpose_is_rejected_not_hidden(tmp_path):
    context, captures = base_context(tmp_path)
    block = standards.precision_block(True, FAILING_PRECISION, 'qualification')
    assert block['status'] == 'fail' and '144.0' in block['reasons'][0]
    reloaded, result = _write_and_validate(tmp_path, context, captures, block)
    assert reloaded['observed']['precision']['reasons'] == block['reasons']
    assert result['ok'] is True and result['qualification'] == 'rejected'


def test_retained_14892_shape_is_measurement_only(tmp_path):
    """candidate61_compare_14892_950_02: structurally conformant, precision failing, characterization purpose."""
    context, captures = base_context(tmp_path)
    context['config']['evaluation'] = {'purpose': 'timing_precision_characterization', 'read_precision': True}
    block = standards.precision_block(True, FAILING_PRECISION, 'timing_precision_characterization')
    assert block['status'] == 'deferred'
    _, result = _write_and_validate(tmp_path, context, captures, block)
    assert result['ok'] is True and result['qualification'] == 'measurement_only'


def test_deferred_outside_characterization_is_a_validation_failure(tmp_path):
    context, captures = base_context(tmp_path)
    block = standards.precision_block(True, FAILING_PRECISION, 'timing_precision_characterization')
    _, result = _write_and_validate(tmp_path, context, captures, block)
    assert result['ok'] is False and result['qualification'] == 'rejected'


def test_untimed_arm_is_not_applicable_and_qualifies(tmp_path):
    context, captures = base_context(tmp_path, arm_name='size_only')
    context['arm']['T'] = 0
    block = standards.precision_block(False, None, reason='size_only arm has no timing target')
    _, result = _write_and_validate(tmp_path, context, captures, block)
    assert result['precision']['status'] == 'not_applicable'
    assert result['ok'] is True and result['qualification'] == 'qualified'


@pytest.mark.parametrize('block, needle', [
    ({'required': True, 'status': 'not_applicable', 'reasons': ['x']}, 'required but status not_applicable'),
    ({'required': False, 'status': 'pass', 'reasons': []}, 'not required but status'),
    ({'required': True, 'status': 'pass', 'reasons': [], 'evidence': FAILING_PRECISION}, 'does not support'),
    ({'required': True, 'status': 'fail', 'reasons': []}, 'without reasons'),
    ({'required': True, 'status': 'ok', 'reasons': []}, 'not in'),
])
def test_inconsistent_precision_blocks_are_rejected(tmp_path, block, needle):
    context, captures = base_context(tmp_path)
    _, result = _write_and_validate(tmp_path, context, captures, block)
    assert result['ok'] is False and result['qualification'] == 'rejected'
    assert any(needle in f for f in result['failures']), result['failures']


# ---- review fixes: the requirement comes from the context, and claimed statuses are re-checked ---------------

def test_timed_arm_cannot_self_declare_not_applicable(tmp_path):
    context, captures = base_context(tmp_path)                      # combined, T=1, separate_ack by default
    _, result = _write_and_validate(tmp_path, context, captures,
                                    {'required': False, 'status': 'not_applicable', 'reasons': ['x']})
    assert result['ok'] is False and result['qualification'] == 'rejected'
    assert any('the context requires True' in f for f in result['failures']), result['failures']


@pytest.mark.parametrize('evidence', [
    {'pass': True, 'eligible': 0, 'absolute_error_us': {'p99': 10.0}},
    {'pass': True, 'eligible': 500, 'absolute_error_us': {'p99': 9999.0}},
    {'pass': True, 'eligible': 500},
])
def test_claimed_pass_is_rechecked_against_the_fixed_bound(tmp_path, evidence):
    context, captures = base_context(tmp_path)
    block = {'required': True, 'status': 'pass', 'reasons': [], 'evidence': evidence}
    _, result = _write_and_validate(tmp_path, context, captures, block)
    assert result['ok'] is False and result['qualification'] == 'rejected'
    assert any('does not support' in f for f in result['failures']), result['failures']


def test_insufficient_evidence_is_never_deferred():
    thin = {'pass': False, 'eligible': 5, 'absolute_error_us': {'p99': 144.0}}
    assert standards.precision_block(True, thin, 'timing_precision_characterization')['status'] == 'fail'
    assert standards.precision_block(True, {'pass': False}, 'timing_precision_characterization')['status'] == 'fail'


def test_declared_exemption_and_unbound_connections_are_not_applicable(tmp_path):
    context, captures = base_context(tmp_path)
    context['precision_exempt'] = 'loss/recovery trial: READ precision is not evaluated'
    assert standards.precision_requirement(context) == (False, context['precision_exempt'])
    _, result = _write_and_validate(tmp_path, context, captures,
                                    standards.precision_block(False, None, reason=context['precision_exempt']))
    assert result['ok'] is True and result['qualification'] == 'qualified'
    unbound = dict(context, precision_exempt=None, unbound_native=True)
    assert standards.precision_requirement(unbound)[0] is False


def test_piggyback_fixture_has_no_clrt_target(tmp_path):
    context, _ = base_context(tmp_path)
    context['trial'] = dict(context['trial'], fixture='piggyback')
    required, reason = standards.precision_requirement(context)
    assert required is False and 'piggyback' in reason

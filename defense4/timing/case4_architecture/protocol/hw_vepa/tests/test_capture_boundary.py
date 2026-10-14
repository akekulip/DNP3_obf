import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import capture_boundary  # noqa: E402
import pcaptk as tk  # noqa: E402


def write_json(path, value):
    Path(path).write_text(json.dumps(value))


def frame(payload, sport=20000, dport=24000, src='192.168.10.62', dst='192.168.10.61', seq=1000):
    return tk.frame(src, dst, sport, dport, seq, 2000, tk.PSH | tk.ACK, payload)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def response_payload(appseq, body_len=40):
    return tk.read_response(app_seq=appseq, body_len=body_len)


def checker_result(*appseqs, payloads=None):
    payloads = payloads or [response_payload(appseq) for appseq in appseqs]
    return {'outstation_port': 20000, 'master_port': 24000, 'raw_result': {
        'verdicts': [{'index': i, 'kind': 'READ', 'wire_len': 61, 'app_seq': appseq, 'ok': True,
                      'request_serial': i, 'wire_image_sha256': sha(payloads[i]),
                      'tuple': {'src': {'ip': '192.168.10.62', 'port': 20000},
                                'dst': {'ip': '192.168.10.61', 'port': 24000}, 'incarnation': 0}}
                     for i, appseq in enumerate(appseqs)]}}


def make_boundary(tmp_path, *, physical_len=61, offload_gro=False, restored=True,
                  calibration=True, drop_stats=0, include_attempt=True, appseqs=(0,), random61=False,
                  split_extra=False, different_same_appseq=False):
    physical = tmp_path / 'in.pcap'
    calibration_in = tmp_path / 'calibration_in.pcap'
    calibration_out = tmp_path / 'calibration_out.pcap'
    offloads = tmp_path / 'capture_offloads.json'
    expected = tmp_path / 'calibration_expected.json'
    calibration_result = tmp_path / 'calibration_result.json'
    run_result = tmp_path / 'result.json'

    physical_records = []
    if include_attempt:
        for i, appseq in enumerate(appseqs):
            physical_records.append((100 + i, frame(response_payload(appseq)[:physical_len], seq=5000 + i * physical_len)))
    if split_extra:
        physical_records.append((250, frame(response_payload(appseqs[0])[:20], seq=7000)))
    if different_same_appseq:
        physical_records.append((260, frame(tk.read_response(app_seq=appseqs[0], func=0x82, body_len=40), seq=8000)))
    if random61:
        physical_records.append((300, frame(bytes([0x42]) * 61, seq=9000)))
    tk.write_pcap(str(physical), physical_records)

    calibration_payloads = [bytes([0x11]) * 256, bytes([0x22]) * 256]
    calibration_in_frames = [frame(calibration_payloads[0], seq=1000), frame(calibration_payloads[1], seq=1256)]
    calibration_out_frames = list(calibration_in_frames)
    tk.write_pcap(str(calibration_out), [(100, calibration_out_frames[0]), (101, calibration_out_frames[1])])
    tk.write_pcap(str(calibration_in), [(200, calibration_in_frames[0]), (201, calibration_in_frames[1])])
    write_json(expected, {
        'interface': 'enp1s0',
        'source_namespace': 'vision-test',
        'send_command': 'afpacket-calibrate --payload 256',
        'direction': 'in',
        'tuple': {'src': '192.168.10.62', 'dst': '192.168.10.61', 'sport': 20000, 'dport': 24000},
        'frames': [frame_bytes.hex() for frame_bytes in calibration_in_frames],
    })
    features_before = {'gro': True, 'lro': False, 'rx-gro-hw': False, 'rx-gro-list': False}
    features_during = {'gro': offload_gro, 'lro': False, 'rx-gro-hw': False, 'rx-gro-list': False}
    write_json(offloads, {
        'interface': 'enp1s0',
        'before': {'features': features_before, 'raw': 'before', 'command': 'ethtool -k enp1s0'},
        'during': {'features': features_during, 'raw': 'during', 'command': 'ethtool -K enp1s0 gro off'},
        'after': {'features': features_before if restored else features_during,
                  'raw': 'after', 'command': 'ethtool -K enp1s0 gro on'},
        'restore_ok': restored,
        'commands': ['ethtool -k enp1s0', 'ethtool -K enp1s0 gro off'],
    })
    stats = {'captured': 2, 'dropped_kernel': drop_stats, 'dropped_interface': 0}
    write_json(calibration_result, {'capture_commands': ['tcpdump -i enp1s0 -Q in'], 'tcpdump_stats': stats})
    write_json(run_result, {'capture_commands': {'in': 'tcpdump -i enp1s0 -Q in -w in.pcap'},
                            'tcpdump_stats': {'captured': 1 if include_attempt else 0,
                                              'dropped_kernel': 0, 'dropped_interface': 0}})
    return {
        'in': {'path': str(physical)},
        'capture_offloads': {'path': str(offloads)},
        'calibration_expected': {'path': str(expected)},
        'calibration_in': {'path': str(calibration_in)},
        'calibration_out': {'path': str(calibration_out)},
        'calibration_result': {'path': str(calibration_result)},
        'run_result': {'path': str(run_result)},
    }


def test_valid_boundary_evidence_binds_files_and_segment_length(tmp_path):
    captures = make_boundary(tmp_path)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is True


def test_empty_attempts_fail_when_transformed_segments_are_expected(tmp_path):
    captures = make_boundary(tmp_path, include_attempt=False)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('no protected response payload evidence' in failure or 'missing transformed response attempts' in failure for failure in result['failures'])


def test_payload_length_mismatch_fails(tmp_path):
    captures = make_boundary(tmp_path, physical_len=60)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('protected response segment' in failure and 'expected 61' in failure for failure in result['failures'])


def test_capture_offload_settings_must_disable_receive_aggregation(tmp_path):
    captures = make_boundary(tmp_path, offload_gro=True)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('during.gro' in failure for failure in result['failures'])


def test_calibration_boundaries_and_drop_stats_are_required(tmp_path):
    captures = make_boundary(tmp_path, drop_stats=3)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('dropped_kernel' in failure for failure in result['failures'])
    Path(captures['calibration_in']['path']).write_bytes(Path(captures['calibration_out']['path']).read_bytes()[:80])
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('calibration_in' in failure for failure in result['failures'])


def test_restore_must_be_verified(tmp_path):
    captures = make_boundary(tmp_path, restored=False)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('restore_ok' in failure or 'after features' in failure for failure in result['failures'])


def test_main_capture_must_retain_incoming_command_and_stats(tmp_path):
    captures = make_boundary(tmp_path)
    write_json(captures['run_result']['path'], {'capture_commands': {'out': 'tcpdump -Q out'},
                                                'tcpdump_stats': {'captured': 1, 'dropped_kernel': 0,
                                                                  'dropped_interface': 0}})
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('incoming physical capture command' in failure for failure in result['failures'])


def test_random_61_byte_tcp_segment_is_not_boundary_evidence(tmp_path):
    captures = make_boundary(tmp_path, random61=True)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('not a valid DNP3 response' in failure for failure in result['failures'])


def test_missing_checker_bound_response_attempt_fails(tmp_path):
    captures = make_boundary(tmp_path, appseqs=(0,))
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=2, checker_result=checker_result(0, 1))
    assert result['ok'] is False
    assert any('missing transformed response attempts' in failure for failure in result['failures'])


def test_split_protected_server_payload_fails_even_when_expected_response_is_present(tmp_path):
    captures = make_boundary(tmp_path, split_extra=True)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('protected response segment' in failure and 'expected 61' in failure for failure in result['failures'])


def test_same_appseq_different_payload_hash_fails(tmp_path):
    captures = make_boundary(tmp_path, different_same_appseq=True)
    result = capture_boundary.validate_boundary_evidence(
        captures, required_payload_len=61, expected_attempts=1, checker_result=checker_result(0))
    assert result['ok'] is False
    assert any('different image' in failure for failure in result['failures'])

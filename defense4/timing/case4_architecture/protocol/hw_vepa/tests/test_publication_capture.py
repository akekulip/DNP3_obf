"""Additive publication observations keep capture precision and legacy intervals."""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
import pcaptk as tk
import clrt_check as cc
import wire_check as wc


def write_ns(path, records):
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 262144, 1))
        for timestamp, frame in records:
            stream.write(struct.pack('<IIII', timestamp // 10**9, timestamp % 10**9, len(frame), len(frame) + 4))
            stream.write(frame)


def capture(tmp_path, piggy=False):
    m, o = wc.MASTER_IP, wc.OUTSTATION_IP
    req = tk.frame(m, o, 40000, 20000, 1001, 5001, tk.PSH | tk.ACK, tk.read_request())
    ack = tk.frame(o, m, 20000, 40000, 5001, 1021, tk.ACK)
    resp = tk.frame(o, m, 20000, 40000, 5001, 1021, tk.PSH | tk.ACK, tk.read_response())
    base = 1700000000 * 10**9
    op, ip = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    write_ns(op, [(base + 1101, req), (base + 9999, resp)])
    records = [(base + 1307, req), (base + 10203, resp)]
    if not piggy:
        records.insert(1, (base + 2011, ack))
    write_ns(ip, records)
    return op, ip


def test_original_ns_lengths_and_legacy_precision(tmp_path):
    op, ip = capture(tmp_path)
    seg = wc.parse(op)[0][0]
    assert seg['timestamp_ns'] == 1700000000000001101
    assert seg['t_us'] == 1700000000000001
    assert seg['capture_resolution'] == 'ns'
    assert seg['original_len'] == seg['captured_len'] + 4
    row = cc.analyze(op, ip)['exchanges'][0]
    assert (row['ack_lat_us'], row['clrt_us'], row['rt_us']) == (1, 8, 9)
    pub = row['publication']
    assert pub['ack_latency_ns'] == 910
    assert pub['clrt_ns'] == 8192
    assert pub['response_availability_ns'] == 8898
    assert pub['request_delivery_ns'] == 206
    assert pub['operate_hold_ns'] is None
    assert row['observation']['request']['packet_index'] == 0
    json.dumps(cc.analyze(op, ip), allow_nan=False)


def test_piggyback_is_null_only_in_publication(tmp_path):
    row = cc.analyze(*capture(tmp_path, piggy=True))['exchanges'][0]
    assert row['clrt_us'] == 0 and row['piggyback']
    assert row['publication']['clrt_ns'] is None
    assert row['publication']['null_reasons']['clrt_ns'] == 'piggyback_ack'


def test_microsecond_pcap_preserves_exact_resolution(tmp_path):
    path = tmp_path / 'us.pcap'
    tk.write_pcap(path, [(1234567, tk.frame(wc.MASTER_IP, wc.OUTSTATION_IP, 1, 2, 1, 0, tk.SYN))])
    seg = wc.parse(path)[0][0]
    assert seg['timestamp_ns'] == 1234567000
    assert seg['capture_resolution'] == 'us'


def test_missing_ack_and_response_stay_null_with_reasons(tmp_path):
    op, ip = capture(tmp_path)
    write_ns(ip, [])
    row = cc.analyze(op, ip)['exchanges'][0]
    assert not row['complete']
    assert row['publication']['clrt_ns'] is None
    assert row['publication']['ack_timestamp_ns'] is None
    assert row['publication']['null_reasons']['ack_latency_ns'] == 'missing_covering_ack'
    assert row['observation']['ack'] is None


def test_retransmitted_request_never_gets_invented_delivery_timestamp(tmp_path):
    op, ip = capture(tmp_path)
    records, _ = wc.read_pcap_records(op)
    write_ns(op, [(records[0]['timestamp_ns'], records[0]['frame']),
                  (records[0]['timestamp_ns'] + 100, records[0]['frame']),
                  (records[1]['timestamp_ns'], records[1]['frame'])])
    row = cc.analyze(op, ip)['exchanges'][0]
    assert row['retransmitted'] and row['attempts'] == 2
    assert len(row['observation']['attempts']) == 2
    assert row['publication']['request_delivery_ns'] is None
    assert row['publication']['null_reasons']['request_delivery_ns'] == 'ambiguous_or_missing_request_reflection'


def test_balanced_capture_loss_cannot_pair_different_request_tcp_sequences(tmp_path):
    def request(seq):
        return tk.frame(wc.MASTER_IP, wc.OUTSTATION_IP, 40000, 20000, seq, 5001, tk.PSH | tk.ACK, tk.read_request())
    op, ip = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    tk.write_pcap(op, [(100, request(1001)), (300, request(1641))])
    tk.write_pcap(ip, [(210, request(1321)), (310, request(1641))])
    rows = cc.analyze(op, ip)['exchanges']
    assert rows[0]['publication']['request_delivery_ns'] is None
    assert rows[0]['observation']['request_delivered'] is None
    assert rows[1]['publication']['request_delivery_ns'] == 10000


def test_balanced_capture_loss_cannot_pair_responses_with_different_ack_identity(tmp_path):
    def response(seq, ack):
        return tk.frame(wc.OUTSTATION_IP, wc.MASTER_IP, 20000, 40000, seq, ack, tk.PSH | tk.ACK, tk.read_response())
    op, ip = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    req = tk.frame(wc.MASTER_IP, wc.OUTSTATION_IP, 40000, 20000, 1001, 5001, tk.PSH | tk.ACK, tk.read_request())
    tk.write_pcap(op, [(100, req), (200, response(5001, 1021)), (400, response(5641, 1661))])
    tk.write_pcap(ip, [(310, response(5321, 1341)), (410, response(5641, 1661))])
    rows = cc.analyze(op, ip)['exchanges']
    assert rows[0]['publication']['response_availability_ns'] is None
    assert rows[0]['observation']['response_available'] is None
    forward, _ = cc._capture_pairs(wc.assign_incarnations(wc.parse(op)[0]), wc.assign_incarnations(wc.parse(ip)[0]))
    assert 1 not in forward
    assert forward[2]['index'] == 1


def test_shared_legacy_response_cannot_establish_multiple_publication_completions(tmp_path):
    def request(seq):
        return tk.frame(wc.MASTER_IP, wc.OUTSTATION_IP, 40000, 20000, seq, 5001, tk.PSH | tk.ACK, tk.read_request())
    response = tk.frame(wc.OUTSTATION_IP, wc.MASTER_IP, 20000, 40000, 5001, 1341, tk.PSH | tk.ACK, tk.read_response())
    op, ip = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    tk.write_pcap(op, [(100, request(1001)), (300, request(1321)), (320, response)])
    tk.write_pcap(ip, [(110, request(1001)), (310, request(1321)), (330, response)])
    rows = cc.analyze(op, ip)['exchanges']
    assert [r['response_packet_index'] for r in rows] == [2, 2]
    assert [r['rt_us'] for r in rows] == [230, 30]  # legacy unchanged
    for row in rows:
        pub = row['publication']
        assert pub['publication_complete'] is False
        assert pub['response_latency_ns'] is None
        assert pub['response_availability_ns'] is None
        assert pub['clrt_ns'] is None
        assert pub['null_reasons']['response_latency_ns'] == 'ambiguous_shared_response'


def test_valid_crc_semantic_mutation_cannot_establish_response_correspondence(tmp_path):
    req = tk.frame(wc.MASTER_IP, wc.OUTSTATION_IP, 40000, 20000, 1001, 5001, tk.PSH | tk.ACK, tk.read_request())
    def response(payload):
        return tk.frame(wc.OUTSTATION_IP, wc.MASTER_IP, 20000, 40000, 5001, 1021, tk.PSH | tk.ACK, payload)
    native = tk.read_response()
    altered = tk.dnp3_frame(bytes([0xc0, 0xc0, 0x81, 0x81, 0]) + bytes([1]) * 28)
    assert wc.dnp3_ok(native)[0] and wc.dnp3_ok(altered)[0]
    op, ip = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    tk.write_pcap(op, [(100, req), (200, response(native))])
    tk.write_pcap(ip, [(110, req), (210, response(altered))])
    row = cc.analyze(op, ip)['exchanges'][0]
    assert row['rt_us'] == 110  # legacy capture result unchanged
    assert row['publication']['response_availability_ns'] is None
    assert row['observation']['response_available'] is None


def test_crc_valid_prefix_of_truncated_tcp_response_is_not_complete_correspondence(tmp_path):
    req = tk.frame(wc.MASTER_IP, wc.OUTSTATION_IP, 40000, 20000, 1001, 5001, tk.PSH | tk.ACK, tk.read_request())
    native = tk.read_response()
    def response(payload):
        return tk.frame(wc.OUTSTATION_IP, wc.MASTER_IP, 20000, 40000, 5001, 1021, tk.PSH | tk.ACK, payload)
    # Captured payload is one CRC-valid frame, but the IP/TCP lengths declare another
    # frame that was not captured. Exact prefix bytes do not establish whole-packet identity.
    truncated = response(native + native)[:-len(native)]
    op, ip = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    tk.write_pcap(op, [(100, req), (200, response(native))])
    tk.write_pcap(ip, [(110, req), (210, truncated)])
    row = cc.analyze(op, ip)['exchanges'][0]
    assert row['resp_crc_ok'] is True
    assert row['publication']['response_availability_ns'] is None
    assert row['publication']['null_reasons']['response_availability_ns'] == 'response_capture_truncated'


def test_declared_read61_reencoding_preserves_all_application_point_bytes(tmp_path):
    header = bytes.fromhex('c0c0810000')
    points = bytes(range(23))
    native = tk.dnp3_frame(header + bytes.fromhex('0a02000016') + points)
    encoded_user = (header + bytes.fromhex('0a02000005') + points[:6] + bytes.fromhex('0a02000609') +
                    points[6:10] + bytes.fromhex('0a02010a001600') + points[10:])
    encoded = tk.dnp3_frame(encoded_user)
    assert len(native) == 49 and len(encoded) == 61
    assert cc._response_content_matches(native, encoded)
    altered = tk.dnp3_frame(encoded_user[:-1] + bytes([encoded_user[-1] ^ 1]))
    assert wc.dnp3_ok(altered)[0]
    assert not cc._response_content_matches(native, altered)


def test_declared_ctl61_reencoding_checks_transport_sequence_and_all_app_bytes():
    app = bytes.fromhex('c08100000c012801000100') + bytes([1, 1, 100, 0, 0, 0, 100, 0, 0, 0, 0])
    assert len(app) == 22
    native = tk.dnp3_frame(bytes([0xc5]) + app)
    parts = [(0x45, app[:15]), (0x06, app[15:21]), (0x87, app[21:])]
    encoded = b''.join(tk.dnp3_frame(bytes([th]) + part) for th, part in parts)
    assert len(native) == 37 and len(encoded) == 61
    assert cc._response_content_matches(native, encoded)
    altered = (tk.dnp3_frame(bytes([parts[0][0]]) + parts[0][1]) +
               tk.dnp3_frame(bytes([0x07]) + parts[1][1]) +
               tk.dnp3_frame(bytes([parts[2][0]]) + parts[2][1]))
    assert wc.dnp3_ok(altered)[0]
    assert not cc._response_content_matches(native, altered)

import struct
import sys
import zlib
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
pytest.importorskip('scapy')
import overhead_v2 as ov  # noqa: E402

MASTER, RELAY = (192, 168, 10, 1), (192, 168, 10, 7)
SYN, ACK, PSH = 0x02, 0x10, 0x08


def tcp_frame(seq, flags, payload=b'', sport=60000, dport=20000, src=MASTER, dst=RELAY, options=b''):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, 0, (20 + len(options)) // 4 << 4, flags,
                      1024, 0, 0) + options + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, bytes(src), bytes(dst))
    return b'\x00' * 6 + b'\x11' * 6 + b'\x08\x00' + ip + tcp


def with_fcs(frame):
    return frame + struct.pack('<I', zlib.crc32(frame) & 0xffffffff)


def write_pcap(path, frames, linktype=1, snaplen=262144, truncate=None):
    data = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype)
    for i, frame in enumerate(frames):
        cap = frame[:truncate] if truncate and i == 0 else frame
        data += struct.pack('<IIII', 1000 + i, 0, len(cap), len(frame)) + cap
    Path(path).write_bytes(data)
    return path


OPTIONS = b'\x01\x01\x08\x0a' + b'\x00' * 8          # NOP NOP timestamp: 32-octet TCP header as captured


def flow(isn=1000):
    return [tcp_frame(isn, SYN), tcp_frame(isn + 1, ACK | PSH, b'abcdef', options=OPTIONS),
            tcp_frame(isn + 7, ACK, options=OPTIONS)]


def test_frame_bytes_without_fcs(tmp_path):
    frames = flow()
    stats = ov.direction_stats(ov.read_pcap(write_pcap(tmp_path / 'a.pcap', frames)), ov.flow_key(MASTER, 60000, RELAY,
                                                                                                 20000))
    assert stats['frames'] == 3 and stats['captured_frame_bytes'] == sum(len(f) for f in frames)
    assert stats['fcs_frames'] == 0 and stats['other_frames'] == 0 and stats['truncated_frames'] == 0
    assert stats['payload_bytes'] == 6 and stats['pure_acks'] == 1 and stats['syn'] == 1
    assert stats['wire_estimate_bytes'] == sum(max(len(f), 60) + 4 + 8 + 12 for f in frames)
    assert len(frames[0]) == 54 and ov.wire_estimate(54) == 60 + 24      # short frames are padded to 60 + FCS


def test_frame_bytes_with_fcs_are_detected_and_not_counted_twice(tmp_path):
    plain = ov.read_pcap(write_pcap(tmp_path / 'a.pcap', flow()))
    fcs = ov.read_pcap(write_pcap(tmp_path / 'b.pcap', [with_fcs(f) for f in flow()]))
    key = ov.flow_key(MASTER, 60000, RELAY, 20000)
    a, b = ov.direction_stats(plain, key), ov.direction_stats(fcs, key)
    assert b['fcs_frames'] == 3 and b['captured_frame_bytes'] == a['captured_frame_bytes'] + 12
    assert b['wire_estimate_bytes'] == a['wire_estimate_bytes'] and b['payload_bytes'] == a['payload_bytes']
    padded = tcp_frame(5, ACK) + b'\x00' * 6                            # 60-octet minimum with zero padding
    assert not ov.has_fcs(padded, 54) and ov.has_fcs(with_fcs(tcp_frame(5, ACK)), 54)


def test_pcap_header_truncation_and_foreign_frames_are_reported(tmp_path):
    frames = flow() + [tcp_frame(1, ACK, b'zz', sport=60001)]
    capture = ov.read_pcap(write_pcap(tmp_path / 'a.pcap', frames, snaplen=65535, truncate=40))
    assert capture['linktype'] == 1 and capture['snaplen'] == 65535
    stats = ov.direction_stats(capture, ov.flow_key(MASTER, 60000, RELAY, 20000))
    assert stats['truncated_frames'] == 1 and stats['other_frames'] == 1
    assert stats['wire_length_bytes'] == sum(len(f) for f in frames[:3])


def test_retransmission_is_counted_by_byte_overlap():
    isn = 1000
    segments = [dict(seq=isn, flags=SYN, payload=b''), dict(seq=isn + 1, flags=ACK, payload=b'abcdef'),
                dict(seq=isn + 1, flags=ACK, payload=b'abc'),          # identical-start overlap: 3 octets
                dict(seq=isn + 3, flags=ACK, payload=b'cdefgh')]       # resegmented: 4 old octets, 2 new
    r = ov.retransmissions(segments)
    assert r == dict(payload_bytes=15, unique_bytes=8, retransmitted_bytes=7, retransmitted_segments=2)


def test_retransmission_overlap_across_sequence_wrap():
    isn = 2 ** 32 - 3
    segments = [dict(seq=isn, flags=SYN, payload=b''), dict(seq=isn + 1, flags=ACK, payload=b'abcdef'),
                dict(seq=(isn + 4) & 0xffffffff, flags=ACK, payload=b'defg')]
    r = ov.retransmissions([dict(s, seq=s['seq'] & 0xffffffff) for s in segments])
    assert r['retransmitted_bytes'] == 3 and r['unique_bytes'] == 7 and r['retransmitted_segments'] == 1


def rows_for(blocks=2, shift=2.0):
    rows = []
    for b in range(blocks):
        for arm, extra in (('off', 0.0), ('combined', shift)):
            for i, (operation, workload) in enumerate([('READ', 'mixed'), ('READ', 'integrity'), ('SELECT', ''),
                                                       ('OPERATE', '')] * 10):
                rows.append(dict(block_id='e%02d_d5_r%02d' % (b + 1, b + 1), d_ms=5, arm=arm, operation=operation,
                                 read_class=workload, rt_ms=1.0 + i * 0.1 + extra, ack_ms=0.5 + extra / 2))
    return rows


def test_latency_tails_and_block_paired_added_latency():
    rows = rows_for()
    tails = {(t['d_ms'], t['arm'], t['class'], t['field']): t for t in ov.latency_tails(rows)}
    off_all = tails[(5, 'off', 'all', 'rt_ms')]
    values = [r['rt_ms'] for r in rows if r['arm'] == 'off']
    assert off_all['n'] == 80 and off_all['max'] == pytest.approx(max(values))
    assert off_all['p99'] == pytest.approx(np.percentile(values, 99))
    assert tails[(5, 'combined', 'SELECT', 'rt_ms')]['n'] == 20
    added = {(a['d_ms'], a['arm'], a['class'], a['field'], a['stat']): a for a in ov.latency_added(rows)}
    p50 = added[(5, 'combined', 'all', 'rt_ms', 'p50')]
    assert p50['estimate'] == pytest.approx(2.0) and p50['blocks'] == 2
    assert p50['lower'] == pytest.approx(2.0) and p50['upper'] == pytest.approx(2.0)
    assert added[(5, 'combined', 'mixed', 'ack_ms', 'p99')]['estimate'] == pytest.approx(1.0)
    assert not any(a['arm'] == 'off' for a in added.values())

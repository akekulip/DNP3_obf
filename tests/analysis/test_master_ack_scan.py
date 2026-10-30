"""master_ack_scan on synthetic captures: each class the inherited N limitation would not forward is detected, ordinary
traffic is not, and the retained hardware captures carry none of them."""
import sys
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, Raw
from scapy.utils import PcapWriter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import master_ack_scan as mas  # noqa: E402

MASTER, RELAY, PORT = '192.168.10.1', '192.168.10.7', 60000
ISN_M, ISN_R = 1000, 5000


def frame(src, sport, dport, flags, seq, ack, window, payload=b''):
    packet = Ether() / IP(src=src, dst=RELAY if src == MASTER else MASTER) / \
        TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=window)
    return bytes(packet / Raw(payload) if payload else packet)


def write(path, frames):
    writer = PcapWriter(str(path), linktype=1, nano=True)
    writer.write_header(None)
    for t, raw in frames:
        writer.write_packet(raw, sec=t // 10 ** 9, usec=t % 10 ** 9, caplen=len(raw), wirelen=len(raw))
    writer.close()


def trial(tmp_path, extra=(), window=502):
    """Handshake, one 25-octet request, the relay's ACK and response, the master's ACK; EXTRA master frames
    (t_ns, flags, seq, ack, window, payload) are added to out.pcap."""
    m = lambda t, flags, seq, ack, win, payload=b'': (t, frame(MASTER, PORT, mas.RELAY_PORT, flags, seq, ack, win, payload))
    r = lambda t, flags, seq, ack, payload=b'': (t, frame(RELAY, mas.RELAY_PORT, PORT, flags, seq, ack, 8192, payload))
    out = [m(1000, 'S', ISN_M, 0, 64240), m(3000, 'A', ISN_M + 1, ISN_R + 1, window),
           m(4000, 'PA', ISN_M + 1, ISN_R + 1, window, b'r' * 25), m(9000, 'A', ISN_M + 26, ISN_R + 142, window)]
    out += [m(*e) for e in extra]
    inn = [r(2000, 'SA', ISN_R, ISN_M + 1), r(5000, 'A', ISN_R + 1, ISN_M + 26),
           r(8000, 'PA', ISN_R + 1, ISN_M + 26, b'x' * 141)]
    path = tmp_path / 't'
    path.mkdir(exist_ok=True)
    write(path / 'out.pcap', sorted(out))
    write(path / 'in.pcap', sorted(inn))
    return mas.scan(path)


def test_ordinary_traffic_has_no_hit(tmp_path):
    result = trial(tmp_path)
    assert result['pure_acks'] == 2 and result['master_segments'] == 4
    assert all(result[k] == 0 for k in mas.CLASSES) and result['examples'] == []


@pytest.mark.parametrize('extra,klass', [
    ((6000, 'A', ISN_M + 26, ISN_R + 1, 900), 'window_change_outstanding'),
    ((6000, 'A', ISN_M + 26, ISN_R + 1, 0), 'zero_window'),
    ((9500, 'A', ISN_M + 26, ISN_R + 142, 900), 'window_change_idle'),
    ((9500, 'A', ISN_M + 25, ISN_R + 142, 502), 'keepalive'),
    ((9500, 'A', ISN_M + 25, ISN_R + 142, 502, b'k'), 'keepalive')])
def test_each_class_is_detected(tmp_path, extra, klass):
    result = trial(tmp_path, extra=[extra])
    assert result[klass] == 1, result
    assert sum(result[k] for k in mas.CLASSES) == 1 + (klass == 'zero_window')   # a zero window is also a change


def test_a_repeated_ack_with_the_same_window_is_not_a_window_update(tmp_path):
    result = trial(tmp_path, extra=[(9500, 'A', ISN_M + 26, ISN_R + 142, 502)])
    assert all(result[k] == 0 for k in mas.CLASSES)


@pytest.mark.skipif(not any((ROOT / 'results/hardware/blocks').rglob('out.pcap')), reason='retained captures absent')
def test_the_retained_hardware_captures_carry_none(tmp_path):
    out = mas.scan_all(ROOT / 'results/hardware/blocks')
    assert out['errors'] == [] and out['trials'] >= 498 and out['totals']['master_segments'] > 60000
    assert all(out['totals'][k] == 0 for k in mas.CLASSES) and out['trials_with_hits'] == []

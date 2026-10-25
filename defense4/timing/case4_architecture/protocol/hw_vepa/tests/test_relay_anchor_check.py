"""relay_anchor_check: J, switch residence and the latency split are reported only from validated, correlated,
bounded anchors; every incomplete or unbounded case stays 'unproven' with its reason (Philip, 2026-10-25)."""
import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import relay_anchor_check as rac  # noqa: E402

MASTER, RELAY = bytes([192, 168, 10, 1]), bytes([192, 168, 10, 7])
MPORT, RPORT = 60001, 20000
OP_J = 2_400_000
EPOCH = 1_800_000_000 * 10**9


def frame(src, dst, sport, dport, seq, ack, flags, payload):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 1024, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, src, dst)
    return b'\x00' * 12 + b'\x08\x00' + ip + tcp


def dnp3(fc, app_seq=0):
    # link header (10 bytes incl. CRC) + transport + application control + function code at offset 12
    return b'\x05\x64' + b'\x00' * 8 + bytes([0xC0, 0xC0 | app_seq, fc]) + b'\x00' * 10


def pcap(path, records, nano=True):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b23c4d if nano else 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for t_ns, fr in records:
            sub = t_ns % 10**9 if nano else (t_ns % 10**9) // 1000
            f.write(struct.pack('<IIII', t_ns // 10**9, sub, len(fr), len(fr)) + fr)


def phc(offset_ns, bound_ns=300):
    return {'offset_ns': offset_ns, 'bound_ns': bound_ns, 'narrow_count': 10, 'narrow_spread_ns': 20}


def clocks(master_off=-316_000_000, tap_off=-302_000_000, drift=0, mode='adapter_unsynced'):
    return {'master': {'iface': 'enp59s0f0np0', 'mode': mode, 'before': phc(master_off),
                       'after': phc(master_off + drift)},
            'tap': {'iface': 'tapnic', 'mode': mode, 'before': phc(tap_off), 'after': phc(tap_off + drift)}}


def scenario(tmp_path, operates=3, j_ns=2_500_000, drop_tap=None, master_off=-316_000_000, tap_off=-302_000_000):
    """Master TX/RX (master PHC time) and relay-leg tap (tap PHC time) of OPERATE exchanges.
    Real (CLOCK_REALTIME) instants: request TX at t, relay leg at t + j, response on the relay leg 5 ms later,
    master RX 40 us after that."""
    out, inn, tap = [], [], []
    for i in range(operates):
        t = EPOCH + i * 50_000_000
        seq = 1000 + i * 45
        req = frame(MASTER, RELAY, MPORT, RPORT, seq, 500, 0x18, dnp3(4, i))
        rsp = frame(RELAY, MASTER, RPORT, MPORT, 500 + i * 49, seq + len(dnp3(4)), 0x18, dnp3(0x81, i))
        out.append((t + master_off, req))
        if i != drop_tap:
            tap.append((t + j_ns + tap_off, req))
            tap.append((t + j_ns + 5_000_000 + tap_off, rsp))
        inn.append((t + j_ns + 5_040_000 + master_off, rsp))
    for name, recs in (('out.pcap', out), ('in.pcap', inn), ('tap.pcap', tap)):
        pcap(tmp_path / name, recs)
    return tmp_path


def run(d, cl=None, operates=3, max_bound=5_000):
    return rac.evaluate(d / 'out.pcap', d / 'in.pcap', d / 'tap.pcap', clocks() if cl is None else cl, MPORT,
                        op_j_ns=OP_J, expected_operates=operates, max_bound_ns=max_bound)


def test_measured_j_and_split_when_everything_correlates(tmp_path):
    r = run(scenario(tmp_path))
    j = r['operate_j']
    assert j['status'] == 'measured' and j['pass'] is True
    assert j['n'] == 3 and abs(j['min_ns'] - 2_500_000) <= 1 and j['bound_ns'] == 600
    assert r['relay_turnaround']['status'] == 'measured' and r['relay_turnaround']['bound_ns'] == 0
    assert abs(r['relay_turnaround']['max_ns'] - 5_000_000) <= 1
    res = r['switch_residence']
    assert res['status'] == 'measured' and abs(res['min_ns'] - 40_000) <= 1 and res['bound_ns'] == 600


def test_j_below_op_j_beyond_the_bound_fails(tmp_path):
    r = run(scenario(tmp_path, j_ns=2_300_000))
    assert r['operate_j']['status'] == 'measured' and r['operate_j']['pass'] is False


def test_j_within_the_bound_of_op_j_is_unproven_not_pass(tmp_path):
    r = run(scenario(tmp_path, j_ns=OP_J + 100))       # 100 ns above op_j, bound 600 ns
    assert r['operate_j']['status'] == 'unproven' and 'within the uncertainty' in r['operate_j']['reason']


def test_missing_relay_leg_operate_is_unproven(tmp_path):
    r = run(scenario(tmp_path, drop_tap=1))
    assert r['operate_j']['status'] == 'unproven' and 'not observed on the relay leg' in r['operate_j']['reason']


def test_fewer_operates_than_expected_is_unproven(tmp_path):
    r = run(scenario(tmp_path, operates=2), operates=3)
    assert r['operate_j']['status'] == 'unproven' and 'expected 3' in r['operate_j']['reason']


def test_host_timestamps_have_no_clock_bound(tmp_path):
    r = run(scenario(tmp_path), cl=clocks(mode='host'))
    for key in ('operate_j', 'switch_residence', 'request_forwarding'):
        assert r[key]['status'] == 'unproven' and 'host timestamps' in r[key]['reason']
    assert r['relay_turnaround']['status'] == 'measured'     # one capture, one clock


def test_bound_wider_than_declared_maximum_is_unproven(tmp_path):
    r = run(scenario(tmp_path), max_bound=500)
    assert r['operate_j']['status'] == 'unproven' and 'exceeds' in r['operate_j']['reason']


def test_drift_between_samples_widens_the_bound(tmp_path):
    r = run(scenario(tmp_path), cl=clocks(drift=4_000))
    assert r['operate_j']['bound_ns'] == 600 + 4_000       # half the change per clock, two clocks


def test_missing_or_malformed_clock_record_is_unproven(tmp_path):
    d = scenario(tmp_path)
    for broken in ({}, {'master': clocks()['master']}, dict(clocks(), tap={'mode': 'adapter_unsynced'})):
        r = run(d, cl=broken)
        assert r['operate_j']['status'] == 'unproven' and 'clock' in r['operate_j']['reason']


def test_retransmitted_operate_uses_first_transmission_and_first_arrival(tmp_path):
    d = scenario(tmp_path, operates=1)
    recs = list(rac.tcp_records(d / 'out.pcap'))
    first = recs[0]
    pcap(d / 'out.pcap', [(first['time_ns'], frame(MASTER, RELAY, MPORT, RPORT, first['seq'], 500, 0x18, dnp3(4))),
                          (first['time_ns'] + 210_000_000,
                           frame(MASTER, RELAY, MPORT, RPORT, first['seq'], 500, 0x18, dnp3(4)))])
    r = run(d, operates=1)
    assert r['operate_j']['status'] == 'measured' and abs(r['operate_j']['min_ns'] - 2_500_000) <= 1
    assert r['operate_j']['retransmitted'] == 1


def test_microsecond_pcaps_are_read_too(tmp_path):
    path = tmp_path / 'u.pcap'
    pcap(path, [(EPOCH + 1_234_567_000, frame(MASTER, RELAY, MPORT, RPORT, 1, 2, 0x18, dnp3(1)))], nano=False)
    assert [r['time_ns'] for r in rac.tcp_records(path)] == [EPOCH + 1_234_567_000]


def test_rejects_unknown_pcap(tmp_path):
    path = tmp_path / 'x.pcap'
    path.write_bytes(b'\x00' * 24)
    with pytest.raises(ValueError):
        list(rac.tcp_records(path))

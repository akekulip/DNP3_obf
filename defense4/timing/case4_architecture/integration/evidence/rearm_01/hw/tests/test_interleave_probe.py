"""interleave_probe.py: plan shape, injector compatibility and the fail-closed judge on synthetic captures (offline)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import contention_probe as cp  # noqa: E402
import interleave_probe as ip  # noqa: E402
import vision_contention as vc  # noqa: E402

EP = cp.Endpoints('192.0.2.61', '192.0.2.62', 59400, 20000, '02:00:00:00:00:61', '02:00:00:00:00:62',
                  '02:00:00:00:00:09')


def plan():
    return ip.build_interleave_plan(EP)


def test_plan_is_bounded_and_places_the_rst_before_the_response():
    p = plan()
    assert len(p['points']) == len(ip.KINDS) * len(ip.OFFSETS_US) == 10
    for point in p['points']:
        t = {e['frame']: e['t_ns'] for e in p['schedule'] if e['tag'] == point['tag']}
        assert t['response'] - t['rst'] == point['offset_us'] * 1000
        assert t['rst'] > t['bare_ack'] and t['syn2'] > t['response'] and t['response2'] > t['request2']


def test_every_frame_passes_the_injectors_own_validation():
    vc.validate_schedule(plan())


def pad(frame_hex, length):
    frame = bytes.fromhex(frame_hex)
    ihl = (frame[14] & 0x0f) * 4
    tcp = 14 + ihl
    dataofs = (frame[tcp + 12] >> 4) * 4
    head, payload = frame[:tcp + dataofs], (frame[tcp + dataofs:] + bytes(length))[:length]
    return (head[:16] + (len(head) - 14 + length).to_bytes(2, 'big') + head[18:] + payload).hex()


def switch_output(p, drop_rst=None, copy=None, late_copy=None, foreign=None, padded=True):
    """A correct switch's returned frames, in order, per point: relayed SYN, relayed request, the relayed RST, (an
    optional first-response copy), relayed SYN2, relayed request2, reconnect response at the master."""
    out = []
    for point in p['points']:
        f, tag = point['frames'], point['tag']
        out += [f['syn'], f['request']]
        if tag != drop_rst:
            out.append(f['rst'])
        if tag == copy:
            out.append(pad(f['response'], 61))
        out.append(f['syn2'])
        if tag == late_copy:
            out.append(pad(f['response'], 61))
        out.append(f['request2'])
        if tag == foreign:
            out.append(pad(f['response2'], 61).replace(pad(f['response2'], 61)[76:84], 'deadbeef', 1))
        out.append(pad(f['response2'], 61) if padded else f['response2'])
    return out


INJECT = lambda p: dict(applied=True, sent=len(p['schedule']),
                        tcpdump={'out': {'captured': 140, 'dropped_kernel': 0}, 'in': {'captured': 90, 'dropped_kernel': 0}})


def snap(restarts, busy=None, term=0, fallbacks=0):
    cells = list(busy or [0] * 8)
    cells[ip.RESTART_CELL] = restarts
    return {'n_counters': {'count_busy': cells, 'count_term': [term, 0, 0, 0]},
            'outcomes': {cp.OUT_ACK_FALLBACK: fallbacks, cp.OUT_RESP_FALLBACK: 0}}


def run(tmp_path, restarts=1, inject='default', vision_rc=0, after=None, **switch):
    p = plan()
    out, inp = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    cp.write_pcap(out, [(e['t_ns'], bytes.fromhex(e['bytes'])) for e in p['schedule']])
    cp.write_pcap(inp, [(i * 1000, bytes.fromhex(x)) for i, x in enumerate(switch_output(p, **switch))])
    return ip.judge_interleave(p, out, inp, snap(0), after or snap(restarts),
                               inject=INJECT(p) if inject == 'default' else inject, vision_rc=vision_rc)


def test_correct_delivery_with_a_restart_passes(tmp_path):
    r = run(tmp_path)
    assert r['verdict'] == 'PASS', r['failures']
    assert all(row['measured_offset_us'] == row['requested_offset_us'] for row in r['points'])


def test_one_copy_before_the_reconnect_is_allowed(tmp_path):
    assert run(tmp_path, copy='interleave_READ_1us')['verdict'] == 'PASS'


def test_correct_delivery_without_a_restart_is_not_exercised(tmp_path):
    assert run(tmp_path, restarts=0)['verdict'] == 'NOT_EXERCISED'


def test_a_lost_first_rst_fails(tmp_path):
    r = run(tmp_path, drop_rst='interleave_SELECT_2us')
    assert r['verdict'] == 'FAIL' and any('RST relayed 0' in f for f in r['failures'])


def test_a_first_response_copy_after_the_reconnect_fails(tmp_path):
    """Code review: a copy released into the next connection's lifetime was previously counted as at most once."""
    r = run(tmp_path, late_copy='interleave_READ_3us')
    assert r['verdict'] == 'FAIL' and any('unexpected master-bound' in f for f in r['failures'])


def test_a_rewritten_or_foreign_payload_at_the_master_fails(tmp_path):
    assert run(tmp_path, foreign='interleave_SELECT_0us')['verdict'] == 'FAIL'


def test_an_unpadded_reconnect_response_fails(tmp_path):
    assert run(tmp_path, padded=False)['verdict'] == 'FAIL'


def test_busy_drop_exhaustion_stale_duplicate_abort_or_fallback_fail(tmp_path):
    for after in (snap(1, busy=[1, 0, 0, 0, 0, 0, 0, 0]), snap(1, busy=[0, 0, 0, 1, 0, 0, 0, 0]),
                  snap(1, busy=[0, 0, 0, 0, 1, 0, 0, 0]), snap(1, term=1), snap(1, fallbacks=1)):
        assert run(tmp_path, after=after)['verdict'] == 'FAIL'


def test_measurement_failures_are_invalid_not_switch_failures(tmp_path):
    p = plan()
    short = dict(INJECT(p), sent=10)
    dropped = dict(INJECT(p), tcpdump={'out': {'dropped_kernel': 3}, 'in': {'dropped_kernel': 0}})
    for kwargs in (dict(vision_rc=2), dict(inject=None), dict(inject=short), dict(inject=dropped),
                   dict(after={'n_counters': {'count_busy': [0] * 4}})):
        assert run(tmp_path, **kwargs)['verdict'] == 'INVALID', kwargs


def test_an_empty_in_capture_is_invalid(tmp_path):
    p = plan()
    out, inp = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    cp.write_pcap(out, [(e['t_ns'], bytes.fromhex(e['bytes'])) for e in p['schedule']])
    cp.write_pcap(inp, [])
    assert ip.judge_interleave(p, out, inp, snap(0), snap(1), inject=INJECT(p))['verdict'] == 'INVALID'


def test_a_duplicated_first_request_fails(tmp_path):
    """Re-review: an outstation-bound duplicate (SELECT: a command reaching the outstation twice) is checked."""
    p = plan()
    out, inp = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    cp.write_pcap(out, [(e['t_ns'], bytes.fromhex(e['bytes'])) for e in p['schedule']])
    frames = switch_output(p)
    dup = p['points'][5]['frames']['request']
    frames.insert(frames.index(dup) + 1, dup)
    cp.write_pcap(inp, [(i * 1000, bytes.fromhex(x)) for i, x in enumerate(frames)])
    r = ip.judge_interleave(p, out, inp, snap(0), snap(1), inject=INJECT(p))
    assert r['verdict'] == 'FAIL' and any('first request relayed 2' in f for f in r['failures'])


def test_an_unpadded_first_response_copy_fails(tmp_path):
    """Re-review: the one allowed copy must be the 61-octet image; a native copy would be a size leak."""
    p = plan()
    out, inp = tmp_path / 'out.pcap', tmp_path / 'in.pcap'
    cp.write_pcap(out, [(e['t_ns'], bytes.fromhex(e['bytes'])) for e in p['schedule']])
    frames = switch_output(p)
    f = p['points'][0]['frames']
    frames.insert(frames.index(f['syn2']), f['response'])          # native 49-octet copy, before SYN2
    cp.write_pcap(inp, [(i * 1000, bytes.fromhex(x)) for i, x in enumerate(frames)])
    assert ip.judge_interleave(p, out, inp, snap(0), snap(1), inject=INJECT(p))['verdict'] == 'FAIL'


def test_unreadable_outcomes_or_absent_status_are_invalid(tmp_path):
    bad = snap(1)
    bad['outcomes'][cp.OUT_ACK_FALLBACK] = None
    assert run(tmp_path, after=bad)['verdict'] == 'INVALID'
    assert run(tmp_path, vision_rc=None)['verdict'] == 'INVALID'
    assert run(tmp_path, inject=['not', 'a', 'dict'])['verdict'] == 'INVALID'

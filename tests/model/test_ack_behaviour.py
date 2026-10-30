"""Master-ACK behaviour driver (labelled, outside the model gate): the rule's classification logic and the case table.
Pure functions only; the model run is scripts/model/run_ack_behaviour.py. The rule is registered in
results/analysis/ack_behaviour/DESIGN.json."""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/model'))

import model_ack_behaviour as ab  # noqa: E402
import vectors  # noqa: E402

DESIGN = ROOT / 'results/analysis/ack_behaviour/DESIGN.json'


def seg(order, seq, ack, window=4096, tsval=100, payload_len=0, options=('ts',), flags=0x10):
    return dict(order=order, seq=seq, ack=ack, window=window, tsval=tsval, payload_len=payload_len,
                options=list(options), flags=flags, direction='m2r')


def test_case_table_covers_every_family_for_both_classes_and_both_t_settings():
    names = [c['case'] for c in ab.CASES]
    assert len(names) == len(set(names)) == len(ab.SCENARIOS) * 4
    for scenario in ab.SCENARIOS:
        combos = {(c['read_class'], c['timed']) for c in ab.CASES if c['scenario'] == scenario}
        assert combos == {('mixed', True), ('mixed', False), ('integrity', True), ('integrity', False)}
    assert {v['family'] for v in ab.SCENARIOS.values()} == {1, 2, 3, 4, 5, 6}
    design = json.loads(DESIGN.read_text())
    assert set(ab.SCENARIOS) == {k for k in design['cases'] if k != 'dimensions'}
    for name, spec in ab.SCENARIOS.items():
        assert spec['family'] == design['cases'][name]['family']
        assert spec['evidence_kind'] == design['cases'][name]['evidence_kind']


def test_forced_nonconforming_and_control_cases_are_labelled():
    assert {s for s, v in ab.SCENARIOS.items() if v['evidence_kind'] == 'forced_register'} == {'late_ack_wire_order'}
    assert {s for s, v in ab.SCENARIOS.items() if not v.get('conforming', True)} == {'r2_offset'}
    assert {s for s, v in ab.SCENARIOS.items() if v.get('control')} == {'window_increase_idle', 'duplicate_ack_idle',
                                                                         'response_ack_control'}


def test_the_driver_carries_the_registered_rule_verbatim():
    design = json.loads(DESIGN.read_text())
    assert ab.RULE == design['rule']
    assert set(ab.OUTCOMES) == set(design['operational_definitions']['classification'])


def test_serial_arithmetic_wraps():
    assert ab.seq_ge(5, 5) and ab.seq_ge(6, 5) and not ab.seq_ge(5, 6)
    assert ab.seq_ge(2, 0xfffffffe) and not ab.seq_ge(0xfffffffe, 2)


def test_the_late_handshake_ack_is_covered_by_the_read_that_overtook_it():
    ack = seg(0, 1001, 9001, tsval=10)
    read = seg(1, 1001, 9001, tsval=11, payload_len=25, flags=0x18)
    assert ab.covers(read, ack) and ab.obsolete(ack, [read])
    r1_ack = seg(4, 2026, 9142, tsval=20)                     # the ACK of response 1, sent before READ 2
    read2 = seg(5, 2026, 9142, tsval=21, payload_len=27, flags=0x18)
    assert ab.obsolete(r1_ack, [read2])


def test_each_missing_element_breaks_coverage():
    ack = seg(0, 1001, 9001, tsval=10)
    assert not ab.covers(seg(0, 1001, 9001, tsval=10), ack)                 # not later
    assert not ab.covers(seg(1, 1000, 9001, tsval=11), ack)                 # sequence before
    assert not ab.covers(seg(1, 1001, 9000, tsval=11), ack)                 # acknowledgment before
    assert not ab.covers(seg(1, 1001, 9001, window=4608, tsval=11), ack)    # different window
    assert not ab.covers(seg(1, 1001, 9001, tsval=9), ack)                  # older timestamp
    assert not ab.covers(seg(1, 1001, 9001, tsval=11, options=()), ack)     # option not carried
    assert ab.covers(seg(1, 1001, 9001, tsval=11), ack)
    assert not ab.obsolete(ack, [])


def test_a_one_octet_probe_needs_its_octet_covered():
    probe = seg(3, 1025, 9142, tsval=30, payload_len=1)
    assert not ab.covers(seg(4, 1025, 9142, tsval=31), probe)
    assert ab.covers(seg(4, 1026, 9142, tsval=31, payload_len=25), probe)


def test_r2_at_isn_plus_3_is_not_covered_by_the_read_at_isn_plus_1():
    read = seg(1, 1001, 9001, tsval=11, payload_len=27, flags=0x18)
    assert not ab.obsolete(seg(0, 1003, 9001, tsval=10), [read])
    assert ab.obsolete(seg(0, 999, 9001, tsval=10), [read])


def test_new_information_is_a_newer_ack_or_a_changed_window():
    before = [seg(0, 1001, 9001, tsval=10), seg(1, 1001, 9001, tsval=11, payload_len=25, flags=0x18)]
    assert ab.new_information(seg(2, 1026, 9001, window=4608, tsval=12), before) == dict(new_ack=False, new_window=True)
    assert ab.new_information(seg(2, 1026, 9001, window=0, tsval=12), before) == dict(new_ack=False, new_window=True)
    assert ab.new_information(seg(2, 1026, 9142, tsval=12), before) == dict(new_ack=True, new_window=False)
    assert ab.new_information(seg(2, 1025, 9001, tsval=12), before) == dict(new_ack=False, new_window=False)
    assert ab.new_information(seg(2, 1026, 9001, tsval=12), []) == dict(new_ack=True, new_window=True)
    updated = before + [seg(2, 1026, 9001, window=4608, tsval=12)]          # the relay's view is the latest window
    assert ab.new_information(seg(3, 1026, 9001, window=4608, tsval=13), updated)['new_window'] is False
    assert ab.new_information(seg(3, 1026, 9001, window=4096, tsval=13), updated)['new_window'] is True


def state(**overrides):
    base = dict(owner=0xe0001, client=1026, server=9001, epoch=7, application_state=[1, 2], retry_epoch=7,
                work_phase=4, work_generation=40, counter=40)
    base.update(overrides)
    return base


def test_state_unchanged_ignores_only_the_generation_counters():
    assert ab.state_unchanged(state(), state(work_generation=41, counter=41))
    for key, value in (('owner', 0x50001), ('client', 1025), ('server', 9002), ('epoch', 8),
                       ('application_state', [1, 3]), ('retry_epoch', 0), ('work_phase', 1)):
        assert not ab.state_unchanged(state(), state(**{key: value})), key
    assert not ab.state_unchanged(state(), dict(state(), owner=None))


def test_classification_has_exactly_three_outcomes():
    meets, suppress, violates = ab.OUTCOMES
    assert ab.classify(True, False, False) == meets            # forwarding is always permitted
    assert ab.classify(True, True, True) == meets
    assert ab.classify(False, True, True) == suppress
    assert ab.classify(False, True, False) == violates         # obsolete but state changed
    assert ab.classify(False, False, True) == violates         # not obsolete
    assert ab.classify(False, False, False) == violates


def test_the_relay_replies_only_to_a_forwarded_probe_before_its_rcv_nxt():
    assert ab.relay_replies(True, 1025, 1026)
    assert not ab.relay_replies(True, 1026, 1026)
    assert not ab.relay_replies(False, 1025, 1026)
    assert ab.relay_replies(True, 0xffffffff, 0)


def ts_frame(window=4096, payload=b''):
    tcp = struct.pack('!HHIIBBHHH', 59410, 20000, 1001, 9001, (32 // 4) << 4, 0x10, window, 0, 0)
    tcp += bytes.fromhex('0101080a') + struct.pack('!II', 77, 66) + payload
    src, dst = 0xc0a80a01, 0xc0a80a07
    tcp = tcp[:16] + struct.pack('!H', vectors.checksum(struct.pack('!IIBBH', src, dst, 0, 6, len(tcp)) + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBHII', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', vectors.checksum(ip)) + ip[12:]
    return bytes.fromhex('0030a7024ca23cfdfecc5dc00800') + ip + tcp


def tcp_checksum_ok(frame):
    ip_len = struct.unpack('!H', frame[16:18])[0]
    tcp = frame[34:14 + ip_len]
    return vectors.checksum(frame[26:34] + struct.pack('!BBH', 0, 6, len(tcp)) + tcp) == 0


def test_tcp_fields_and_window_rewrite():
    frame = ts_frame(payload=b'\x55')
    fields = ab.tcp_fields(frame)
    assert (fields['seq'], fields['ack'], fields['window'], fields['tsval'], fields['tsecr'], fields['payload_len'],
            fields['options']) == (1001, 9001, 4096, 77, 66, 1, ['ts'])
    assert tcp_checksum_ok(frame)
    for window in (0, 4608, 65535):
        changed = ab.with_window(frame, window)
        assert ab.tcp_fields(changed)['window'] == window and tcp_checksum_ok(changed)
        assert changed[:48] == frame[:48] and changed[52:] == frame[52:]


def test_claim_order_comes_from_the_successful_stage0_claims():
    def claim(seq, before_phase):
        return dict(segment=dict(direction='m2r', seq=seq, flags=0x10, payload_len=0), port=9,
                    steps=[dict(table='t', status='hit', action='n_Ingress.claim_work', default=False,
                                salu=((before_phase << 32) | 5, (1 << 32) | 6))])
    read = dict(direction='m2r', seq=1001, flags=0x10, payload_len=0)
    ack = dict(direction='m2r', seq=2002, flags=0x10, payload_len=0)
    passes = [claim(2002, 1), claim(1001, 4), claim(2002, 4)]   # the ACK's first claim found the cell held
    assert ab.claimed_before(passes, read, ack) is True
    assert ab.claimed_before(passes, ack, read) is False
    assert ab.claimed_before(passes[:2], read, ack) is True     # the ACK never claimed: the READ came first
    assert ab.claimed_before([], read, ack) is None

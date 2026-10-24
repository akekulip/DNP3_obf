import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import relay_check
import pcaptk as tk


def test_partial_sbo_wire_is_not_complete():
    records = [dict(operation='SELECT', outcome='OK', response_wire_hex='0564')]
    failures = relay_check.master_checks(dict(ok=True, counts={'SELECT': 1}, planned={'SELECT': 1}, records=records), 59410)
    assert failures


def test_wrong_socket_identity_fails_even_for_ok_outcome():
    rec = dict(operation='READ', outcome='OK', local_address=['192.168.10.61', 59410],
               peer_address=['192.168.10.7', 20000])
    assert relay_check.master_checks(dict(ok=True, counts={'READ': 1}, planned={'READ': 1}, records=[rec]), 59410)


def test_193_wrapped_application_identities_cannot_reuse_earlier_tcp_ranges(tmp_path):
    payload = tk.read_request()
    path = tmp_path / 'wrap.pcap'
    frames = [(1, tk.frame('192.168.10.1', '192.168.10.7', 59410, 20000, 100, 0, tk.SYN))]
    # Last of the planned 193 responses is missing; all preceding wire identities repeat.
    frames += [(2 + i, tk.frame('192.168.10.1', '192.168.10.7', 59410, 20000,
                               101 + i * len(payload), 1, tk.ACK | tk.PSH, payload)) for i in range(192)]
    tk.write_pcap(path, frames)
    segments = relay_check.wc.parse(path)[0]
    cursor = 0
    for _ in range(192):
        span = relay_check.stream_contains(segments, payload.hex(), cursor)
        assert span
        cursor = span['end_offset']
    assert relay_check.stream_contains(segments, payload.hex(), cursor) is None


def test_shortened_self_reported_plan_does_not_match_frozen_denominator():
    short = dict(ok=True, counts={'READ': 1, 'SELECT': 0, 'OPERATE': 0},
                 planned={'READ': 1, 'SELECT': 0, 'OPERATE': 0}, records=[])
    assert any('frozen' in failure for failure in relay_check.master_checks(
        short, 59410, dict(READ=65, SELECT=64, OPERATE=64), 'mixed_full'))


def test_graceful_close_requires_both_current_fins_and_final_acks():
    wire = dict(exchanges=[dict(request=dict(sequence_end=100), response=dict(sequence_end=200))],
                packets=dict(out=[dict(flags=tk.FIN | tk.ACK, seq=100, ack=200, payload_len=0),
                                  dict(flags=tk.ACK, seq=101, ack=201, payload_len=0)],
                             **{'in': [dict(flags=tk.FIN | tk.ACK, seq=200, ack=101, payload_len=0)]}))
    assert relay_check.close_checks(wire, 'graceful') == []
    wire['packets']['out'].pop()
    assert relay_check.close_checks(wire, 'graceful')
    wire['packets']['in'][0]['seq'] = 999
    assert any('both FINs' in reason for reason in relay_check.close_checks(wire, 'graceful'))


def test_fresh_handshake_cannot_reuse_old_connection_frontiers():
    import pytest
    wire = dict(packets=dict(out=[dict(flags=tk.SYN, seq=100, ack=0, payload_len=0),
                                  dict(flags=tk.ACK, seq=101, ack=201, payload_len=0)],
                             **{'in': [dict(flags=tk.SYN | tk.ACK, seq=200, ack=101, payload_len=0),
                                       dict(flags=tk.ACK | tk.PSH, seq=201, ack=101, payload_len=91)]}),
                exchanges=[dict(operation='READ', response=dict(sequence_start=201))])
    previous = relay_check.freshness(wire)
    with pytest.raises(ValueError, match='overlaps/precedes'):
        relay_check.freshness(wire, previous)
    wire['exchanges'][0]['response']['sequence_start'] = 202
    with pytest.raises(ValueError, match='old mapping offset'):
        relay_check.freshness(wire)

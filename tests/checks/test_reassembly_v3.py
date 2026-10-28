"""TCP reassembly v3: unique stream bytes, first-arrival completion and byte-overlap retransmissions."""
import pytest

from scripts.checks import relay_check, wire_check
from fixtures import conversation, packet, pcap

ISN = 200
WRAP_ISN = 0xfffffff9


def relay_segments(tmp_path, data, isn=ISN):
    """Parsed relay->master segments: a SYNACK at isn, then (time_us, stream offset, payload) data packets.
    Stream offset 1 is the first data byte, as in master coordinates."""
    frames = [(1, packet(False, isn, 101, 18))]
    frames += [(time_us, packet(False, (isn + offset) & 0xffffffff, 101, 24, payload))
               for time_us, offset, payload in data]
    path = tmp_path / 'in.pcap'
    pcap(path, frames)
    return wire_check.parse(path)[0]


def find(segments, wanted, minimum_offset=0):
    return relay_check.stream_contains(segments, wanted.hex(), minimum_offset)


def test_overlapping_shorter_retransmission_counts_unique_bytes_and_first_completion(tmp_path):
    span = find(relay_segments(tmp_path, [(100, 1, b'abcdef'), (200, 1, b'abc')]), b'abcdef')
    assert span['actual_payload_lengths'] == [6]
    assert [p['timestamp_ns'] for p in span['packets']] == [100000]
    assert (span['first_timestamp_ns'], span['complete_timestamp_ns']) == (100000, 100000)
    assert (span['unique_bytes'], span['packet_bytes'], span['retransmitted_bytes']) == (6, 9, 3)
    assert span['retransmitted_segments'] == 1


def test_coalesced_fragments_are_found_in_order_inside_one_segment(tmp_path):
    segments = relay_segments(tmp_path, [(100, 1, b'abcdef')])
    first = find(segments, b'abc')
    assert first['actual_payload_lengths'] == [3]
    assert first['packets'][0]['payload_len'] == 6        # the packet record keeps its whole payload
    assert (first['start_offset'], first['end_offset']) == (1, 4)
    second = find(segments, b'def', first['end_offset'])
    assert second is not None
    assert (second['start_offset'], second['end_offset']) == (4, 7)
    assert (second['sequence_start'], second['sequence_end']) == (ISN + 4, ISN + 7)
    assert second['actual_payload_lengths'] == [3] and second['unique_bytes'] == 3
    assert second['complete_timestamp_ns'] == 100000


def test_segment_starting_before_the_span_start_contributes_its_overlap(tmp_path):
    segments = relay_segments(tmp_path, [(100, 1, b'abc'), (200, 2, b'bcdef')])
    first = find(segments, b'abc')
    assert first['actual_payload_lengths'] == [3]
    assert (first['packet_bytes'], first['retransmitted_bytes'], first['retransmitted_segments']) == (5, 2, 1)
    second = find(segments, b'def', first['end_offset'])
    assert second is not None
    assert second['start_offset'] == 4
    assert second['actual_payload_lengths'] == [3]
    assert [p['timestamp_ns'] for p in second['packets']] == [200000]
    assert second['complete_timestamp_ns'] == 200000
    assert (second['unique_bytes'], second['packet_bytes'], second['retransmitted_bytes']) == (3, 3, 0)


def test_resegmented_retransmission_is_counted_by_byte_overlap(tmp_path):
    segments = relay_segments(tmp_path, [(100, 1, b'abcdef'), (200, 1, b'ab'), (300, 3, b'cdef')])
    span = find(segments, b'abcdef')
    assert span['actual_payload_lengths'] == [6]
    assert span['complete_timestamp_ns'] == 100000
    assert (span['unique_bytes'], span['packet_bytes'], span['retransmitted_bytes']) == (6, 12, 6)
    assert span['retransmitted_segments'] == 2


def test_completion_is_when_the_last_missing_byte_first_arrives(tmp_path):
    segments = relay_segments(tmp_path, [(100, 3, b'cdef'), (300, 1, b'abcdef')])
    span = find(segments, b'abcdef')
    assert span['actual_payload_lengths'] == [4, 2]
    assert (span['first_timestamp_ns'], span['complete_timestamp_ns']) == (100000, 300000)
    assert (span['unique_bytes'], span['packet_bytes'], span['retransmitted_bytes']) == (6, 10, 4)


def test_sequence_numbers_wrap_across_two_to_the_32(tmp_path):
    segments = relay_segments(tmp_path, [(100, 1, b'abcd'), (200, 5, b'efghij'), (300, 3, b'cdefgh'),
                                         (400, 11, b'xyz')], isn=WRAP_ISN)
    first = find(segments, b'abcdefghij')
    assert (first['sequence_start'], first['sequence_end']) == (0xfffffffa, 4)
    assert (first['start_offset'], first['end_offset']) == (1, 11)
    assert first['actual_payload_lengths'] == [4, 6]
    assert first['complete_timestamp_ns'] == 200000
    assert (first['packet_bytes'], first['retransmitted_bytes']) == (16, 6)
    second = find(segments, b'xyz', first['end_offset'])
    assert (second['sequence_start'], second['sequence_end']) == (4, 7)
    assert second['actual_payload_lengths'] == [3]


def test_conflicting_bytes_on_overlap_are_refused(tmp_path):
    segments = relay_segments(tmp_path, [(100, 1, b'abcdef'), (200, 4, b'dXf')])
    assert find(segments, b'abcdef') is None


def rewrite_incoming(root, extra):
    """Re-write the conversation's in.pcap with extra (time_us, frame) packets, in time order."""
    records, _ = wire_check.read_pcap_records(root / 'in.pcap')
    pcap(root / 'in.pcap', sorted([(r['t_us'], r['frame']) for r in records] + extra, key=lambda p: p[0]))


def first_response(root):
    return next(s for s in wire_check.parse(root / 'in.pcap')[0] if s['len'])


def test_analyze_counts_a_resegmented_response_retransmission(tmp_path):
    conversation(tmp_path)
    original = first_response(tmp_path)
    seq, ack, payload = original['seq'], original['ack'], original['payload']
    rewrite_incoming(tmp_path, [(15, packet(False, seq, ack, 24, payload[:10])),
                                (16, packet(False, seq + 10, ack, 24, payload[10:]))])
    report = relay_check.analyze(tmp_path, 59410, dict(READ=0, SELECT=1, OPERATE=1), 'full')
    assert report['schema'] == 'sel751-wire-v3'
    assert report['ok'], report['failures']
    assert report['retransmissions'] == {'out': 0, 'in': 2}
    assert report['retransmitted_bytes'] == {'out': 0, 'in': len(payload)}
    assert report['packet_bytes']['in'] == report['unique_bytes']['in'] + len(payload)
    response = report['exchanges'][0]['response']
    assert response['actual_payload_lengths'] == [len(payload)]
    assert response['complete_timestamp_ns'] == original['timestamp_ns']
    assert (response['retransmitted_bytes'], response['retransmitted_segments']) == (len(payload), 2)


def test_analyze_fails_a_span_with_conflicting_retransmitted_bytes(tmp_path):
    conversation(tmp_path)
    original = first_response(tmp_path)
    forged = bytearray(original['payload'])
    forged[12] ^= 0xff
    rewrite_incoming(tmp_path, [(15, packet(False, original['seq'], original['ack'], 24, bytes(forged)))])
    report = relay_check.analyze(tmp_path, 59410, dict(READ=0, SELECT=1, OPERATE=1), 'full')
    assert not report['ok']
    assert 'complete request/response TCP span missing: SELECT' in report['failures']


@pytest.mark.parametrize('split_tcp', [False, True])
def test_clean_conversation_has_no_retransmitted_bytes(tmp_path, split_tcp):
    conversation(tmp_path, split_tcp=split_tcp)
    report = relay_check.analyze(tmp_path, 59410, dict(READ=0, SELECT=1, OPERATE=1), 'full')
    assert report['ok'], report['failures']
    assert report['retransmissions'] == {'out': 0, 'in': 0}
    assert report['retransmitted_bytes'] == {'out': 0, 'in': 0}
    assert report['packet_bytes'] == report['unique_bytes']
    for exchange in report['exchanges']:
        for span in (exchange['request'], exchange['response']):
            assert sum(span['actual_payload_lengths']) == span['unique_bytes'] == span['packet_bytes']
            assert span['unique_bytes'] == span['end_offset'] - span['start_offset']


def test_span_with_a_missing_byte_is_never_found(tmp_path):
    segments = relay_segments(tmp_path, [(100, 1, b'abc'), (200, 5, b'ef')])
    assert find(segments, b'abcdef') is None
    assert find(segments, b'abc') is not None


def test_several_connection_incarnations_are_refused(tmp_path):
    frames = [(1, packet(False, ISN, 101, 18)), (2, packet(False, ISN + 5000, 101, 18)),
              (100, packet(False, ISN + 1, 101, 24, b'abcdef'))]
    pcap(tmp_path / 'in.pcap', frames)
    assert find(wire_check.parse(tmp_path / 'in.pcap')[0], b'abcdef') is None


def test_minimum_offset_skips_an_identical_earlier_span(tmp_path):
    segments = relay_segments(tmp_path, [(100, 1, b'abcabc')])
    assert find(segments, b'abc')['start_offset'] == 1
    later = find(segments, b'abc', 2)
    assert (later['start_offset'], later['end_offset']) == (4, 7)
    assert find(segments, b'abc', 5) is None


def test_segment_starting_before_the_first_data_byte_is_placed_by_signed_offset(tmp_path):
    segments = relay_segments(tmp_path, [(100, -2, b'zzXabc')])
    span = find(segments, b'abc')
    assert (span['start_offset'], span['sequence_start']) == (1, ISN + 1)
    assert span['actual_payload_lengths'] == [3] and span['packet_bytes'] == 3

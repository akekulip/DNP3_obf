#!/usr/bin/env python3
"""Physical relay evidence from one master NIC; no reflected-copy or switch-residence claim."""
import argparse
import bisect
import hashlib
import json
import statistics
from pathlib import Path
import sys

if __package__:
    from . import wire_check as wc
    from .endpoint_profiles import MASTER_IP, RELAY_IP, RELAY_PORT, validate_tcp_observation
else:
    import wire_check as wc
    from endpoint_profiles import MASTER_IP, RELAY_IP, RELAY_PORT, validate_tcp_observation

# The same CRC/transport/application codec used by the guarded relay master.  The
# adjacent path is used on Vision; the second path is the repository layout.
_active = Path(__file__).resolve().parent / 'active_harness'
if not _active.is_dir():
    _active = Path(__file__).resolve().parents[1] / 'hardware/active_harness'
sys.path.insert(0, str(_active))
import dnp3_codec as codec

SCHEMA_VERSION = 'sel751-wire-v3'
SELECT_ONLY = 'select-only plan: '
# IEEE 1815 function codes that operate an output: OPERATE, DIRECT_OPERATE, DIRECT_OPERATE_NR
OPERATE_FUNCTIONS = (codec.FUNC_OPERATE, 0x05, 0x06)


def application_from_wire(raw):
    """One CRC-valid, fully reassembled application fragment, with no trailing bytes."""
    frames = []
    while raw:
        frame, rest = codec.parse_frame(raw)
        if frame is None or len(rest) >= len(raw):
            raise ValueError('incomplete DNP3 link frame')
        frames.append(frame)
        raw = rest
    assembler = codec.TransportAssembler()
    fragments = []
    for frame in frames:
        fragment = assembler.add(frame.user_data)
        if fragment is not None:
            fragments.append(fragment)
    if assembler.in_progress or len(fragments) != 1:
        raise ValueError('expected one complete DNP3 application fragment')
    return fragments[0]


def application_observation(request_wire, response_wire, record):
    """Decode the located wire bytes; master strings are claims to check, never authority."""
    request = application_from_wire(request_wire)
    response = application_from_wire(response_wire)
    failures = []
    for prefix, actual in (('request', request), ('response', response)):
        if record.get(prefix + '_app_hex') != actual.hex():
            failures.append(prefix + ' application metadata differs from decoded wire')
    functions = {'READ': codec.FUNC_READ, 'SELECT': codec.FUNC_SELECT, 'OPERATE': codec.FUNC_OPERATE}
    operation = record.get('operation')
    if len(request) < 2 or request[0] & 0xf0 != 0xc0 or request[1] != functions.get(operation):
        failures.append('request application function/header differs from operation')
        return dict(ok=False, failures=failures, points=[])
    decoded = codec.parse_application_response(response)
    kwargs = dict(expect_seq=request[0] & 15, expect_function=request[1], require_success=True)
    if operation == 'READ':
        workload = codec.read_workload_for_request(request)
        if record.get('workload') != workload:
            failures.append('READ workload metadata differs from decoded request')
        kwargs['expect_read_workload'] = workload
    else:
        kwargs['expect_points'] = [1, 3]
        # CROB request and response have the same object layout; insert only the
        # response function/IIN header to reuse the codec's object decoder.
        command = codec.parse_application_response(request[:1] + b'\x81\x00\x00' + request[2:])
        failures += ['request: ' + error for error in codec.validate_response(command, **kwargs)]
        wanted = [(obj['group'], obj['variation'], obj['qualifier'],
                   [(p['index'], p['raw_hex'][:-2]) for p in obj['points']]) for obj in command.objects]
        echoed = [(obj['group'], obj['variation'], obj['qualifier'],
                   [(p['index'], p['raw_hex'][:-2]) for p in obj['points']]) for obj in decoded.objects]
        if wanted != echoed:
            failures.append('response CROB echo differs from captured request')
    failures += codec.validate_response(decoded, **kwargs)
    points = [[index, codec.STATUS_NAMES.get(status, str(status))] for index, status in decoded.points]
    if operation != 'READ' and record.get('points') != points:
        failures.append('CROB point metadata differs from decoded wire: %r' % points)
    return dict(ok=not failures, failures=failures, points=points,
                request_app_hex=request.hex(), response_app_hex=response.hex())


def plan_checks(master, expected, select_only=False):
    """A planned OPERATE count other than SELECT is accepted only for an explicit select-only plan (E4b), which plans
    SELECTs and no OPERATE, comes from a master that ran select-only and records no OPERATE."""
    if not select_only:
        if expected.get('SELECT') != expected.get('OPERATE'):
            return ['planned OPERATE differs from SELECT without an explicit select-only plan']
        if 'sbo_select_only' in master:
            return [SELECT_ONLY + 'the master ran select-only but the frozen plan is SELECT then OPERATE']
        return []
    failures = []
    if not expected.get('SELECT') or expected.get('OPERATE') != 0:
        failures.append(SELECT_ONLY + 'needs planned SELECT >= 1 and OPERATE 0, got %r' % (expected,))
    if master.get('sbo_select_only') is not True:
        failures.append(SELECT_ONLY + 'the master did not run the select-only workload')
    operates = sum(r.get('operation') == 'OPERATE' for r in master.get('records') or [])
    if operates:
        failures.append(SELECT_ONLY + '%d OPERATE master record(s)' % operates)
    return failures


def request_functions(stream):
    """Application function of every complete request in the reassembled master-to-relay stream, in stream order."""
    if stream is None:
        raise ValueError('no single-incarnation master stream')
    functions = []
    for _start, data in stream['runs']:
        raw, assembler = bytes(data), codec.TransportAssembler()
        while raw:
            frame, raw = codec.parse_frame(raw)
            if frame is None:
                raise ValueError('incomplete DNP3 link frame')
            fragment = assembler.add(frame.user_data)
            if fragment is not None:
                functions.append(fragment[1] if len(fragment) > 1 else None)
        if assembler.in_progress:
            raise ValueError('unfinished transport fragment')
    return functions


def select_only_wire_checks(stream, records):
    """From captured bytes, not master claims: no OPERATE-class request left the master, and the captured request
    sequence is exactly the recorded one."""
    try:
        functions = request_functions(stream)
    except (ValueError, codec.TransportError) as error:
        return [SELECT_ONLY + 'captured master stream cannot be decoded: %s' % error]
    failures = []
    operates = sum(function in OPERATE_FUNCTIONS for function in functions)
    if operates:
        failures.append(SELECT_ONLY + '%d OPERATE request(s) in the captured master stream' % operates)
    names = {codec.FUNC_READ: 'READ', codec.FUNC_SELECT: 'SELECT', codec.FUNC_OPERATE: 'OPERATE'}
    if [names.get(function, function) for function in functions] != [r.get('operation') for r in records]:
        failures.append(SELECT_ONLY + 'captured request sequence differs from the master records')
    return failures


def master_checks(master, master_port, expected=None, schedule=None, select_only=False):
    failures = []
    records = master.get('records') or []
    if expected is None:
        failures.append('frozen expected transaction denominators not supplied')
    else:
        failures += plan_checks(master, expected, select_only)
        actual = {operation: sum(r.get('operation') == operation and r.get('outcome') == 'OK' for r in records)
                  for operation in ('READ', 'SELECT', 'OPERATE')}
        if actual != expected or master.get('counts') != expected or master.get('planned') != expected:
            failures.append('master records/counts/plan differ from frozen expected denominators')
        order = ('mixed', 'integrity') if schedule == 'mixed_full' else ('mixed',) if schedule == 'mixed' else ('integrity',)
        workloads = [r.get('workload') for r in records if r.get('operation') == 'READ']
        if workloads != [order[i % len(order)] for i in range(expected['READ'])]:
            failures.append('READ workload sequence differs from frozen schedule')
    if not master.get('ok') or not records or master.get('counts') != master.get('planned'):
        failures.append('complete planned master denominators missing or failed')
    for rec in records:
        if rec.get('outcome') != 'OK':
            failures.append('master transaction failed: ' + str(rec.get('operation')))
        if rec.get('local_address') != [MASTER_IP, master_port] or rec.get('peer_address') != [RELAY_IP, RELAY_PORT]:
            failures.append('actual socket identity missing or mismatched')
        for prefix in ('request', 'response'):
            try:
                raw = bytes.fromhex(rec[prefix + '_wire_hex'])
                frames = [bytes.fromhex(v) for v in rec[prefix + '_frames_hex']]
                app = bytes.fromhex(rec[prefix + '_app_hex'])
                if not raw or not app or b''.join(frames) != raw or not wc.dnp3_ok(raw)[0]:
                    raise ValueError('incomplete wire/frame/application identity')
                wanted_dst, wanted_src = (0, 1) if prefix == 'request' else (1, 0)
                if any(int.from_bytes(frame[4:6], 'little') != wanted_dst or
                       int.from_bytes(frame[6:8], 'little') != wanted_src for frame in frames):
                    raise ValueError('DNP3 address identity mismatch')
            except (KeyError, TypeError, ValueError):
                failures.append(prefix + ' complete wire/frame/application evidence missing or invalid')
        try:
            observation = application_observation(bytes.fromhex(rec.get('request_wire_hex', '')),
                                                  bytes.fromhex(rec.get('response_wire_hex', '')), rec)
            failures += [str(rec.get('operation')) + ' application: ' + error
                         for error in observation['failures']]
        except (ValueError, TypeError, codec.TransportError):
            failures.append('request complete wire/frame/application evidence cannot be reassembled')
    return failures


def packet_record(seg):
    frame = seg['frame']
    ihl = (frame[14] & 15) * 4
    tcp = 14 + ihl
    tcp_len = (frame[tcp + 12] >> 4) * 4
    return dict(index=seg['index'], timestamp_ns=seg['timestamp_ns'], seq=seg['seq'], ack=seg['ack'],
                flags=seg['flags'], payload_len=seg['len'], payload_hex=seg['payload'].hex(),
                ipv4_header_bytes=ihl, tcp_header_bytes=tcp_len, tcp_options_hex=frame[tcp + 20:tcp + tcp_len].hex())


def stream_offset(seq, origin):
    """Signed 32-bit distance of seq from origin, so one stream may wrap across 2**32."""
    delta = (seq - origin) & 0xffffffff
    return delta - 0x100000000 if delta & 0x80000000 else delta


def reassemble(segments, origin):
    """First-arrival reconstruction of one TCP direction, in stream offsets from origin.

    Payload segments are taken in arrival order (timestamp, then capture index).  ``pieces`` are disjoint
    (start, end, segment start, segment) ranges sorted by start: the bytes whose first captured copy is that
    segment.  ``copies`` holds every payload segment as (start, end, segment), sorted by start.  ``conflicts``
    holds the offsets where a later copy differs from the first-arriving byte."""
    pieces, starts, copies, conflicts = [], [], [], set()
    for seg in sorted((s for s in segments if s['len']), key=lambda s: (s['timestamp_ns'], s['index'])):
        start = stream_offset(seg['seq'], origin)
        end = start + seg['len']
        copies.append((start, end, seg))
        gaps, cursor = [], start
        i = max(bisect.bisect_right(starts, start) - 1, 0)
        while i < len(pieces) and pieces[i][0] < end:
            a, b, first_start, first = pieces[i]
            if b > cursor:
                if a > cursor:
                    gaps.append((cursor, a))
                low, high = max(a, cursor), min(b, end)
                mine = seg['payload'][low - start:high - start]
                theirs = first['payload'][low - first_start:high - first_start]
                conflicts.update(low + j for j, byte in enumerate(mine) if byte != theirs[j])
                cursor = high
            i += 1
        if cursor < end:
            gaps.append((cursor, end))
        for a, b in gaps:
            k = bisect.bisect_left(starts, a)
            starts.insert(k, a)
            pieces.insert(k, (a, b, start, seg))
    runs = []  # contiguous first-arrival bytes as [start, bytearray]
    for a, b, first_start, first in pieces:
        chunk = first['payload'][a - first_start:b - first_start]
        if runs and runs[-1][0] + len(runs[-1][1]) == a:
            runs[-1][1] += chunk
        else:
            runs.append([a, bytearray(chunk)])
    copies.sort(key=lambda c: c[0])
    return dict(origin=origin, pieces=pieces, starts=starts, copies=copies, copy_starts=[c[0] for c in copies],
                longest=max((c[1] - c[0] for c in copies), default=0), conflicts=conflicts, runs=runs)


def tcp_stream(segments):
    """First-arrival reassembly anchored at the single SYN; None for zero or several connection incarnations."""
    syns = {s['seq'] for s in segments if s['flags'] & wc.SYN}
    if len(syns) != 1:
        return None  # multiple connection incarnations cannot be silently combined
    return reassemble(segments, next(iter(syns)))


def span_record(stream, begin, wanted):
    """Each unique byte credited to its first-arriving packet; every overlapping copy counted as packet bytes."""
    finish = begin + len(wanted)
    unique = {}
    pieces = stream['pieces']
    i = max(bisect.bisect_right(stream['starts'], begin) - 1, 0)
    while i < len(pieces) and pieces[i][0] < finish:
        a, b, _, seg = pieces[i]
        if b > begin:
            unique[seg['index']] = (seg, unique.get(seg['index'], (seg, 0))[1] + min(b, finish) - max(a, begin))
        i += 1
    packet_bytes = retransmitted_segments = 0
    copies = stream['copies']
    i = bisect.bisect_left(stream['copy_starts'], begin - stream['longest'])
    while i < len(copies) and copies[i][0] < finish:
        a, b, seg = copies[i]
        carried = max(0, min(b, finish) - max(a, begin))
        packet_bytes += carried
        retransmitted_segments += carried > unique.get(seg['index'], (seg, 0))[1]
        i += 1
    parts = sorted(unique.values(), key=lambda part: (part[0]['timestamp_ns'], part[0]['index']))
    origin = stream['origin']
    return dict(sequence_start=(origin + begin) & 0xffffffff, complete=True,
                packets=[packet_record(seg) for seg, _ in parts],
                sequence_end=(origin + finish) & 0xffffffff, start_offset=begin, end_offset=finish,
                actual_payload_lengths=[count for _, count in parts], wire_hex=wanted.hex(),
                first_timestamp_ns=min(seg['timestamp_ns'] for seg, _ in parts),
                complete_timestamp_ns=max(seg['timestamp_ns'] for seg, _ in parts),
                unique_bytes=len(wanted), packet_bytes=packet_bytes, retransmitted_bytes=packet_bytes - len(wanted),
                retransmitted_segments=retransmitted_segments)


def locate(stream, raw, minimum_offset=0):
    """First exact span of raw at a stream byte offset >= minimum_offset, refusing spans with conflicting bytes.

    A span may start or end inside a segment.  complete_timestamp_ns is when its last missing byte first
    arrived; actual_payload_lengths are the unique span bytes each first-arriving packet contributed."""
    wanted = bytes.fromhex(raw)
    if not wanted or stream is None:
        return None
    for run_start, data in stream['runs']:
        position = data.find(wanted, max(minimum_offset - run_start, 0))
        while position >= 0:
            begin = run_start + position
            if not any(begin <= offset < begin + len(wanted) for offset in stream['conflicts']):
                return span_record(stream, begin, wanted)
            position = data.find(wanted, position + 1)
    return None


def stream_contains(segments, raw, minimum_offset=0):
    """Find an exact contiguous TCP span by stream byte offset; retransmitted copies never add bytes or time."""
    return locate(tcp_stream(segments), raw, minimum_offset)


def byte_counts(segments):
    """Payload accounting of one direction by byte overlap: unique stream bytes, packet bytes (every captured
    copy), retransmitted bytes, and retransmitted segments (payload segments carrying an already-captured byte).
    Anchored at the single SYN, else at the first-arriving payload segment."""
    data = [s for s in segments if s['len']]
    if not data:
        return dict(unique_bytes=0, packet_bytes=0, retransmitted_bytes=0, retransmitted_segments=0)
    syns = {s['seq'] for s in segments if s['flags'] & wc.SYN}
    origin = next(iter(syns)) if len(syns) == 1 else min(data, key=lambda s: (s['timestamp_ns'], s['index']))['seq']
    stream = reassemble(segments, origin)
    contributed = {}
    for a, b, _, seg in stream['pieces']:
        contributed[seg['index']] = contributed.get(seg['index'], 0) + b - a
    unique = sum(contributed.values())
    packet = sum(b - a for a, b, _ in stream['copies'])
    return dict(unique_bytes=unique, packet_bytes=packet, retransmitted_bytes=packet - unique,
                retransmitted_segments=sum(contributed.get(seg['index'], 0) < b - a for a, b, seg in stream['copies']))


def analyze(root, master_port, expected=None, schedule=None, select_only=False):
    root = Path(root)
    master = json.loads((root / 'master.json').read_text())
    result = json.loads((root / 'result.json').read_text())
    failures = master_checks(master, master_port, expected, schedule, select_only=select_only)
    streams, packets = {}, {}
    for direction, src, dst, sport, dport in [('out', MASTER_IP, RELAY_IP, master_port, RELAY_PORT),
                                            ('in', RELAY_IP, MASTER_IP, RELAY_PORT, master_port)]:
        segments, _ = wc.parse(root / (direction + '.pcap'))
        segments = [s for s in segments if (s['src'], s['dst'], s['sport'], s['dport']) == (src, dst, sport, dport)]
        streams[direction] = segments
        packets[direction] = [packet_record(s) for s in segments]
        if not any(s['flags'] & wc.SYN for s in segments):
            failures.append(direction + ' fresh SYN/options evidence missing')
        for seg in segments:
            ip_ok, tcp_ok, offload = wc.ip_tcp_checksum(seg)
            if not ip_ok or (not tcp_ok and not (direction == 'out' and offload)):
                failures.append(direction + ' IPv4/TCP checksum invalid')
        stats = (result.get('tcpdump') or {}).get(direction) or {}
        if stats.get('dropped_kernel') != 0 or stats.get('dropped_interface', 0) != 0:
            failures.append(direction + ' capture drop evidence missing or nonzero')
    exchanges = []
    cursors = dict(out=0, **{'in': 0})
    reassembled = {direction: tcp_stream(stream) for direction, stream in streams.items()}
    accounting = {direction: byte_counts(stream) for direction, stream in streams.items()}
    if select_only:
        failures += select_only_wire_checks(reassembled['out'], master.get('records', []))
    for record in master.get('records', []):
        request = locate(reassembled['out'], record.get('request_wire_hex', ''), cursors['out'])
        response = locate(reassembled['in'], record.get('response_wire_hex', ''), cursors['in'])
        if not request or not response:
            failures.append('complete request/response TCP span missing: ' + str(record.get('operation')))
        else:
            cursors.update(out=request['end_offset'], **{'in': response['end_offset']})
            if any(packet['ack'] != request['sequence_end'] for packet in response['packets']):
                failures.append('response does not acknowledge exactly its associated request')
        ack_candidates = [packet for packet in streams['in'] if request and response and
                          request['first_timestamp_ns'] <= packet['timestamp_ns'] <= response['complete_timestamp_ns'] and
                          packet['flags'] & wc.ACK and packet['ack'] == request['sequence_end']]
        first_ack = min(ack_candidates, key=lambda p: p['timestamp_ns']) if ack_candidates else None
        # the CLRT an on-path adversary sees: first ACK of the request -> complete response
        complete_clrt = ((response['complete_timestamp_ns'] - first_ack['timestamp_ns']) / 1000
                         if response and first_ack else None)
        application = None
        if request and response:
            try:
                application = application_observation(bytes.fromhex(request['wire_hex']),
                                                      bytes.fromhex(response['wire_hex']), record)
            except (ValueError, TypeError, codec.TransportError) as error:
                failures.append('captured DNP3 application cannot be decoded: ' + str(error))
        exchanges.append(dict(operation=record.get('operation'), workload=record.get('workload'),
                              request=request, response=response,
                              application=application,
                              ack_timestamp_ns=first_ack['timestamp_ns'] if first_ack else None,
                              complete_clrt_us=complete_clrt, piggyback=bool(first_ack and first_ack['len'])))
    offload = json.loads((root / 'capture_offloads.json').read_text()) if (root / 'capture_offloads.json').is_file() else {}
    if offload.get('restore_ok') is not True:
        failures.append('capture offload restoration missing or failed')
    totals = {key: {direction: counts[key] for direction, counts in accounting.items()}
              for key in ('retransmitted_segments', 'retransmitted_bytes', 'unique_bytes', 'packet_bytes')}
    report = dict(schema=SCHEMA_VERSION, ok=not failures, failures=failures, packets=packets, exchanges=exchanges,
                capture_drops={direction: (result.get('tcpdump') or {}).get(direction) for direction in streams},
                retransmissions=totals['retransmitted_segments'], retransmitted_bytes=totals['retransmitted_bytes'],
                unique_bytes=totals['unique_bytes'], packet_bytes=totals['packet_bytes'],
                observation_scope='single master NIC TX/RX; SYN/options and TCP sequence spans retained',
                independent_packet_boundary_calibration=False, same_packet_preservation_proven=False,
                artifacts={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                           [root / 'out.pcap', root / 'in.pcap', root / 'master.json', root / 'result.json']})
    try:
        validate_tcp_observation(report)
    except (ValueError, KeyError, TypeError) as error:
        report['failures'].append(str(error))
    report['ok'] = not report['failures']
    return report


def visible_clrt(report):
    """The CLRT each class shows at the master NIC (the adversary's vantage), reported, never gated: n, min, median,
    max and every value in microseconds. A piggybacked ACK has no separate CLRT and is counted apart."""
    result = {}
    for operation in ('READ mixed', 'READ integrity', 'SELECT', 'OPERATE'):
        op, _, workload = operation.partition(' ')
        rows = [row for row in report['exchanges'] if row['operation'] == op and
                (not workload or row.get('workload') == workload)]
        values = sorted(row['complete_clrt_us'] for row in rows
                        if not row['piggyback'] and row['complete_clrt_us'] is not None)
        result[operation] = dict(n=len(values), piggyback=sum(bool(row['piggyback']) for row in rows),
                                 min_us=values[0] if values else None,
                                 median_us=statistics.median(values) if values else None,
                                 max_us=values[-1] if values else None, values_us=values)
    return result


def close_checks(report, mode):
    """Close proof at the master NIC, bound to this connection's last complete TCP spans."""
    failures = []
    exchanges = report.get('exchanges') or []
    if not exchanges or not exchanges[-1].get('request') or not exchanges[-1].get('response'):
        return ['close proof lacks complete final transaction frontiers']
    out, incoming = report['packets']['out'], report['packets']['in']
    if mode == 'rst':
        if not any(p['flags'] & wc.RST for p in out):
            failures.append('planned master RST absent from capture')
        return failures
    master_end = exchanges[-1]['request']['sequence_end']
    relay_end = exchanges[-1]['response']['sequence_end']
    master_fin = [p for p in out if p['flags'] & wc.FIN and (p['seq'] + p['payload_len']) & 0xffffffff == master_end]
    relay_fin = [p for p in incoming if p['flags'] & wc.FIN and (p['seq'] + p['payload_len']) & 0xffffffff == relay_end]
    if not master_fin or not relay_fin:
        failures.append('graceful close lacks both FINs at the completed transaction frontiers')
    if not any(p['flags'] & wc.ACK and p['ack'] == (master_end + 1) & 0xffffffff for p in incoming):
        failures.append('relay final ACK does not acknowledge the master FIN')
    if not any(p['flags'] & wc.ACK and p['ack'] == (relay_end + 1) & 0xffffffff for p in out):
        failures.append('master final ACK does not acknowledge the relay FIN')
    return failures


def freshness(report, previous=None):
    """Fresh handshake/frontiers in master coordinates; never infer a second switch observation."""
    out, incoming = report['packets']['out'], report['packets']['in']
    clients = {p['seq'] for p in out if p['flags'] == wc.SYN}
    servers = {p['seq'] for p in incoming if p['flags'] == wc.SYN | wc.ACK}
    if len(clients) != 1 or len(servers) != 1:
        raise ValueError('missing or ambiguous physical fresh SYN/SYNACK')
    client, server = next(iter(clients)), next(iter(servers))
    if any(p['ack'] != (client + 1) & 0xffffffff for p in incoming if p['flags'] == wc.SYN | wc.ACK) or not any(
            p['flags'] == wc.ACK and not p['payload_len'] and p['seq'] == (client + 1) & 0xffffffff and
            p['ack'] == (server + 1) & 0xffffffff for p in out):
        raise ValueError('physical fresh handshake final ACK/SYNACK identity failed')
    observed = dict(client_isn=client, server_isn=server, frontiers={}, observation_scope='master TCP coordinates only')
    for name, packets, isn in (('client', out, client), ('server', incoming, server)):
        spans = [((p['seq'] - isn) & 0xffffffff) + p['payload_len'] + bool(p['flags'] & wc.SYN) +
                 bool(p['flags'] & wc.FIN) for p in packets if not p['flags'] & wc.RST]
        if not spans or max(spans) >= 0x80000000:
            raise ValueError('ambiguous physical current sequence range')
        observed['frontiers'][name] = (isn + max(spans)) & 0xffffffff
        if previous and not 2 <= (((isn + 1) - previous['frontiers'][name]) & 0xffffffff) <= 0x7fffffff:
            raise ValueError('physical new %s ISN overlaps/precedes prior frontier' % name)
    reads = [row for row in report['exchanges'] if row['operation'] == 'READ']
    if not reads or not reads[0].get('response') or reads[0]['response']['sequence_start'] != (server + 1) & 0xffffffff:
        raise ValueError('physical first READ inherited an old mapping offset')
    return observed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--master-port', type=int, required=True)
    parser.add_argument('--reads', type=int, required=True)
    parser.add_argument('--sbo', type=int, required=True)
    parser.add_argument('--read-schedule', choices=('mixed_full', 'mixed', 'full'), required=True)
    parser.add_argument('--select-only', action='store_true', help='E4b plan: --sbo SELECTs and no OPERATE')
    args = parser.parse_args(argv)
    try:
        result = analyze(args.root, args.master_port,
                         dict(READ=args.reads, SELECT=args.sbo, OPERATE=0 if args.select_only else args.sbo),
                         args.read_schedule, select_only=args.select_only)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = dict(ok=False, failures=[str(error)])
    (args.root / 'relay_wire.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Physical relay evidence from one master NIC; no reflected-copy or switch-residence claim."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

import wire_check as wc
from endpoint_profiles import MASTER_IP, RELAY_IP, RELAY_PORT, validate_tcp_observation


def master_checks(master, master_port, expected=None, schedule=None):
    failures = []
    records = master.get('records') or []
    if expected is None:
        failures.append('frozen expected transaction denominators not supplied')
    else:
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
    return failures


def packet_record(seg):
    frame = seg['frame']
    ihl = (frame[14] & 15) * 4
    tcp = 14 + ihl
    tcp_len = (frame[tcp + 12] >> 4) * 4
    return dict(index=seg['index'], timestamp_ns=seg['timestamp_ns'], seq=seg['seq'], ack=seg['ack'],
                flags=seg['flags'], payload_len=seg['len'], payload_hex=seg['payload'].hex(),
                ipv4_header_bytes=ihl, tcp_header_bytes=tcp_len, tcp_options_hex=frame[tcp + 20:tcp + tcp_len].hex())


def stream_contains(segments, raw, minimum_offset=0):
    """Find an exact contiguous TCP sequence span, tolerating identical retransmissions only."""
    wanted = bytes.fromhex(raw)
    if not wanted:
        return None
    syns = {s['seq'] for s in segments if s['flags'] & wc.SYN}
    if len(syns) != 1:
        return None  # multiple connection incarnations cannot be silently combined
    origin = next(iter(syns))
    for first in sorted(segments, key=lambda s: (s['seq'] - origin) & 0xffffffff):
        if not first['len']:
            continue
        start = first['seq']
        start_offset = (start - origin) & 0xffffffff
        if start_offset < minimum_offset:
            continue
        covered = {}
        conflict = False
        for seg in segments:
            offset = (seg['seq'] - start) & 0xffffffff
            if offset >= len(wanted):
                continue
            for j, byte in enumerate(seg['payload']):
                if offset + j >= len(wanted):
                    break
                if offset + j in covered and covered[offset + j] != byte:
                    conflict = True
                covered[offset + j] = byte
        if not conflict and len(covered) == len(wanted) and bytes(covered[i] for i in range(len(wanted))) == wanted:
            earliest = {}
            for seg in segments:
                offset = (seg['seq'] - start) & 0xffffffff
                if seg['len'] and offset < len(wanted):
                    key = (seg['seq'], seg['payload'])
                    if key not in earliest or seg['timestamp_ns'] < earliest[key]['timestamp_ns']:
                        earliest[key] = seg
            parts = [packet_record(s) for s in earliest.values()]
            return dict(sequence_start=start, complete=True, packets=parts,
                        sequence_end=(start + len(wanted)) & 0xffffffff,
                        start_offset=start_offset, end_offset=start_offset + len(wanted),
                        actual_payload_lengths=[p['payload_len'] for p in parts],
                        first_timestamp_ns=min(p['timestamp_ns'] for p in parts),
                        complete_timestamp_ns=max(p['timestamp_ns'] for p in parts))
    return None


def analyze(root, master_port, expected=None, schedule=None):
    root = Path(root)
    master = json.loads((root / 'master.json').read_text())
    result = json.loads((root / 'result.json').read_text())
    failures = master_checks(master, master_port, expected, schedule)
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
    for record in master.get('records', []):
        request = stream_contains(streams['out'], record.get('request_wire_hex', ''), cursors['out'])
        response = stream_contains(streams['in'], record.get('response_wire_hex', ''), cursors['in'])
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
        first_clrt = ((response['first_timestamp_ns'] - first_ack['timestamp_ns']) / 1000
                      if response and first_ack else None)
        complete_clrt = ((response['complete_timestamp_ns'] - first_ack['timestamp_ns']) / 1000
                         if response and first_ack else None)
        exchanges.append(dict(operation=record.get('operation'), workload=record.get('workload'),
                              request=request, response=response,
                              master_rtt_ns=(response['complete_timestamp_ns'] - request['first_timestamp_ns']
                                             if request and response else None),
                              ack_timestamp_ns=first_ack['timestamp_ns'] if first_ack else None,
                              first_clrt_us=first_clrt, complete_clrt_us=complete_clrt,
                              piggyback=bool(first_ack and first_ack['len']),
                              switch_residence_ns=None, operate_j_ns=None,
                              null_reason='only master NIC observed'))
    offload = json.loads((root / 'capture_offloads.json').read_text()) if (root / 'capture_offloads.json').is_file() else {}
    if offload.get('restore_ok') is not True:
        failures.append('capture offload restoration missing or failed')
    report = dict(schema='sel751-wire-v1', ok=not failures, failures=failures, packets=packets, exchanges=exchanges,
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


def precision(report, target_ns):
    result = {}
    for operation in ('READ', 'SELECT', 'OPERATE'):
        rows = [row for row in report['exchanges'] if row['operation'] == operation]
        eligible = [row for row in rows if not row['piggyback'] and row['complete_clrt_us'] is not None]
        errors = sorted(abs(row['complete_clrt_us'] - target_ns / 1000) for row in eligible)
        p99 = errors[max(0, math.ceil(.99 * len(errors)) - 1)] if errors else None
        result[operation] = dict(planned=len(rows), eligible=len(eligible),
                                 p99_nearest_rank_abs_error_us=p99, max_abs_error_us=max(errors) if errors else None,
                                 pass_=len(eligible) == len(rows) and len(rows) >= 20 and p99 <= 100)
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
    args = parser.parse_args(argv)
    try:
        result = analyze(args.root, args.master_port,
                         dict(READ=args.reads, SELECT=args.sbo, OPERATE=args.sbo), args.read_schedule)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = dict(ok=False, failures=[str(error)])
    (args.root / 'relay_wire.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())

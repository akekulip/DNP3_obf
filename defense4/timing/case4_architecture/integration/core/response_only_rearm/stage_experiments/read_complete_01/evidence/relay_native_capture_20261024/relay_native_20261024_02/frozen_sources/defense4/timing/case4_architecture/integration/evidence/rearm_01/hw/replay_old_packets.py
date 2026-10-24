#!/usr/bin/env python3
"""Replay checksum-valid old software-endpoint frames unchanged; dry-run unless --apply.

Run on Vision's parent NIC, with new traffic paused. This script never calls SSH,
changes switch state, constructs private headers, or repairs captured checksums.
Copy wire_check.py beside this file when deploying outside the repository.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
if len(HERE.parents) >= 4:
    sys.path.append(str(HERE.parents[3] / 'protocol/hw_vepa'))
import wire_check as wc

MASTER, OUTSTATION, SERVER_PORT = '192.168.10.61', '192.168.10.62', 20000
INTERFACE = 'enp59s0f0np0'                 # Vision parent NIC, external switch dev 9
CLASSES = ('SYN', 'SYN_ACK', 'READ_REQUEST', 'READ_RESPONSE', 'PURE_ACK', 'FIN', 'RST')
MASK = 0xffffffff


def records(path):
    """Require complete Ethernet classic-pcap records before using the existing reader."""
    data = Path(path).read_bytes()
    magic = data[:4]
    if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
        raise ValueError('not classic pcap: %s' % path)
    endian = '<' if magic[0] in (0xd4, 0x4d) else '>'
    if len(data) < 24 or struct.unpack(endian + 'I', data[20:24])[0] != 1:
        raise ValueError('capture must use Ethernet link type: %s' % path)
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError('truncated pcap record: %s' % path)
        incl, orig = struct.unpack(endian + 'II', data[offset + 8:offset + 16])
        offset += 16 + incl
        if incl != orig or offset > len(data):
            raise ValueError('truncated captured frame: %s' % path)
    return wc.read_pcap(path)[0]


def segment(frame, master_port):
    if len(frame) < 54 or frame[12:14] != b'\x08\x00':
        raise ValueError('not Ethernet IPv4')
    ihl, total = (frame[14] & 15) * 4, int.from_bytes(frame[16:18], 'big')
    tcp = 14 + ihl
    if frame[14] >> 4 != 4 or ihl < 20 or total < ihl + 20 or len(frame) < 14 + total or frame[23] != 6:
        raise ValueError('malformed IPv4/TCP')
    if int.from_bytes(frame[20:22], 'big') & 0x3fff:
        raise ValueError('fragmented IPv4')
    offset = (frame[tcp + 12] >> 4) * 4
    if offset < 20 or ihl + offset > total:
        raise ValueError('malformed TCP header')
    src, dst = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
    sport, dport, seq, ack = struct.unpack('!HHII', frame[tcp:tcp + 12])
    direction = 'M->O' if (src, dst, sport, dport) == (MASTER, OUTSTATION, master_port, SERVER_PORT) else 'O->M'
    if direction == 'O->M' and (src, dst, sport, dport) != (OUTSTATION, MASTER, SERVER_PORT, master_port):
        raise ValueError('other flow')
    payload, flags = frame[tcp + offset:14 + total], frame[tcp + 13]
    ip_ok, tcp_ok, offloaded = wc.ip_tcp_checksum({'frame': frame})
    if not ip_ok:
        raise ValueError('ip checksum')
    if not tcp_ok:
        raise ValueError('TX offload placeholder' if offloaded else 'tcp checksum')
    if payload and not wc.dnp3_ok(payload)[0]:
        raise ValueError('DNP3 CRC')
    kind = ('RST' if flags & wc.RST else 'FIN' if flags & wc.FIN else
            'SYN' if flags == wc.SYN and not payload else
            'SYN_ACK' if flags == wc.SYN | wc.ACK and not payload else
            'PURE_ACK' if flags == wc.ACK and not payload else
            'READ_REQUEST' if direction == 'M->O' and len(payload) >= 18 and payload[12:18] == b'\x01\x0a\x02\x00\x00\x16' else
            'READ_RESPONSE' if direction == 'O->M' and len(payload) >= 17 and payload[12] == 0x81 and payload[15:17] == b'\x0a\x02' else None)
    if kind is None:
        raise ValueError('unselected application')
    return dict(direction=direction, seq=seq, ack=ack, flags=flags, payload_bytes=len(payload),
                src_mac=frame[6:12].hex(':'), dst_mac=frame[:6].hex(':'), **{'class': kind})


def handshake(packets):
    clients = {p['seq'] for p in packets if p['class'] == 'SYN' and p['direction'] == 'M->O'}
    servers = {p['seq'] for p in packets if p['class'] == 'SYN_ACK' and p['direction'] == 'O->M'}
    if len(clients) != 1 or len(servers) != 1:
        raise ValueError('missing or ambiguous connection ISNs')
    client, server = next(iter(clients)), next(iter(servers))
    if any(p['ack'] != (client + 1) & MASK for p in packets if p['class'] == 'SYN_ACK'):
        raise ValueError('SYNACK does not match client ISN')
    if not any(p['class'] == 'PURE_ACK' and p['direction'] == 'M->O' and
               p['seq'] == (client + 1) & MASK and p['ack'] == (server + 1) & MASK for p in packets):
        raise ValueError('missing completed handshake ACK')
    return {'client': client, 'server': server}


def collect(paths, master_port, dedupe=False):
    if not 0 < master_port < 65536 or master_port == SERVER_PORT:
        raise ValueError('invalid software master port')
    packets, frames, skipped, seen = [], [], [], set()
    duplicates = 0
    for path in paths:
        for index, (timestamp, frame) in enumerate(records(path)):
            try:
                packet = segment(frame, master_port)
            except ValueError as error:
                skipped.append(dict(capture=str(path), index=index, reason=str(error)))
                continue
            sha = hashlib.sha256(frame).hexdigest()
            if dedupe and sha in seen:
                duplicates += 1
                continue
            seen.add(sha)
            packet.update(capture=str(path), index=index, t_us=timestamp, sha256=sha, frame_bytes=len(frame))
            packets.append(packet)
            frames.append(frame)
    counts = Counter(p['class'] for p in packets)
    manifest = dict(tuple=[MASTER, master_port, OUTSTATION, SERVER_PORT], isns=handshake(packets),
                    counts={kind: counts[kind] for kind in CLASSES}, packets=packets, skipped=skipped,
                    duplicates_skipped=duplicates, missing_classes=[kind for kind in CLASSES if not counts[kind]])
    return manifest, frames


def fresh_guard(old, new_paths, master_port, client, server):
    if not new_paths or client is None or server is None or not all(0 <= n <= MASK for n in (client, server)):
        raise ValueError('apply requires fresh handshake pcap and declared new client/server ISNs')
    new, _ = collect(new_paths, master_port, dedupe=True)
    if new['isns'] != {'client': client, 'server': server}:
        raise ValueError('declared new ISNs do not match fresh same-tuple handshake')
    for direction, key in (('M->O', 'client'), ('O->M', 'server')):
        previous = old['isns'][key]
        spans = [((p['seq'] - previous) & MASK) + p['payload_bytes'] + bool(p['flags'] & (wc.SYN | wc.FIN))
                 for p in old['packets'] if p['direction'] == direction]
        frontier = (previous + max(spans)) & MASK
        distance = (new['isns'][key] + 1 - frontier) & MASK
        if max(spans) >= 0x80000000 or not 2 <= distance <= 0x7fffffff:
            raise ValueError('new %s ISN overlaps ambiguous old sequence range' % key)
    return new['isns']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out_pcap'); parser.add_argument('in_pcap')
    parser.add_argument('--master-port', type=int, required=True)
    parser.add_argument('--dedupe', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--interface')
    parser.add_argument('--new-pcap', action='append')
    parser.add_argument('--new-client-isn', type=int); parser.add_argument('--new-server-isn', type=int)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args(argv)
    inputs = [Path(p) for p in [args.out_pcap, args.in_pcap] + (args.new_pcap or [])]
    if args.json and any(args.json.resolve() == p.resolve() or
                         (args.json.exists() and args.json.samefile(p)) for p in inputs):
        raise ValueError('JSON output must not overwrite a retained capture')
    if args.apply and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise ValueError('apply requires DEFENSE4_HW_AUTHORIZED=1')
    if args.apply and args.interface != INTERFACE:
        raise ValueError('apply requires explicit parent interface %s' % INTERFACE)
    manifest, frames = collect([args.out_pcap, args.in_pcap], args.master_port, args.dedupe)
    manifest.update(applied=False, interface=args.interface, sent=0)
    if args.apply:
        manifest['new_isns'] = fresh_guard(manifest, args.new_pcap, args.master_port,
                                          args.new_client_isn, args.new_server_isn)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw:
            raw.bind((args.interface, 0))
            for frame in frames:
                if raw.send(frame) != len(frame):
                    raise OSError('short raw frame send')
                manifest['sent'] += 1
        manifest['applied'] = True
    output = json.dumps(manifest, indent=2) + '\n'
    if args.json:
        args.json.write_text(output)
    print(output, end='')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.stderr.write('replay refused: %s\n' % error)
        sys.exit(2)

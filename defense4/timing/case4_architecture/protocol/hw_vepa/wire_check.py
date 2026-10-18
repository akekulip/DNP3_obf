#!/usr/bin/env python3
"""Independent wire check for a software-endpoint run (self-contained; does not reuse the mapper's code).

  wire_check.py OUT.pcap IN.pcap [--json FILE]

OUT = `tcpdump -Q out` on the parent NIC (frames as the endpoints sent them); IN = `-Q in` (frames as
the switch returned them). Both carry the same host NIC clock, so every interval below is a
host-capture-point interval, not an isolated ASIC forwarding time.

For every DNP3-bearing segment it recomputes each DNP3 block CRC and the IPv4/TCP checksums. It then
pairs each returned segment with the sent segment it reflects. The switch reflection is 1:1 and
order-preserving per (four-tuple, connection incarnation, direction), but it may translate TCP
sequence/ack numbers non-affinely (response padding shifts every later sequence number) and pad the
payload, so neither raw sequence nor payload bytes survive a reflection. The pairing therefore:

  * groups segments by four-tuple, connection incarnation (each client SYN starts a new incarnation)
    and direction;
  * sorts each group by ISN-relative sequence, which both undoes capture reordering and makes the
    order comparable across the translation;
  * aligns the sent and returned orders by (flags, has-payload) with a longest-common-subsequence
    match, so a lost reflection shows up as an unmatched sent segment, a re-reflected one as a
    duplicate, and a spurious returned segment as unmatched returned.

No latency sample is ever taken from an unmatched pair. A per-packet reference mapping records, for
every returned segment, the sent segment index it was paired with (or null).

Checksum-offload note: a frame the master's kernel handed to the NIC for checksum offload carries only
the TCP pseudo-header sum in its checksum field, not the on-wire checksum. Those appear only in the
SENT capture and are not wire corruption. Returned frames are validated; sent frames are classified as
'offloaded' rather than 'bad'.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

MASTER_IP = '192.168.10.61'
OUTSTATION_IP = '192.168.10.62'

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


# --- DNP3 and TCP/IP integrity (self-contained; DNP3 CRC polynomial 0xA6BC, reflected) ---

def dnp3_crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return (~c) & 0xFFFF


def dnp3_ok(payload):
    """(ok, reason) for a TCP payload of one or more back-to-back DNP3 link frames: for every frame the start octets,
    header CRC and every data-block CRC, and the payload must end exactly on a frame boundary. Several frames occur
    when one response is carried as several transport segments in one TCP segment (61-octet profile)."""
    p, base = payload, 0
    while True:
        if len(p) - base < 10 or p[base:base + 2] != b'\x05\x64':
            return False, 'no start' if base == 0 else 'no start at %d' % base
        if dnp3_crc(p[base:base + 8]) != int.from_bytes(p[base + 8:base + 10], 'little'):
            return False, 'header crc' if base == 0 else 'header crc at %d' % base
        if p[base + 2] < 5:
            return False, 'LEN %d < 5' % p[base + 2]
        i, n = base + 10, p[base + 2] - 5
        while n > 0:
            k = min(16, n)
            blk, c = p[i:i + k], p[i + k:i + k + 2]
            if len(c) < 2 or dnp3_crc(blk) != int.from_bytes(c, 'little'):
                return False, 'block crc at %d' % i
            i += k + 2
            n -= k
        if i == len(p):
            return True, 'ok'
        if i > len(p):
            return False, 'truncated'
        base = i


def _sum16(data):
    if len(data) % 2:
        data = data + b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def ip_tcp_checksum(seg):
    """(ip_ok, tcp_ok, tcp_offloaded) for one parsed segment dict."""
    frame = seg['frame']
    ihl = (frame[14] & 0x0f) * 4
    ip = frame[14:14 + ihl]
    have_ip = int.from_bytes(frame[24:26], 'big')
    calc_ip = _sum16(ip[:10] + b'\0\0' + ip[12:])
    total_len = int.from_bytes(frame[16:18], 'big')
    segment = bytearray(frame[14 + ihl:14 + total_len])
    have_tcp = int.from_bytes(segment[16:18], 'big')
    segment[16:18] = b'\0\0'
    pseudo = frame[26:34] + struct.pack('!BBH', 0, 6, len(segment))
    calc_tcp = _sum16(pseudo + bytes(segment))
    # A checksum-offloaded sender frame carries only the TCP pseudo-header sum (un-complemented) in the
    # checksum field; that is a placeholder the NIC overwrites on the wire, not corruption.
    pseudo_only = _sum16(pseudo) ^ 0xffff
    offloaded = (have_tcp == pseudo_only)
    return (have_ip == calc_ip), (have_tcp == calc_tcp), offloaded


# --- classic pcap reader (microsecond or nanosecond; integer timestamps at file resolution) ---

def read_pcap_records(path):
    """Lossless classic-pcap records; timestamp_ns is an integer, never epoch float.

    ``read_pcap`` retains its historical (t_us, frame) API for existing callers.
    Resolution describes file encoding, not a claim of clock accuracy.
    """
    data = Path(path).read_bytes()
    if len(data) < 24:
        return [], 'us'
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        endian, res = '<', 'us'
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian, res = '>', 'us'
    elif magic == b'\x4d\x3c\xb2\xa1':
        endian, res = '<', 'ns'
    elif magic == b'\xa1\xb2\x3c\x4d':
        endian, res = '>', 'ns'
    else:
        raise ValueError('not a classic pcap: %r' % magic)
    off, out = 24, []
    while off + 16 <= len(data):
        ts_s, ts_f, incl, orig = struct.unpack(endian + 'IIII', data[off:off + 16])
        frame = data[off + 16:off + 16 + incl]
        if len(frame) < incl:
            break
        t_us = ts_s * 1_000_000 + (ts_f // 1000 if res == 'ns' else ts_f)
        out.append(dict(t_us=t_us, timestamp_ns=ts_s * 1_000_000_000 + ts_f * (1 if res == 'ns' else 1000),
                        timestamp_seconds=ts_s, timestamp_fraction=ts_f, captured_len=incl, original_len=orig,
                        capture_resolution=res, frame=frame))
        off += 16 + incl
    return out, res


def read_pcap(path):
    records, res = read_pcap_records(path)
    return [(r['t_us'], r['frame']) for r in records], res


def parse(path):
    """IPv4/TCP segments as dicts with integer microsecond timestamps and an in-file index."""
    frames, res = read_pcap_records(path)
    segs = []
    for idx, record in enumerate(frames):
        t_us, frame = record['t_us'], record['frame']
        if len(frame) < 34 or frame[12:14] != b'\x08\x00':
            continue
        ihl = (frame[14] & 0x0f) * 4
        if frame[14 + 9] != 6:              # IP protocol TCP
            continue
        total_len = int.from_bytes(frame[16:18], 'big')
        tcp_off = 14 + ihl
        if ihl < 20 or len(frame) < tcp_off + 20:
            continue
        dataofs = (frame[tcp_off + 12] >> 4) * 4
        src = '.'.join(str(b) for b in frame[26:30])
        dst = '.'.join(str(b) for b in frame[30:34])
        sport = int.from_bytes(frame[tcp_off:tcp_off + 2], 'big')
        dport = int.from_bytes(frame[tcp_off + 2:tcp_off + 4], 'big')
        seq = int.from_bytes(frame[tcp_off + 4:tcp_off + 8], 'big')
        ack = int.from_bytes(frame[tcp_off + 8:tcp_off + 12], 'big')
        flags = frame[tcp_off + 13]
        payload = frame[14 + ihl + dataofs:14 + total_len]
        seg = {'index': idx, 't_us': t_us, 'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
               'seq': seq, 'ack': ack, 'flags': flags, 'len': len(payload), 'payload': payload,
               'frame': frame}
        seg.update({key: value for key, value in record.items() if key != 'frame'})
        seg['ip_len'] = total_len
        seg['tcp_payload_declared_len'] = max(0, total_len - ihl - dataofs)
        seg['frame_sha256'] = hashlib.sha256(frame).hexdigest()
        seg['dir'] = 'M->O' if src == MASTER_IP else ('O->M' if src == OUTSTATION_IP else '%s->%s' % (src, dst))
        seg['flow'] = tuple(sorted(((src, sport), (dst, dport))))
        segs.append(seg)
    return segs, res


# --- connection incarnation and ISN-relative ordering ---

def assign_incarnations(segs):
    """A new incarnation per flow begins at each pure SYN (client open). Segments before the first SYN
    of their flow get incarnation 0. The per-direction ISN of an incarnation is the seq of its SYN
    (SYN or SYN-ACK). rel_seq is seq - ISN (modulo 2^32), which orders a direction's stream even across
    a non-affine sequence translation."""
    counter = {}
    isn = {}
    for s in sorted(segs, key=lambda s: (s['t_us'], s['index'])):
        flow = s['flow']
        if s['flags'] & SYN and not (s['flags'] & ACK):
            counter[flow] = counter.get(flow, -1) + 1
        s['inc'] = max(counter.get(flow, 0), 0)
        if s['flags'] & SYN:
            isn.setdefault((flow, s['inc'], s['dir']), s['seq'])
    for s in segs:
        base = isn.get((s['flow'], s['inc'], s['dir']))
        s['isn_known'] = base is not None
        s['rel_seq'] = (s['seq'] - base) & 0xffffffff if base is not None else s['seq']
    return segs


def _tag(s):
    return (s['flags'], s['len'] > 0)


def _lcs_align(a, b):
    """Index pairs (i, j) of a longest common subsequence of tag(a[i]) == tag(b[j]), order-preserving."""
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            dp[i][j] = dp[i + 1][j + 1] + 1 if _tag(a[i]) == _tag(b[j]) else max(dp[i + 1][j], dp[i][j + 1])
    pairs, i, j = [], 0, 0
    while i < n and j < m:
        if _tag(a[i]) == _tag(b[j]):
            pairs.append((i, j))
            i += 1
            j += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            i += 1
        else:
            j += 1
    return pairs


def match(sent, returned):
    """Pair returned segments to the sent segments they reflect, per flow/incarnation/direction.

    Returns a dict with matched pairs, the unmatched and duplicate categories, and a per-returned-packet
    reference mapping (returned in-file index -> sent in-file index or None)."""
    groups = {}
    for role, segs in (('s', sent), ('r', returned)):
        for s in segs:
            groups.setdefault((s['flow'], s['inc'], s['dir']), {'s': [], 'r': []})[role].append(s)

    matched, unmatched_sent, unmatched_returned, duplicate_returned = [], [], [], []
    reordered = []
    mapping = {}
    for key, g in groups.items():
        S = sorted(g['s'], key=lambda s: s['rel_seq'])
        R_time = sorted(g['r'], key=lambda s: (s['t_us'], s['index']))
        R = sorted(g['r'], key=lambda s: s['rel_seq'])
        if [x['index'] for x in R_time] != [x['index'] for x in R]:
            reordered += [x['index'] for x in R_time if R_time.index(x) != R.index(x)]
        pairs = _lcs_align(S, R)
        matched_s = {i for i, _ in pairs}
        matched_r = {j for _, j in pairs}
        for i, j in pairs:
            s, r = S[i], R[j]
            matched.append({'sent_index': s['index'], 'returned_index': r['index'], 'dir': s['dir'],
                            'latency_us': r['t_us'] - s['t_us'], 'flags': s['flags'],
                            'seq_delta': (r['seq'] - s['seq']) & 0xffffffff,
                            'ack_delta': (r['ack'] - s['ack']) & 0xffffffff if s['flags'] & ACK else None,
                            'sent_len': s['len'], 'returned_len': r['len'],
                            'payload_identical': s['payload'] == r['payload']})
            mapping[r['index']] = s['index']
        for i, s in enumerate(S):
            if i not in matched_s:
                unmatched_sent.append({'sent_index': s['index'], 'dir': s['dir'], 'flags': s['flags'], 'len': s['len']})
        # a duplicate re-reflection shares (rel_seq, flags, len) with a returned segment that already paired
        matched_ret_sigs = {(R[j]['rel_seq'], R[j]['flags'], R[j]['len']) for _, j in pairs}
        for j, r in enumerate(R):
            if j in matched_r:
                continue
            mapping[r['index']] = None
            rec = {'returned_index': r['index'], 'dir': r['dir'], 'flags': r['flags'], 'len': r['len']}
            if (r['rel_seq'], r['flags'], r['len']) in matched_ret_sigs:
                duplicate_returned.append(rec)
            else:
                unmatched_returned.append(rec)
    return {'matched': matched, 'unmatched_sent': unmatched_sent, 'unmatched_returned': unmatched_returned,
            'duplicate_returned': duplicate_returned, 'reordered_returned_indices': sorted(set(reordered)),
            'reference_mapping': mapping}


def analyze(out_path, in_path):
    sent = assign_incarnations(parse(out_path)[0])
    returned = assign_incarnations(parse(in_path)[0])
    m = match(sent, returned)

    def integrity(segs, validate):
        bad_dnp3, bad_tcp, offloaded = [], [], []
        for s in segs:
            if s['len']:
                ok, reason = dnp3_ok(s['payload'])
                if not ok and s['payload'][:2] == b'\x05\x64':
                    bad_dnp3.append({'index': s['index'], 'reason': reason})
            ip_ok, tcp_ok, off = ip_tcp_checksum(s)
            if not tcp_ok:
                (offloaded if off else bad_tcp).append(s['index'])
        return {'dnp3_crc_bad': bad_dnp3,
                'tcp_checksum_bad': bad_tcp if validate else 'not validated (sender capture)',
                'tcp_checksum_offloaded': offloaded}

    rep = {'note': 'intervals are host-capture-point (same parent-NIC clock), not ASIC forwarding time; '
                   'timestamps are integer microseconds at the capture resolution',
           'sent': len(sent), 'returned': len(returned),
           'sent_integrity': integrity(sent, validate=False),
           'returned_integrity': integrity(returned, validate=True),
           'matched': len(m['matched']), 'unmatched_sent': m['unmatched_sent'],
           'unmatched_returned': m['unmatched_returned'], 'duplicate_returned': m['duplicate_returned'],
           'reordered_returned_indices': m['reordered_returned_indices'],
           'reference_mapping': m['reference_mapping']}
    for d in ('M->O', 'O->M'):
        s_d = [x for x in sent if x['dir'] == d and x['len']]
        r_d = [x for x in returned if x['dir'] == d and x['len']]
        rep['%s sent payload lengths' % d] = sorted(set(x['len'] for x in s_d))
        rep['%s returned payload lengths' % d] = sorted(set(x['len'] for x in r_d))
        md = [x for x in m['matched'] if x['dir'] == d]
        rep['%s matched' % d] = len(md)
        rep['%s seq delta set' % d] = sorted(set(x['seq_delta'] for x in md))
        rep['%s ack delta set' % d] = sorted(set(x['ack_delta'] for x in md if x['ack_delta'] is not None))
        rep['%s payload identical count' % d] = sum(x['payload_identical'] for x in md)
    lat = [x['latency_us'] for x in m['matched']]
    rep['reflect latency us min/median/max'] = (
        [min(lat), sorted(lat)[len(lat) // 2], max(lat)] if lat else None)
    # the padded images: outstation-sent vs master-received length and transport/app/func bytes
    si = {x['index']: x for x in sent}
    ex = []
    for mm in m['matched']:
        s = si[mm['sent_index']]
        if s['dir'] == 'O->M' and s['len']:
            ex.append({'sent_len': mm['sent_len'], 'returned_len': mm['returned_len'],
                       'sent_tp_app_func': s['payload'][10:13].hex(),
                       'returned_tp_app_func': (next((x for x in returned if x['index'] == mm['returned_index']))['payload'][10:13].hex())})
    rep['O->M reflected images'] = ex
    return rep


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('out_pcap')
    ap.add_argument('in_pcap')
    ap.add_argument('--json')
    a = ap.parse_args()
    report = analyze(a.out_pcap, a.in_pcap)
    if a.json:
        json.dump(report, open(a.json, 'w'), indent=1, default=str)
    print(json.dumps(report, indent=1, default=str))
    # a wire check that found a spurious returned segment or a bad returned checksum is a failure
    bad = (report['returned_integrity']['tcp_checksum_bad'] or
           report['returned_integrity']['dnp3_crc_bad'] or report['unmatched_returned'])
    sys.exit(1 if bad else 0)

"""Classic PCAP, IPv4/TCP and DNP3 integrity for current SEL-751 captures."""
import hashlib
import struct
from pathlib import Path

MASTER_IP = "192.168.10.1"
OUTSTATION_IP = "192.168.10.7"
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

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

"""Read DNP3 link frames out of a classic Ethernet pcap, per TCP direction.

TCP is a byte stream (13.2.1-.3, pp.377-384), so frames are cut from the reassembled stream of each
direction, not from individual segments. A retransmitted segment (same sequence number, same bytes)
is counted once; a different payload at an already-seen sequence number is an error.
"""
import struct


def packets(path):
    data = open(path, 'rb').read()
    if data[:4] != b'\xd4\xc3\xb2\xa1':
        raise ValueError('not a little-endian microsecond pcap')
    if struct.unpack('<I', data[20:24])[0] != 1:
        raise ValueError('link type is not Ethernet')
    p = 24
    while p + 16 <= len(data):
        sec, usec, incl, _orig = struct.unpack('<IIII', data[p:p + 16])
        yield sec + usec * 1e-6, data[p + 16:p + 16 + incl]
        p += 16 + incl


def tcp_segments(path):
    """Yield (time, (src, sport), (dst, dport), seq, flags, payload) for every IPv4/TCP packet."""
    for t, f in packets(path):
        if len(f) < 34 or f[12:14] != b'\x08\x00' or f[23] != 6:
            continue
        ihl = (f[14] & 0x0F) * 4
        ip_len = struct.unpack('!H', f[16:18])[0]
        tcp = f[14 + ihl:14 + ip_len]
        sport, dport, seq = struct.unpack('!HHI', tcp[:8])
        off = (tcp[12] >> 4) * 4
        yield t, (f[26:30], sport), (f[30:34], dport), seq, tcp[13], tcp[off:]


def streams(path):
    """Return {(src, dst): bytes}, each direction reassembled in sequence order without duplicates."""
    segs = {}
    for _t, src, dst, seq, _flags, payload in tcp_segments(path):
        if not payload:
            continue
        seen = segs.setdefault((src, dst), {})
        if seq in seen and seen[seq] != payload:
            raise ValueError('different payload at the same sequence number %d' % seq)
        seen[seq] = payload
    out = {}
    for key, seen in segs.items():
        base = min(seen)
        buf, nxt = b'', base
        for seq in sorted(seen, key=lambda s: (s - base) & 0xFFFFFFFF):
            pl = seen[seq]
            rel = (seq - nxt) & 0xFFFFFFFF
            if rel > 0x7FFFFFFF:            # overlaps what we already have
                skip = (nxt - seq) & 0xFFFFFFFF
                if skip >= len(pl):
                    continue
                pl = pl[skip:]
            elif rel:
                raise ValueError('gap of %d octets in the stream' % rel)
            buf += pl
            nxt = (nxt + len(pl)) & 0xFFFFFFFF
        out[key] = buf
    return out


def frames(stream):
    """Cut a reassembled stream into complete link frames using LEN."""
    out, p = [], 0
    while p < len(stream):
        if stream[p:p + 2] != b'\x05\x64' or p + 3 > len(stream):
            raise ValueError('stream not aligned on a link frame at %d' % p)
        user = stream[p + 2] - 5
        n = 10 + user + 2 * (-(-user // 16))
        out.append(stream[p:p + n])
        p += n
    return out

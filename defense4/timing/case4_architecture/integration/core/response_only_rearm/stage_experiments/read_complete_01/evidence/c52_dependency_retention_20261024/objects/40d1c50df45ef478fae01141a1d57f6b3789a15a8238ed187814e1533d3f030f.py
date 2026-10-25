"""Read DNP3 link frames out of a classic Ethernet pcap, per TCP direction.

TCP is a byte stream (13.2.1-.3, pp.377-384), so frames are cut from the reassembled stream of each
direction, not from individual segments. A retransmitted segment (same sequence number, same bytes)
is counted once; a different payload at an already-seen sequence number is an error.
"""
import struct

SYN, ACK = 0x02, 0x10
HALF32 = 1 << 31


def packets(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != b'\xd4\xc3\xb2\xa1':
        raise ValueError('not a little-endian microsecond pcap')
    if struct.unpack('<I', data[20:24])[0] != 1:
        raise ValueError('link type is not Ethernet')
    p = 24
    while p + 16 <= len(data):
        sec, usec, incl, _orig = struct.unpack('<IIII', data[p:p + 16])
        yield sec + usec * 1e-6, data[p + 16:p + 16 + incl]
        p += 16 + incl


def tcp_records(path):
    """Yield TCP packet records for every IPv4/TCP packet."""
    for t, f in packets(path):
        if len(f) < 34 or f[12:14] != b'\x08\x00' or f[23] != 6:
            continue
        ihl = (f[14] & 0x0F) * 4
        ip_len = struct.unpack('!H', f[16:18])[0]
        tcp = f[14 + ihl:14 + ip_len]
        sport, dport, seq, ack = struct.unpack('!HHII', tcp[:12])
        off = (tcp[12] >> 4) * 4
        yield {'time': t, 'src': (f[26:30], sport), 'dst': (f[30:34], dport), 'seq': seq, 'ack': ack,
               'flags': tcp[13], 'payload': tcp[off:]}


def tcp_segments(path):
    """Yield (time, (src, sport), (dst, dport), seq, flags, payload) for compatibility."""
    for r in tcp_records(path):
        yield r['time'], r['src'], r['dst'], r['seq'], r['flags'], r['payload']


def _flow(src, dst):
    return tuple(sorted((src, dst)))


def _delta(seq, base):
    d = (seq - base) & 0xFFFFFFFF
    if d == HALF32:
        raise ValueError('ambiguous TCP sequence attribution across half the serial space')
    return d


def _assemble(records, origin, require_handshake):
    """Reassemble one direction after incarnation assignment.

    records are (arrival order, seq, payload). origin is the first byte's sequence number when the
    handshake identifies it; otherwise the first payload sequence in capture order becomes the origin.
    """
    if not records:
        return b''
    if require_handshake and origin is None:
        raise ValueError('payload stream without handshake-backed sequence origin')
    base = origin if origin is not None else records[0][1]
    positioned = []
    for order, seq, payload in records:
        rel = _delta(seq, base)
        if rel > HALF32:
            raise ValueError('ambiguous TCP sequence attribution before stream origin')
        positioned.append((rel, order, payload))
    buf = bytearray()
    for rel, _order, payload in sorted(positioned):
        if rel > len(buf):
            raise ValueError('gap of %d octets in the stream' % (rel - len(buf)))
        overlap = min(len(payload), len(buf) - rel)
        if overlap:
            have = bytes(buf[rel:rel + overlap])
            want = payload[:overlap]
            if have != want:
                raise ValueError('conflicting overlap at stream offset %d' % rel)
            payload = payload[overlap:]
            rel += overlap
        if payload:
            if rel != len(buf):
                raise ValueError('ambiguous TCP sequence attribution at stream offset %d' % rel)
            buf.extend(payload)
    return bytes(buf)


def streams(path, include_incarnation=False, require_handshake=False):
    """Return reassembled TCP byte streams.

    The default key is the historical ``(src, dst)`` tuple and fails closed if a capture contains more
    than one incarnation for the same direction. With include_incarnation=True the key is
    ``(src, dst, incarnation)``.
    """
    current_inc, origins, segs, order = {}, {}, {}, 0
    pending = {}
    for r in tcp_records(path):
        src, dst, seq, ack, flags, payload = r['src'], r['dst'], r['seq'], r['ack'], r['flags'], r['payload']
        flow = _flow(src, dst)
        if flags & SYN and not (flags & ACK):
            p = pending.get(flow)
            if p is None or p['client'] != src or p['server'] != dst or p['client_syn'] != seq:
                pending[flow] = {'client': src, 'server': dst, 'client_syn': seq, 'server_syn': None}
        elif flags & SYN and flags & ACK:
            p = pending.get(flow)
            if p is not None and p['server'] == src and p['client'] == dst and ack == ((p['client_syn'] + 1) & 0xFFFFFFFF):
                p['server_syn'] = seq
        elif flags & ACK:
            p = pending.get(flow)
            if (p is not None and p['client'] == src and p['server'] == dst and p['server_syn'] is not None
                    and ack == ((p['server_syn'] + 1) & 0xFFFFFFFF)):
                inc = current_inc.get(flow, -1) + 1
                current_inc[flow] = inc
                origins[(p['client'], p['server'], inc)] = (p['client_syn'] + 1) & 0xFFFFFFFF
                origins[(p['server'], p['client'], inc)] = (p['server_syn'] + 1) & 0xFFFFFFFF
                pending.pop(flow, None)
        inc = max(current_inc.get(flow, 0), 0)
        if payload:
            segs.setdefault((src, dst, inc), []).append((order, seq, payload))
        order += 1
    out = {}
    for key, records in segs.items():
        out[key] = _assemble(records, origins.get(key), require_handshake)
    if include_incarnation:
        return out
    collapsed = {}
    for (src, dst, inc), data in out.items():
        key = (src, dst)
        if key in collapsed:
            raise ValueError('multiple TCP incarnations for %r; request incarnation-aware streams' % (key,))
        collapsed[key] = data
    return collapsed


def frames(stream):
    """Cut a reassembled stream into complete link frames using LEN."""
    out, p = [], 0
    while p < len(stream):
        if stream[p:p + 2] != b'\x05\x64' or p + 3 > len(stream):
            raise ValueError('stream not aligned on a link frame at %d' % p)
        user = stream[p + 2] - 5
        if user < 0:
            raise ValueError('LEN %d < 5 at %d' % (stream[p + 2], p))
        n = 10 + user + 2 * (-(-user // 16))
        if p + n > len(stream):
            raise ValueError('truncated link frame at %d' % p)
        out.append(stream[p:p + n])
        p += n
    return out

"""Decode full-READ captures: objects, link frames, transport segments, fragments, TCP segments, times.

Reuses the independent IEEE 1815-2012 oracle of read_reencode_01 (dnp3_std: CRC, deframe, transport
reassembly, header parsing) and its pcap reader (capture.tcp_records). The oracle's scope is widened
here, once, to the measurement objects a full READ returns. Sizes are from Annex A; response qualifiers
from Clause 12 (pp.352-357): static objects 00/01 (Tables 12-2 g1, 12-6 g10, 12-10 g20, 12-14 g30),
event objects 17/28 (e.g. Table 12-16 g32). Group 60 (class data) is request-only (4.2.2.7.1.1).
"""
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'read_reencode_01'))
import capture  # noqa: E402
import dnp3_std as std  # noqa: E402

# (group, variation) -> octets per object, all with a leading flags octet except where noted.
MEASUREMENT_SIZE = {
    (1, 2): 1,                      # binary input with flags (A.2)
    (2, 1): 1,                      # binary input event without time (A.3)
    (10, 2): 1,                     # binary output status with flags (A.6)
    (20, 1): 5, (20, 2): 3,         # counter 32/16-bit with flag (A.11)
    (22, 1): 5, (22, 2): 3,         # counter event 32/16-bit with flag (A.13)
    (30, 1): 5, (30, 2): 3,         # analog input 32/16-bit with flag (A.15)
    (30, 3): 4, (30, 4): 2,         # analog input 32/16-bit without flag
    (30, 5): 5,                     # analog input single-precision float with flag
    (32, 1): 5, (32, 2): 3,         # analog input event 32/16-bit (A.17)
}
STATIC = {(1, 2), (10, 2), (20, 1), (20, 2), (30, 1), (30, 2), (30, 3), (30, 4), (30, 5)}
EVENT = set(MEASUREMENT_SIZE) - STATIC
for gv, size in MEASUREMENT_SIZE.items():
    std.OBJECT_SIZE.setdefault(gv, size)
    std.RESPONSE_QUALIFIERS.setdefault(gv, {0x00, 0x01} if gv in STATIC else {0x17, 0x28})

NAMES = {1: 'binary input', 2: 'binary input event', 10: 'binary output status', 20: 'counter',
         22: 'counter event', 30: 'analog input', 32: 'analog input event', 60: 'class data'}


def request_headers(b):
    """Object headers of a READ request: a READ names points by range or class and carries no objects."""
    out, p = [], 0
    while p < len(b):
        g, v, q = b[p], b[p + 1], b[p + 2]
        if q not in std.REQUEST_QUALIFIERS:
            raise std.StdError('request qualifier 0x%02x' % q)
        n = header_octets(q)
        field = b[p + 3:p + n]
        if q in (0x00, 0x01):
            w = 1 if q == 0x00 else 2
            fmt = '<B' if w == 1 else '<H'
            rng = [struct.unpack(fmt, field[:w])[0], struct.unpack(fmt, field[w:])[0]]
        else:
            rng = None
        out.append({'group': g, 'variation': v, 'qualifier': q, 'range': rng})
        p += n
    return out


def header_octets(qualifier):
    """Object-header octets before the objects: group, variation, qualifier + range or count field."""
    return 3 + {0x00: 2, 0x01: 4, 0x06: 0, 0x17: 1, 0x28: 2}[qualifier]


def describe_objects(objs):
    """One row per object header of a parsed fragment, with its complete encoded size."""
    rows = []
    for g, v, q, lst in objs:
        n = len(lst)
        idx = [i for i, _ in lst]
        size = std.OBJECT_SIZE.get((g, v), 0)
        prefix = {0x17: 1, 0x28: 2}.get(q, 0)
        rows.append({'group': g, 'variation': v, 'qualifier': q, 'type': NAMES.get(g, '?'),
                     'count': n, 'first_index': idx[0] if idx else None, 'last_index': idx[-1] if idx else None,
                     'octets_per_point': size + prefix, 'header_octets': header_octets(q),
                     'block_octets': header_octets(q) + n * (size + prefix)})
    return rows


def frame_cut(buf):
    """Length of the first complete link frame in buf, or 0 when buf does not yet hold one."""
    if len(buf) < 3:
        return 0
    if buf[:2] != b'\x05\x64':
        raise ValueError('stream not aligned on a link frame')
    user = buf[2] - 5
    n = std.frame_length(user)
    return n if len(buf) >= n else 0


def direction_frames(records):
    """In-order (time, frame bytes, tcp_payload_lengths) for one direction; a frame's time is the arrival
    of the TCP segment that completed it. Retransmissions (an already-seen sequence) are skipped."""
    out, buf, seen, segs, base = [], b'', set(), [], None
    for r in records:
        if not r['payload']:
            continue
        key = (r['seq'], r['payload'])
        if key in seen:
            continue
        seen.add(key)
        if base is not None and r['seq'] != base:
            raise ValueError('out-of-order TCP data; extend the decoder before relying on it')
        base = (r['seq'] + len(r['payload'])) & 0xFFFFFFFF
        buf += r['payload']
        segs.append((r['time'], len(r['payload'])))
        while True:
            n = frame_cut(buf)
            if not n:
                break
            out.append({'time': r['time'], 'frame': buf[:n], 'segments': list(segs)})
            buf, segs = buf[n:], []
    return out


def transactions(pcap, outstation_port=20000):
    """Pair each master request fragment with the response fragment that follows it."""
    recs = list(capture.tcp_records(pcap))
    req = [r for r in recs if r['dst'][1] == outstation_port]
    rsp = [r for r in recs if r['src'][1] == outstation_port]
    req_frames, rsp_frames = direction_frames(req), direction_frames(rsp)
    out = []
    pending = list(rsp_frames)
    for rf in req_frames:
        _, user = std.deframe(rf['frame'])
        q = std.request(std.fragment_user(user[1:]))
        if q['function'] != 0x01:
            continue
        frames_of_rsp = []
        while pending and pending[0]['time'] < rf['time']:
            pending.pop(0)
        while pending:
            f = pending.pop(0)
            frames_of_rsp.append(f)
            if std.deframe(f['frame'])[1][0] & std.FIN:
                break
        frags, events = std.reassemble([f['frame'] for f in frames_of_rsp])
        if len(frags) != 1 or events:
            raise std.StdError('response did not reassemble into one fragment: %r' % events)
        app, lengths, _seq = frags[0]
        r = std.response(std.fragment_user(app))
        objs = std.parse_objects(r['objects'], response=True)
        tcp_lens = [n for f in frames_of_rsp for _t, n in f['segments']]
        segs_t = [t for f in frames_of_rsp for t, _n in f['segments']]
        out.append({
            'request_time': rf['time'], 'request_frame_octets': len(rf['frame']),
            'request_objects': request_headers(q['objects']),
            'response_function': r['function'], 'iin': r['iin'].hex(),
            'app_octets': len(app) , 'fragment_octets_incl_app_header': len(app),
            'link_frames': [len(f['frame']) for f in frames_of_rsp],
            'transport': [std.deframe(f['frame'])[1][0] for f in frames_of_rsp],
            'tcp_segments': tcp_lens, 'tcp_payload_octets': sum(tcp_lens),
            'first_response_time': segs_t[0], 'complete_response_time': frames_of_rsp[-1]['time'],
            'objects': describe_objects(objs),
            'points': [(g, v, i, d.hex()) for g, v, i, d in std.points(objs)],
            'response_frames_hex': [f['frame'].hex() for f in frames_of_rsp],
        })
    return out


def summary(txs):
    """Distinct response shapes and their sizes."""
    shapes = {}
    for t in txs:
        key = (tuple(t['link_frames']), tuple(t['tcp_segments']),
               tuple((o['group'], o['variation'], o['qualifier'], o['count']) for o in t['objects']))
        shapes.setdefault(key, 0)
        shapes[key] += 1
    return [{'link_frames': list(k[0]), 'tcp_segments': list(k[1]), 'objects': [list(o) for o in k[2]], 'n': n}
            for k, n in sorted(shapes.items(), key=lambda kv: -kv[1])]


if __name__ == '__main__':
    import json
    txs = transactions(sys.argv[1])
    print(json.dumps({'n': len(txs), 'shapes': summary(txs), 'example': {k: v for k, v in txs[0].items()
                                                                          if k != 'points'}}, indent=1))

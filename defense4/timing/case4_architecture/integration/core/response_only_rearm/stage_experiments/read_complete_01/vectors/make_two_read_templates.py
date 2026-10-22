"""Two-READ-target templates from the hardware workload's own loopback captures (Python >= 3.10).

Writes two_read_templates.json: for each retained native capture (evidence/m1_two_read_01/native_capture_v<k>, the
real case4_socket_gate_read_schedule outstation and master, mixed_full schedule, base database, fixture variant k) and
each READ class (mixed, integrity), the first captured request's DNP3 octets, the native response as link frames and as
TCP segments, and the reference encoder's image under the two-READ profile targets [141, 271]
(general_read_padding.pad_read, reserved 1024..4095). Two variants carry different measurement values and flags, so a
consumer that embedded one capture's bytes would disagree with the other. read_class_templates.json (the c12 profile's
input) is not touched.

  python3 make_two_read_templates.py
"""
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'software/source/full_read_01'))
sys.path.insert(0, str(ROOT / 'software/source/read_reencode_01'))
import capture  # noqa: E402
import general_read_padding as gp  # noqa: E402

std = gp.std
TARGETS = [141, 271]
PAD_START, PAD_STOP = 1024, 4095
EVIDENCE = ROOT / 'evidence/m1_two_read_01'
VARIANTS = ('v0', 'v1')


def read_class(app):
    """READ class from the request's object headers (after control and function)."""
    objs, groups, p = app[2:], [], 0
    while p < len(objs):
        g, v, q = objs[p], objs[p + 1], objs[p + 2]
        groups.append((g, v)); p += 3 + {0x00: 2, 0x01: 4, 0x06: 0}[q]
    if groups == [(1, 2), (30, 1)]:
        return 'mixed'
    if sorted(groups) == [(60, 1), (60, 2), (60, 3), (60, 4)]:
        return 'integrity'
    raise ValueError('unexpected READ request %r' % groups)


def templates(pcap):
    recs = [r for r in capture.tcp_records(pcap) if r['payload']]
    req = [r['payload'] for r in recs if r['dst'][1] == 20000]
    rsp = [r for r in recs if r['src'][1] == 20000]
    stream = b''.join(r['payload'] for r in rsp)
    bounds, acc = [], 0
    for r in rsp:
        bounds.append((acc, acc + len(r['payload']))); acc += len(r['payload'])
    frags, pos, cur = [], 0, None
    while pos < len(stream):
        n = std.frame_length(stream[pos + 2] - 5)
        frame = stream[pos:pos + n]
        user = std.deframe(frame)[1]
        if user[0] & std.FIR:
            cur = dict(frames=[], start=pos)
        cur['frames'].append(frame)
        pos += n
        if user[0] & std.FIN:
            cur['end'] = pos; frags.append(cur); cur = None
    reads = iter(q for q in req if std.deframe(q[:std.frame_length(q[2] - 5)])[1][2] == 0x01)
    out = {}
    for f in frags:
        native = b''.join(f['frames'])
        user0 = std.deframe(f['frames'][0])[1]
        if user0[2] != 0x81 or user0[5:7] == b'\x0c\x01':
            continue                                       # SELECT/OPERATE responses
        q = next(reads)
        cls = read_class(std.deframe(q[:std.frame_length(q[2] - 5)])[1][1:])
        if cls in out:
            continue
        r = gp.pad_read(q, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
        out[cls] = dict(request=q.hex(), request_len=len(q), native=native.hex(), native_len=len(native),
                        native_frames=[len(x) for x in f['frames']],
                        native_tcp=[b - a for a, b in bounds if a < f['end'] and b > f['start']],
                        expected=r.output.hex(), expected_len=len(r.output),
                        expected_frames=[len(x) for x in gp.split_frames(r.output)], status=r.status,
                        target=r.target, construction=r.construction, padding_points=r.padding_points)
    return out


def main():
    doc = dict(source='hardware workload loopback captures (evidence/m1_two_read_01/native_capture_v*)',
               pad_read_sha256=hashlib.sha256((ROOT / 'software/source/full_read_01/general_read_padding.py')
                                              .read_bytes()).hexdigest(),
               targets=TARGETS, reserved=[PAD_START, PAD_STOP], variants={})
    for v in VARIANTS:
        pcap = EVIDENCE / ('native_capture_' + v) / 'capture.pcap'
        doc['variants'][v] = dict(capture_sha256=hashlib.sha256(pcap.read_bytes()).hexdigest(), classes=templates(pcap))
    a, b = (doc['variants'][v]['classes'] for v in VARIANTS)
    doc['variants_differ'] = {c: a[c]['native'] != b[c]['native'] for c in a}
    (HERE / 'two_read_templates.json').write_text(json.dumps(doc, indent=1) + '\n')
    for v, rec in doc['variants'].items():
        print(v, {c: (t['native_len'], t['native_tcp'], t['expected_frames'], t['target'], t['padding_points'],
                      t['construction']) for c, t in rec['classes'].items()})
    print('variants_differ', doc['variants_differ'])


if __name__ == '__main__':
    main()

"""Per-class READ request/response templates from the fixture endpoint's loopback captures (Python >= 3.10).

Writes read_class_templates.json: for each database (base, large) and READ class (range, analog, class0, integrity),
the first captured request's DNP3 octets, the native response's DNP3 octets as link frames and as TCP segments, and the
reference encoder's expected image under the frozen policy (pad_read status/target/construction). The model drivers
use these real bytes (re-addressed and re-sequenced by their own packet builders) instead of hand-made frames.

  python3 make_read_class_templates.py
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
POLICY = json.loads((ROOT / 'policy/policy.json').read_text())
TARGETS = POLICY['selected']['targets']
PAD_START, PAD_STOP = POLICY['profile']['reserved_padding_range']
EVIDENCE = ROOT.parents[3] / 'evidence/rearm_01/repeat_sbo_endpoint/loopback_evidence_20261021'


def read_class(app):
    g, v = app[2], app[3]
    return {10: 'range', 30: 'analog'}.get(g) or ('class0' if (g, v, len(app)) == (60, 1, 5) else 'integrity')


def exchanges(pcap):
    recs = [r for r in capture.tcp_records(pcap) if r['payload']]
    req = [r['payload'] for r in recs if r['dst'][1] == 20000]
    rsp = [r for r in recs if r['src'][1] == 20000]
    return req, rsp


def main():
    out = dict(source='fixture endpoint loopback captures (repeat_sbo_endpoint/loopback_evidence_20261021)',
               policy_sha256=hashlib.sha256((ROOT / 'policy/policy.json').read_bytes()).hexdigest(), databases={})
    for db in ('base', 'large'):
        pcap = EVIDENCE / ('b_rotate4_%s' % db) / 'capture.pcap'
        req, rsp = exchanges(pcap)
        stream = b''.join(r['payload'] for r in rsp)
        seg_lens = [len(r['payload']) for r in rsp]
        # cut the response byte stream into fragments, tracking which TCP segment lengths carried each
        frags, pos, seg_i, seg_off = [], 0, 0, 0
        cur = None
        while pos < len(stream):
            n = std.frame_length(stream[pos + 2] - 5)
            frame = stream[pos:pos + n]
            user = std.deframe(frame)[1]
            if user[0] & std.FIR:
                cur = dict(frames=[], start=pos)
            cur['frames'].append(frame)
            pos += n
            if user[0] & std.FIN:
                cur['end'] = pos
                frags.append(cur)
                cur = None
        # TCP segment boundaries in stream offsets
        bounds, acc = [], 0
        for L in seg_lens:
            bounds.append((acc, acc + L))
            acc += L
        classes = {}
        reads = [q for q in req if std.deframe(q[:std.frame_length(q[2] - 5)])[1][2] == 0x01]
        reads_iter = iter(reads)
        for f in frags:
            native = b''.join(f['frames'])
            user0 = std.deframe(f['frames'][0])[1]
            if user0[2] != 0x81 or (user0[5:7] == b'\x0c\x01'):
                continue                                   # SELECT/OPERATE responses
            q = next(reads_iter)
            qapp = std.deframe(q[:std.frame_length(q[2] - 5)])[1][1:]
            cls = read_class(qapp)
            if cls in classes:
                continue
            r = gp.pad_read(q, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
            classes[cls] = dict(request=q.hex(), native=native.hex(), native_len=len(native),
                                native_frames=[len(x) for x in f['frames']],
                                native_tcp=[b - a for a, b in bounds if a < f['end'] and b > f['start']],
                                expected=r.output.hex(), expected_len=len(r.output), status=r.status,
                                target=r.target, construction=r.construction, padding_points=r.padding_points)
        out['databases'][db] = classes
    (HERE / 'read_class_templates.json').write_text(json.dumps(out, indent=1) + '\n')
    for db, cl in out['databases'].items():
        print(db, {k: (v['native_len'], v['native_tcp'], v['expected_len'], v['status'], v['construction']) for k, v in cl.items()})


if __name__ == '__main__':
    main()

"""Per-class READ reference vectors for the Python-3.8 harness tests (run with Python >= 3.10).

Reads the REAL loopback captures of the READ-class schedule endpoint (repeat_sbo_endpoint/
loopback_evidence_20261021/b_rotate4_{base,large}/capture.pcap) with read_reencode_01/capture.py, takes the first
three exchanges of every READ class on each database, and writes, for each, the request link frames, the native response
link frames (each TCP segment kept separately), and the reference encoder's output under the frozen policy:
read_complete_01/software/source/full_read_01/general_read_padding.pad_read with policy.json's targets and reserved
range, plus the endpoints' final JSON records (master.log/outstation.log) of both runs. tests/test_read_classes.py
loads read_class_vectors.json; nothing here runs under the harness.

  ~/.venvs/research/bin/python make_read_class_vectors.py
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ARCH = HERE.parents[3]
STAGE = ARCH / 'integration/core/response_only_rearm/stage_experiments'
LOOPBACK = ARCH / 'integration/evidence/rearm_01/repeat_sbo_endpoint/loopback_evidence_20261021'
sys.path.insert(0, str(STAGE / 'read_complete_01/vectors'))
import derive  # noqa: E402  (loads the frozen policy and the reference encoder)

sys.path.insert(0, str(STAGE / 'read_reencode_01'))
import capture  # noqa: E402

gp = derive.gp
ORDER = ('range', 'analog', 'class0', 'integrity')
OUTSTATION_PORT = 20000
PER_CLASS = 3            # the first three exchanges of each class on each database (varied sequence numbers)


def directed(path):
    """(request stream, response stream, response TCP segment payloads in order) of the one connection."""
    streams = capture.streams(str(path), include_incarnation=True, require_handshake=True)
    req = [v for k, v in streams.items() if k[1][1] == OUTSTATION_PORT]
    rsp = [v for k, v in streams.items() if k[0][1] == OUTSTATION_PORT]
    assert len(req) == 1 and len(rsp) == 1
    segs, seen = [], set()
    for r in capture.tcp_records(str(path)):
        if r['src'][1] == OUTSTATION_PORT and r['payload'] and r['seq'] not in seen:
            seen.add(r['seq'])
            segs.append(r['payload'])
    return req[0], rsp[0], segs


def fragments(frames):
    """Group link frames into transport series FIR..FIN."""
    out, cur = [], []
    for f in frames:
        _h, u = gp.std.deframe(f)
        if u[0] & 0x40:
            cur = []
        cur.append(f)
        if u[0] & 0x80:
            out.append(cur)
            cur = []
    return out


def main():
    rows = []
    for db in ('base', 'large'):
        path = LOOPBACK / ('b_rotate4_%s' % db) / 'capture.pcap'
        req_stream, rsp_stream, segs = directed(path)
        requests = fragments(capture.frames(req_stream))
        responses = fragments(capture.frames(rsp_stream))
        seg_lens = [len(s) for s in segs]
        assert len(requests) == len(responses), (len(requests), len(responses))
        slot = 0
        seg_pos = 0
        for req, rsp in zip(requests, responses):
            nseg = 0
            total = sum(len(f) for f in rsp)
            acc = 0
            while acc < total:
                acc += seg_lens[seg_pos + nseg]
                nseg += 1
            response_segments = [s.hex() for s in segs[seg_pos:seg_pos + nseg]]
            seg_pos += nseg
            _h, ru = gp.std.deframe(req[0])
            if ru[2] != 1:
                continue
            cls = ORDER[slot % 4]
            slot += 1
            if sum(r['db'] == db and r['class'] == cls for r in rows) >= PER_CLASS:
                continue
            request, native = b''.join(req), b''.join(rsp)
            r = gp.pad_read(request, native, derive.TARGETS, pad_start=derive.PAD_START, pad_stop=derive.PAD_STOP)
            rows.append(dict(db=db, slot=slot - 1, **{'class': cls}, request=request.hex(), native=native.hex(),
                             native_frames=[f.hex() for f in rsp], native_segments=response_segments,
                             status=r.status, construction=r.construction, expected=r.output.hex(),
                             native_len=len(native), expected_len=len(r.output)))
    records = {}
    for db in ('base', 'large'):
        for side in ('master', 'outstation'):
            log = LOOPBACK / ('b_rotate4_%s' % db) / ('%s.log' % side)
            records['%s_%s' % (side, db)] = json.loads(log.read_text().strip().splitlines()[-1])
    out = dict(source=[str((LOOPBACK / ('b_rotate4_%s' % db) / 'capture.pcap').relative_to(ARCH)) for db in
                       ('base', 'large')],
               endpoint_records=records,
               policy_targets=derive.TARGETS, reserved_range=[derive.PAD_START, derive.PAD_STOP],
               encoder='general_read_padding.pad_read', vectors=rows)
    (HERE / 'read_class_vectors.json').write_text(json.dumps(out, indent=1) + '\n')
    for row in rows:
        print(row['db'], row['class'], row['native_len'], '->', row['expected_len'], row['status'],
              row['construction'], [len(bytes.fromhex(s)) for s in row['native_segments']])


if __name__ == '__main__':
    main()

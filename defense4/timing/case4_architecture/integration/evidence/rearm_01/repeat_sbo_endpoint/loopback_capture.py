#!/usr/bin/env python3
"""Loopback capture and independent decode of the repeated-SBO endpoint workload (software only).

run: outstation and master of one endpoint binary over 127.0.0.1 inside a private user+network namespace
(unshare -rn, as full_read_01/endpoint/run_full_read.py does), with dumpcap on lo, so the capture holds the real
kernel TCP segments. The endpoints' environment is the caller's CASE4_* controls; nothing else is set.

decode: cut the capture with read_complete_01's capture.py (TCP reassembly per direction) and dnp3_std.py
(link CRCs, transport reassembly), pair each request with its response, and report per exchange the request
kind (READ class from its object headers, SELECT, OPERATE), request octets, response link-frame lengths, the TCP
segment lengths carrying the response, IIN, and per-class / per-database size rows.

  loopback_capture.py run --binary BIN --output DIR [--reads 1] [--env CASE4_SBO_CYCLES=64 ...]
  loopback_capture.py decode --output DIR
  loopback_capture.py compare DIR_A DIR_B          # identical request/response bytes and TCP segmentation
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
STD_DIR = HERE.parents[2] / ('core/response_only_rearm/stage_experiments/read_complete_01/software/source/'
                             'read_reencode_01')


def _load(name):
    spec = importlib.util.spec_from_file_location('rs_' + name, STD_DIR / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


STD, CAP = _load('dnp3_std'), _load('capture')
PORT = 20000


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def to_microsecond_pcap(src, dst):
    """Rewrite a little-endian nanosecond pcap as a microsecond pcap (as run_full_read.py does)."""
    data = Path(src).read_bytes()
    if data[:4] != b'\x4d\x3c\xb2\xa1':
        raise ValueError('expected a little-endian nanosecond pcap')
    out, p = bytearray(b'\xd4\xc3\xb2\xa1' + data[4:24]), 24
    while p + 16 <= len(data):
        sec, nsec, incl, orig = struct.unpack('<IIII', data[p:p + 16])
        out += struct.pack('<IIII', sec, nsec // 1000, incl, orig) + data[p + 16:p + 16 + incl]
        p += 16 + incl
    Path(dst).write_bytes(bytes(out))


def run(binary, output, reads, controls, range_bits=8, lifetime=120):
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    binary = Path(binary).resolve(); stop = output / 'stop'; q = lambda p: shlex.quote(str(p))
    script = f"""set -e
ip link set lo up
dumpcap -q -i lo -F pcap -f 'tcp port {PORT}' -w - > {q(output / 'capture_ns.pcap')} 2> {q(output / 'dumpcap.log')} &
TD=$!
sleep 0.5
{q(binary)} outstation 127.0.0.1 {PORT} {q(stop)} {lifetime} > {q(output / 'outstation.log')} 2>&1 &
OS=$!
for i in $(seq 100); do grep -q READY {q(output / 'outstation.log')} && break; sleep 0.05; done
set +e
{q(binary)} master 127.0.0.1 {PORT} {q(stop)} {reads} '' {range_bits} 0 > {q(output / 'master.log')} 2>&1
MRC=$?
touch {q(stop)}
wait $OS
sleep 0.6; kill -INT $TD; wait $TD
exit $MRC
"""
    env = {k: v for k, v in os.environ.items() if not k.startswith('CASE4_')}
    env.update(CASE4_PAD58B_SOCKET_GATE='1', **controls)
    rc = subprocess.run(['unshare', '-rn', 'bash', '-c', script], env=env).returncode
    to_microsecond_pcap(output / 'capture_ns.pcap', output / 'capture.pcap')
    meta = dict(binary=str(binary), binary_sha256=sha256(binary), reads=reads, range_bits=range_bits,
                controls=controls, master_rc=rc, runner_sha256=sha256(__file__),
                capture='dumpcap on lo inside unshare -rn; real kernel TCP segments')
    (output / 'run.json').write_text(json.dumps(meta, indent=2) + '\n')
    return rc


def direction_segments(path):
    """Per (src, dst): the stream and its distinct TCP payload segments as (stream offset, length)."""
    streams = CAP.streams(path, require_handshake=True)
    origin, segs = {}, {}
    for r in CAP.tcp_records(path):
        key = (r['src'], r['dst'])
        if r['flags'] & CAP.SYN:
            origin[key] = (r['seq'] + 1) & 0xFFFFFFFF
        elif r['payload']:
            off = (r['seq'] - origin[key]) & 0xFFFFFFFF
            segs.setdefault(key, {})[off] = len(r['payload'])     # a retransmission lands on the same offset
    return streams, {k: sorted(v.items()) for k, v in segs.items()}


def request_kind(app):
    fc, objs = app[1], app[2:]
    if fc in (3, 4):
        return {3: 'SELECT', 4: 'OPERATE'}[fc]
    if fc != 1:
        return 'function_%d' % fc
    groups = []
    p = 0
    while p < len(objs):                       # READ request headers: g, v, q and a 0/2/4-octet range field
        g, v, qual = objs[p], objs[p + 1], objs[p + 2]
        groups.append((g, v)); p += 3 + {0x00: 2, 0x01: 4, 0x06: 0}[qual]
    if groups == [(10, 2)]:
        return 'READ:range'
    if groups == [(30, 0)]:
        return 'READ:analog'
    if groups == [(60, 1)]:
        return 'READ:class0'
    if sorted(groups) == [(60, 1), (60, 2), (60, 3), (60, 4)]:
        return 'READ:integrity'
    if groups == [(1, 2), (30, 1)]:            # one READ, two headers, in this order
        return 'READ:mixed'
    return 'READ:' + ','.join('g%dv%d' % gv for gv in groups)


def decode(output):
    output = Path(output)
    streams, segs = direction_segments(output / 'capture.pcap')
    to_out = [k for k in streams if k[1][1] == PORT]
    to_master = [k for k in streams if k[0][1] == PORT]
    if len(to_out) != 1 or len(to_master) != 1:
        raise ValueError('expected one TCP connection, got %r' % list(streams))
    req_stream, rsp_stream = streams[to_out[0]], streams[to_master[0]]
    req_frames, rsp_frames = CAP.frames(req_stream), CAP.frames(rsp_stream)
    for f in req_frames + rsp_frames:
        STD.deframe(f)                                         # every header and block CRC; raises on any error
    req_frags, req_events = STD.reassemble(req_frames)
    rsp_frags, rsp_events = STD.reassemble(rsp_frames)
    if req_events or rsp_events:
        raise ValueError('transport events: %r %r' % (req_events, rsp_events))
    if len(req_frags) != len(rsp_frags):
        raise ValueError('%d requests, %d responses' % (len(req_frags), len(rsp_frags)))
    # stream offset of each response fragment, to attribute TCP segments
    offsets, p = [], 0
    for app, lengths, _seq in rsp_frags:
        offsets.append((p, p + sum(lengths))); p += sum(lengths)
    rsp_segs = segs[to_master[0]]
    exchanges = []
    for i, ((qapp, qlen, _), (rapp, rlen, _), (a, b)) in enumerate(zip(req_frags, rsp_frags, offsets)):
        if (qapp[0] & 0x0F) != (rapp[0] & 0x0F) or rapp[1] != 0x81:
            raise ValueError('exchange %d: sequence or function mismatch' % i)
        covering = [(o, n) for o, n in rsp_segs if o < b and o + n > a]
        aligned = covering and covering[0][0] == a and covering[-1][0] + covering[-1][1] == b
        exchanges.append(dict(i=i, kind=request_kind(qapp), request_octets=sum(qlen), request_app_octets=len(qapp),
                              response_frames=rlen, response_octets=sum(rlen), response_apdu_octets=len(rapp),
                              tcp_segments=[n for _o, n in covering], segments_frame_aligned=bool(aligned),
                              iin=rapp[2:4].hex()))
    result = dict(capture_sha256=sha256(output / 'capture.pcap'), link_crcs='all valid (dnp3_std.deframe)',
                  request_frames=len(req_frames), response_frames=len(rsp_frames), exchanges=exchanges,
                  request_stream_sha256=hashlib.sha256(req_stream).hexdigest(),
                  response_stream_sha256=hashlib.sha256(rsp_stream).hexdigest(),
                  request_segments=[n for _o, n in segs[to_out[0]]], response_segments=[n for _o, n in rsp_segs])
    table = {}
    for e in exchanges:
        row = table.setdefault(e['kind'], dict(count=0, shapes={}))
        row['count'] += 1
        shape = json.dumps(dict(request_octets=e['request_octets'], response_octets=e['response_octets'],
                                response_frames=e['response_frames'], tcp_segments=e['tcp_segments'],
                                segments_frame_aligned=e['segments_frame_aligned'], iin=e['iin']), sort_keys=True)
        row['shapes'][shape] = row['shapes'].get(shape, 0) + 1
    result['per_kind'] = table
    (output / 'decode.json').write_text(json.dumps(result, indent=1) + '\n')
    return result


def compare(a, b):
    da, db = (json.loads((Path(d) / 'decode.json').read_text()) for d in (a, b))
    keys = ('request_stream_sha256', 'response_stream_sha256', 'request_segments', 'response_segments')
    same = {k: da[k] == db[k] for k in keys}
    same['exchanges'] = [{k: v for k, v in e.items()} for e in da['exchanges']] == db['exchanges']
    return same


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--binary', required=True); r.add_argument('--output', required=True)
    r.add_argument('--reads', type=int, default=1); r.add_argument('--range-bits', type=int, default=8)
    r.add_argument('--env', action='append', default=[], help='CASE4_NAME=value for both endpoints')
    d = sub.add_parser('decode'); d.add_argument('--output', required=True)
    c = sub.add_parser('compare'); c.add_argument('a'); c.add_argument('b')
    args = ap.parse_args(argv)
    if args.cmd == 'run':
        controls = dict(item.split('=', 1) for item in args.env)
        if any(not k.startswith('CASE4_') for k in controls):
            raise SystemExit('--env takes CASE4_* controls only')
        rc = run(args.binary, args.output, args.reads, controls, args.range_bits)
        out = decode(args.output)
        print(json.dumps(dict(master_rc=rc, per_kind=out['per_kind']), indent=1))
        return rc
    if args.cmd == 'decode':
        print(json.dumps(decode(args.output)['per_kind'], indent=1)); return 0
    same = compare(args.a, args.b)
    print(json.dumps(same, indent=1))
    return 0 if all(same.values()) else 1


if __name__ == '__main__':
    sys.exit(main())

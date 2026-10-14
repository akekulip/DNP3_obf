#!/usr/bin/env python3
"""Profile-exact check of every response attempt the master received, beside the general standards check.

check_capture.py accepts any legal response encoding that preserves the native semantics and length. This
module checks the separate claim that the pinned candidate61 encoding (or the unchanged native image) is what
reached the master, attempt by attempt:

  native (padding off, or an unbound connection)   the wire TCP payload equals the native image byte for byte
  candidate61 READ 49 -> 61   one frame, LEN 50, transport octet unchanged, the native application header and
                              IIN, then G10V2 q0x00 0-5, q0x00 6-9, q0x01 10-22 carrying the native flags in order
  candidate61 SELECT/OPERATE 37 -> 61   the 22 native application octets split 15/6/1 into frames 28/19/14,
                              transport FIR|s, s+1, FIN|s+2 (mod 64) from the native transport sequence s

The expected image is built here from the native response in out.pcap (no project encoder is imported), and
every outstation->master TCP segment carrying payload, retransmissions included, must equal exactly one whole
expected image. A retransmission is never folded into the first attempt.

  python3 profile_check.py RUN_DIR --master-port P [--outstation-port 20000] \
      --expect READ=61 --expect SELECT=61 --expect OPERATE=61 [-o profile.json]
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import capture  # noqa: E402
import dnp3_std as std  # noqa: E402

PROFILE = 'candidate61'
NATIVE_LEN = {'READ': 49, 'SELECT': 37, 'OPERATE': 37}
READ_RANGES = ((0x00, 0, 5), (0x00, 6, 9), (0x01, 10, 22))
CONTROL_SPLIT = (15, 6, 1)
FIR, FIN = 0x40, 0x80


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _header(native_header8, user_len):
    h = bytearray(native_header8)
    h[2] = 5 + user_len
    return bytes(h)


def _read61(header8, user):
    """user = transport + app header(2) + IIN(2) + '0a 02 00 00 16' + 23 flags (the native 49-byte READ)."""
    if len(user) != 33 or user[5:10] != b'\x0a\x02\x00\x00\x16':
        raise std.StdError('native READ is not one G10V2 q0x00 0-22 object (%s)' % user[5:10].hex())
    flags = user[10:33]
    body = bytearray(user[:5])
    for qualifier, start, stop in READ_RANGES:
        body += b'\x0a\x02' + bytes([qualifier])
        body += bytes([start, stop]) if qualifier == 0x00 else struct.pack('<HH', start, stop)
        body += flags[start:stop + 1]
    return std.frame(_header(header8, len(body)), bytes(body))


def _control61(header8, user):
    """user = transport + 22 application octets (the native 37-byte SELECT/OPERATE response)."""
    if len(user) != 23:
        raise std.StdError('native control response has %d user octets, expected 23' % len(user))
    th, app = user[0], user[1:]
    if th & (FIR | FIN) != (FIR | FIN):
        raise std.StdError('native control response is not a single FIR|FIN segment')
    seq, out, p = th & 0x3F, b'', 0
    for i, size in enumerate(CONTROL_SPLIT):
        flags = (FIR if i == 0 else 0) | (FIN if i == len(CONTROL_SPLIT) - 1 else 0)
        segment = bytes([flags | ((seq + i) & 0x3F)]) + app[p:p + size]
        out += std.frame(_header(header8, len(segment)), segment)
        p += size
    return out


def expected_image(kind, native_frame, expected_len):
    """The exact image the master must receive for this response under this arm's expected length."""
    header8, user = std.deframe(native_frame)
    if expected_len == len(native_frame):
        return native_frame
    if expected_len == 61 and kind == 'READ':
        return _read61(header8, user)
    if expected_len == 61 and kind in ('SELECT', 'OPERATE'):
        return _control61(header8, user)
    raise std.StdError('no %s profile for %s %d -> %d' % (PROFILE, kind, len(native_frame), expected_len))


def _native_responses(out_pcap, outstation_port, master_port, require_handshake):
    """Native responses (one frame each) paired with the function of the request they answer, in order."""
    streams = capture.streams(out_pcap, include_incarnation=True, require_handshake=require_handshake)
    rsp = [v for k, v in streams.items() if k[0][1] == outstation_port and k[1][1] == master_port]
    req = [v for k, v in streams.items() if k[0][1] == master_port and k[1][1] == outstation_port]
    if len(rsp) != 1 or len(req) != 1:
        raise std.StdError('expected one native response and one request stream, found %d/%d' % (len(rsp), len(req)))
    # CONFIRM (function 0) has no response; every other request is answered in order
    requests = [f for f in (std.request(std.fragment_user(app))['function']
                            for app, _lens, _seq in std.reassemble(capture.frames(req[0]))[0]) if f != 0]
    frames = capture.frames(rsp[0])
    kinds = {1: 'READ', 3: 'SELECT', 4: 'OPERATE'}
    return [(kinds.get(requests[i], 'other') if i < len(requests) else None, f) for i, f in enumerate(frames)]


def _attempts(in_pcap, outstation_port, master_port):
    """Every outstation->master TCP segment with payload, in capture order (no reassembly, no dedup), and
    the stream origin from the outstation's SYN-ACK (None when the capture holds no handshake)."""
    out, origins = [], []
    for r in capture.tcp_records(in_pcap):
        if r['src'][1] != outstation_port or r['dst'][1] != master_port:
            continue
        if r['flags'] & capture.SYN and r['flags'] & capture.ACK:
            origins.append((r['seq'] + 1) & 0xFFFFFFFF)
        elif r['payload']:
            out.append({'time': r['time'], 'seq': r['seq'], 'payload': r['payload']})
    if len(set(origins)) > 1:
        raise ValueError('more than one TCP incarnation on master port %s' % master_port)
    return out, (origins[0] if origins else None)


def check(run_dir, master_port, expected_lengths, outstation_port=20000, require_handshake=True):
    """expected_lengths: {kind: [length]} as standards.json expected.lengths for this arm/connection."""
    run_dir = Path(run_dir)
    failures, verdicts = [], []
    try:
        natives = _native_responses(run_dir / 'out.pcap', outstation_port, master_port, require_handshake)
        attempts, origin = _attempts(run_dir / 'in.pcap', outstation_port, master_port)
        if origin is None and require_handshake:
            raise ValueError('no handshake-backed stream origin for master port %s' % master_port)
    except (OSError, ValueError) as error:
        return {'profile': PROFILE, 'conformant': False, 'failures': ['capture unreadable: %s' % error],
                'verdicts': [], 'responses': 0, 'attempts': 0}
    expected = []
    for i, (kind, frame) in enumerate(natives):
        want = (expected_lengths or {}).get(kind) if kind else None
        try:
            if kind is None:
                raise std.StdError('native response #%d has no request' % i)
            target = want[0] if want else len(frame)     # unlisted kinds must arrive unchanged
            image = expected_image(kind, frame, target)
        except std.StdError as error:
            failures.append('response #%d (%s): %s' % (i, kind, error))
            image = None
        expected.append((kind, image))
    if origin is None and attempts:
        origin = attempts[0]['seq']                    # legacy payload-only fixtures only
    offsets, p = {}, 0
    for i, (_kind, image) in enumerate(expected):
        offsets[p] = i
        p += len(image) if image is not None else len(natives[i][1])
    seen = set()
    for n, a in enumerate(attempts):
        rel = (a['seq'] - origin) & 0xFFFFFFFF
        index = offsets.get(rel)
        v = {'attempt': n, 'time': a['time'], 'stream_offset': rel, 'payload_len': len(a['payload']),
             'payload_sha256': _sha(a['payload']), 'response': index,
             'retransmission': index in seen}
        if index is None:
            v.update(ok=False, error='segment does not start at an expected response boundary')
        else:
            kind, image = expected[index]
            v['kind'] = kind
            v['expected_len'] = len(image) if image is not None else None
            if image is None:
                v.update(ok=False, error='no expected image')
            elif a['payload'] != image:
                v.update(ok=False, error='payload differs from the %s image (%d octets, want %d)'
                         % (PROFILE if len(image) != len(natives[index][1]) else 'native', len(a['payload']), len(image)))
            else:
                v['ok'] = True
            seen.add(index)
        if not v['ok']:
            failures.append('attempt #%d (%s): %s' % (n, v.get('kind'), v['error']))
        verdicts.append(v)
    for i in range(len(expected)):
        if i not in seen:
            failures.append('response #%d (%s): no attempt reached the master' % (i, expected[i][0]))
    counts = {}
    for kind, _image in expected:
        counts[kind] = counts.get(kind, 0) + 1
    return {'profile': PROFILE, 'conformant': not failures, 'failures': failures, 'verdicts': verdicts,
            'responses': len(expected), 'attempts': len(attempts),
            'retransmissions': sum(1 for v in verdicts if v['retransmission']), 'counts': counts,
            'master_port': master_port, 'outstation_port': outstation_port, 'expected_lengths': expected_lengths}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run_dir')
    ap.add_argument('--master-port', type=int, required=True)
    ap.add_argument('--outstation-port', type=int, default=20000)
    ap.add_argument('--expect', action='append', default=[], help='KIND=LEN, e.g. READ=61')
    ap.add_argument('-o', '--output')
    a = ap.parse_args(argv)
    lengths = {k: [int(v)] for k, v in (item.split('=', 1) for item in a.expect)}
    res = check(a.run_dir, a.master_port, lengths, a.outstation_port)
    if a.output:
        Path(a.output).write_text(json.dumps(res, indent=1) + '\n')
    summary = {k: res.get(k) for k in ('conformant', 'responses', 'attempts', 'counts')}
    summary['failures'] = res['failures'][:6]
    print(json.dumps(summary, indent=1))
    return 0 if res['conformant'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

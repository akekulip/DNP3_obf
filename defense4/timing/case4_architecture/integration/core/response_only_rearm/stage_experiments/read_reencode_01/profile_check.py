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

Per-class READ (check(..., read_classes={class: {'native': n, 'image': m}}), the READ-class schedule endpoint):
every READ is classified from its request bytes (protocol/hw_vepa/read_classes.py) and held to its own class. A
class at its target must arrive unchanged; a padded class must arrive as policy_image, the read_complete_01
prefix construction over the whole native response (one or several link frames). Responses are compared as the
reassembled aggregate: every outstation->master segment must carry exactly the expected octets at its stream
offset, and every octet of every expected image must arrive.
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
READ_PAD_START, READ_PAD_STOP = 1024, 4095    # read_complete_01/policy/policy.json reserved_padding_range
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


def _read_prefix(header8, user, expected_len):
    """read_complete_01 policy READ (one native frame, e.g. 49 -> 141), written here from the encoding, not from
    the project encoder: a new FIR frame carries the native transport sequence s, application header and IIN, then
    a G1V2 q0x01 object over the reserved indices from 1024 whose first n-4 zero flag octets fill it; the native
    frame follows unchanged in length as FIN, sequence s+1, its four application octets replaced by the last four
    zero flags. n is the one count that makes the total expected_len."""
    if user[0] & (FIR | FIN) != (FIR | FIN) or len(user) < 6:
        raise std.StdError('native READ is not a single FIR|FIN frame with an application header and IIN')
    native_len = len(std.frame(header8, user))
    for n in range(4, READ_PAD_STOP - READ_PAD_START + 2):
        obj = b'\x01\x02\x01' + struct.pack('<HH', READ_PAD_START, READ_PAD_START + n - 1) + bytes(n)
        first = bytes([FIR | (user[0] & 0x3F)]) + user[1:5] + obj[:-4]
        if len(first) > 250:                                  # one link frame carries at most 250 user octets
            break
        if native_len + len(std.frame(_header(header8, len(first)), first)) == expected_len:
            rest = bytes([FIN | ((user[0] + 1) & 0x3F)]) + obj[-4:] + user[5:]
            return std.frame(_header(header8, len(first)), first) + std.frame(header8, rest)
    raise std.StdError('no %s READ prefix reaches %d octets from %d' % (PROFILE, expected_len, native_len))


def policy_image(native_frames, expected_len):
    """read_complete_01 policy construction over a whole native response (its link frames, FIR..FIN), written
    from the encoding: a new FIR frame carries the native transport sequence s, application header and IIN and a
    G1V2 q0x01 object over the reserved indices from 1024 whose first n-4 zero flags fill it; every native frame
    follows unchanged in length, renumbered s+1.., keeping only its FIN bit, the first one's four application octets
    replaced by the last four zero flags. n is the one count that makes the aggregate expected_len, with the prefix
    in one link frame. A native already at expected_len is returned unchanged."""
    parts = [std.deframe(f) for f in native_frames]
    if not parts:
        raise std.StdError('no native frames')
    header8, user = parts[0]
    if not user[0] & FIR or len(user) < 6 or not parts[-1][1][0] & FIN:
        raise std.StdError('native READ is not one transport series FIR..FIN with an application header and IIN')
    native_len = sum(len(f) for f in native_frames)
    if expected_len == native_len:                            # already at its target: unchanged
        return b''.join(native_frames)
    for n in range(4, READ_PAD_STOP - READ_PAD_START + 2):
        obj = b'\x01\x02\x01' + struct.pack('<HH', READ_PAD_START, READ_PAD_START + n - 1) + bytes(n)
        first = bytes([FIR | (user[0] & 0x3F)]) + user[1:5] + obj[:-4]
        if len(first) > 250:                                  # one link frame carries at most 250 user octets
            break
        prefix = std.frame(_header(header8, len(first)), first)
        if native_len + len(prefix) == expected_len:
            out = prefix
            for i, (h, u) in enumerate(parts):
                th = (u[0] & FIN) | (((u[0] & 0x3F) + 1) & 0x3F)
                out += std.frame(h, bytes([th]) + (obj[-4:] + u[5:] if i == 0 else u[1:]))
            return out
    raise std.StdError('no READ prefix reaches %d octets from %d' % (expected_len, native_len))


def expected_image(kind, native_frame, expected_len):
    """The exact image the master must receive for this response under this arm's expected length."""
    header8, user = std.deframe(native_frame)
    if expected_len == len(native_frame):
        return native_frame
    if expected_len == 61 and kind == 'READ':
        return _read61(header8, user)
    if kind == 'READ' and expected_len > 61:
        return _read_prefix(header8, user, expected_len)
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


def _classifier():
    """read_classes.classify_request from protocol/hw_vepa (the one request classifier), loaded on demand."""
    import importlib.util
    path = HERE.parents[4] / 'protocol' / 'hw_vepa' / 'read_classes.py'
    spec = importlib.util.spec_from_file_location('dnp3_read_classes', str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.classify_request


def _series(frames):
    """Group link frames into transport series FIR..FIN (each one solicited response)."""
    out, cur = [], None
    for f in frames:
        _h, u = std.deframe(f)
        if u and u[0] & FIR:
            if cur:
                raise std.StdError('native response series restarted before FIN')
            cur = []
        if cur is None:
            raise std.StdError('native continuation frame without FIR')
        cur.append(f)
        if u and u[0] & FIN:
            out.append(cur)
            cur = None
    if cur:
        raise std.StdError('native response series without FIN at end of stream')
    return out


def _native_by_class(out_pcap, outstation_port, master_port, require_handshake):
    """[(kind, READ class or None, native frames)] in order; READs classified from their request bytes."""
    streams = capture.streams(out_pcap, include_incarnation=True, require_handshake=require_handshake)
    rsp = [v for k, v in streams.items() if k[0][1] == outstation_port and k[1][1] == master_port]
    req = [v for k, v in streams.items() if k[0][1] == master_port and k[1][1] == outstation_port]
    if len(rsp) != 1 or len(req) != 1:
        raise std.StdError('expected one native response and one request stream, found %d/%d' % (len(rsp), len(req)))
    classify = _classifier()
    requests = [app for app, _lens, _seq in std.reassemble(capture.frames(req[0]))[0]
                if std.request(std.fragment_user(app))['function'] != 0]
    kinds = {1: 'READ', 3: 'SELECT', 4: 'OPERATE'}
    out = []
    for i, frames in enumerate(_series(capture.frames(rsp[0]))):
        if i >= len(requests):
            out.append((None, None, frames))
            continue
        kind = kinds.get(requests[i][1], 'other')
        out.append((kind, classify(requests[i]) if kind == 'READ' else None, frames))
    return out


def _check_by_class(run_dir, master_port, expected_lengths, read_classes, outstation_port, require_handshake):
    failures, verdicts = [], []
    try:
        natives = _native_by_class(run_dir / 'out.pcap', outstation_port, master_port, require_handshake)
        attempts, origin = _attempts(run_dir / 'in.pcap', outstation_port, master_port)
        if origin is None and require_handshake:
            raise ValueError('no handshake-backed stream origin for master port %s' % master_port)
    except (OSError, ValueError) as error:
        return {'profile': PROFILE, 'conformant': False, 'failures': ['capture unreadable: %s' % error],
                'verdicts': [], 'responses': 0, 'attempts': 0}
    expected = []
    for i, (kind, cls, frames) in enumerate(natives):
        native = b''.join(frames)
        try:
            if kind is None:
                raise std.StdError('native response #%d has no request' % i)
            if kind == 'READ':
                if cls not in read_classes:
                    raise std.StdError('READ class %s is not declared for this build' % cls)
                e = read_classes[cls]
                if len(native) != e['native']:
                    raise std.StdError('READ %s native %d octets, declared %d' % (cls, len(native), e['native']))
                image = native if e['image'] == e['native'] else policy_image(frames, e['image'])
            else:
                want = (expected_lengths or {}).get(kind)
                if len(frames) != 1:
                    raise std.StdError('%s native response spans %d frames' % (kind, len(frames)))
                image = expected_image(kind, frames[0], want[0] if want else len(native))
        except std.StdError as error:
            failures.append('response #%d (%s%s): %s' % (i, kind, ' ' + cls if cls else '', error))
            image = None
        expected.append((kind, cls, image, native))
    if origin is None and attempts:
        origin = attempts[0]['seq']
    spans, p = [], 0
    for kind, cls, image, native in expected:
        size = len(image) if image is not None else len(native)
        spans.append((p, p + size))
        p += size
    covered = [set() for _ in expected]
    for n, a in enumerate(attempts):
        rel = (a['seq'] - origin) & 0xFFFFFFFF
        index = next((i for i, (lo, hi) in enumerate(spans) if lo <= rel < hi), None)
        v = {'attempt': n, 'time': a['time'], 'stream_offset': rel, 'payload_len': len(a['payload']),
             'payload_sha256': _sha(a['payload']), 'response': index}
        if index is None:
            v.update(ok=False, retransmission=False, error='segment starts outside every expected response')
        else:
            kind, cls, image, native = expected[index]
            lo, hi = spans[index]
            octets = set(range(rel - lo, rel - lo + len(a['payload'])))
            v.update(kind=kind, read_class=cls, retransmission=bool(octets & covered[index]),
                     expected_len=len(image) if image is not None else None)
            if image is None:
                v.update(ok=False, error='no expected image')
            elif rel + len(a['payload']) > hi:
                v.update(ok=False, error='segment crosses the end of the expected response')
            elif a['payload'] != image[rel - lo:rel - lo + len(a['payload'])]:
                v.update(ok=False, error='payload differs from the %s image at offset %d'
                         % ('native' if image == native else 'policy', rel - lo))
            else:
                v['ok'] = True
                covered[index] |= octets
        if not v['ok']:
            failures.append('attempt #%d (%s): %s' % (n, v.get('kind'), v['error']))
        verdicts.append(v)
    for i, (kind, cls, image, native) in enumerate(expected):
        if image is not None and len(covered[i]) != len(image):
            failures.append('response #%d (%s%s): %d of %d octets reached the master'
                            % (i, kind, ' ' + cls if cls else '', len(covered[i]), len(image)))
    counts, class_counts = {}, {}
    for kind, cls, _image, _native in expected:
        counts[kind] = counts.get(kind, 0) + 1
        if cls is not None:
            class_counts[cls] = class_counts.get(cls, 0) + 1
    return {'profile': PROFILE, 'conformant': not failures, 'failures': failures, 'verdicts': verdicts,
            'responses': len(expected), 'attempts': len(attempts),
            'retransmissions': sum(1 for v in verdicts if v.get('retransmission')), 'counts': counts,
            'class_counts': class_counts, 'master_port': master_port, 'outstation_port': outstation_port,
            'expected_lengths': expected_lengths, 'read_classes': read_classes}


def check(run_dir, master_port, expected_lengths, outstation_port=20000, require_handshake=True, read_classes=None):
    """expected_lengths: {kind: [length]} as standards.json expected.lengths for this arm/connection.
    read_classes: the per-class READ declaration (standards expected.read_classes); None keeps the legacy check."""
    run_dir = Path(run_dir)
    if read_classes is not None:
        return _check_by_class(run_dir, master_port, expected_lengths, read_classes, outstation_port,
                               require_handshake)
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

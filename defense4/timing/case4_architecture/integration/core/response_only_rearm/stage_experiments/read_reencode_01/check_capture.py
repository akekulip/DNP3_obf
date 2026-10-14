#!/usr/bin/env python3
"""IEEE 1815 check of a hardware run's captures: what the master actually received (in.pcap) against what
the outstation sent (out.pcap).

For every outstation response in the master-side stream:
  READ     legal under the response rules (dnp3_std) and carrying exactly the native response's ordered
           points, IIN, function and sequence; the frame length is reported (58 expected when re-encoded).
  SELECT / OPERATE   Rule 8 echo against the master's request as it reached the outstation (out.pcap).
Native-side frames are matched to wire-side frames by position in each reassembled stream.

  python3 check_capture.py RUN_DIR [--master-port P] [--outstation-port 20000] [-o result.json]

Exit 0 when every READ is legal and equal and every control response satisfies Rule 8; 1 otherwise. The
result JSON lists every frame verdict, so an all-58 run reports its control non-conformance explicitly.
The CLI requires handshake-backed TCP streams by default for qualification; use --legacy-payload-only only for
old retained payload-only fixtures.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import capture  # noqa: E402
import dnp3_std as std  # noqa: E402


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _endpoint_meta(endpoint):
    host, port = endpoint
    return {'ip': '.'.join(str(b) for b in host), 'port': port}


def _tuple_meta(key):
    src, dst, inc = key
    return {'src': _endpoint_meta(src), 'dst': _endpoint_meta(dst), 'incarnation': inc}


def _consume_images(frames, fragments):
    images, offset = [], 0
    for _app, lens, _seq in fragments:
        count = len(lens)
        image = b''.join(frames[offset:offset + count])
        images.append({'frame_count': count, 'sha256': _sha(image), 'frame_sha256': [_sha(f) for f in frames[offset:offset + count]]})
        offset += count
    return images


def _streams(path, require_handshake=False):
    return {k: capture.frames(v) for k, v in capture.streams(path, include_incarnation=True,
                                                             require_handshake=require_handshake).items()}


def directed(path, src_port, dst_port, require_handshake=False):
    found = [(k, v) for k, v in _streams(path, require_handshake).items()
             if k[0][1] == src_port and (dst_port is None or k[1][1] == dst_port)]
    if len(found) != 1:
        raise SystemExit('expected one %s->%s stream in %s, found %d' % (src_port, dst_port, path, len(found)))
    (src, dst, _inc), frames = found[0]
    return frames, dst[1]


def _semantic_read_ok(nu, wu):
    _, npts = std.check_read_response(nu)
    std.check_read_response(wu, expect=npts)
    return nu[1:5] == wu[1:5]


def _conversation(native_rsp, wire_rsp, native_req, wire_req, expected_lengths, failures, verdicts, response_key=None):
    native_frags, native_events = std.reassemble(native_rsp)
    wire_frags, wire_events = std.reassemble(wire_rsp)
    native_req_frags, native_req_events = std.reassemble(native_req)
    wire_req_frags, wire_req_events = std.reassemble(wire_req)
    for side, events in (('native', native_events), ('wire', wire_events),
                         ('native request', native_req_events), ('wire request', wire_req_events)):
        for ev in events:
            failures.append('%s transport: %s' % (side, ev))
    if [x[0] for x in native_req_frags] != [x[0] for x in wire_req_frags]:
        failures.append('request stream differs between capture points')
    if len(native_frags) != len(wire_frags):
        failures.append('response count differs: native %d, wire %d' % (len(native_frags), len(wire_frags)))

    request_infos = []
    controls_expected, controls_observed = 0, 0
    for serial, (app, lens, seq) in enumerate(native_req_frags):
        user = std.fragment_user(app)
        req = std.request(user)
        request_infos.append({'serial': serial, 'function': req['function'], 'app_seq': user[1] & 0x0F,
                              'transport_seq': seq, 'application_sha256': _sha(app), 'user': user,
                              'lengths': lens})
        if req['function'] in (3, 4):
            controls_expected += 1

    native_images = _consume_images(native_rsp, native_frags)
    wire_images = _consume_images(wire_rsp, wire_frags)
    tuple_info = _tuple_meta(response_key) if response_key is not None else None
    for i, ((napp, nlens, nseq), (wapp, wlens, wseq)) in enumerate(zip(native_frags, wire_frags)):
        nu, wu = std.fragment_user(napp), std.fragment_user(wapp)
        v = {'index': len(verdicts), 'native_len': sum(nlens), 'wire_len': sum(wlens), 'segments': len(wlens),
             'native_transport_seq': nseq, 'wire_transport_seq': wseq,
             'native_app_sha256': _sha(napp), 'wire_app_sha256': _sha(wapp),
             'native_image_sha256': native_images[i]['sha256'] if i < len(native_images) else None,
             'wire_image_sha256': wire_images[i]['sha256'] if i < len(wire_images) else None,
             'wire_frame_sha256': wire_images[i]['frame_sha256'] if i < len(wire_images) else [],
             'wire_frame_count': wire_images[i]['frame_count'] if i < len(wire_images) else None}
        if tuple_info is not None:
            v['tuple'] = tuple_info
        try:
            if i >= len(request_infos):
                raise std.StdError('response has no matching serialized request')
            req = request_infos[i]
            v['request_serial'] = req['serial']
            v['request_function'] = req['function']
            v['request_app_seq'] = req['app_seq']
            v['app_seq'] = wu[1] & 0x0F
            v['native_app_seq'] = nu[1] & 0x0F
            v['wire_app_seq'] = wu[1] & 0x0F
            v['request_app_sha256'] = req['application_sha256']
            expected_seq = req['app_seq']
            if (nu[1] & 0x0F) != expected_seq or (wu[1] & 0x0F) != expected_seq:
                raise std.StdError('application sequence mismatch: request %d, native %d, wire %d'
                                   % (expected_seq, nu[1] & 0x0F, wu[1] & 0x0F))
            if nu[2] == 0x81 and nu[5:7] == b'\x0a\x02':
                v['kind'] = 'READ'
                if req['function'] != 1:
                    raise std.StdError('READ response matched request function 0x%02x' % req['function'])
                v['transport_ok'] = _semantic_read_ok(nu, wu)
                if not v['transport_ok']:
                    raise std.StdError('application header or IIN changed')
                v['ok'] = True
            elif req['function'] in (3, 4):
                v['kind'] = 'SELECT' if req['function'] == 3 else 'OPERATE'
                controls_observed += 1
                v['transport_ok'] = napp == wapp
                if not v['transport_ok']:
                    raise std.StdError('application fragment changed')
                outcome = std.check_control_outcome(req['user'], wu)
                if v['kind'] == 'SELECT':
                    v['select_authorizes_operate'] = outcome['authorizes_or_succeeds']
                else:
                    v['operate_success'] = outcome['authorizes_or_succeeds']
                if not outcome['authorizes_or_succeeds']:
                    raise std.StdError('%s does not %s: %s' %
                                       (v['kind'], 'authorize OPERATE' if v['kind'] == 'SELECT' else 'succeed',
                                        '; '.join(outcome['reasons'])))
                v['ok'] = True
            else:
                v['kind'], v['transport_ok'], v['ok'] = 'other', napp == wapp, napp == wapp
                if req['function'] == 1:            # the READ length gate would otherwise never see it
                    raise std.StdError('READ request answered by a non-Group 10 Var 2 response')
                if not v['ok']:
                    raise std.StdError('unclassified response changed')
            expected = expected_lengths.get(v['kind'])
            if expected is not None and v['wire_len'] != expected:
                raise std.StdError('wire length %d != expected %d' % (v['wire_len'], expected))
        except std.StdError as error:
            v.setdefault('kind', None)
            v.setdefault('transport_ok', False)
            v['ok'], v['error'] = False, str(error)
            failures.append('%s #%d: %s' % (v.get('kind'), v['index'], error))
        verdicts.append(v)
    if len(native_frags) < len(request_infos):
        missing = request_infos[len(native_frags):]
        failures.append('missing responses: expected %d, observed %d' % (len(request_infos), len(native_frags)))
    if controls_observed != controls_expected:
        failures.append('missing control responses: expected %d, observed %d' % (controls_expected, controls_observed))


def check(run_dir, outstation_port=20000, master_port=None, expected_lengths=None, require_handshake=False):
    run_dir = Path(run_dir)
    expected_lengths = expected_lengths or {}
    out_streams = _streams(run_dir / 'out.pcap', require_handshake)
    in_streams = _streams(run_dir / 'in.pcap', require_handshake)
    verdicts, failures = [], []

    response_keys = set()
    for streams in (out_streams, in_streams):
        for key in streams:
            if key[0][1] == outstation_port and (master_port is None or key[1][1] == master_port):
                response_keys.add(key)
            if key[1][1] == outstation_port and (master_port is None or key[0][1] == master_port):
                response_keys.add((key[1], key[0], key[2]))
    if not response_keys:
        raise SystemExit('expected at least one stream involving outstation port %s in %s'
                         % (outstation_port, run_dir))
    for key in sorted(response_keys, key=lambda k: (k[2], k[1][1])):
        req_key = (key[1], key[0], key[2])
        missing = [name for name, streams, k in (('native request', out_streams, req_key),
                                                ('wire request', in_streams, req_key)) if k not in streams]
        if missing:
            failures.append('missing %s for stream %r' % (', '.join(missing), key))
            continue
        _conversation(out_streams.get(key, []), in_streams.get(key, []), out_streams[req_key], in_streams[req_key],
                      expected_lengths, failures, verdicts, key)
    mports = sorted(set(k[1][1] for k in response_keys))
    return {'run_dir': str(run_dir), 'master_port': mports[0] if len(mports) == 1 else None,
            'responses': len(verdicts), 'verdicts': verdicts,
            'failures': failures, 'conformant': not failures}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run_dir')
    ap.add_argument('--outstation-port', type=int, default=20000)
    ap.add_argument('--master-port', type=int)
    ap.add_argument('--legacy-payload-only', action='store_true',
                    help='allow payload-only retained fixtures without a confirmed TCP handshake')
    ap.add_argument('-o', '--output')
    a = ap.parse_args(argv)
    res = check(a.run_dir, a.outstation_port, a.master_port, require_handshake=not a.legacy_payload_only)
    text = json.dumps(res, indent=2)
    if a.output:
        Path(a.output).write_text(text + '\n')
    summary = {k: sum(1 for v in res['verdicts'] if v['kind'] == k and v['ok']) for k in ('READ', 'SELECT', 'OPERATE')}
    print(json.dumps({'conformant': res['conformant'], 'passed_by_kind': summary, 'failures': res['failures'][:6],
                      'failure_count': len(res['failures'])}, indent=1))
    return 0 if res['conformant'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

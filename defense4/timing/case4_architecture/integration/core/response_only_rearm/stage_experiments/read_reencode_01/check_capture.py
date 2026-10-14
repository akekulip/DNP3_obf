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
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import capture  # noqa: E402
import dnp3_std as std  # noqa: E402


def directed(path, src_port, dst_port):
    found = [(k, v) for k, v in capture.streams(path).items()
             if k[0][1] == src_port and (dst_port is None or k[1][1] == dst_port)]
    if len(found) != 1:
        raise SystemExit('expected one %s->%s stream in %s, found %d' % (src_port, dst_port, path, len(found)))
    (src, dst), data = found[0]
    return capture.frames(data), dst[1]


def check(run_dir, outstation_port=20000, master_port=None):
    run_dir = Path(run_dir)
    native_rsp, mport = directed(run_dir / 'out.pcap', outstation_port, master_port)
    wire_rsp, _ = directed(run_dir / 'in.pcap', outstation_port, mport)
    native_req, _ = directed(run_dir / 'out.pcap', mport, outstation_port)
    verdicts, failures = [], []
    # Clause 8: judge application fragments, not link frames. A response may span several transport segments
    # (link frames) in the wire stream; each side is reassembled with the transport receive rules first.
    native_frags, native_events = std.reassemble(native_rsp)
    wire_frags, wire_events = std.reassemble(wire_rsp)
    for side, events in (('native', native_events), ('wire', wire_events)):
        for ev in events:
            failures.append('%s transport: %s' % (side, ev))
    if len(native_frags) != len(wire_frags):
        failures.append('response count differs: native %d, wire %d' % (len(native_frags), len(wire_frags)))
    controls = [std.deframe(f)[1] for f in native_req if std.request(std.deframe(f)[1])['function'] in (3, 4)]
    ci = 0
    for i, ((napp, nlens, _), (wapp, wlens, _)) in enumerate(zip(native_frags, wire_frags)):
        nu, wu = std.fragment_user(napp), std.fragment_user(wapp)
        v = {'index': i, 'native_len': sum(nlens), 'wire_len': sum(wlens), 'segments': len(wlens)}
        try:
            if nu[2] == 0x81 and nu[5:7] == b'\x0a\x02':
                v['kind'] = 'READ'
                _, npts = std.check_read_response(nu)
                std.check_read_response(wu, expect=npts)
                if nu[1:5] != wu[1:5]:
                    raise std.StdError('application header or IIN changed')
                v['ok'] = True
            elif ci < len(controls):
                v['kind'] = ('SELECT', 'OPERATE')[controls[ci][2] - 3]
                std.check_control_echo(controls[ci], wu)
                ci += 1
                v['ok'] = True
            else:
                v['kind'], v['ok'] = 'other', napp == wapp
                if not v['ok']:
                    raise std.StdError('unclassified response changed')
        except std.StdError as error:
            if v.get('kind') in ('SELECT', 'OPERATE'):
                ci += 1
            v['ok'], v['error'] = False, str(error)
            failures.append('%s #%d: %s' % (v.get('kind'), i, error))
        verdicts.append(v)
    return {'run_dir': str(run_dir), 'master_port': mport, 'responses': len(wire_frags), 'verdicts': verdicts,
            'failures': failures, 'conformant': not failures}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run_dir')
    ap.add_argument('--outstation-port', type=int, default=20000)
    ap.add_argument('--master-port', type=int)
    ap.add_argument('-o', '--output')
    a = ap.parse_args(argv)
    res = check(a.run_dir, a.outstation_port, a.master_port)
    text = json.dumps(res, indent=2)
    if a.output:
        Path(a.output).write_text(text + '\n')
    summary = {k: sum(1 for v in res['verdicts'] if v['kind'] == k and v['ok']) for k in ('READ', 'SELECT', 'OPERATE')}
    print(json.dumps({'conformant': res['conformant'], 'passed_by_kind': summary, 'failures': res['failures'][:6],
                      'failure_count': len(res['failures'])}, indent=1))
    return 0 if res['conformant'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

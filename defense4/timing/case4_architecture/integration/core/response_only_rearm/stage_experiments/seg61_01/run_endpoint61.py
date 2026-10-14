#!/usr/bin/env python3
"""Gate 2 of the 61-octet experiment: the pinned OpenDNP3 master/outstation pair through endpoint_proxy.py (61-octet
images), via read_reencode_01/run_endpoint.py with this directory's proxy and an independent Clause 8 / Rule 8 check.
  python3 -B run_endpoint61.py --output FRESH --work FRESH_BUILD --dependency-cache DIR --reads 20
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'read_reencode_01')]
import run_endpoint as base  # noqa: E402
import dnp3_std as std  # noqa: E402
import encode61  # noqa: E402


def check_tee(tee_path, reads):
    failures, counts = [], {'read': 0, 'control': 0, 'passthrough': 0, 'requests': 0}
    requests, responses = [], []
    for line in Path(tee_path).read_text().splitlines():
        ev = json.loads(line)
        if ev['direction'] == 'master_to_outstation':
            counts['requests'] += 1
            requests.append(bytes.fromhex(ev['frame_hex']))
            continue
        native, sent = bytes.fromhex(ev['native_frame_hex']), bytes.fromhex(ev['sent_frame_hex'])
        counts[ev['kind']] += 1
        if sent != (encode61.encode(native) or native):
            failures.append('sent bytes differ from the independent recompute: ' + ev['sent_frame_hex'])
        frames = encode61.split_frames(sent)
        frags, events = std.reassemble(frames)
        if events or len(frags) != 1:
            failures.append('transport reassembly failed: %s' % events)
            continue
        if frags[0][0] != std.deframe(native)[1][1:] and ev['kind'] != 'read':
            failures.append('application octets changed in a %s response' % ev['kind'])
        if ev['kind'] != 'passthrough' and len(sent) != encode61.SIZE:
            failures.append('%s image is %d octets' % (ev['kind'], len(sent)))
        if ev['kind'] == 'read':
            try:
                _, npts = std.check_read_response(std.deframe(native)[1])
                std.check_read_response(std.fragment_user(frags[0][0]), expect=npts)
            except std.StdError as error:
                failures.append('READ: %s' % error)
        responses.append(std.fragment_user(frags[0][0]))
    if counts['read'] != reads or counts['control'] != 2:
        failures.append('expected %d READ and 2 control images, saw %s' % (reads, counts))
    controls = [(q, r) for q, r in zip(requests, responses) if std.deframe(q)[1][2] in (3, 4)]
    for q, r in controls:
        try:
            std.check_control_echo(std.deframe(q)[1], r)
        except std.StdError as error:
            failures.append('Rule 8: %s' % error)
    if len(controls) != 2:
        failures.append('expected SELECT and OPERATE, found %d control exchanges' % len(controls))
    return counts, failures


base.HERE = HERE
base.OWN_SOURCES = ['encode61.py', 'endpoint_proxy.py', 'run_endpoint61.py']
base.check_tee = check_tee

if __name__ == '__main__':
    raise SystemExit(base.main())

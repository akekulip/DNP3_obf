#!/usr/bin/env python3
"""Independent check of a proxy_demo run against the master's own record and both captured legs.

Pass requires, for every READ:
  wire    master-facing response: every link CRC valid, one reassembled fragment, size in the target
          set (or native when ineligible), and its object octets begin with the outstation's object
          octets byte for byte (original measurements and indexes preserved, nothing reordered);
  master  every scan completed, every task SUCCESS, no IIN beyond the native run's; every requested point
          delivered; every delivered configured point carries the outstation's value and flags; every
          other delivered point is a declared padding point (binary input >= 16, value 0, flags 0x00).
"""
import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fullread as fr  # noqa: E402
import dnp3_std as std  # noqa: E402
import pad_oracle as po  # noqa: E402


def master_record(d):
    return json.loads([l for l in (Path(d) / 'master.log').read_text().splitlines() if l.startswith('{')][-1])


def size_verdict(size, native, targets):
    """Return a failure string if a master-facing response of `size` octets is wrong for a native of
    `native` octets under `targets`, else None. A response that stayed native when a target was reachable
    (e.g. a disabled padder) FAILS; a response is left native only when it is genuinely ineligible
    (at/above every target so it cannot be reduced)."""
    expected = po.choose_target(native, targets)       # smallest reachable target >= native
    if expected is None:
        if size != native or native < max(targets):
            return 'ineligible response size %d (native %d) not left native as required' % (size, native)
        return None
    if size != expected:
        return 'response size %d did not reach the required target %d (native %d)' % (size, expected, native)
    return None


def verify(run_dir, native_dir, fixture_dir, targets):
    run_dir = Path(run_dir)
    meta = json.loads((run_dir / 'run.json').read_text())
    failures = []
    master_tx = fr.transactions(run_dir / 'capture.pcap', outstation_port=20001)
    out_tx = fr.transactions(run_dir / 'capture.pcap', outstation_port=20000)
    if len(master_tx) != meta['reads'] or len(out_tx) != meta['reads']:
        failures.append('transactions master-side %d outstation-side %d, expected %d'
                        % (len(master_tx), len(out_tx), meta['reads']))
    sizes = {}
    for m, o in zip(master_tx, out_tx):
        size = m['tcp_payload_octets']
        native = o['tcp_payload_octets']
        sizes[size] = sizes.get(size, 0) + 1
        if targets:
            v = size_verdict(size, native, targets)
            if v:
                failures.append(v)
        mo = [p for p in m['points']]
        oo = [p for p in o['points']]
        if mo[:len(oo)] != oo:
            failures.append('original points not preserved as the prefix of the delivered response')
            break
    native_same = master_record(native_dir)['scans'][0]['points']
    fixture = master_record(fixture_dir)['scans'][0]['points']
    rec = master_record(run_dir)
    if len(rec['scans']) != meta['reads'] or not all(s['completed'] for s in rec['scans']):
        failures.append('master scans incomplete')
    if set(rec['tasks']) != {'SUCCESS'}:
        failures.append('task results %r' % rec['tasks'])
    native_iin = set(master_record(native_dir)['iin'])
    if not set(rec['iin']) <= native_iin:
        failures.append('IIN beyond native: %r' % rec['iin'])
    real_extra, synthetic = set(), set()
    for s in rec['scans']:
        got = s['points']
        if not set(native_same) <= set(got):
            failures.append('a requested point was not delivered')
            break
        wrong = [k for k in got if k in fixture and got[k] != fixture[k]]
        if wrong:
            failures.append('delivered value differs from the outstation database: %r' % wrong[:3])
            break
        scan_synth = {k for k in got if k not in fixture}
        real_extra |= {k for k in got if k in fixture and k not in native_same}
        synthetic |= scan_synth
        # every synthetic padding point, in EVERY scan, must be a bi:>=16 point with value 0, flags 0x00
        bad = [k for k in scan_synth if not (k.startswith('bi:') and int(k[3:]) >= 16)]
        if bad:
            failures.append('added points outside the declared padding range: %r' % sorted(bad)[:3])
            break
        corrupt = [k for k in scan_synth if got[k] != [0, 0]]
        if corrupt:
            failures.append('a padding point is not value 0 with flags 0x00: %r' % sorted(corrupt)[:3])
            break
    first = sorted((t['first_response_time'] - t['request_time']) * 1e3 for t in master_tx)
    done = sorted((t['complete_response_time'] - t['request_time']) * 1e3 for t in master_tx)
    return {'run': str(run_dir), 'passed': not failures, 'failures': failures, 'sizes_master_facing': sizes,
            'sizes_outstation_facing': sorted({t['tcp_payload_octets'] for t in out_tx}),
            'master_request_octets': sorted({t['request_frame_octets'] for t in master_tx}),
            'outstation_request_octets': sorted({t['request_frame_octets'] for t in out_tx}),
            'first_ms_median': first[len(first) // 2] if first else None,
            'complete_ms_median': done[len(done) // 2] if done else None,
            'iin': rec['iin'], 'tasks': rec['tasks'], 'points_per_scan': sorted({len(s['points']) for s in rec['scans']}),
            'requested_points': len(native_same), 'real_points_added': len(real_extra), 'synthetic_points_added': len(synthetic)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run'); ap.add_argument('--native', required=True, help='native run of the same READ mode')
    ap.add_argument('--fixture', required=True, help='native integrity run: every configured point and value')
    ap.add_argument('--targets', default='')
    a = ap.parse_args(argv)
    targets = [int(t) for t in a.targets.split(',') if t]
    r = verify(a.run, a.native, a.fixture, targets)
    print(json.dumps(r, indent=1))
    return 0 if r['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

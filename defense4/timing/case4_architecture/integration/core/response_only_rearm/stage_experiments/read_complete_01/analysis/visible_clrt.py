#!/usr/bin/env python3
"""Before/after visible CLRT on the physical SEL-751 (c68, Philip 2026-10-25). Read-only on evidence.

Before = the 'off' arm (no obfuscation in the switch); after = the 'combined' arm (timing + size). Both captured on
the master NIC, the vantage of an adversary between the master and the switch. For each block (D) and class (mixed
READ, integrity READ, SELECT, OPERATE) it reports the CLRT (first ACK of the request -> complete response) as n, min,
median and max, and the response sizes. No threshold is applied.

  python3 visible_clrt.py OUT.json BLOCK_DIR [BLOCK_DIR ...]
"""
import glob
import json
import statistics
import sys
from pathlib import Path

CLASSES = (('READ', 'mixed'), ('READ', 'integrity'), ('SELECT', None), ('OPERATE', None))


def summarize(values):
    values = sorted(values)
    return dict(n=len(values), min_ms=values[0] / 1000 if values else None,
                median_ms=statistics.median(values) / 1000 if values else None,
                max_ms=values[-1] / 1000 if values else None)


def arm_summary(trial_dir):
    wire = json.loads((trial_dir / 'relay_wire.json').read_text())
    out = {}
    for operation, workload in CLASSES:
        rows = [e for e in wire['exchanges'] if e['operation'] == operation and
                (workload is None or e.get('workload') == workload)]
        name = operation + (' ' + workload if workload else '')
        clrt = [e['complete_clrt_us'] for e in rows if not e['piggyback'] and e['complete_clrt_us'] is not None]
        sizes = sorted({sum(e['response']['actual_payload_lengths']) for e in rows if e.get('response')})
        out[name] = dict(summarize(clrt), piggyback=sum(bool(e['piggyback']) for e in rows),
                         response_bytes=sizes, exchanges=len(rows))
    return out


def main(argv):
    out, blocks = Path(argv[0]), [Path(b) for b in argv[1:]]
    if out.exists():
        raise SystemExit('refusing to overwrite ' + str(out))
    result = dict(observation='master NIC (adversary vantage between master and switch); CLRT = first ACK of the '
                              'request -> complete response', blocks={})
    for block in blocks:
        run = json.loads((block / 'campaign_run.json').read_text())
        entry = dict(D_ms=run['effective']['timing_params_ns']['gap'] / 1e6, block_ok=run.get('ok'))
        for label, arm in (('before', 'off'), ('after', 'combined')):
            directory = Path(glob.glob(str(block / 'physical_relay' / arm / '*_t0'))[0])
            entry[label] = dict(arm=arm, trial=str(directory), **{'classes': arm_summary(directory)})
        result['blocks'][block.name] = entry
    out.write_text(json.dumps(result, indent=1) + '\n')
    for name, entry in result['blocks'].items():
        print('%s  D=%s ms' % (name, entry['D_ms']))
        for cls in entry['before']['classes']:
            b, a = entry['before']['classes'][cls], entry['after']['classes'][cls]
            print('  %-15s before n=%3d %4s B  min/median/max %7.3f %7.3f %7.3f ms | after n=%3d %4s B  %7.3f %7.3f %7.3f ms'
                  % (cls, b['n'], b['response_bytes'], b['min_ms'], b['median_ms'], b['max_ms'],
                     a['n'], a['response_bytes'], a['min_ms'], a['median_ms'], a['max_ms']))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

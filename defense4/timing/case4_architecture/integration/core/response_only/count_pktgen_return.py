#!/usr/bin/env python3
"""Count what enters T on PKTGEN_RETURN (196) in a tofino-model log, by the frame's first 32 bits, plus T's
admit_request and drop_clone executions. On a correct program every READ clone (first word 0xE100gggg) appears
exactly once per admitted READ and drop_clone == number of clones.

  python3 count_pktgen_return.py <model_*.log> [--port 196]
"""
import argparse
import collections
import re


def count(path, port=196):
    lines = open(path, errors='replace').read().splitlines()
    heads = collections.Counter()
    for i, line in enumerate(lines):
        if 'Ingress Pkt from port %d ' % port in line:
            for j in range(i + 1, min(i + 6, len(lines))):
                octets = re.findall(r'\b[0-9a-f]{2}\b', lines[j].split('>:')[-1])
                if len(octets) >= 4:
                    heads[''.join(octets[:4])] += 1
                    break
    admit = sum('Execute Action: t_Ingress.admit_request' in l for l in lines)
    drop_clone = sum('Action: t_Ingress.drop_clone' in l for l in lines)
    return dict(heads=dict(sorted(heads.items())), admit_request=admit, drop_clone=drop_clone)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('--port', type=int, default=196)
    a = ap.parse_args()
    r = count(a.log, a.port)
    for k, v in r['heads'].items():
        print('%s  x%d' % (k, v))
    print('admit_request %d  drop_clone %d' % (r['admit_request'], r['drop_clone']))
    repeats = {k: v for k, v in r['heads'].items() if k.startswith('e100') and v > 1}
    others = {k: v for k, v in r['heads'].items() if not k.startswith('e1')}
    print('READ clones seen more than once: %s; non-clone frames: %s' % (repeats or 'none', others or 'none'))

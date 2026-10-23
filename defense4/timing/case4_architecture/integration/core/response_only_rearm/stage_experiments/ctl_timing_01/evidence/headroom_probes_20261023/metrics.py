#!/usr/bin/env python3
"""Per-control resource summary of one bf-p4c out dir (N=p0 ingress, E=p0 egress, T=p1 ingress, X=p1 egress).

  python3 metrics.py OUTDIR [--json]
"""
import json
import re
import sys
from pathlib import Path

ROLE = {('p0', 'ingress'): 'N', ('p0', 'egress'): 'E', ('p1', 'ingress'): 'T', ('p1', 'egress'): 'X'}
COLS = ['xbar', 'hash_bits', 'gateways', 'rams', 'tcams', 'map_rams', 'adb', 'vliw']


def stage_numbers(node):
    if isinstance(node, dict):
        if 'stage_number' in node:
            yield node['stage_number']
        for v in node.values():
            yield from stage_numbers(v)
    elif isinstance(node, list):
        for v in node:
            yield from stage_numbers(v)


def gress_of(name, names):
    base = name
    if base.startswith('egresshdr') or 'checksum' in base and 'egress' in base:
        return 'egress'
    if base.startswith('ingresshdr'):
        return 'ingress'
    for cand in (base, re.sub(r'-gateway$', '', base), re.sub(r'\$\w+$', '', base),
                 re.sub(r'_0(-gateway)?$', '', base), re.sub(r'(_\d+)?(-gateway)?$', '', base)):
        if cand in names:
            return names[cand]
        for pre in ('n_Ingress.', 't_Ingress.', 'r_Egress.', 'x_Egress.'):
            if pre + cand in names:
                return names[pre + cand]
    if base.startswith(('n_Ingress', 't_Ingress')):
        return 'ingress'
    if base.startswith(('r_Egress', 'x_Egress')):
        return 'egress'
    return '?'


def pipe_metrics(out, pipe):
    ctx = json.loads((out / pipe / 'context.json').read_text())
    names = {}
    for t in ctx['tables']:
        names[t['name']] = t.get('direction')
    res = {g: dict(stages=set(), **{c: 0 for c in COLS}, salu=0, registers=[], hash_dist=0, unknown=[])
           for g in ('ingress', 'egress')}
    for t in ctx['tables']:
        g = t.get('direction')
        if g in res:
            res[g]['stages'].update(n for n in stage_numbers(t) if type(n) is int and n >= 0)
            if t.get('table_type') == 'stateful':
                res[g]['registers'].append(t['name'])
    log = (out / pipe / 'logs/mau.resources.log').read_text().split('Allocated Resource Usage')[1]
    for line in log.splitlines():
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) < 13 or not cells[1].lstrip('-').isdigit():
            continue
        name, vals = cells[0], [int(x) for x in cells[2:10]]
        g = gress_of(name, names)
        if g not in res:
            res['ingress']['unknown'].append(name)
            continue
        for c, v in zip(COLS, vals):
            res[g][c] += v
    raw = json.loads((out / pipe / 'logs/resources.json').read_text())['resources']
    for st in raw['mau']['mau_stages']:
        for m in st['meter_alus']['meters']:
            gs = {gress_of(u['used_by'], names) for u in m['usages']}
            for g in gs & set(res):
                res[g]['salu'] += 1
        for u in st['hash_distribution_units']['units']:
            gs = {gress_of(x['used_by'], names) for x in u['usages']}
            for g in gs & set(res):
                res[g]['hash_dist'] += 1
    phv = json.loads((out / pipe / 'logs/phv.json').read_text())
    for g in res:
        cs = [c for c in phv['containers'] if c['gress'] == g and c.get('slices')]
        res[g]['phv_containers'] = len(cs)
        res[g]['phv_bits'] = sum(c['bit_width'] for c in cs)
        used = 0
        for c in cs:
            bits = set()
            for s in c['slices']:
                lo = s.get('phv_lsb', s.get('container_lsb', 0)); hi = s.get('phv_msb', s.get('container_msb', lo))
                bits.update(range(lo, hi + 1))
            used += len(bits)
        res[g]['phv_used_bits'] = used
    dep = out / pipe / 'logs/table_dependency_summary.log'
    lines = dep.read_text().splitlines() if dep.is_file() else []
    for g in res:
        chains = [l.strip() for l in lines if ' -> ' in l and l.rstrip().endswith('(' + g + ')')]
        res[g]['chain'] = chains[0] if chains else ''
        st = sorted(res[g]['stages'])
        res[g]['stages'] = st
        res[g]['occupied'] = len(st)
    return res


def summarize(out):
    out = Path(out)
    result = {}
    for pipe in ('p0', 'p1'):
        for g, r in pipe_metrics(out, pipe).items():
            result[ROLE[(pipe, g)]] = r
    return result


if __name__ == '__main__':
    r = summarize(sys.argv[1])
    if '--json' in sys.argv:
        print(json.dumps(r, indent=1))
    else:
        hdr = 'role occ maxst phvC phvBits used xbar hbit hdist gw sram tcam map adb vliw salu regs'
        print(hdr)
        for k in 'NETX':
            v = r[k]
            print(k, v['occupied'], (v['stages'][-1] if v['stages'] else '-'), v['phv_containers'], v['phv_bits'],
                  v['phv_used_bits'], v['xbar'], v['hash_bits'], v['hash_dist'], v['gateways'], v['rams'],
                  v['tcams'], v['map_rams'], v['adb'], v['vliw'], v['salu'], len(v['registers']),
                  ('UNK:' + ','.join(v['unknown'])) if v['unknown'] else '')
        for k in 'NETX':
            print(k, 'chain:', r[k]['chain'])

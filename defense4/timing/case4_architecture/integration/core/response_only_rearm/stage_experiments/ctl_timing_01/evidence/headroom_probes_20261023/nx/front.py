#!/usr/bin/env python3
"""Stages 0-3 of pipe 0: per-table xbar bytes/hash bits/hash-dist units, per-stage totals, guard stage.  usage: front.py BUILD"""
import json, sys, collections, re
from pathlib import Path
b = sys.argv[1]; maxs = int(sys.argv[2]) if len(sys.argv) > 2 else 3
L = Path(f'/home/philip/Projects/DNP3/.scratch_p4/build_{b}/out/p0/logs')
raw = json.loads((L / 'resources.json').read_text())['resources']['mau']
hd = collections.defaultdict(list)
for st in raw['mau_stages']:
    s = st['stage_number']
    for u in st['hash_distribution_units']['units']:
        for x in u['usages']:
            hd[s].append(x['used_by'])
log = (L / 'mau.resources.log').read_text().split('Allocated Resource Usage')[1]
rows = collections.defaultdict(list)
for line in log.splitlines():
    c = [x.strip() for x in line.strip().strip('|').split('|')]
    if len(c) >= 13 and c[1].lstrip('-').isdigit():
        s = int(c[1])
        if 0 <= s <= maxs and (int(c[2]) or int(c[3])):
            rows[s].append((c[0], int(c[2]), int(c[3])))
    if len(c) >= 13 and c[0] == 'Totals': pass
for s in range(0, maxs + 1):
    xb = sum(r[1] for r in rows[s]); hb = sum(r[2] for r in rows[s])
    units = sorted(set(hd[s]))
    print(f'stage {s}: xbar {xb}B hashbits {hb} hashdist {len(hd[s])} units used_by {units}')
    for r in sorted(rows[s], key=lambda r: -r[1]):
        print(f'   {r[0]:55s} xbar {r[1]:3d} hash {r[2]:3d}')
ts = (L / 'table_summary.log').read_text().split('Table allocation done')[-1]
for line in ts.splitlines():
    if 'n_Ingress.guard ' in line or line.strip().endswith('n_Ingress.guard  |') or 'n_Ingress.guard' in line and 'guard_' not in line:
        print('GUARD', line.strip())

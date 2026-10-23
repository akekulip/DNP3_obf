#!/usr/bin/env python3
"""Per-stage table list + resources for p0 ingress (N) and p0 egress (E).  usage: stages.py OUTDIR [pipe] [--tables]"""
import json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from metrics import gress_of, COLS
out = Path(sys.argv[1]); pipe = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('-') else 'p0'
ctx = json.loads((out/pipe/'context.json').read_text())
names = {t['name']: t.get('direction') for t in ctx['tables']}
log = (out/pipe/'logs/mau.resources.log').read_text().split('Allocated Resource Usage')[1]
S = {}
for line in log.splitlines():
    cells = [c.strip() for c in line.strip().strip('|').split('|')]
    if len(cells) < 13 or not cells[1].lstrip('-').isdigit(): continue
    st = int(cells[1]);
    if st < 0: continue
    g = gress_of(cells[0], names)
    d = S.setdefault((g, st), dict(tables=[], **{c: 0 for c in COLS}, salu=0, hd=0))
    if not cells[0].endswith('-gateway') or True: d['tables'].append(cells[0])
    for c, v in zip(COLS, [int(x) for x in cells[2:10]]): d[c] += v
raw = json.loads((out/pipe/'logs/resources.json').read_text())['resources']
for i, st in enumerate(raw['mau']['mau_stages']):
    sn = st.get('stage_number', i)
    for m in st['meter_alus']['meters']:
        for g in {gress_of(u['used_by'], names) for u in m['usages']}:
            S.setdefault((g, sn), dict(tables=[], **{c: 0 for c in COLS}, salu=0, hd=0))['salu'] += 1
    for u in st['hash_distribution_units']['units']:
        for g in {gress_of(x['used_by'], names) for x in u['usages']}:
            S.setdefault((g, sn), dict(tables=[], **{c: 0 for c in COLS}, salu=0, hd=0))['hd'] += 1
for g in ('ingress', 'egress'):
    print('==', pipe, g)
    print('st  xbar hbit gw sram tcam map adb vliw salu hd ntab')
    for st in range(12):
        d = S.get((g, st))
        if not d: print(f'{st:2d}  -'); continue
        print(f"{st:2d} {d['xbar']:5d} {d['hash_bits']:4d} {d['gateways']:2d} {d['rams']:4d} {d['tcams']:4d} {d['map_rams']:3d} {d['adb']:3d} {d['vliw']:4d} {d['salu']:4d} {d['hd']:2d} {len([t for t in d['tables'] if not t.endswith('-gateway')]):3d}")
        if '--tables' in sys.argv: print('     ', ' '.join(t for t in d['tables'] if not t.endswith('-gateway')))

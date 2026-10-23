#!/usr/bin/env python3
"""Per-stage SHARED resource use on one pipe, split N(ingress)/E(egress).  usage: stage_util.py OUTDIR [pipe]"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from metrics import gress_of
out = Path(sys.argv[1]); pipe = sys.argv[2] if len(sys.argv) > 2 else 'p0'
ctx = json.loads((out/pipe/'context.json').read_text()); names = {t['name']: t.get('direction') for t in ctx['tables']}
R = json.loads((out/pipe/'logs/resources.json').read_text())['resources']['mau']['mau_stages']
G = lambda n: {'ingress': 'i', 'egress': 'e'}.get(gress_of(n, names), '?')
def cnt(items, key='used_by'):
    c = {'i': 0, 'e': 0, '?': 0}
    for it in items:
        gs = {G(u[key]) for u in it.get('usages', [])} if 'usages' in it else {G(it[key])}
        for g in gs: c[g] += 1
    return c
print('st | ltab/16 i e | xbarEx/128 i e | xbarTern/66 i e | gw/16 | sram/80 i e | tcam/24 i e | map/48 | salu/4 i e | hdist/6 | exmSB/8 | tindB/8 | vliw/32 i e')
for st in R:
    s = st['stage_number']
    lt = cnt(st['logical_tables']['ids'], 'table_name')
    xe = {'i': 0, 'e': 0, '?': 0}; xt = {'i': 0, 'e': 0, '?': 0}
    for b in st['xbar_bytes']['bytes']:
        gs = {G(u['used_by']) for u in b['usages']}
        for g in gs: (xe if b['byte_type'] == 'exact' else xt)[g] += 1
    gw = cnt(st['gateways']['gateways']); sr = cnt(st['rams']['srams']); tc = cnt(st['tcams']['tcams'])
    mr = cnt(st['map_rams']['maprams']); sa = cnt(st['meter_alus']['meters']); hd = cnt(st['hash_distribution_units']['units'])
    eb = cnt(st['exm_search_buses']['ids']); tb = cnt(st['tind_result_buses']['ids'])
    vi = {'i': 0, 'e': 0}
    for ins in st['vliw']['instructions']:
        for cu in ins.get('color_usages', []):
            vi[cu['gress'][0]] = vi.get(cu['gress'][0], 0) + 1
    f = lambda c: f"{c['i']:3d}{c['e']:3d}"
    t = lambda c: f"{c['i']+c['e']+c['?']:3d}"
    print(f"{s:2d} | {t(lt)}={f(lt)} | {t(xe)}={f(xe)} | {t(xt)}={f(xt)} | {t(gw)} | {t(sr)}={f(sr)} | {t(tc)}={f(tc)} | {t(mr)} | {t(sa)}={f(sa)} | {t(hd)} | {t(eb)} | {t(tb)} | {vi.get('i',0):3d}{vi.get('e',0):3d}")

#!/usr/bin/env python3
"""cont.py OUTDIR gress field...  -> container(s) and co-residents"""
import json, sys
p = json.load(open(sys.argv[1] + '/p0/logs/phv.json')); g = sys.argv[2]
for f in sys.argv[3:]:
    for c in p['containers']:
        if c['gress'] != g: continue
        ns = [s['field_slice']['field_name'] for s in c.get('slices', [])]
        if f in ns:
            print(f, '->', c['phv_number'], c['bit_width'], sorted(set(ns)))

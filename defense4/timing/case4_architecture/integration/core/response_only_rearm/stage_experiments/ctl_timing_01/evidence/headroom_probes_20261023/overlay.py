#!/usr/bin/env python3
"""List E (p0 egress) containers holding never-valid-in-E checksum-list headers together with other live fields."""
import json, sys
ABSENT = tuple('hdr.'+h+'.' for h in 'dl rh robj p03 p45 c0 p69 p1012 p1321 c1 p22 c2 cb0 ctn cd2 cs2 cd3 cs3'.split())
p = json.load(open(sys.argv[1] + '/p0/logs/phv.json'))
bad = 0
for c in p['containers']:
    if c['gress'] != 'egress':
        continue
    names = [s['field_slice']['field_name'] for s in c.get('slices', [])]
    a = [n for n in names if n.startswith(tuple('egress::' + x for x in ABSENT)) or n.startswith(ABSENT)]
    if a:
        others = [n for n in names if n not in a and '$valid' not in n]
        print(c['phv_number'], c['bit_width'], a, 'SHARED_WITH' if others else 'clean', others)
        bad += bool(others)
print('shared containers:', bad)

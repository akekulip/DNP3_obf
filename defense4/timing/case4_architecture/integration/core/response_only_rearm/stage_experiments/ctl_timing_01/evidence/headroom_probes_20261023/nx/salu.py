#!/usr/bin/env python3
"""SALUs per stage 4-11 for N (p0 ingress) and E (p0 egress) + E's tables >= 6.  usage: salu.py BUILD..."""
import json, sys, collections
for b in sys.argv[1:]:
    ctx = json.load(open(f'/home/philip/Projects/DNP3/.scratch_p4/build_{b}/out/p0/context.json'))
    per = collections.defaultdict(list)
    for t in ctx['tables']:
        if t.get('table_type') == 'stateful':
            for s in sorted({x['stage_number'] for x in t.get('stage_tables', [])}):
                per[s].append(('N:' if t['direction'] == 'ingress' else 'E:') + t['name'].split('.')[-1])
    print(b, ' | '.join(f"{s}:{len(per[s])}[{','.join(per[s])}]" for s in range(4, 12) if per[s]))

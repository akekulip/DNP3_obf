"""Group a tofino-model log into ingress/egress packet records (tables, actions, global timestamp, frame bytes); dump records whose frame contains every given hex pattern.
usage: trace_model_log.py LOG OUT.json HEXPATTERN [HEXPATTERN ...]   (all patterns must occur in the frame)"""
import json, re, sys
LINE = re.compile(r'^:(\d\d-\d\d \d\d:\d\d:\d\d\.\d+):\s+:(0x[0-9a-f]+|-):(0x[0-9a-f]+|-):<([0-9]),([0-9-]),([-0-9]+)>:(.*)$')
HEX = re.compile(r'^(?:[0-9a-f]{2} )+$')
recs, order = {}, []
cur_dump = {}
for raw in open(sys.argv[1], errors='replace'):
    m = LINE.match(raw.strip('\n').replace('\t', ' ', 1) if False else raw.rstrip('\n').lstrip())
    if not m:
        continue
    wall, ig, eg, _pipe, _x, stage, text = m.groups()
    key = ('I', ig) if ig != '-' else (('E', eg) if eg != '-' else None)
    if key is None:
        continue
    text = text.strip()
    r = recs.get(key)
    if text.startswith('========== Ingress Pkt from port') or text.startswith('========== Egress Pkt from TM'):
        r = {'kind': key[0], 'id': key[1], 'wall': wall, 'head': text, 'frame': '', 'events': [], 'tstamp': None}
        recs[key] = r; order.append(r); cur_dump[key] = 'want'
        continue
    if r is None:
        continue
    if text == 'Packet :':
        continue
    if HEX.match(text + ' ') and cur_dump.get(key) == 'want':
        r['frame'] += text.replace(' ', '')
        continue
    if r['frame']:
        cur_dump[key] = 'done'
    if 'global_tstamp[31:0]' in text and r['tstamp'] is None:
        mm = re.search(r'value (0x[0-9a-f]+)', text); r['tstamp'] = mm.group(1) if mm else None
    if 'global_tstamp[47:32]' in text:
        mm = re.search(r'value\s+(0x[0-9a-f]+)', text); r['tstamp_hi'] = mm.group(1) if mm else None
    if re.search(r'Table \S+ is (hit|miss)|Execute (Default )?Action|drop_ctl|egress_port|ucast_egress_port|Mirror|Deparser|resubmit|bypass_egress|Egress Pkt|========== Packet to input', text):
        r['events'].append('%s %s' % (stage, text[:160]))
pats = [p.lower() for p in sys.argv[3:]]
hits = [r for r in order if all(p in r['frame'] for p in pats)]
json.dump(hits, open(sys.argv[2], 'w'), indent=1)
print(len(order), 'records;', len(hits), 'matching')

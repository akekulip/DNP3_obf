"""T's clock (global_tstamp[39:8], 256 ns units) of the ingress packets whose header lines have the given wall times."""
import re, sys
log, walls = sys.argv[1], sys.argv[2:]
want = set(walls); ids = {}; out = {}
for line in open(log, errors='replace'):
    m = re.match(r'^:10-1[67] ([0-9:.]+):\s+:(0x[0-9a-f]+|-):', line)
    if not m:
        continue
    wall, pid = m.groups()
    if 'Ingress Pkt from port' in line and wall in want:
        ids[pid] = wall
    elif pid in ids and ids[pid] not in out and 'global_tstamp[39:8]' in line and 'to value' in line:
        out[ids[pid]] = int(re.search(r'to value\s+(0x[0-9a-f]+)', line).group(1), 16) * 256
for w in walls:
    print(w, out.get(w))

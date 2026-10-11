"""Independent wire check for the active-padding run (scapy; does not reuse the mapper's code).
Usage: pad_wire.py OUT.pcap IN.pcap   (OUT = -Q out on the parent: sent by endpoints; IN = -Q in: returned by the switch)
For every DNP3-bearing segment: side, direction, payload length, every DNP3 block CRC, IP and TCP checksum recomputed.
Pairs each returned segment with its sent original by (direction, order) and reports seq/ack translation."""
import sys, json
from scapy.all import rdpcap, IP, TCP
M, O = '192.168.10.61', '192.168.10.62'
def crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return (~c) & 0xFFFF
def dnp3_ok(p):
    if len(p) < 10 or p[0:2] != b'\x05\x64': return False, 'no start'
    if crc(p[0:8]) != int.from_bytes(p[8:10], 'little'): return False, 'header crc'
    i, n = 10, p[2] - 5
    while n > 0:
        k = min(16, n)
        blk, c = p[i:i + k], p[i + k:i + k + 2]
        if len(c) < 2 or crc(blk) != int.from_bytes(c, 'little'): return False, 'block crc at %d' % i
        i += k + 2; n -= k
    return i == len(p), 'trailing' if i != len(p) else 'ok'
def cks_ok(pkt):
    ip, tcp = pkt[IP], pkt[TCP]
    a, b = ip.chksum, tcp.chksum
    re = IP(bytes(ip)); del re.chksum; del re[TCP].chksum; re = IP(bytes(re))
    return re.chksum == a and re[TCP].chksum == b
def segs(path):
    out = []
    for pkt in rdpcap(path):
        if IP not in pkt or TCP not in pkt: continue
        ip, t = pkt[IP], pkt[TCP]
        d = 'M->O' if ip.src == M else 'O->M'
        pl = bytes(t)[t.dataofs * 4: ip.len - ip.ihl * 4]   # IP length, not frame: excludes Ethernet min-frame padding
        out.append({'t': float(pkt.time), 'dir': d, 'flags': str(t.flags), 'seq': t.seq, 'ack': t.ack, 'len': len(pl),
                    'pl': pl, 'cks': cks_ok(pkt), 'dnp3': dnp3_ok(pl) if pl else None})
    return out
sent, ret = segs(sys.argv[1]), segs(sys.argv[2])
rep = {'sent': len(sent), 'returned': len(ret), 'checksum_bad_returned': sum(not s['cks'] for s in ret),
       'checksum_bad_sent': sum(not s['cks'] for s in sent)}
for name, L in (('sent', sent), ('returned', ret)):
    for d in ('M->O', 'O->M'):
        data = [s for s in L if s['dir'] == d and s['len']]
        rep['%s %s payload lengths' % (name, d)] = sorted(set(s['len'] for s in data))
        rep['%s %s count' % (name, d)] = len(data)
        rep['%s %s dnp3 crc bad' % (name, d)] = [s['dnp3'] for s in data if not s['dnp3'][0]]
# pair returned with sent per direction in order (the switch reflects every frame once)
pairs = {}
for d in ('M->O', 'O->M'):
    a = [s for s in sent if s['dir'] == d]; b = [s for s in ret if s['dir'] == d]
    pairs[d] = list(zip(a, b))
    rep['%s sent vs returned frames' % d] = (len(a), len(b))
    rep['%s flags sequence identical' % d] = [x['flags'] for x in a] == [y['flags'] for y in b]
    rep['%s payload identical count' % d] = sum(x['pl'] == y['pl'] for x, y in pairs[d])
    rep['%s seq delta set' % d] = sorted(set((y['seq'] - x['seq']) & 0xffffffff for x, y in pairs[d]))
    rep['%s ack delta set' % d] = sorted(set((y['ack'] - x['ack']) & 0xffffffff for x, y in pairs[d] if 'A' in x['flags']))
# the 58-byte images: what the master received vs what the outstation sent
ex = [(x['len'], y['len'], x['pl'][10:13].hex(), y['pl'][10:13].hex()) for x, y in pairs['O->M'] if x['len']]
rep['O->M (outstation sent len, master received len, sent tp/app/func, recv tp/app/func)'] = ex
# switch latency per reflected frame (same NIC clock for both captures)
lat = [ (y['t'] - x['t']) * 1e6 for d in pairs for x, y in pairs[d]]
rep['reflect latency us min/median/max'] = (round(min(lat), 1), round(sorted(lat)[len(lat) // 2], 1), round(max(lat), 1))
print(json.dumps(rep, indent=1, default=str))

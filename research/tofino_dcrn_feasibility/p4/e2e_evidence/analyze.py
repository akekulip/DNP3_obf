import sys
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP

MASTER, OUT, PORT = "10.0.1.10", "10.0.2.10", 20000

def analyze(path, label):
    pkts = rdpcap(path)
    # group response payload frames (from outstation) by tcp.seq -> list of timestamps
    resp = defaultdict(list)   # seq -> [ts]
    reqs = []                  # (ts, seq, len) master READ requests (payload>0)
    payload_by_seq = {}
    for p in pkts:
        if IP not in p or TCP not in p: continue
        ip, tcp = p[IP], p[TCP]
        plen = len(tcp.payload)
        if plen == 0: continue
        if ip.src == OUT and tcp.sport == PORT:
            resp[tcp.seq].append(float(p.time))
            payload_by_seq.setdefault(tcp.seq, bytes(tcp.payload))
        elif ip.src == MASTER and tcp.dport == PORT:
            reqs.append((float(p.time), tcp.seq, plen))
    # per-seq hold = max(ts)-min(ts) (first outstation-TX vs held return-to-master)
    holds = []
    for seq, ts in resp.items():
        spread_ms = (max(ts) - min(ts)) * 1000.0
        holds.append((min(ts), seq, len(payload_by_seq[seq]), spread_ms, len(ts)))
    holds.sort()
    print("=== %s ===" % label)
    print("  unique response segments: %d ; request(payload) frames: %d" % (len(resp), len(reqs)))
    # split: 'held' (spread large) vs 'passthrough' (spread ~0)
    big = [h[3] for h in holds if h[3] > 10]
    small = [h[3] for h in holds if h[3] <= 10]
    def stats(x):
        if not x: return "n=0"
        x=sorted(x); n=len(x)
        return "n=%d min=%.2f med=%.2f max=%.2f mean=%.2f ms" % (n, x[0], x[n//2], x[-1], sum(x)/n)
    print("  response hold-spread >10ms  : %s" % stats(big))
    print("  response hold-spread <=10ms : %s" % stats(small))
    print("  sample per-segment [start_t, seq, paylen, spread_ms, ncopies]:")
    for h in holds[:14]:
        print("     t=%.4f seq=%d len=%d spread=%.2fms copies=%d" % h)
    return payload_by_seq

p0 = analyze(sys.argv[1], "P0_NATIVE")
print()
p1 = analyze(sys.argv[2], "P1_FIXED")
print()
# byte-identity: same response payloads present in both (by content)
set0 = set(p0.values()); set1 = set(p1.values())
common = set0 & set1
print("=== BYTE-IDENTITY (response payloads) ===")
print("  distinct payloads P0=%d P1=%d ; identical-content shared=%d" % (len(set0), len(set1), len(common)))
# the large DNP3 read responses (len>100) must be byte-identical across P0/P1
big0 = {v for v in set0 if len(v) > 100}
big1 = {v for v in set1 if len(v) > 100}
print("  large (>100B) response payloads: P0=%d P1=%d shared-identical=%d" % (len(big0), len(big1), len(big0 & big1)))

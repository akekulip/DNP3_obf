import sys
from collections import defaultdict
from scapy.all import rdpcap, wrpcap, IP, TCP
def key(p):
    ip, tcp = p[IP], p[TCP]
    return (ip.src, ip.dst, tcp.sport, tcp.dport, tcp.seq, tcp.ack, len(tcp.payload), bytes(tcp.payload)[:8])
for path in sys.argv[1:]:
    pkts = [p for p in rdpcap(path) if IP in p and TCP in p]
    groups = defaultdict(list)
    for p in pkts: groups[key(p)].append(p)
    before, after = [], []
    for k, g in groups.items():
        g.sort(key=lambda x: float(x.time))
        before.append(g[0]); after.append(g[-1])   # first = pre-hold emit, last = post-hold arrival
    before.sort(key=lambda x: float(x.time)); after.sort(key=lambda x: float(x.time))
    base = path.rsplit("_wire",1)[0]
    wrpcap(base + "_before_hold.pcap", before)
    wrpcap(base + "_after_hold.pcap", after)
    print("%s: before=%d after=%d frames" % (base.split("/")[-1], len(before), len(after)))

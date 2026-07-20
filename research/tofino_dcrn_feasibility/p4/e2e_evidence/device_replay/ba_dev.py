import sys
from scapy.all import rdpcap, IP, TCP
MASTER, OUT, PORT = "10.0.1.10", "10.0.2.10", 20000
def gaps(path, label):
    ev = []
    for p in rdpcap(path):
        if IP not in p or TCP not in p: continue
        ip, tcp = p[IP], p[TCP]
        if len(tcp.payload) == 0: continue
        t = float(p.time)
        if ip.src == MASTER and tcp.dport == PORT: ev.append((t, 'req'))
        elif ip.src == OUT and tcp.sport == PORT and len(tcp.payload) >= 30: ev.append((t, 'resp'))
    ev.sort(); g = []; lr = None
    for t, k in ev:
        if k == 'req': lr = t
        elif k == 'resp' and lr is not None: g.append((t-lr)*1000.0); lr = None
    g = sorted(x for x in g if 0 <= x < 100000)
    if not g: print("  %-11s no pairs" % label); return
    n=len(g); print("  %-11s n=%d  median=%.2f ms  (min=%.2f max=%.2f)" % (label, n, g[n//2], g[0], g[-1]))
for dev in ("sel751","ab1400","ion7550"):
    print(dev + ":")
    gaps("%s/%s_before_hold.pcap" % (sys.argv[1], dev), "BEFORE hold")
    gaps("%s/%s_after_hold.pcap"  % (sys.argv[1], dev), "AFTER hold")

import sys
from scapy.all import rdpcap, IP, TCP
MASTER, OUT, PORT = "10.0.1.10", "10.0.2.10", 20000
def gaps(path, label):
    pkts = rdpcap(path)
    ev = []  # (t, kind) kind='req' or 'resp' (first big response only)
    for p in pkts:
        if IP not in p or TCP not in p: continue
        ip, tcp = p[IP], p[TCP]
        if len(tcp.payload) == 0: continue
        t = float(p.time)
        if ip.src == MASTER and tcp.dport == PORT and len(tcp.payload) < 40:
            ev.append((t, 'req'))
        elif ip.src == OUT and tcp.sport == PORT and len(tcp.payload) >= 100:
            ev.append((t, 'resp'))
    ev.sort()
    # pair each req with the next resp
    g = []
    last_req = None
    for t, k in ev:
        if k == 'req': last_req = t
        elif k == 'resp' and last_req is not None:
            g.append((t - last_req) * 1000.0); last_req = None
    g = [x for x in g if x >= 0]
    if not g:
        print("%-14s no req/resp pairs (frames=%d)" % (label, len(pkts))); return
    g.sort(); n = len(g)
    print("%-14s req->resp gap: n=%d  min=%.2f  median=%.2f  max=%.2f  mean=%.2f ms"
          % (label, n, g[0], g[n//2], g[-1], sum(g)/n))
    print("   samples: " + ", ".join("%.1f" % x for x in g[:8]) + " ms")
gaps(sys.argv[1], "BEFORE hold")
gaps(sys.argv[2], "AFTER hold")

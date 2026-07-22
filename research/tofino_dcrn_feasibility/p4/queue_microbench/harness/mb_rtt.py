import sys
from scapy.all import PcapReader
MAGIC=b"MBQ1"
# group frames by seq; each real should appear exactly twice (tx out, rx return, same clock)
by={}
with PcapReader(sys.argv[1]) as pr:
    for pkt in pr:
        raw=bytes(pkt); ts=float(pkt.time); w=len(raw)
        i=raw.find(MAGIC)
        if i<0 or i+8>len(raw): continue
        seq=int.from_bytes(raw[i+4:i+8],"big")
        by.setdefault(seq,[]).append((ts,w))
deltas=[]; sizes=set()
for seq,fr in by.items():
    if len(fr)!=2: continue          # require exactly 2 (clean, no overlap/residual)
    fr.sort()
    deltas.append((fr[1][0]-fr[0][0])*1000.0)  # ms, same clock
    sizes.add((fr[0][1],fr[1][1]))
deltas.sort()
def pct(x,p):
    if not x: return float('nan')
    k=(len(x)-1)*p/100.0; lo=int(k); hi=min(lo+1,len(x)-1); return x[lo]+(x[hi]-x[lo])*(k-lo)
tot=len(by); clean=len(deltas); dirty=sum(1 for s,f in by.items() if len(f)!=2)
if deltas:
    m=sum(deltas)/len(deltas); std=(sum((d-m)**2 for d in deltas)/len(deltas))**0.5
    print("n_clean=%d/%d dirty=%d sizes=%s  delta_ms p50=%.3f p90=%.3f p99=%.3f min=%.3f max=%.3f mean=%.3f std=%.3f"
          %(clean,tot,dirty,sorted(sizes),pct(deltas,50),pct(deltas,90),pct(deltas,99),min(deltas),max(deltas),m,std))
else:
    print("n_clean=0/%d dirty=%d (NO clean 2-frame pairs)"%(tot,dirty))

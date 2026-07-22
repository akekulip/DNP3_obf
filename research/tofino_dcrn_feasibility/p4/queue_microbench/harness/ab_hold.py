import sys
from scapy.all import PcapReader
MAGIC=b"MBQ1"; by={}
with PcapReader(sys.argv[1]) as pr:
    for pkt in pr:
        raw=bytes(pkt); ts=float(pkt.time); w=len(raw)
        i=raw.find(MAGIC)
        if i<0: continue
        seq=int.from_bytes(raw[i+4:i+8],"big"); by.setdefault(seq,[]).append((ts,w))
holds=[]; seqs=[]
for s,fr in by.items():
    if len(fr)!=2: continue
    fr.sort(); holds.append((fr[1][0]-fr[0][0])*1000.0); seqs.append(s)
holds.sort()
def pct(x,p):
    if not x: return float('nan')
    k=(len(x)-1)*p/100.0; lo=int(k); hi=min(lo+1,len(x)-1); return x[lo]+(x[hi]-x[lo])*(k-lo)
import statistics as st
print("n=%d dup=%d missing=%d p50=%.4f p95=%.4f p99=%.4f mean=%.4f std=%.4f min=%.4f max=%.4f"%(
  len(holds), len(seqs)-len(set(seqs)), (max(seqs)-min(seqs)+1-len(set(seqs))) if seqs else -1,
  pct(holds,50),pct(holds,95),pct(holds,99), st.mean(holds) if holds else 0,
  st.pstdev(holds) if len(holds)>1 else 0, min(holds) if holds else 0, max(holds) if holds else 0))

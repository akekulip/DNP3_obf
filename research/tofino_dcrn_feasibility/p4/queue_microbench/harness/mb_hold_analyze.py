import sys
from scapy.all import PcapReader, Ether
MAGIC=b"MBQ1"
by_seq={}   # seq -> {"tx":ts(64B out), "rx":ts(128B returned)}
sizes={}
with PcapReader(sys.argv[1]) as pr:
    for pkt in pr:
        raw=bytes(pkt); wire=len(raw); ts=float(pkt.time)
        i=raw.find(MAGIC)
        if i<0 or i+8>len(raw): continue
        seq=int.from_bytes(raw[i+4:i+8],"big")
        sizes[wire]=sizes.get(wire,0)+1
        d=by_seq.setdefault(seq,{})
        if wire<=64: d.setdefault("tx",ts)      # outbound original (64B)
        else:        d.setdefault("rx",ts)      # returned held+padded (128B)
holds=[]
for seq,d in sorted(by_seq.items()):
    if "tx" in d and "rx" in d:
        holds.append((d["rx"]-d["tx"])*1000.0)   # ms
holds.sort()
def pct(x,p):
    if not x: return float("nan")
    k=(len(x)-1)*p/100.0; lo=int(k); hi=min(lo+1,len(x)-1)
    return x[lo]+(x[hi]-x[lo])*(k-lo)
print("wire-size histogram:", dict(sorted(sizes.items())))
print("matched tx<->rx pairs: %d / %d seqs" % (len(holds), len(by_seq)))
if holds:
    print("HOLD ms  min=%.2f  p50=%.2f  p90=%.2f  p99=%.2f  max=%.2f  mean=%.2f  std=%.2f" % (
        min(holds), pct(holds,50), pct(holds,90), pct(holds,99), max(holds),
        sum(holds)/len(holds), (sum((h-sum(holds)/len(holds))**2 for h in holds)/len(holds))**0.5))
    print("all holds ms:", [round(h,1) for h in holds])

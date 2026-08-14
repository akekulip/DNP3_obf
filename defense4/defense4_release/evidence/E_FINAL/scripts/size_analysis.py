#!/usr/bin/env python3
"""Response segmentation: for each DNP3 app response (func 0x81), collect the relay->master
app-data segment sizes and classify single-49 vs [28,21]. Report escape (49B) count."""
import sys
from scapy.all import rdpcap, IP, TCP
M,R="192.168.10.1","192.168.10.7"
def fn(pl): return pl[12] if len(pl)>=13 and pl[0]==0x05 and pl[1]==0x64 else None
P=rdpcap(sys.argv[1]); label=sys.argv[2]
# walk: each response burst = contiguous R2M app-data packets ending at/around a 0x81
single49=split2821=other=escape49=0; vectors={}
i=0; evs=[(("M2R" if p[IP].src==M else "R2M"), fn(bytes(p[TCP].payload)), len(bytes(p[TCP].payload))) for p in P if IP in p and TCP in p]
# group consecutive R2M app-data (len in {21,28,49}) as one response
j=0
while j<len(evs):
    d,f,ln=evs[j]
    if d=="R2M" and (f==0x81 or ln in (21,28,49)) and ln>=21:
        seg=[]
        while j<len(evs) and evs[j][0]=="R2M" and (evs[j][1]==0x81 or evs[j][2] in (21,28,49)) and evs[j][2]>=21:
            seg.append(evs[j][2]); j+=1
        v=tuple(sorted(seg))
        vectors[v]=vectors.get(v,0)+1
        if seg==[49] or v==(49,): single49+=1; escape49+=1
        elif set(seg)<={21,28} and 21 in seg and 28 in seg: split2821+=1
        elif 49 in seg: escape49+=seg.count(49); other+=1
        else: other+=1
    else: j+=1
print("%s: responses: single[49]=%d  split[28,21]=%d  other=%d  | 49B-source-copy-escapes=%d"%(
    label,single49,split2821,other,escape49 if label!='native' else 0))
print("   vectors:", {str(k):v for k,v in sorted(vectors.items(),key=lambda x:-x[1])[:5]})

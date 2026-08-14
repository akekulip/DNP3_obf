#!/usr/bin/env python3
"""Per-OPERATE BOR timing from a master-facing pcap: T0, T_ack(=T0+A), T_echo(=T0+R)."""
import sys, statistics as st
from scapy.all import rdpcap, IP, TCP
M, R = "192.168.10.1", "192.168.10.7"
def fn(pl): return pl[12] if len(pl) >= 13 and pl[0] == 0x05 and pl[1] == 0x64 else None
def rows(pcap):
    P = rdpcap(pcap); evs = []
    for pk in P:
        if IP in pk and TCP in pk:
            evs.append((float(pk.time), "M2R" if pk[IP].src == M else "R2M",
                        fn(bytes(pk[TCP].payload)), len(bytes(pk[TCP].payload)), int(pk[TCP].flags)))
    out = []
    for i, (t, d, f, ln, fl) in enumerate(evs):
        if d == "M2R" and f == 0x04:
            t0 = t; ta = te = None; nop = 1
            for (tt, dd, ff, ll, ffl) in evs[i+1:]:
                if dd == "R2M" and (ffl & 0x10) and ta is None: ta = tt
                if dd == "R2M" and ff == 0x81 and te is None: te = tt
                if dd == "M2R" and ff == 0x04 and tt > t0: break
            if ta and te:
                out.append(((ta-t0)*1e3, (te-t0)*1e3, (te-ta)*1e3))
    return out
def s(x): return "med=%.2f mean=%.2f std=%.3f"%(st.median(x),st.mean(x),st.pstdev(x))
if __name__=="__main__":
    label=sys.argv[2] if len(sys.argv)>2 else ""
    r=rows(sys.argv[1]); A=[a for a,_,_ in r]; Rr=[b for _,b,_ in r]; D=[c for _,_,c in r]
    print("%s n_operate=%d | A(T_ack-T0): %s | R(T_echo-T0): %s | echo-ACK(R-A): %s"%(label,len(r),s(A),s(Rr),s(D)))
    # also emit CSV
    if len(sys.argv)>3:
        with open(sys.argv[3],"w") as f:
            f.write("Jpolicy,txn,A_ms,R_ms,echo_ack_ms\n")
            for k,(a,b,c) in enumerate(r): f.write("%s,%d,%.3f,%.3f,%.3f\n"%(label,k,a,b,c))

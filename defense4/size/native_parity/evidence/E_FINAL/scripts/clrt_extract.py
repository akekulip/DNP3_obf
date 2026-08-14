#!/usr/bin/env python3
"""Formby-style extractor: pcap -> per-transaction CSV.
Per DNP3 request (READ func1 / SELECT func3 / OPERATE func4): T_req, then the relay's first
R2M ACK (any ACK-bearing packet after the request = T_ack), then the DNP3 app response
(func 0x81 = T_resp). CLRT = T_resp - T_ack. Also req_len, response segment vector, cold flag.
Usage: clrt_extract.py <pcap> <class> <mode>  -> CSV on stdout (cold=1 marks first txn/conn)."""
import sys
from scapy.all import rdpcap, IP, TCP
MASTER, RELAY = "192.168.10.1", "192.168.10.7"
def dnpfunc(pl): return pl[12] if len(pl) >= 13 and pl[0] == 0x05 and pl[1] == 0x64 else None
def main():
    pcap, cls, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    P = rdpcap(pcap)
    evs = []
    for pk in P:
        if IP not in pk or TCP not in pk: continue
        ip = pk[IP]; pl = bytes(pk[TCP].payload)
        evs.append((float(pk.time), "M2R" if ip.src == MASTER else "R2M",
                    dnpfunc(pl), len(pl), int(pk[TCP].flags)))
    print("class,mode,txn,req_func,t_req,t_ack,t_resp,clrt_ms,req_len,resp_seg_vector,resp_total,cold")
    txn = 0; first_seen = True
    for i, (t, d, f, ln, fl) in enumerate(evs):
        if d == "M2R" and (fl & 0x02):   # a SYN => new connection => next request is cold
            first_seen = True
        if d == "M2R" and f in (1, 3, 4):
            t_req = t; t_ack = t_resp = None; segs = []
            for (tt, dd, ff, ll, ffl) in evs[i+1:]:
                if dd == "R2M" and (ffl & 0x10) and t_ack is None:   # first ACK-bearing R2M
                    t_ack = tt
                if dd == "R2M" and ff == 0x81 and t_resp is None:
                    t_resp = tt
                if dd == "R2M" and ll > 0 and ll <= 40 and t_resp is not None and ff is None:
                    segs.append(ll)
                if dd == "R2M" and ff == 0x81:
                    segs.insert(0, ll) if ll <= 40 else None
                if dd == "M2R" and ff in (1, 3, 4) and tt > t_req: break
            clrt = (t_resp - t_ack) * 1e3 if (t_ack and t_resp) else ""
            # response segment vector = the [.., ..] app-data segments (21/28/49)
            allseg = [s for s in segs if s in (21, 28, 49)]
            segv = "|".join(str(s) for s in allseg[:3])
            tot = sum(allseg) if allseg else ""
            cold = 1 if first_seen else 0; first_seen = False
            txn += 1
            print("%s,%s,%d,%d,%.6f,%s,%s,%s,%d,%s,%s,%d" % (
                cls, mode, txn, f, t_req,
                ("%.6f" % t_ack) if t_ack else "", ("%.6f" % t_resp) if t_resp else "",
                ("%.3f" % clrt) if clrt != "" else "", ln, segv, tot, cold))
if __name__ == "__main__": main()

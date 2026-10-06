#!/usr/bin/env python3
"""extract_clrt.py <pcap> — master-facing CLRT per DNP3 transaction.
Master=192.168.10.1, outstation=192.168.10.7:20000. For each request we pair the
outstation's transport-layer ACK and its application response; CLRT = t_resp - t_ack.
Classify by the request's DNP3 application function code (1=READ,3=SELECT,4=OPERATE)."""
import sys, statistics as st
from scapy.all import PcapReader, TCP, IP, Raw
MASTER, OUT = "192.168.10.1", "192.168.10.7"
FUNC = {1: "READ", 3: "SELECT", 4: "OPERATE"}

def app_func(payload):
    b = bytes(payload)
    if len(b) >= 13 and b[0] == 0x05 and b[1] == 0x64:
        return b[12]           # link hdr(10) + transport(10) app_ctrl(11) func(12)
    return None

def main(path):
    rows = []
    state = None   # (t_req, func)
    t_ack = None
    for pkt in PcapReader(path):
        if IP not in pkt or TCP not in pkt: continue
        ip, tcp = pkt[IP], pkt[TCP]
        ts = float(pkt.time)
        plen = len(tcp.payload) if Raw in pkt else 0
        m2r = ip.src == MASTER and ip.dst == OUT and tcp.dport == 20000
        r2m = ip.src == OUT and ip.dst == MASTER and tcp.sport == 20000
        if m2r and plen > 0:
            f = app_func(pkt[Raw].load) if Raw in pkt else None
            state = (ts, f); t_ack = None
        elif r2m and state is not None:
            if plen == 0 and t_ack is None:
                t_ack = ts
            elif plen > 0:
                if t_ack is not None:
                    rows.append((state[1], (ts - t_ack) * 1e3, (t_ack - state[0]) * 1e3))
                state = None; t_ack = None
    out = {}
    for f, clrt, ackd in rows:
        out.setdefault(FUNC.get(f, "F%s" % f), []).append((clrt, ackd))
    res = {}
    for k, v in out.items():
        c = sorted(x[0] for x in v); a = sorted(x[1] for x in v)
        res[k] = dict(n=len(c), clrt_med=round(st.median(c), 3),
                      clrt_sd=round(st.pstdev(c), 3) if len(c) > 1 else 0.0,
                      ack_med=round(st.median(a), 3))
    return res

if __name__ == "__main__":
    import json; print(json.dumps(main(sys.argv[1])))

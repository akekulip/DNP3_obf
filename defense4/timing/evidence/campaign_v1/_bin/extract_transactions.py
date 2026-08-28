#!/usr/bin/env python3
"""extract_transactions.py — tidy per-transaction CSV across all campaign_v1 sessions.
One row per DNP3 transaction, master-facing: request -> outstation ACK -> application response.
Features: clrt_ms (resp-ack), ack_ms (ack-req), rt_ms (resp-req)."""
import csv, glob, os, sys
from scapy.all import PcapReader, TCP, IP, Raw
MASTER, OUT = "192.168.10.1", "192.168.10.7"
FUNC = {1: "READ", 3: "SELECT", 4: "OPERATE"}

def app_func(b):
    if len(b) >= 13 and b[0] == 0x05 and b[1] == 0x64: return b[12]
    return None

def rows_for(path, session, block, arm):
    out = []
    state = None; t_ack = None
    for pkt in PcapReader(path):
        if IP not in pkt or TCP not in pkt: continue
        ip, tcp = pkt[IP], pkt[TCP]; ts = float(pkt.time)
        has = Raw in pkt; plen = len(tcp.payload) if has else 0
        m2r = ip.src == MASTER and ip.dst == OUT and tcp.dport == 20000
        r2m = ip.src == OUT and ip.dst == MASTER and tcp.sport == 20000
        if m2r and plen > 0:
            state = (ts, app_func(bytes(pkt[Raw].load))); t_ack = None
        elif r2m and state is not None:
            if plen == 0 and t_ack is None:
                t_ack = ts
            elif plen > 0:
                if t_ack is not None:
                    t_req, f = state
                    out.append(dict(session=session, block=block, arm=arm,
                                    txn_class=FUNC.get(f, "F%s" % f),
                                    clrt_ms=(ts - t_ack) * 1e3,
                                    ack_ms=(t_ack - t_req) * 1e3,
                                    rt_ms=(ts - t_req) * 1e3))
                state = None; t_ack = None
    return out

def main(root, dest):
    fields = ["session", "block", "arm", "txn_class", "clrt_ms", "ack_ms", "rt_ms"]
    n = 0
    with open(dest, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader()
        for pc in sorted(glob.glob(os.path.join(root, "s[0-9][0-9]", "raw_pcaps", "*.pcap"))):
            base = os.path.basename(pc)[:-5]          # sNN_bK_arm
            session, block, arm = base.split("_", 2)
            for r in rows_for(pc, session, block, arm):
                w.writerow({k: (round(r[k], 6) if k.endswith("_ms") else r[k]) for k in fields}); n += 1
            print("%s %d" % (base, n), flush=True)
    print("TOTAL %d" % n)

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

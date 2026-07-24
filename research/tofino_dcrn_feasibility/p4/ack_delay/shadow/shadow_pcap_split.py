#!/usr/bin/env python3
"""
shadow_pcap_split.py — split the committed physical-relay pcap into the two B1 injection halves,
preserving capture order. Runs OFFLINE on the dev host (scapy present); output is classic pcap.

  dp8_inject.pcap = every frame with tcp.dst_port == 20000  (master->outstation; dir 0 on dp8:
                    the 300 DNP3 READs + master pure-ACKs + SYN/handshake)
  dp9_inject.pcap = every frame with tcp.src_port == 20000  (outstation->master; dir 1 on dp9:
                    the 300 DNP3 responses + CLRT pure-ACKs + SYN-ACK/FIN)

Injecting each half from the physically correct port reproduces the real inline directions, so
the silicon P4's physical-direction gate (DNP3_READ needs dir==0, DNP3_RESP needs dir==1) is
exercised exactly as in a live deployment (see GATE1_REPLAY_TOPOLOGY_RECONCILIATION.md §0').
"""
import argparse, os
from scapy.all import PcapReader, wrpcap, IP, TCP


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--dnp3-port", type=int, default=20000)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    dp8, dp9, other = [], [], []
    for p in PcapReader(args.pcap):
        if IP not in p or TCP not in p:
            other.append(p); continue
        if int(p[TCP].dport) == args.dnp3_port:
            dp8.append(p)
        elif int(p[TCP].sport) == args.dnp3_port:
            dp9.append(p)
        else:
            other.append(p)

    dp8_path = os.path.join(args.outdir, "dp8_inject.pcap")
    dp9_path = os.path.join(args.outdir, "dp9_inject.pcap")
    wrpcap(dp8_path, dp8)
    wrpcap(dp9_path, dp9)
    print("dp8_inject (dst==%d, -> Vision/dp8, dir 0): %d frames  %s" % (args.dnp3_port, len(dp8), dp8_path))
    print("dp9_inject (src==%d, -> Hulk/dp9,  dir 1): %d frames  %s" % (args.dnp3_port, len(dp9), dp9_path))
    print("neither (not injected): %d frames" % len(other))


if __name__ == "__main__":
    main()

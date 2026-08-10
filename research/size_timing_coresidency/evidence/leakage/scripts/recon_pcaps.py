"""Reconnaissance over the six device captures.

Prints, per pcap: packet count, TCP flows, endpoints, DNP3 port usage, SYN/SYN-ACK
option sets, TTLs, and a first look at how responses are segmented.

Read-only. Writes nothing.
"""

import sys
from collections import Counter, defaultdict

from scapy.all import PcapReader, IP, TCP

PCAP_DIR = "/home/philip/Projects/DNP3/Traffic Trace"
PCAPS = ["SEL751.pcap", "SEL751L.pcap", "AB1400.pcap", "AB1400L.pcap",
         "ION7550.pcap", "ION7550L.pcap"]


def recon(path):
    n = 0
    flows = Counter()
    ttl_by_ip = defaultdict(Counter)
    opts_by_ip = defaultdict(Counter)
    ports = Counter()
    payload_by_dir = defaultdict(Counter)
    first_ts = None
    last_ts = None
    with PcapReader(path) as rd:
        for pkt in rd:
            n += 1
            if IP not in pkt or TCP not in pkt:
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            ts = float(pkt.time)
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            key = tuple(sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)]))
            flows[key] += 1
            ttl_by_ip[ip.src][ip.ttl] += 1
            ports[tcp.dport] += 1
            if tcp.flags & 0x02:  # SYN or SYN-ACK
                opts_by_ip[ip.src][str(tcp.options)] += 1
            plen = len(bytes(tcp.payload))
            payload_by_dir[(ip.src, tcp.sport)][plen] += 1
    print("=" * 78)
    print(path)
    print("  packets:", n, " duration_s: %.1f" % ((last_ts - first_ts) if first_ts else 0))
    print("  flows:", len(flows))
    for k, v in flows.most_common(8):
        print("    ", k, v)
    print("  dports:", ports.most_common(6))
    print("  TTL by src:", {k: dict(v) for k, v in ttl_by_ip.items()})
    print("  SYN options by src:")
    for k, v in opts_by_ip.items():
        for o, c in v.items():
            print("     ", k, "x%d" % c, o)
    print("  payload-length histogram by (src,sport) [top 8]:")
    for k, v in payload_by_dir.items():
        print("     ", k, v.most_common(8), "total_nonzero=%d" % sum(c for L, c in v.items() if L > 0))


if __name__ == "__main__":
    for name in PCAPS:
        recon("%s/%s" % (PCAP_DIR, name))

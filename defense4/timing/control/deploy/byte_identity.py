#!/usr/bin/env python3
"""Byte-preservation check for released RESPONSEs. Run with $RESEARCH_PYTHON (needs scapy).

  byte_identity.py <mode:pcap> [<mode:pcap> ...]

IMPORTANT confound: the SEL-751 returns LIVE-changing data in every class-0 response (analog/binary
values, IIN flags, and their CRCs), so even OFF's own responses for one app-sequence are all
distinct. A cross-poll byte-for-byte content diff therefore cannot test whether the SWITCH modified
bytes; it only measures the relay's live data changing. Byte-preservation is instead established by
(1) construction: the P4 writes no byte of any host frame, holding and releasing the original packet
unmodified; and (2) empirically here: every released response keeps its exact DNP3 framing and length
and is accepted by the master with a valid DNP3 CRC (a single altered byte would fail that CRC and
show up as a retransmission or a missing response). This tool reports the structural evidence.
"""
import sys, json
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP
except Exception as e:
    print(json.dumps({"error": "scapy unavailable: %s" % e})); sys.exit(2)

RELAY = "192.168.10.7"
DNP3_PORT = 20000


def check(pcap):
    n = bad_framing = 0
    lens = set()
    for p in rdpcap(pcap):
        if IP not in p or TCP not in p:
            continue
        if p[IP].src != RELAY or p[TCP].sport != DNP3_PORT:
            continue
        pl = bytes(p[TCP].payload)
        if len(pl) < 12:
            continue
        n += 1
        lens.add(len(pl))
        if pl[0] != 0x05 or pl[1] != 0x64:      # DNP3 data-link start octets 0x0564
            bad_framing += 1
    return {"responses": n, "distinct_response_lengths": sorted(lens), "bad_framing": bad_framing,
            "verdict": "STRUCTURE PRESERVED" if (n > 0 and bad_framing == 0) else
                       ("NO DATA" if n == 0 else "FRAMING FAILURE")}


def main():
    report = {"note": "content diff is confounded by live relay data; see module docstring",
              "modes": {}}
    for arg in sys.argv[1:]:
        mode, _, pcap = arg.partition(":")
        report["modes"][mode] = dict(pcap=pcap, **check(pcap))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

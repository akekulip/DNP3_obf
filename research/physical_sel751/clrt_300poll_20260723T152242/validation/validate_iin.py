#!/usr/bin/env python3
"""Task 1: extract + decode the DNP3 IIN from every RESPONSE frame in the committed pcap (read-only)."""
import os, json
from collections import Counter
from scapy.all import PcapReader, TCP, IP

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(BASE, "evidence", "clrt_300poll_20260723T152242.pcap")
RELAY = "192.168.10.7"
NAMES1 = {0: "BROADCAST", 1: "CLASS1_EVENTS", 2: "CLASS2_EVENTS", 3: "CLASS3_EVENTS",
          4: "NEED_TIME", 5: "LOCAL_CONTROL", 6: "DEVICE_TROUBLE", 7: "DEVICE_RESTART"}
NAMES2 = {0: "FUNC_NOT_SUPPORTED", 1: "OBJECT_UNKNOWN", 2: "PARAMETER_ERROR", 3: "EVENT_BUFFER_OVERFLOW",
          4: "ALREADY_EXECUTING", 5: "CONFIG_CORRUPT", 6: "RESERVED2_6", 7: "RESERVED2_7"}


def main():
    pairs = Counter()
    for p in PcapReader(PCAP):
        if TCP not in p or IP not in p:
            continue
        pl = bytes(p[TCP].payload)
        if pl[:2] != b"\x05\x64" or len(pl) < 15 or pl[2] <= 5 or pl[12] != 129 or p[IP].src != RELAY:
            continue
        pairs[(pl[13], pl[14])] += 1     # wire order: IIN1 at offset 13, IIN2 at offset 14
    (i1, i2), n = pairs.most_common(1)[0]
    out = dict(response_frames=sum(pairs.values()),
               distinct_pairs={f"IIN1=0x{k[0]:02X},IIN2=0x{k[1]:02X}": v for k, v in pairs.items()},
               wire_order="IIN1 first (offset 13), IIN2 second (offset 14)",
               IIN1_hex=f"0x{i1:02X}", IIN2_hex=f"0x{i2:02X}",
               IIN1_bits=[f"IIN1.{k} {NAMES1[k]}" for k in range(8) if i1 & (1 << k)] or ["none"],
               IIN2_bits=[f"IIN2.{k} {NAMES2[k]}" for k in range(8) if i2 & (1 << k)] or ["none"],
               ambiguous_16bit={"IIN1<<8|IIN2": f"0x{(i1 << 8) | i2:04X}",
                                "IIN2<<8|IIN1": f"0x{(i2 << 8) | i1:04X}"},
               all_responses_identical=(len(pairs) == 1 and n == sum(pairs.values())))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Experiment 1, phase 4: deterministic offline PCAP transformations.

Produces transformed COPIES in ../pcaps/. Never touches originals. Each output
is a counterfactual trace: syntactic validity is checked in run_validate.py;
this script does NOT claim endpoints would negotiate or operate correctly.

Transforms (each includes T0 IP normalization):
  T0  canonical TTL(64) + IP-ID policy(0,DF) + IPv4 checksum
  T1  T0 + TSval/TSecr translation to a public per-endpoint origin (layout kept)
  T2  T0 + canonical TCP option layout: suppress TS/WScale/SACK in the handshake,
        public MSS(1460), public data_offset (SYN/SYN-ACK -> [MSS] doff=6;
        established -> no options doff=5); recompute lengths + checksums
  T3  T2 + per-flow ISN normalization (seq/ack delta so ISN starts at a public
        origin), with the reverse ack translation on the opposite direction
"""
import os
from scapy.all import rdpcap, wrpcap, Ether, IP, TCP, Raw

import exp1_lib as L

HERE = os.path.dirname(os.path.abspath(__file__))
PCAPS = os.path.normpath(os.path.join(HERE, "..", "pcaps"))
os.makedirs(PCAPS, exist_ok=True)

PUB_TTL = 64
PUB_MSS = 1460
M32 = (1 << 32)


def endpoint(pk):
    return (pk[IP].src, int(pk[TCP].sport))


def flowkey(pk):
    ip, tcp = pk[IP], pk[TCP]
    return tuple(sorted([(ip.src, int(tcp.sport)), (ip.dst, int(tcp.dport))]))


def precompute_offsets(pkts):
    """First TSval and first seq per (flow, endpoint) for origin translation."""
    ts0, seq0 = {}, {}
    for pk in pkts:
        if IP not in pk or TCP not in pk:
            continue
        fk, ep = flowkey(pk), endpoint(pk)
        # ISN: the SYN carries the initial seq
        fl = int(pk[TCP].flags)
        if (fl & 0x02) and (fk, ep) not in seq0:
            seq0[(fk, ep)] = int(pk[TCP].seq)
        for o in pk[TCP].options:
            if isinstance(o, (tuple, list)) and o[0] == "Timestamp":
                if (fk, ep) not in ts0:
                    ts0[(fk, ep)] = int(o[1][0])
    return ts0, seq0


MIN_ETH = 60  # minimum Ethernet frame (excluding FCS)


def real_payload(pk):
    """Real TCP segment payload (DNP3 bytes), excluding any L2 min-frame padding,
    using the original IPv4 total length as ground truth."""
    ip, tcp = pk[IP], pk[TCP]
    plen = int(ip.len) - ip.ihl * 4 - tcp.dataofs * 4
    raw = bytes(tcp.payload)
    return raw[:max(0, plen)]


def transform(pkts, mode):
    ts0, seq0 = precompute_offsets(pkts)
    out = []
    for orig in pkts:
        if IP not in orig or TCP not in orig:
            out.append(orig)
            continue
        oip, otcp = orig[IP], orig[TCP]
        fk, ep = flowkey(orig), endpoint(orig)
        peer = next((e for e in fk if e != ep), None)
        rp = real_payload(orig)
        # --- options per mode ---
        newopts = list(otcp.options)
        if mode == "T1":
            tmp = []
            for o in otcp.options:
                if isinstance(o, (tuple, list)) and o[0] == "Timestamp":
                    tsval, tsecr = int(o[1][0]), int(o[1][1])
                    ntsval = (tsval - ts0.get((fk, ep), 0)) % M32
                    ntsecr = (tsecr - ts0.get((fk, peer), 0)) % M32 if tsecr else 0
                    tmp.append(("Timestamp", (ntsval, ntsecr)))
                else:
                    tmp.append(o)
            newopts = tmp
        if mode in ("T2", "T3"):
            newopts = [("MSS", PUB_MSS)] if (int(otcp.flags) & 0x02) else []
        # --- seq/ack per mode ---
        seq, ack = int(otcp.seq), int(otcp.ack)
        if mode == "T3":
            os_ = seq0.get((fk, ep))
            op_ = seq0.get((fk, peer))
            if os_ is not None:
                seq = (seq - os_) % M32
            if op_ is not None and (int(otcp.flags) & 0x10):
                ack = (ack - op_) % M32
        # --- rebuild cleanly: Ether(orig MACs)/IP(normalized)/TCP(newopts)/payload ---
        eth = Ether(src=orig[Ether].src, dst=orig[Ether].dst, type=orig[Ether].type)
        ip = IP(src=oip.src, dst=oip.dst, ttl=PUB_TTL, id=0, flags="DF",
                frag=0, proto=6, tos=int(oip.tos))
        tcp = TCP(sport=int(otcp.sport), dport=int(otcp.dport), seq=seq, ack=ack,
                  flags=int(otcp.flags), window=int(otcp.window),
                  urgptr=int(otcp.urgptr), options=newopts)
        pkt = eth / ip / tcp
        if rp:
            pkt = pkt / Raw(load=rp)
        raw = bytes(pkt)  # scapy fills ip.len, dataofs, checksums
        if len(raw) < MIN_ETH:            # Ethernet minimum-length padding
            raw = raw + b"\x00" * (MIN_ETH - len(raw))
        out.append(Ether(raw))
    return out


def main():
    manifest = []
    import hashlib
    for cap in L.ALL_CAPS:
        src = os.path.join(L.TRAFFIC_TRACE, cap)
        pkts = rdpcap(src)
        base = cap.replace(".pcap", "")
        for mode in ["T0", "T1", "T2", "T3"]:
            outp = os.path.join(PCAPS, f"{base}_{mode}.pcap")
            tp = transform(pkts, mode)
            wrpcap(outp, tp)
            h = hashlib.sha256(open(outp, "rb").read()).hexdigest()
            manifest.append({"src": cap, "mode": mode,
                             "out": os.path.relpath(outp, os.path.join(HERE, "..")),
                             "packets": len(tp), "sha256": h,
                             "committed": cap in L.SHORT_CAPS})
            print(f"  {cap:14} {mode}  -> {os.path.basename(outp):24} pkts={len(tp)} sha={h[:12]}")
    import json
    with open(os.path.normpath(os.path.join(HERE, "..", "out", "transform_manifest.json")), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nwrote {len(manifest)} transformed pcaps + out/transform_manifest.json")


if __name__ == "__main__":
    main()

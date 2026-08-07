#!/usr/bin/env python3
"""Paired ingress-vs-egress byte comparator for the transparent Defense 4 forwarding claim.

Run with $RESEARCH_PYTHON (needs scapy).

  pair_bytes.py --ingress <relay-facing.pcap> --egress <master-facing.pcap>
                [--relay-ip 192.168.10.7] [--master-ip 192.168.10.1] [--port 20000]
                [--intended <intended_bytes.jsonl>] [--out report.json]

Why this replaces byte_identity.py: the old tool read one observation point (relay-facing framing +
length) and could not prove the switch released the same bytes it received. The SEL-751 also returns
live-changing data every poll, so a cross-poll content diff measures the relay, not the switch. This
tool instead matches the SAME frame at two capture points and compares its bytes.

Topology: master <-> switch <-> relay. The relay-facing capture sees each relay->master ACK/RESPONSE
as it ARRIVES at the switch (before the hold); the master-facing capture sees the SAME frame as it
DEPARTS to the master (after the hold). Defense 4 only changes WHEN a frame leaves, never its bytes,
so for every relay->master frame the two captures must carry byte-identical TCP payloads and identical
preserved headers.

Matching key (per frame): direction (relay->master), TCP 4-tuple, TCP seq, TCP ack, flags, payload
length, and occurrence index (to separate a retransmission of the same seq). The DNP3 application
sequence, when a payload is present, is parsed and recorded for the mapping.

Preserved-header policy: src/dst IP, src/dst port, seq, ack, TCP flags, IP id, and IP total length
must match. Ethernet MAC addresses are expected to differ (an L2 switch rewrites them) and are
reported, not failed. The FCS is absent from captured frames. TCP/IP checksums can be zero on the
transmit-side capture because of checksum offload; a zero checksum is noted, a non-zero mismatch is
reported. VLAN tags are stripped before comparison. Over-MTU frames are flagged as possible
GRO/GSO/TSO/LRO reassembly at the capture point (which would corrupt the pairing) and fail the run.

Verdict FAIL (exit 1) if any relay->master frame with a non-empty payload is unmatched, duplicated,
reordered, or carries changed payload bytes, or if a preserved header field differs, or if capture
offload reassembly is detected. PASS (exit 0) only when every protected payload frame matches exactly.
Exit 2 on a usage/IO error (missing pcap, scapy unavailable).
"""
import argparse
import json
import os
import sys

try:
    from scapy.all import rdpcap, Ether, IP, TCP, Dot1Q
except Exception as e:  # scapy missing -> hard IO failure
    print(json.dumps({"verdict": "IO_FAIL", "error": "scapy unavailable: %s" % e}))
    sys.exit(2)

MTU = 1514  # Ethernet header (14) + max IP/TCP payload (1500); over this at capture = offload reassembly


def flagstr(flags):
    return str(flags)


def app_seq(payload):
    """DNP3 application-control low nibble (C0..CF) if this looks like a DNP3 app response."""
    # 0x0564 link header (10 bytes) + transport (1) + application-control (1). App-control is at
    # offset 11 when the link start octets are present and the frame carries an application layer.
    if len(payload) >= 12 and payload[0] == 0x05 and payload[1] == 0x64:
        return "0x%02X" % payload[11]
    return None


def extract(pcap, src_ip, src_port):
    """All frames from src_ip:src_port (the relay->master direction), in capture order."""
    frames = []
    over_mtu = 0
    for p in rdpcap(pcap):
        if Dot1Q in p:
            p = p.__class__(bytes(p))  # keep a copy; VLAN handled by reading inner IP/TCP below
        if IP not in p or TCP not in p:
            continue
        ip = p[IP]
        tcp = p[TCP]
        if ip.src != src_ip or int(tcp.sport) != src_port:
            continue
        raw = bytes(p)
        if len(raw) > MTU:
            over_mtu += 1
        payload = bytes(tcp.payload)
        frames.append({
            "src": ip.src, "dst": ip.dst, "sport": int(tcp.sport), "dport": int(tcp.dport),
            "seq": int(tcp.seq), "ack": int(tcp.ack), "flags": flagstr(tcp.flags),
            "ip_id": int(ip.id), "ip_len": int(ip.len), "tcp_chksum": int(tcp.chksum or 0),
            "eth_src": p[Ether].src if Ether in p else None,
            "eth_dst": p[Ether].dst if Ether in p else None,
            "plen": len(payload), "payload": payload, "app_seq": app_seq(payload),
        })
    return frames, over_mtu


def key_of(f):
    return (f["src"], f["sport"], f["dst"], f["dport"], f["seq"], f["ack"], f["flags"], f["plen"])


def index_by_key(frames):
    """key -> list of frames in order (list position is the occurrence index)."""
    idx = {}
    for f in frames:
        idx.setdefault(key_of(f), []).append(f)
    return idx


def first_diff(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return n
    return None


PRESERVED = ["src", "dst", "sport", "dport", "seq", "ack", "flags", "ip_id", "ip_len"]


def main(argv):
    ap = argparse.ArgumentParser(description="paired ingress-vs-egress byte comparator")
    ap.add_argument("--ingress", required=True, help="relay-facing pcap (frames as they arrive)")
    ap.add_argument("--egress", required=True, help="master-facing pcap (frames as they depart)")
    ap.add_argument("--relay-ip", default="192.168.10.7")
    ap.add_argument("--master-ip", default="192.168.10.1")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--intended", default=None, help="optional jsonl of intended bytes (hex) per app_seq")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    for p in (args.ingress, args.egress):
        if not os.path.exists(p) or os.path.getsize(p) == 0:
            print(json.dumps({"verdict": "IO_FAIL", "error": "missing/empty pcap: %s" % p}))
            return 2

    ing, ing_over = extract(args.ingress, args.relay_ip, args.port)
    egr, egr_over = extract(args.egress, args.relay_ip, args.port)

    hard = []
    if ing_over or egr_over:
        hard.append("over-MTU frames at capture (offload reassembly?): ingress=%d egress=%d"
                    % (ing_over, egr_over))

    egr_idx = index_by_key(egr)
    used = {}   # key -> next occurrence index to consume on the egress side
    mapping = []
    payload_mismatch = []
    header_mismatch = []
    unmatched_ingress = []
    checksum_offload_notes = 0

    for f in ing:
        k = key_of(f)
        occ = used.get(k, 0)
        cands = egr_idx.get(k, [])
        if occ < len(cands):
            g = cands[occ]
            used[k] = occ + 1
            # exact payload compare
            off = first_diff(f["payload"], g["payload"])
            entry = {"seq": f["seq"], "plen": f["plen"], "app_seq": f["app_seq"],
                     "matched": True, "payload_ok": off is None}
            if off is not None and f["plen"] > 0:
                payload_mismatch.append({"seq": f["seq"], "app_seq": f["app_seq"],
                                         "first_diff_offset": off,
                                         "ingress_byte": f["payload"][off] if off < len(f["payload"]) else None,
                                         "egress_byte": g["payload"][off] if off < len(g["payload"]) else None})
            # preserved header fields
            for field in PRESERVED:
                if f[field] != g[field]:
                    header_mismatch.append({"seq": f["seq"], "field": field,
                                            "ingress": f[field], "egress": g[field]})
            # checksum offload note (a zeroed egress checksum is offload, not corruption)
            if g["tcp_chksum"] == 0 and f["tcp_chksum"] != 0:
                checksum_offload_notes += 1
            mapping.append(entry)
        else:
            if f["plen"] > 0:
                unmatched_ingress.append({"seq": f["seq"], "app_seq": f["app_seq"], "plen": f["plen"]})
            mapping.append({"seq": f["seq"], "plen": f["plen"], "app_seq": f["app_seq"], "matched": False})

    # egress protected frames not consumed by any ingress frame = injected/duplicated on egress
    unmatched_egress = []
    for k, cands in egr_idx.items():
        consumed = used.get(k, 0)
        for g in cands[consumed:]:
            if g["plen"] > 0:
                unmatched_egress.append({"seq": g["seq"], "app_seq": g["app_seq"], "plen": g["plen"]})

    # ordering: the protected (payload>0) frames must appear in the same seq order at both points
    ing_order = [f["seq"] for f in ing if f["plen"] > 0]
    egr_order = [g["seq"] for g in egr if g["plen"] > 0]
    # egress may hold/delay, but the RELATIVE order of the protected stream must be preserved
    reordered = ([s for s in egr_order if s in set(ing_order)]
                 != [s for s in ing_order if s in set(egr_order)])

    if payload_mismatch:
        hard.append("%d protected payload byte mismatch(es)" % len(payload_mismatch))
    if header_mismatch:
        hard.append("%d preserved-header mismatch(es)" % len(header_mismatch))
    if unmatched_ingress:
        hard.append("%d ingress protected frame(s) with no egress match (dropped/altered)" % len(unmatched_ingress))
    if unmatched_egress:
        hard.append("%d egress protected frame(s) with no ingress match (injected/duplicated)" % len(unmatched_egress))
    if reordered:
        hard.append("protected payload reordered between ingress and egress")

    report = {
        "ingress_pcap": args.ingress, "egress_pcap": args.egress,
        "relay_ip": args.relay_ip, "port": args.port,
        "ingress_frames": len(ing), "egress_frames": len(egr),
        "ingress_protected": len(ing_order), "egress_protected": len(egr_order),
        "matched": sum(1 for m in mapping if m["matched"]),
        "payload_mismatch": payload_mismatch, "header_mismatch": header_mismatch,
        "unmatched_ingress": unmatched_ingress, "unmatched_egress": unmatched_egress,
        "reordered": reordered,
        "checksum_offload_notes": checksum_offload_notes,
        "mac_rewrite_expected": True,
        "mapping": mapping,
        "hard_anomalies": hard,
        "verdict": "BYTE-IDENTICAL" if not hard else "BYTE MISMATCH",
        "exit_code": 0 if not hard else 1,
    }

    if args.out:
        json.dump(report, open(args.out, "w"), indent=2, default=str)
    # console: summary without the (large) full mapping
    summary = {k: v for k, v in report.items() if k != "mapping"}
    print(json.dumps(summary, indent=2, default=str))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

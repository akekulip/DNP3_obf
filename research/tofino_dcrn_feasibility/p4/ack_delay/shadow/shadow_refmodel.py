#!/usr/bin/env python3
"""
Reference model of the DNP3 shadow classifier (dnp3_shadow.p4), Phase 1 / charter §G.

This mirrors, in Python, the exact classification the passive P4 performs, so the classification
LOGIC can be verified offline against real traffic (the committed physical-relay pcap) without the
switch. The shadow is passive: it changes nothing; this model therefore only *labels* packets, it
never mutates them (byte/size/order identity is trivially preserved).

Classification rules (identical qualification style to dcrn_defense1.p4):
  - Non-IPv4 / non-TCP                              -> UNRELATED
  - TCP RST                                         -> TCP_RST
  - TCP FIN                                         -> TCP_FIN
  - payload==0, ACK set, SYN/FIN/RST clear          -> PURE_ACK
  - port 20000 involved, payload>0:
        0x0564 + link_len>5 + func==1               -> DNP3_READ
        0x0564 + link_len>5 + func==129             -> DNP3_RESPONSE
        0x0564 + (link_len<=5 OR other func)        -> LINK_STATUS_OR_OTHER_DNP3
        payload but not 0x0564                       -> MALFORMED
  - anything else                                    -> UNRELATED
Direction: request = dst_port==20000 (master->outstation); response/ack = src_port==20000.
The zero-payload-ACK gate (never parse a pure ACK as DNP3) is enforced by testing FIN/RST/PURE_ACK
before the DNP3 branch and by requiring payload>0 for any DNP3 label — mirroring the P4 length gate
total_len >= 30 + 4*data_offset.
"""
DNP3_PORT = 20000
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10

CLASSES = ["UNRELATED", "TCP_FIN", "TCP_RST", "PURE_ACK", "DNP3_READ", "DNP3_RESPONSE",
           "LINK_STATUS_OR_OTHER_DNP3", "MALFORMED"]


def classify(ipsrc, ipdst, sport, dport, flags, payload):
    """Return (classification, fields dict). `payload` = raw TCP payload bytes."""
    plen = len(payload)
    involves_dnp3 = (sport == DNP3_PORT or dport == DNP3_PORT)
    direction = 0 if dport == DNP3_PORT else (1 if sport == DNP3_PORT else None)
    f = dict(direction=direction, payload_len=plen, sport=sport, dport=dport,
             flags=flags, dnp3_func=None, dnp3_dst=None, dnp3_src=None, dnp3_app_seq=None,
             link_len=None, note="")

    if flags & RST:
        f["note"] = "rst"; return "TCP_RST", f
    if flags & FIN:
        f["note"] = "fin"; return "TCP_FIN", f
    if plen == 0 and (flags & ACK) and not (flags & (SYN | FIN | RST)):
        return "PURE_ACK", f
    if not involves_dnp3:
        return "UNRELATED", f
    if plen == 0:
        # zero-payload frame to/from 20000 that is not a clean pure ACK (e.g., bare SYN) -> not DNP3
        f["note"] = "zero_payload_non_ack"; return "UNRELATED", f
    # payload > 0 on a DNP3 port: this is where the P4 length gate would have descended into DNP3
    if payload[:2] != b"\x05\x64":
        f["note"] = "no_0x0564_magic"; return "MALFORMED", f
    if len(payload) < 3:
        f["note"] = "truncated_link_len"; return "MALFORMED", f
    link_len = payload[2]; f["link_len"] = link_len
    if link_len <= 5 or len(payload) < 13:
        f["note"] = "link_only_or_truncated_app"
        if len(payload) >= 8:
            f["dnp3_dst"] = payload[4] | (payload[5] << 8); f["dnp3_src"] = payload[6] | (payload[7] << 8)
        return "LINK_STATUS_OR_OTHER_DNP3", f
    f["dnp3_dst"] = payload[4] | (payload[5] << 8)
    f["dnp3_src"] = payload[6] | (payload[7] << 8)
    f["dnp3_func"] = payload[12]
    f["dnp3_app_seq"] = payload[11] & 0x0f
    if payload[12] == 1:
        return "DNP3_READ", f
    if payload[12] == 129:
        return "DNP3_RESPONSE", f
    f["note"] = "other_func_%d" % payload[12]
    return "LINK_STATUS_OR_OTHER_DNP3", f


def classify_scapy(pkt):
    """Classify a scapy packet; returns (classification, fields) or (None, None) if not IP/TCP."""
    from scapy.all import IP, TCP
    if IP not in pkt or TCP not in pkt:
        return None, None
    ip, t = pkt[IP], pkt[TCP]
    return classify(ip.src, ip.dst, int(t.sport), int(t.dport), int(t.flags), bytes(t.payload))

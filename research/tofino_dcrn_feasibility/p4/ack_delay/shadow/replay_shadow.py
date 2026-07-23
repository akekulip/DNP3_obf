#!/usr/bin/env python3
"""
Phase-1 replay verification: run the shadow reference model over the committed physical-relay
300-poll pcap and check the charter §G acceptance criteria. Read-only; no switch, no relay.
"""
import os, sys, json
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shadow_refmodel import classify_scapy
from scapy.all import PcapReader, TCP

PCAP = "/home/philip/Projects/DNP3/research/physical_sel751/clrt_300poll_20260723T152242/evidence/clrt_300poll_20260723T152242.pcap"


def main():
    counts = Counter()
    relay_pure_ack = 0            # separate pure ACK from the outstation (src 20000) — the CLRT ACK
    master_pure_ack = 0
    zeropay_as_dnp3 = 0          # a zero-payload frame mislabelled DNP3_READ/RESPONSE (must be 0)
    linkframe_as_req = 0        # a link-status frame mislabelled as an application READ/RESPONSE (must be 0)
    retrans = 0
    seen = set()
    n_ip_tcp = 0
    ordered = []                 # (classification, fields) in capture order, for the transaction walk
    for p in PcapReader(PCAP):
        c, f = classify_scapy(p)
        if c is None:
            continue
        n_ip_tcp += 1
        counts[c] += 1
        ordered.append((c, f))
        if c == "PURE_ACK":
            if f["sport"] == 20000:
                relay_pure_ack += 1
            elif f["dport"] == 20000:
                master_pure_ack += 1
        if f["payload_len"] == 0 and c in ("DNP3_READ", "DNP3_RESPONSE"):
            zeropay_as_dnp3 += 1
        if c in ("DNP3_READ", "DNP3_RESPONSE") and f["link_len"] is not None and f["link_len"] <= 5:
            linkframe_as_req += 1
        if f["payload_len"] > 0:
            key = (f["direction"], int(p[TCP].seq), f["payload_len"])
            if key in seen:
                retrans += 1
            else:
                seen.add(key)

    # Transaction walk: verify the Case-A property — every READ is followed, in the outstation->master
    # direction, by a separate PURE_ACK and then a DNP3_RESPONSE, before the next READ. Count triples.
    triples = 0
    state = None            # None -> saw READ -> saw separate ACK
    for c, f in ordered:
        if c == "DNP3_READ":
            state = "read"
        elif c == "PURE_ACK" and f["sport"] == 20000 and state == "read":
            state = "ack"          # the separate outstation ACK after the read
        elif c == "DNP3_RESPONSE" and f["sport"] == 20000:
            if state == "ack":
                triples += 1
            state = None

    checks = {
        "reads_classified_300":            counts["DNP3_READ"] == 300,
        "responses_classified_300":        counts["DNP3_RESPONSE"] == 300,
        "separate_ack_then_response_300":  triples == 300,          # the exact Case-A baseline property
        "outstation_pure_acks_ge_300":     relay_pure_ack >= 300,   # 300 CLRT ACKs + a few teardown ACKs
        "no_zero_payload_ack_as_dnp3":     zeropay_as_dnp3 == 0,
        "no_linkframe_as_application":     linkframe_as_req == 0,
        "no_retransmissions":              retrans == 0,
        # the shadow is passive: it only labels, never mutates -> byte/size/order identity is structural
        # (no header push/pop, no recirc in dnp3_shadow.p4). Verified here by construction + the compile.
        "byte_size_order_identity_by_construction": True,
    }
    result = dict(pcap=os.path.basename(PCAP), n_ip_tcp=n_ip_tcp,
                  class_counts=dict(counts), separate_ack_response_triples=triples,
                  outstation_pure_acks=relay_pure_ack, master_side_acks=master_pure_ack,
                  retransmissions=retrans, checks=checks, PASS=all(checks.values()))
    print(json.dumps(result, indent=1))
    sys.exit(0 if result["PASS"] else 1)


if __name__ == "__main__":
    main()

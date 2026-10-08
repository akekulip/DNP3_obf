#!/usr/bin/env python3
"""
build_rrc_pool.py -- builds a TCP-payload-byte-unit record pool from the recovered RRC hardware
PCAPs (9ffa9102:defense4/size/native_parity/evidence/{hw_rrc_readsbo_...,hw_rrc_joint_...}), in the
same per-record schema as extract_inventory_v2.py's *_analysis.json (so evaluate_candidates.py's
leakage()/overhead() functions can be reused unmodified against it -- see Options A/B/C in
DISTRIBUTION_AND_PATTERN_ANALYSIS.md). This is a SEPARATE, clearly labelled evidence pool: it is
TCP-PAYLOAD bytes (not the historical builder's Ethernet-frame-no-fcs-min convention), and it is a
physical-hardware capture of the READ and SBO(SELECT) response-carving trials, not the base/long
fingerprint corpus. Do not merge this pool's numbers with base/long's Ethernet-byte histograms.
"""
import json
import sys
from collections import defaultdict
from scapy.all import PcapReader, TCP, IP

FC_NAME = {0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
           5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR", 129: "RESPONSE", 130: "UNSOLICITED_RESPONSE"}


def dnp3_fc(payload):
    i = payload.find(b"\x05\x64")
    if i < 0 or len(payload) < i + 13:
        return None
    return payload[i + 12]


def extract_trial(pcap_path, trial_label, flow_label):
    """One flow = one (pcap, TCP 4-tuple) persistent connection. Returns per-packet records keyed by
    transaction (grouped by request/response pairing in chronological order, matching the historical
    extractor's transaction_id convention: txn increments on each master_to_outstation opening FC)."""
    recs = []
    idx = 0
    txn = 0
    opening = {"READ", "SELECT", "OPERATE", "DIRECT_OPERATE", "WRITE"}
    cur_op = None
    frag = 0
    for pkt in PcapReader(pcap_path):
        idx += 1
        if IP not in pkt or TCP not in pkt:
            continue
        t = pkt[TCP]
        if t.sport != 20000 and t.dport != 20000:
            continue
        outstation_side = (t.sport == 20000)
        direction = "outstation_to_master" if outstation_side else "master_to_outstation"
        payload = bytes(t.payload)
        pl = len(payload)
        if pl == 0:
            continue  # pure ACKs not materialized in this pcap-derived pool (TCP ACKs only, no role)
        fc = dnp3_fc(payload)
        fc_name = FC_NAME.get(fc, "unknown") if fc is not None else "unknown"
        if fc_name in opening and not outstation_side:
            txn += 1
            cur_op = fc_name
            frag = 0
            role = {"READ": "READ_REQUEST", "SELECT": "SELECT", "OPERATE": "OPERATE",
                    "WRITE": "WRITE_REQUEST"}.get(fc_name, fc_name)
        elif fc_name in ("RESPONSE", "UNSOLICITED_RESPONSE") and outstation_side:
            role = "RESPONSE"
        elif fc_name == "unknown" and outstation_side:
            role = "RESPONSE"  # the un-headered suffix segment of a split response (no 0x0564)
        else:
            role = "unknown"
        op = {"READ": "READ", "SELECT": "SBO", "OPERATE": "SBO"}.get(cur_op, cur_op)
        recs.append({
            "capture_id": trial_label, "capture_index": idx, "ts": float(pkt.time),
            "device": "SEL751_physical", "flow": flow_label,
            "direction": direction, "role": role, "_operation": op,
            "transaction_id": txn, "tcp_payload_bytes": pl,
            "ack_mode_observed": "separate",  # RRC trials are all separate-ACK (SEL-751, confirmed)
        })
    return recs


def main():
    here = __file__.rsplit("/", 1)[0]
    pool = []
    pool += extract_trial(sys.argv[1], "hw_rrc_readsbo_read", "readsbo_read_flow")
    pool += extract_trial(sys.argv[2], "hw_rrc_readsbo_sbo", "readsbo_sbo_flow")
    pool += extract_trial(sys.argv[3], "hw_rrc_joint_read", "joint_read_flow")
    pool += extract_trial(sys.argv[4], "hw_rrc_joint_sbo", "joint_sbo_flow")
    doc = {"schema_version": "rrc_pool_1.0", "scope": "rrc_hardware_pool",
           "size_convention": "tcp_payload_bytes (NOT Ethernet-frame-no-fcs convention)",
           "provenance": "9ffa9102d7a60095ed286f5c5dde2561a679b3d9:defense4/size/native_parity/"
                         "evidence/{hw_rrc_readsbo_20260812T212234Z,hw_rrc_joint_20260812T223342Z}"
                         "/captures/{read,sbo}.pcap",
           "records": pool}
    with open(sys.argv[5], "w") as f:
        json.dump(doc, f, indent=2)
    by = defaultdict(int)
    for r in pool:
        by[(r["direction"], r["role"], r["tcp_payload_bytes"])] += 1
    print("n_records", len(pool))
    for k, v in sorted(by.items()):
        print(" ", k, "x", v)


if __name__ == "__main__":
    main()

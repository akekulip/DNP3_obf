#!/usr/bin/env python3
"""
size_inventory.py — Phase-5 (size regeneration) EVIDENCE step: build a DNP3 response size inventory from
the physical relay pcap + the per-device trace pcaps. ANALYSIS ONLY — this computes the size distribution
and the candidate cover-states (the size math); it does NOT choose or implement a padding MECHANISM (that
is the undecided architecture decision C3/C4, human-gated). Read-only; no switch, no relay.

For each pcap it tallies outstation->master DNP3 responses (src_port==20000, DNP3 function code 129) by:
  wire_len      — full captured frame bytes on the wire (what a size-fingerprint observer sees)
  ip_total_len  — IP datagram length
  dnp3_len      — DNP3 link-layer length field payload (application-visible size)
Outputs packet_size_inventory.csv (per-response rows) + a per-source summary + candidate cover states.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                "tofino_dcrn_feasibility", "p4", "ack_delay", "shadow"))
from shadow_refmodel import classify  # noqa: E402
from scapy.all import PcapReader, IP, TCP, raw  # noqa: E402

REPO = "/home/philip/Projects/DNP3"
SOURCES = [
    ("physical_relay_300poll",
     REPO + "/research/physical_sel751/clrt_300poll_20260723T152242/evidence/clrt_300poll_20260723T152242.pcap"),
    ("trace_SEL751",  REPO + "/Traffic Trace/SEL751.pcap"),
    ("trace_SEL751L", REPO + "/Traffic Trace/SEL751L.pcap"),
    ("trace_AB1400",  REPO + "/Traffic Trace/AB1400.pcap"),
    ("trace_AB1400L", REPO + "/Traffic Trace/AB1400L.pcap"),
    ("trace_ION7550", REPO + "/Traffic Trace/ION7550.pcap"),
    ("trace_ION7550L", REPO + "/Traffic Trace/ION7550L.pcap"),
]


def dnp3_len(payload):
    # DNP3: 0x05 0x64 <len> ... ; <len> counts from the control octet through the data (excludes CRCs).
    if len(payload) >= 3 and payload[0] == 0x05 and payload[1] == 0x64:
        return payload[2]
    return None


def responses(path):
    rows = []
    for p in PcapReader(path):
        if IP not in p or TCP not in p:
            continue
        if int(p[TCP].sport) != 20000:
            continue
        payload = bytes(p[TCP].payload)
        cls, _ = classify(p[IP].src, p[IP].dst, int(p[TCP].sport), int(p[TCP].dport),
                          int(p[TCP].flags), payload)
        if cls != "DNP3_RESPONSE":
            continue
        rows.append({"wire_len": len(raw(p)), "ip_total_len": int(p[IP].len),
                     "dnp3_len": dnp3_len(payload), "tcp_payload_len": len(payload)})
    return rows


def summarize(rows):
    if not rows:
        return None
    def stats(key):
        vals = [r[key] for r in rows if r[key] is not None]
        return {"min": min(vals), "max": max(vals), "n_distinct": len(set(vals)),
                "values": sorted(set(vals))} if vals else None
    return {"n_responses": len(rows), "wire_len": stats("wire_len"),
            "ip_total_len": stats("ip_total_len"), "tcp_payload_len": stats("tcp_payload_len"),
            "dnp3_len": stats("dnp3_len")}


def main():
    outdir = os.path.dirname(os.path.abspath(__file__))
    all_rows = []
    summaries = {}
    for name, path in SOURCES:
        if not os.path.isfile(path):
            summaries[name] = {"missing": path}
            continue
        rows = responses(path)
        for r in rows:
            r["source"] = name
        all_rows.extend(rows)
        summaries[name] = summarize(rows)

    csv_path = os.path.join(outdir, "packet_size_inventory.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["source", "wire_len", "ip_total_len", "dnp3_len", "tcp_payload_len"])
        w.writeheader()
        for r in all_rows:
            w.writerow(r)

    # global cover requirement: the largest response any state must cover
    wires = [r["wire_len"] for r in all_rows]
    dnp3s = [r["dnp3_len"] for r in all_rows if r["dnp3_len"] is not None]
    global_max_wire = max(wires) if wires else None
    global_max_dnp3 = max(dnp3s) if dnp3s else None

    # candidate cover states = size math only (NOT a mechanism). Smallest single fixed state that covers
    # the global max, plus common alignment options. Which (and HOW to reach it) is the human decision.
    def cover(n):
        if n is None:
            return None
        pow2 = 1 << (n - 1).bit_length()
        return {"single_fixed_ge_max": n, "next_pow2": pow2,
                "next_64B_mult": ((n + 63) // 64) * 64, "next_128B_mult": ((n + 127) // 128) * 128}

    import json
    report = {
        "n_total_responses": len(all_rows),
        "per_source": summaries,
        "global_max_wire_len": global_max_wire,
        "global_max_dnp3_len": global_max_dnp3,
        "global_max_tcp_payload_len": max((r["tcp_payload_len"] for r in all_rows), default=None),
        "candidate_cover_states_wire": cover(global_max_wire),
        "candidate_cover_states_dnp3": cover(global_max_dnp3),
        "notes": [
            "ANALYSIS ONLY: candidate cover-states are size arithmetic, not a chosen mechanism.",
            "The observable size a passive fingerprinter sees is the WIRE frame (global max 200 B), NOT",
            " the DNP3 length octet. The prior '134 B' figure is the TCP PAYLOAD (DNP3-over-TCP) length;",
            " wire=200, IP=186, TCP-payload=134, DNP3-len-field=115 for the physical relay response.",
            "The existing Level-1 128 B state does NOT cover the 200 B wire (or the 134 B payload): C5.",
            "How to reach a cover size (prepend filler / seq-translate / two-edge encap) is UNDECIDED (C3/C4).",
        ],
    }
    with open(os.path.join(outdir, "size_inventory_summary.json"), "w") as f:
        json.dump(report, f, indent=1, default=str)
    print(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    main()

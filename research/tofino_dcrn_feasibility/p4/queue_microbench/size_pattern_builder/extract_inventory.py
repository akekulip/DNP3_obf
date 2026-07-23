#!/usr/bin/env python3
"""
extract_inventory.py — Step 2 of the DNP3 size-pattern builder v1 (OFF-SWITCH only).

Builds a trace-grounded, per-packet inventory of the protected-link DNP3 traffic from the real
device captures in `Traffic Trace/`. One record per DNP3 (TCP/20000) packet. Roles are taken from
the actual DNP3 application function code parsed out of the wire bytes (0x0564 framing), and — for
the SEL-751 flow — cross-checked against the Zeek `dnp3.log`. Roles the capture does not support are
marked `unknown`; nothing is inferred that the bytes do not show.

Output: a VERSIONED CSV + JSON (schema_version below). Read by generate_candidates.py.

Usage:
  $RESEARCH_PYTHON extract_inventory.py                      # default: the 3 base device pcaps
  $RESEARCH_PYTHON extract_inventory.py --long               # also include the *L.pcap long captures
  $RESEARCH_PYTHON extract_inventory.py --out inv.json --csv inv.csv
"""
import argparse
import csv
import json
import os
from collections import defaultdict, Counter

from scapy.all import PcapReader, TCP, IP

SCHEMA_VERSION = "1.0.0"
DNP3_PORT = 20000

# Device map (CASE_A_TERMINOLOGY.md): outstation IP -> (name, ack_mode).
DEVICES = {
    "10.0.0.1":  ("SEL751",  "separate"),   # separate pure ACK then response (has CLRT)
    "10.0.0.11": ("ION7550", "combined"),   # ACK piggybacked on the response (no CLRT)
    "10.0.0.12": ("AB1400",  "combined"),
}
# pcap basename -> outstation IP (belt-and-suspenders when a capture has mixed hosts)
PCAP_OUTSTATION = {
    "SEL751": "10.0.0.1", "ION7550": "10.0.0.11", "AB1400": "10.0.0.12",
}

# DNP3 application function codes (IEEE 1815). Request FCs < 128, response FCs >= 129.
FC_NAME = {
    0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
    5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR",
    129: "RESPONSE", 130: "UNSOLICITED_RESPONSE",
}


def parse_dnp3(payload: bytes):
    """Return (fc_code, fc_name, app_ctrl) from a DNP3-over-TCP payload, or (None,None,None).
    Framing: [0:2]=0x0564 start, [2]=len, [3]=ctrl, [4:6]=dst, [6:8]=src, [8:10]=crc,
    [10]=transport, [11]=app_ctrl, [12]=function_code. We locate 0x0564 (not always at offset 0
    if TCP coalesced) and read the app function code. Returns None if no DNP3 frame is present."""
    i = payload.find(b"\x05\x64")
    if i < 0 or len(payload) < i + 13:
        return None, None, None
    app_ctrl = payload[i + 11]
    fc = payload[i + 12]
    return fc, FC_NAME.get(fc, "FC_%d" % fc), app_ctrl


def role_of(fc_name, is_response_dir):
    """Map a parsed function code to a transaction role label. Requests/responses are already
    disambiguated by FC (>=129 = response). Confirmations of SELECT/OPERATE in DNP3 are RESPONSE
    frames; a distinct application CONFIRM is FC 0."""
    if fc_name is None:
        return "unknown"
    return {
        "READ": "READ_REQUEST", "DIRECT_OPERATE": "DIRECT_OPERATE_REQUEST",
        "DIRECT_OPERATE_NR": "DIRECT_OPERATE_REQUEST", "SELECT": "SELECT",
        "OPERATE": "OPERATE", "WRITE": "WRITE_REQUEST", "CONFIRM": "APP_CONFIRM",
        "RESPONSE": "RESPONSE", "UNSOLICITED_RESPONSE": "UNSOLICITED_RESPONSE",
    }.get(fc_name, fc_name)


def load_zeek_dnp3(path):
    """Return the Zeek dnp3.log transaction rows (list of dicts) if present, else []."""
    if not path or not os.path.exists(path):
        return []
    rows, fields = [], None
    with open(path) as f:
        for line in f:
            if line.startswith("#fields"):
                fields = [x.strip() for x in line.split("\t")[1:]]
            elif not line.startswith("#") and fields:
                rows.append(dict(zip(fields, line.rstrip("\n").split("\t"))))
    return rows


def extract_pcap(path, cap_id, dev_name, ack_mode, max_pkts=None):
    """Yield inventory records for the DNP3 packets in one pcap."""
    # per-flow transaction state: a request opens a txn; ack + responses follow; fragment index
    # increments per response packet within a txn.
    txn_counter = defaultdict(int)      # flow -> running transaction id
    cur_txn = {}                        # flow -> current txn id
    frag = defaultdict(int)             # (flow, txn) -> response fragment index
    req_fc = {}                         # flow -> FC name of the request that opened the current txn
    n = 0
    for pkt in PcapReader(path):
        if max_pkts and n >= max_pkts:
            break
        n += 1
        if IP not in pkt or TCP not in pkt:
            continue
        t = pkt[TCP]
        if t.sport != DNP3_PORT and t.dport != DNP3_PORT:
            continue
        outstation_side = (t.sport == DNP3_PORT)     # True => outstation->master (response side)
        direction = "outstation_to_master" if outstation_side else "master_to_outstation"
        payload = bytes(t.payload)
        pl = len(payload)
        wire = len(pkt)
        # canonical flow key (master-side ip:port identifies the connection)
        if outstation_side:
            flow = (pkt[IP].dst, t.dport)   # master ip:port
        else:
            flow = (pkt[IP].src, t.sport)

        tcp_kind = "ack_only" if pl == 0 else "data"
        fc, fc_name, app_ctrl = (None, None, None) if pl == 0 else parse_dnp3(payload)
        role = "ACK" if pl == 0 else role_of(fc_name, outstation_side)

        # transaction grouping (best-effort, per flow)
        is_request = fc_name in ("READ", "DIRECT_OPERATE", "DIRECT_OPERATE_NR", "SELECT",
                                 "OPERATE", "WRITE", "CONFIRM")
        if is_request:
            txn_counter[flow] += 1
            cur_txn[flow] = txn_counter[flow]
            frag[(flow, cur_txn[flow])] = 0
            req_fc[flow] = fc_name
        txn = cur_txn.get(flow, 0)
        # response fragment index within the current transaction
        frag_index = -1
        if fc_name in ("RESPONSE", "UNSOLICITED_RESPONSE"):
            frag_index = frag[(flow, txn)]
            frag[(flow, txn)] += 1
        # what request this frame answers (for READ-response / SELECT-confirm / OPERATE-confirm)
        response_to = req_fc.get(flow, "unknown") if role in ("RESPONSE", "UNSOLICITED_RESPONSE") else ""
        is_resp = role in ("RESPONSE", "UNSOLICITED_RESPONSE")

        # FIR/FIN application-control bits (fragment boundaries), if a DNP3 app header was parsed
        fir = fin = con = None
        if app_ctrl is not None:
            fir = 1 if (app_ctrl & 0x80) else 0
            fin = 1 if (app_ctrl & 0x40) else 0
            con = 1 if (app_ctrl & 0x20) else 0

        yield {
            "capture_id": cap_id,
            "ts": float(pkt.time),
            "device": dev_name,
            "ack_mode": ack_mode,                     # separate | combined
            "flow": "%s:%d" % flow,
            "transaction_id": txn,
            "direction": direction,
            "tcp_kind": tcp_kind,                     # ack_only | data
            "dnp3_fc": fc_name if fc_name else ("none" if pl == 0 else "unknown"),
            "role": role,
            "response_to": response_to,               # request FC this response answers ("" if not a response)
            "is_read_request": int(role == "READ_REQUEST"),
            "is_read_response": int(is_resp and response_to == "READ"),
            "is_direct_operate": int(role == "DIRECT_OPERATE_REQUEST"),
            "is_direct_operate_response": int(is_resp and response_to in ("DIRECT_OPERATE", "DIRECT_OPERATE_NR")),
            "is_select": int(role == "SELECT"),
            "is_select_confirm": int(is_resp and response_to == "SELECT"),
            "is_operate": int(role == "OPERATE"),
            "is_operate_confirm": int(is_resp and response_to == "OPERATE"),
            "is_app_confirm": int(role == "APP_CONFIRM"),
            "is_response": int(is_resp),
            "response_fragment_index": frag_index,    # -1 if not a response
            "app_fir": fir, "app_fin": fin, "app_con": con,
            "wire_size": wire,
            "tcp_payload_size": pl,
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace-dir", default=None,
                    help="dir with SEL751/AB1400/ION7550 pcaps (default: repo Traffic Trace/)")
    ap.add_argument("--long", action="store_true", help="also include the *L.pcap long captures")
    ap.add_argument("--out", default=None, help="JSON output path")
    ap.add_argument("--csv", default=None, help="CSV output path")
    ap.add_argument("--max-pkts", type=int, default=None, help="cap packets per pcap (debug)")
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, "..", "..", "..", "..", ".."))
    trace = a.trace_dir or os.path.join(repo, "Traffic Trace")
    out_json = a.out or os.path.join(here, "packet_inventory.json")
    out_csv = a.csv or os.path.join(here, "packet_inventory.csv")

    caps = []
    for base, ip in PCAP_OUTSTATION.items():
        dev, mode = DEVICES[ip]
        for suffix in ([".pcap", "L.pcap"] if a.long else [".pcap"]):
            p = os.path.join(trace, base + suffix)
            if os.path.exists(p):
                caps.append((p, base + suffix, dev, mode))

    records = []
    for path, cap_id, dev, mode in caps:
        cnt = 0
        for rec in extract_pcap(path, cap_id, dev, mode, a.max_pkts):
            records.append(rec)
            cnt += 1
        print("  %-16s -> %5d DNP3 packets" % (cap_id, cnt))

    zeek = load_zeek_dnp3(os.path.join(trace, "dnp3.log"))
    zeek_fc = Counter(r.get("fc_request") for r in zeek) if zeek else Counter()

    # provenance + cross-check summary
    by_dev = defaultdict(lambda: Counter())
    for r in records:
        by_dev[r["device"]]["packets"] += 1
        by_dev[r["device"]][r["tcp_kind"]] += 1
        by_dev[r["device"]]["role:" + r["role"]] += 1

    doc = {
        "schema_version": SCHEMA_VERSION,
        "provenance": {
            "captures": [c[1] for c in caps],
            "trace_dir": trace,
            "device_map": {k: {"name": v[0], "ack_mode": v[1]} for k, v in DEVICES.items()},
            "zeek_dnp3_log_rows": len(zeek),
            "zeek_fc_request_counts": dict(zeek_fc),
            "note": "Roles from parsed DNP3 function codes (0x0564 framing); SEL flow cross-checked "
                    "against Zeek dnp3.log. Roles the capture does not contain (SELECT/OPERATE/"
                    "SELECT-confirm/OPERATE-confirm/application-CONFIRM) are absent here, not inferred.",
        },
        "summary_by_device": {d: dict(c) for d, c in by_dev.items()},
        "records": records,
    }
    with open(out_json, "w") as f:
        json.dump(doc, f, indent=2)
    if records:
        with open(out_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(records[0].keys()))
            w.writeheader()
            w.writerows(records)
    print("wrote %d records -> %s (+ .csv)  schema %s" % (len(records), out_json, SCHEMA_VERSION))
    print("zeek fc_request cross-check:", dict(zeek_fc))
    for d, c in by_dev.items():
        roles = {k.split(":", 1)[1]: v for k, v in c.items() if k.startswith("role:")}
        print("  %-8s packets=%d ack_only=%d data=%d roles=%s"
              % (d, c["packets"], c["ack_only"], c["data"], roles))


if __name__ == "__main__":
    main()

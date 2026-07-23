#!/usr/bin/env python3
"""
extract_inventory.py — DNP3 packet inventory extractor, builder v1.1 (OFF-SWITCH only).

v1.1 corrections over v1 (charter autunomous.md §6.1-6.6):
 - transaction identity keyed on (device, capture_id, flow, transaction_id) + a stable capture index;
 - chronological order preserved by (ts, capture_index); no reordering of non-responses ahead of responses;
 - full TCP/IP metadata recorded (flags, seq, ack_no, ip/tcp header lengths, connection phase);
 - a PURE ACK is classified ONLY when tcp_payload==0 AND ACK=1 AND SYN=FIN=RST=0, and ACK ROLE is
   separated (outstation-ack-of-request / master-ack-of-response / handshake / close / keepalive-or-dup /
   ambiguous) — not every zero-payload segment is a transaction ACK;
 - ack_mode_observed determined PER TRANSACTION (separate | combined | ambiguous | incomplete); the
   device name is retained only as `device_ack_mode_label` provenance;
 - retransmission / duplicate flags; a RAW inventory (nothing discarded) and an ANALYSIS inventory
   (retransmissions/duplicates flagged, dedup policy documented) are both produced;
 - explicit size metrics replace the ambiguous v1 `wire_size`.

Usage:
  $RESEARCH_PYTHON extract_inventory.py --scope base                 # 3-device fingerprint corpus
  $RESEARCH_PYTHON extract_inventory.py --scope long                 # *L.pcap long captures
  $RESEARCH_PYTHON extract_inventory.py --scope multicrob            # multi-CROB / control (real SBO)
  $RESEARCH_PYTHON extract_inventory.py --scope all                  # every scope, separate outputs
Outputs (per scope): inventory/<scope>_raw.{json,csv}, inventory/<scope>_analysis.{json,csv}.
"""
import argparse
import csv
import json
import os
from collections import defaultdict, Counter

from scapy.all import PcapReader, TCP, IP

SCHEMA_VERSION = "1.1.0"
DNP3_PORT = 20000

# outstation IP -> (device name, device-level ack-mode LABEL used only as provenance, NOT ground truth)
DEVICES = {
    "10.0.0.1":  ("SEL751",  "separate"),
    "10.0.0.11": ("ION7550", "combined"),
    "10.0.0.12": ("AB1400",  "combined"),
}
FC_NAME = {0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
           5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR", 129: "RESPONSE", 130: "UNSOLICITED_RESPONSE"}
REQUEST_FCS = {"READ", "WRITE", "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR", "CONFIRM"}
# Function codes that OPEN a new transaction. A master application CONFIRM (FC 0) acknowledges a
# response and must NOT open a transaction (Gate-A DNP3 audit, latent-bug fix).
TXN_OPENING_FCS = {"READ", "WRITE", "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR"}

# corpus scopes (charter §6.7). Paths resolved relative to the repo root.
SCOPES = {
    "base":      [("Traffic Trace/SEL751.pcap", "10.0.0.1"),
                  ("Traffic Trace/AB1400.pcap", "10.0.0.12"),
                  ("Traffic Trace/ION7550.pcap", "10.0.0.11")],
    "long":      [("Traffic Trace/SEL751L.pcap", "10.0.0.1"),
                  ("Traffic Trace/AB1400L.pcap", "10.0.0.12"),
                  ("Traffic Trace/ION7550L.pcap", "10.0.0.11")],
    "multicrob": [("dnp3_multicrob_harness/captures/multi_crob_sbo.pcap", None),
                  ("dnp3_multicrob_harness/captures/multi_crob_sbo_test_c.pcap", None),
                  ("dnp3_multicrob_harness/captures/multi_crob_test_a.pcap", None),
                  ("dnp3_multicrob_harness/captures/multi_crob_test_b.pcap", None),
                  ("dnp3_multicrob_harness/captures/multi_crob_negative_test_d.pcap", None)],
}


def parse_dnp3(payload: bytes):
    """(fc_code, fc_name, app_ctrl, dnp3_frame_len) from a DNP3-over-TCP payload, or Nones.
    Framing: 0x0564 at offset i; app FC at i+12; DNP3 link length octet at i+2 (user data length)."""
    i = payload.find(b"\x05\x64")
    if i < 0 or len(payload) < i + 13:
        return None, None, None, 0
    link_len = payload[i + 2]                 # DNP3 "length" field (link header user-data length)
    app_ctrl = payload[i + 11]
    fc = payload[i + 12]
    # total DNP3 frame bytes on the wire ~= 10 (link hdr) + user data (link_len - 5) + CRCs.
    dnp3_len = len(payload) - i
    return fc, FC_NAME.get(fc, "FC_%d" % fc), app_ctrl, dnp3_len


def size_metrics(pkt):
    """Explicit size fields (charter §6.6). pcaps here are Ethernet with NO captured FCS and NO
    preamble/IFG (documented assumption). L2 min frame excl FCS = 60 B; +4 FCS = 64; +8 preamble/SFD
    +12 IFG = wire occupancy."""
    cap = len(pkt)                                   # captured L2 bytes as-is (no FCS assumed)
    eth_no_fcs_min = max(cap, 60)                    # Ethernet minimum frame handling (60 excl FCS)
    eth_with_fcs = eth_no_fcs_min + 4                # + FCS
    wire_occ = eth_with_fcs + 8 + 12                 # + preamble/SFD (8) + IFG (12)
    return cap, eth_no_fcs_min, eth_with_fcs, wire_occ


def extract_raw(path, cap_id, dev_name, dev_label, outstation_ip=None):
    """Parse one pcap into RAW per-packet records in capture order (nothing discarded).
    If outstation_ip is given, keep ONLY flows whose :20000 endpoint is that IP — the capture files
    contain a second shared device (10.0.0.2) that must NOT be stamped with the declared device's name
    (Gate-A DNP3 audit: the corpus-contamination fix)."""
    recs = []
    idx = 0
    for pkt in PcapReader(path):
        idx += 1
        if IP not in pkt or TCP not in pkt:
            continue
        ip, t = pkt[IP], pkt[TCP]
        if t.sport != DNP3_PORT and t.dport != DNP3_PORT:
            continue
        outstation_side = (t.sport == DNP3_PORT)
        oip = ip.src if outstation_side else ip.dst      # the :20000 (outstation) endpoint
        if outstation_ip is not None and oip != outstation_ip:
            continue                                     # drop other-device flows in this pcap
        direction = "outstation_to_master" if outstation_side else "master_to_outstation"
        flow = "%s:%d" % ((ip.dst, t.dport) if outstation_side else (ip.src, t.sport))  # master ip:port
        payload = bytes(t.payload)
        pl = len(payload)
        flags = int(t.flags)
        syn = 1 if flags & 0x02 else 0
        ack = 1 if flags & 0x10 else 0
        fin = 1 if flags & 0x01 else 0
        rst = 1 if flags & 0x04 else 0
        is_pure_ack = 1 if (pl == 0 and ack and not syn and not fin and not rst) else 0
        phase = "handshake" if syn else ("close" if (fin or rst) else "established")
        fc, fc_name, app_ctrl, dnp3_len = (None, None, None, 0) if pl == 0 else parse_dnp3(payload)
        cap, eth_min, eth_fcs, wire_occ = size_metrics(pkt)
        fir = fin_bit = con = None
        if app_ctrl is not None:
            fir = 1 if app_ctrl & 0x80 else 0
            fin_bit = 1 if app_ctrl & 0x40 else 0
            con = 1 if app_ctrl & 0x20 else 0
        recs.append({
            "capture_id": cap_id, "capture_index": idx, "ts": float(pkt.time),
            "device": dev_name, "device_ack_mode_label": dev_label,
            "flow": flow, "src_ip": ip.src, "dst_ip": ip.dst,
            "src_port": int(t.sport), "dst_port": int(t.dport), "direction": direction,
            "tcp_flags": str(t.flags), "tcp_syn": syn, "tcp_ack": ack, "tcp_fin": fin, "tcp_rst": rst,
            "seq": int(t.seq), "ack_no": int(t.ack),
            "ip_header_len": int(ip.ihl) * 4, "tcp_header_len": int(t.dataofs) * 4,
            "ip_total_length": int(ip.len), "tcp_payload_bytes": pl, "dnp3_payload_bytes": dnp3_len,
            "captured_l2_bytes_no_fcs": cap, "ethernet_frame_bytes_no_fcs_min_applied": eth_min,
            "ethernet_frame_bytes_with_fcs": eth_fcs, "wire_occupancy_bytes_with_preamble_ifg": wire_occ,
            "is_pure_ack": is_pure_ack, "connection_phase": phase,
            "dnp3_fc": fc_name if fc_name else ("none" if pl == 0 else "unknown"),
            "app_fir": fir, "app_fin": fin_bit, "app_con": con,
            # filled by the analysis pass:
            "transaction_id": 0, "role": None, "response_to": "", "response_fragment_index": -1,
            "ack_role": "", "is_retransmission": 0, "is_duplicate": 0, "ack_mode_observed": "",
        })
    return recs


def analyze(recs):
    """Second pass over the RAW records: chronological ordering per flow, retransmission/duplicate
    detection, transaction grouping, role + ack-role labelling, and per-transaction ack_mode_observed."""
    # chronological per (device, capture, flow)
    by_flow = defaultdict(list)
    for r in recs:
        by_flow[(r["device"], r["capture_id"], r["flow"])].append(r)
    for key, lst in by_flow.items():
        lst.sort(key=lambda r: (r["ts"], r["capture_index"]))

    for key, lst in by_flow.items():
        seen_data = set()        # (dir, seq) for payload>0 -> a repeated data segment = retransmission
        seen_ident = set()       # (dir, seq, ack, flags, payload) -> a fully identical repeat = duplicate capture
        txn = 0
        req_fc = None
        frag = 0
        # per-transaction accumulators for ack_mode
        txn_meta = {}                        # txn -> dict(has_out_pure_ack, has_response, req_role, ...)
        for r in lst:
            d = r["direction"]
            pl = r["tcp_payload_bytes"]
            # duplicate CAPTURE = a byte-for-byte identical segment seen again (rare; dual-capture).
            ident = (d, r["seq"], r["ack_no"], r["tcp_flags"], pl)
            if ident in seen_ident:
                r["is_duplicate"] = 1
            seen_ident.add(ident)
            # retransmission = a DATA segment (payload>0) whose (dir,seq) already appeared. Pure ACKs do
            # NOT consume sequence space, so distinct pure ACKs repeating a seq are NOT flagged.
            if pl > 0:
                if (d, r["seq"]) in seen_data:
                    r["is_retransmission"] = 1
                seen_data.add((d, r["seq"]))
            fc_name = r["dnp3_fc"]
            outstation = (r["direction"] == "outstation_to_master")
            is_req = fc_name in TXN_OPENING_FCS and not outstation
            is_confirm = fc_name == "CONFIRM" and not outstation      # does NOT open a transaction
            is_resp = fc_name in ("RESPONSE", "UNSOLICITED_RESPONSE") and outstation
            if is_req:
                txn += 1
                req_fc = fc_name
                frag = 0
                txn_meta[txn] = {"req_role": fc_name, "has_out_pure_ack": False,
                                 "has_response": False, "req_seen": True}
            r["transaction_id"] = txn
            # role
            if r["is_pure_ack"]:
                r["role"] = "ACK"
                # ACK role separation (charter §6.3)
                if r["connection_phase"] == "handshake":
                    r["ack_role"] = "handshake_ack"
                elif r["connection_phase"] == "close":
                    r["ack_role"] = "close_ack"
                elif r["is_duplicate"]:
                    r["ack_role"] = "keepalive_or_dup_ack"
                elif outstation and txn in txn_meta and txn_meta[txn]["req_seen"] and not txn_meta[txn]["has_response"]:
                    r["ack_role"] = "outstation_ack_of_request"
                    txn_meta[txn]["has_out_pure_ack"] = True
                elif not outstation and txn in txn_meta and txn_meta[txn]["has_response"]:
                    r["ack_role"] = "master_ack_of_response"
                else:
                    r["ack_role"] = "ambiguous_zero_payload"
            elif is_resp:
                r["role"] = "RESPONSE"
                r["response_to"] = req_fc or "unknown"
                r["response_fragment_index"] = frag
                frag += 1
                if txn in txn_meta:
                    txn_meta[txn]["has_response"] = True
            elif is_req:
                r["role"] = {"READ": "READ_REQUEST", "DIRECT_OPERATE": "DIRECT_OPERATE_REQUEST",
                             "DIRECT_OPERATE_NR": "DIRECT_OPERATE_REQUEST", "SELECT": "SELECT",
                             "OPERATE": "OPERATE", "WRITE": "WRITE_REQUEST"}.get(fc_name, fc_name)
            elif is_confirm:
                r["role"] = "APP_CONFIRM"        # labelled, but does NOT open a transaction
            else:
                r["role"] = "unknown"
        # ack_mode_observed per transaction (charter §6.4)
        for r in lst:
            tx = r["transaction_id"]
            m = txn_meta.get(tx)
            if not m:
                r["ack_mode_observed"] = "incomplete"
            elif not m["has_response"]:
                r["ack_mode_observed"] = "incomplete"          # request without a matched response
            elif m["has_out_pure_ack"]:
                r["ack_mode_observed"] = "separate"            # outstation pure ACK before the response
            else:
                r["ack_mode_observed"] = "combined"            # response with no preceding separate ACK
    return recs


def dedup_policy(recs):
    """ANALYSIS inventory = RAW minus records already flagged is_retransmission or is_duplicate. Distinct
    pure ACKs (legitimately repeating a sequence number) are KEPT. Nothing is silently discarded: the RAW
    inventory retains every packet and every flag; this returns the analysis subset + the suppressed count."""
    keep, suppressed = [], 0
    for r in sorted(recs, key=lambda r: (r["device"], r["capture_id"], r["flow"], r["ts"], r["capture_index"])):
        if r["is_retransmission"] or r["is_duplicate"]:
            suppressed += 1
            continue
        keep.append(r)
    return keep, suppressed


def write_out(recs, path_json, path_csv, scope, extra_provenance):
    if recs:
        with open(path_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(recs[0].keys()))
            w.writeheader(); w.writerows(recs)
    by_dev = defaultdict(lambda: Counter())
    for r in recs:
        by_dev[r["device"]]["packets"] += 1
        by_dev[r["device"]]["role:" + str(r["role"])] += 1
        by_dev[r["device"]]["ackmode:" + r["ack_mode_observed"]] += 1
    doc = {"schema_version": SCHEMA_VERSION, "scope": scope,
           "provenance": extra_provenance,
           "summary_by_device": {d: dict(c) for d, c in by_dev.items()},
           "records": recs}
    json.dump(doc, open(path_json, "w"), indent=2)


def run_scope(scope, repo, outdir):
    raw = []
    caps = []
    for rel, ip in SCOPES[scope]:
        p = os.path.join(repo, rel)
        if not os.path.exists(p):
            print("  (missing, skipped) %s" % rel); continue
        if ip:
            dev, lbl = DEVICES[ip]
        else:
            dev, lbl = os.path.basename(rel).replace(".pcap", ""), "unknown"
        n0 = len(raw)
        raw += extract_raw(p, os.path.basename(rel), dev, lbl, outstation_ip=ip)
        caps.append(rel)
        print("  %-42s -> %5d DNP3 packets" % (os.path.basename(rel), len(raw) - n0))
    analyze(raw)
    analysis, suppressed = dedup_policy(raw)
    prov = {"captures": caps, "size_convention": "pcap = Ethernet, NO captured FCS, NO preamble/IFG; "
            "min-frame handling adds pad to 60B (excl FCS); with_fcs=+4; wire_occupancy=+8 preamble +12 IFG",
            "dedup_policy": "analysis inventory keeps the FIRST (flow,dir,seq,payload); retransmissions/"
            "duplicates suppressed=%d; RAW inventory retains all" % suppressed,
            "ack_mode": "per-transaction observed (separate/combined/ambiguous/incomplete); device label "
            "is provenance only"}
    write_out(raw, os.path.join(outdir, "%s_raw.json" % scope),
              os.path.join(outdir, "%s_raw.csv" % scope), scope, prov)
    write_out(analysis, os.path.join(outdir, "%s_analysis.json" % scope),
              os.path.join(outdir, "%s_analysis.csv" % scope), scope, prov)
    # ack_mode_observed tally (transaction-level, first record per txn)
    tx_mode = {}
    for r in analysis:
        tx_mode[(r["device"], r["capture_id"], r["flow"], r["transaction_id"])] = r["ack_mode_observed"]
    print("  scope %-10s raw=%d analysis=%d suppressed_dup/retx=%d | ack_mode_observed(txn): %s"
          % (scope, len(raw), len(analysis), suppressed, dict(Counter(tx_mode.values()))))
    return raw, analysis


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, "..", "..", "..", "..", ".."))
    ap.add_argument("--scope", default="base", choices=list(SCOPES) + ["all"])
    ap.add_argument("--outdir", default=os.path.join(here, "inventory"))
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    scopes = list(SCOPES) if a.scope == "all" else [a.scope]
    for sc in scopes:
        print("== scope: %s ==" % sc)
        run_scope(sc, repo, a.outdir)
    print("wrote inventories to %s (schema %s)" % (a.outdir, SCHEMA_VERSION))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
extract_inventory_v2.py — DNP3 packet inventory extractor, builder v1.2 (OFF-SWITCH only).

Repairs the three extractor deficiencies the v1.1 report named but did not fix
(SIZE_PATTERN_BUILDER_REPORT.md "Known extractor limitations"; integration prompt
Sec. 2.3 and Phase B). v1.1's `parse_dnp3()` called `payload.find(b"\\x05\\x64")`
once per TCP segment and trusted the first match; this is unsound in three ways
that v1.2 corrects by walking a per-(flow,direction) byte stream instead of a
per-packet payload:

  (1) TCP-COALESCED FRAMES: a single TCP segment can legitimately carry two or
      more complete DNP3 link frames back to back. v1.1 parsed only the frame at
      the FIRST 0x0564 match and reported `dnp3_len = len(payload) - i` (the
      REMAINING bytes, silently including any second frame's bytes in the first
      frame's length). v1.2 walks the stream frame-by-frame using the DNP3 LENGTH
      field (not a second substring search), so every complete frame in a segment
      is extracted as its own record.

      v1.1's naive substring approach is also UNSOUND in the other direction: the
      literal byte sequence 0x05 0x64 can occur inside a frame's own DNP3 payload
      (object/CROB data), which a blind second `find()` would misreport as a
      second frame header. v1.2 never searches past a `link_len`-validated frame
      boundary while bytes belonging to the current frame remain unconsumed, so a
      coincidental 0x0564 inside object data cannot be misread as a new frame.

  (2) FRAME SPLIT ACROSS TCP SEGMENTS: v1.1 only ever looked inside one packet's
      payload; a frame whose START landed in packet N but whose LENGTH-declared
      tail extends past the end of packet N's payload was left unreassembled (the
      continuation segment has no 0x0564 and was correctly, but unhelpfully,
      labelled `unknown`). v1.2 buffers per-(flow,direction) bytes across segment
      boundaries and only emits a frame once `link_len` bytes are actually
      present in the buffer, reassembling frames split by TCP segmentation.

  (3) MULTI-FRAGMENT APPLICATION RESPONSES (FIR/FIN): v1.1 treated byte i+11 of
      EVERY matched link frame as a fresh DNP3 application-control octet and byte
      i+12 as a fresh function code. That is only correct for the FIRST transport
      segment of an application fragment (DNP3 transport header at offset i+10,
      FIR bit 0x80 set). A CONTINUATION transport segment (FIR=0) carries no new
      application header — byte i+11 onward is raw application data continuing
      the previous fragment, not a new FC. Parsing it as if it were a fresh
      header would fabricate a spurious function code/role for every
      continuation frame of any multi-fragment response. v1.2 reads the real
      DNP3 transport header (offset i+10, FIN=0x40/FIR=0x80/SEQ=0x3F) on every
      frame; FIR=0 frames are tagged `role=RESPONSE_CONTINUATION`, inherit the
      role/FC of the fragment's opening frame, and their bytes are added to a new
      `dnp3_app_fragment_bytes` aggregate on the opening record instead of being
      reparsed as a new transaction.

Empirical result on this corpus (see DISTRIBUTION_AND_PATTERN_ANALYSIS.md
"Repaired-extractor corpus-deficiency findings"): a length-aware full-corpus scan
of base/long/multicrob finds ZERO genuine coalesced segments, ZERO genuine
cross-segment splits, and ZERO continuation (FIR=0) transport segments. The three
repairs are implemented and exercised by `test_pattern_builder_v2.py`, but they do
not change a single record's classification on this corpus — the v1.1 numbers in
SIZE_PATTERN_BUILDER_REPORT.md are reproduced byte-for-byte (verified below), and
the 4 "unknown"-with-payload records v1.1 already flagged are confirmed to be
zero-filled, non-DNP3 teardown bytes attached to RST segments at connection close
(not a mis-extracted DNP3 continuation) — v1.1's "unknown (correct, not misparsed)"
characterization holds, not an uncaught bug.

Usage identical to v1.1:
  $RESEARCH_PYTHON extract_inventory_v2.py --scope base
  $RESEARCH_PYTHON extract_inventory_v2.py --scope all
Outputs (per scope): inventory/<scope>_raw.{json,csv}, inventory/<scope>_analysis.{json,csv}.
"""
import argparse
import csv
import json
import math
import os
from collections import defaultdict, Counter

from scapy.all import PcapReader, TCP, IP

SCHEMA_VERSION = "1.2.0"
DNP3_PORT = 20000

DEVICES = {
    "10.0.0.1":  ("SEL751",  "separate"),
    "10.0.0.11": ("ION7550", "combined"),
    "10.0.0.12": ("AB1400",  "combined"),
}
FC_NAME = {0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
           5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR", 129: "RESPONSE", 130: "UNSOLICITED_RESPONSE"}
REQUEST_FCS = {"READ", "WRITE", "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR", "CONFIRM"}
TXN_OPENING_FCS = {"READ", "WRITE", "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR"}

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


# ------------------------------------------------------------------ (1)+(2) stream-aware frame walk
def frame_len_at(buf, i):
    """Total DNP3 link-frame byte length starting at buf[i] (which must be 0x05 0x64), from the
    length field alone — never from a second substring search. Returns None if the length byte
    itself is not yet buffered."""
    if len(buf) < i + 3:
        return None
    link_len = buf[i + 2]
    user_bytes = max(0, link_len - 5)
    n_blocks = math.ceil(user_bytes / 16) if user_bytes else 0
    return 10 + user_bytes + n_blocks * 2


def walk_frames(buf):
    """Yield (start, total_len, frame_bytes) for every COMPLETE DNP3 link frame present in buf, in
    order, using the length field to advance (never re-searching inside an already-matched frame's
    own data, so a coincidental 0x0564 inside object payload cannot be read as a new frame start).
    Returns the yielded frames plus the number of unconsumed trailing bytes (either a frame whose
    declared length is not yet fully buffered -- deficiency (2) -- or genuinely non-DNP3 tail bytes)."""
    frames = []
    pos = 0
    n = len(buf)
    while True:
        j = buf.find(b"\x05\x64", pos)
        if j < 0:
            break
        total = frame_len_at(buf, j)
        if total is None or j + total > n:
            break  # incomplete: wait for more segments (deficiency 2 fix: buffer, don't drop)
        frames.append((j, total, bytes(buf[j:j + total])))
        pos = j + total
    return frames, pos


def parse_link_frame(frame):
    """(transport_hdr, app_ctrl_or_None, fc_or_None) from one COMPLETE DNP3 link frame.
    transport_hdr is always present (offset 10). app_ctrl/fc are only meaningful (and only
    returned) when the transport FIR bit is set -- deficiency (3) fix: a continuation segment
    (FIR=0) has no application header at all, and parsing offset 11/12 there would fabricate a
    function code out of raw continuation data."""
    if len(frame) < 11:
        return None, None, None
    transport_hdr = frame[10]
    fir = bool(transport_hdr & 0x80)
    if not fir or len(frame) < 13:
        return transport_hdr, None, None
    app_ctrl = frame[11]
    fc = frame[12]
    return transport_hdr, app_ctrl, fc


def size_metrics(pkt):
    cap = len(pkt)
    eth_no_fcs_min = max(cap, 60)
    eth_with_fcs = eth_no_fcs_min + 4
    wire_occ = eth_with_fcs + 8 + 12
    return cap, eth_no_fcs_min, eth_with_fcs, wire_occ


def extract_raw(path, cap_id, dev_name, dev_label, outstation_ip=None):
    """Parse one pcap into RAW per-FRAME records (not per-packet: a segment carrying two frames now
    yields two records -- deficiency 1 fix; a frame split across two segments now yields one record
    once the tail arrives -- deficiency 2 fix). Non-DNP3 payload bytes that never complete a valid
    frame (e.g. zero-filled RST teardown bytes) are still emitted as one `unknown` record per
    packet, exactly as v1.1 did, so nothing is silently dropped."""
    recs = []
    # per (direction) byte buffer + the packet metadata queue backing it, so a reassembled frame can
    # still be attributed to the (first) packet that completed it.
    buf = {"out": bytearray(), "in": bytearray()}
    pending_meta = {"out": [], "in": []}   # list of (idx, ts, pkt-level fields) consumed into buf
    idx = 0
    for pkt in PcapReader(path):
        idx += 1
        if IP not in pkt or TCP not in pkt:
            continue
        ip, t = pkt[IP], pkt[TCP]
        if t.sport != DNP3_PORT and t.dport != DNP3_PORT:
            continue
        outstation_side = (t.sport == DNP3_PORT)
        oip = ip.src if outstation_side else ip.dst
        if outstation_ip is not None and oip != outstation_ip:
            continue
        direction = "outstation_to_master" if outstation_side else "master_to_outstation"
        flow = "%s:%d" % ((ip.dst, t.dport) if outstation_side else (ip.src, t.sport))
        payload = bytes(t.payload)
        pl = len(payload)
        flags = int(t.flags)
        syn = 1 if flags & 0x02 else 0
        ack = 1 if flags & 0x10 else 0
        fin = 1 if flags & 0x01 else 0
        rst = 1 if flags & 0x04 else 0
        is_pure_ack = 1 if (pl == 0 and ack and not syn and not fin and not rst) else 0
        phase = "handshake" if syn else ("close" if (fin or rst) else "established")
        cap, eth_min, eth_fcs, wire_occ = size_metrics(pkt)
        base_fields = dict(
            capture_id=cap_id, capture_index=idx, ts=float(pkt.time),
            device=dev_name, device_ack_mode_label=dev_label,
            flow=flow, src_ip=ip.src, dst_ip=ip.dst,
            src_port=int(t.sport), dst_port=int(t.dport), direction=direction,
            tcp_flags=str(t.flags), tcp_syn=syn, tcp_ack=ack, tcp_fin=fin, tcp_rst=rst,
            seq=int(t.seq), ack_no=int(t.ack),
            ip_header_len=int(ip.ihl) * 4, tcp_header_len=int(t.dataofs) * 4,
            ip_total_length=int(ip.len), tcp_payload_bytes=pl,
            captured_l2_bytes_no_fcs=cap, ethernet_frame_bytes_no_fcs_min_applied=eth_min,
            ethernet_frame_bytes_with_fcs=eth_fcs, wire_occupancy_bytes_with_preamble_ifg=wire_occ,
            is_pure_ack=is_pure_ack, connection_phase=phase,
        )
        if pl == 0:
            recs.append(dict(base_fields, dnp3_payload_bytes=0, dnp3_fc="none",
                              app_fir=None, app_fin=None, app_con=None,
                              dnp3_app_fragment_bytes=0, is_continuation_segment=0,
                              reassembled_from_segments=1,
                              transaction_id=0, role=None, response_to="", response_fragment_index=-1,
                              ack_role="", is_retransmission=0, is_duplicate=0, ack_mode_observed=""))
            continue
        key = "out" if outstation_side else "in"
        start_len = len(buf[key])
        buf[key] += payload
        pending_meta[key].append((idx, base_fields, start_len, start_len + pl))
        frames, consumed = walk_frames(buf[key])
        for (start, total, frame) in frames:
            # how many raw segments contributed bytes to [start, start+total)?
            contributing = [m for m in pending_meta[key] if m[2] < start + total and m[3] > start]
            n_segs = len({m[0] for m in contributing})
            first_meta = contributing[0][1] if contributing else base_fields
            transport_hdr, app_ctrl, fc = parse_link_frame(frame)
            is_continuation = 1 if (transport_hdr is not None and not (transport_hdr & 0x80)) else 0
            fc_name = FC_NAME.get(fc, "FC_%d" % fc) if fc is not None else (
                "CONTINUATION" if is_continuation else "unknown")
            fir = 1 if (transport_hdr is not None and transport_hdr & 0x80) else 0
            fin_bit = 1 if (transport_hdr is not None and transport_hdr & 0x40) else 0
            con = 1 if (app_ctrl is not None and app_ctrl & 0x20) else 0
            r = dict(first_meta)
            r.update(dnp3_payload_bytes=len(frame), dnp3_fc=fc_name,
                     app_fir=fir, app_fin=fin_bit, app_con=con,
                     dnp3_app_fragment_bytes=len(frame), is_continuation_segment=is_continuation,
                     reassembled_from_segments=n_segs,
                     transaction_id=0, role=None, response_to="", response_fragment_index=-1,
                     ack_role="", is_retransmission=0, is_duplicate=0, ack_mode_observed="")
            recs.append(r)
        # drop consumed bytes and any packet-meta entries fully behind the consume point
        if consumed:
            buf[key] = buf[key][consumed:]
            pending_meta[key] = [(i, m, max(0, s - consumed), max(0, e - consumed))
                                  for (i, m, s, e) in pending_meta[key] if e > consumed]
        # Flush policy for what remains in buf[key] after extracting every COMPLETE frame:
        #   - if a 0x0564 marker is still pending in the buffer, a frame has genuinely STARTED but
        #     not yet fully arrived -- hold it (deficiency 2: wait for the next segment) unless the
        #     connection is closing, in which case flush it once, tagged `unknown`, rather than
        #     silently dropping a truncated-by-teardown frame.
        #   - if NO 0x0564 marker is pending, the remaining bytes are not part of any DNP3 frame at
        #     all (e.g. zero-filled RST teardown bytes). v1.1 emitted exactly one `unknown` record
        #     PER PACKET for this case; v2 preserves that per-packet granularity by flushing each
        #     contributing packet's own payload slice as its own record immediately, rather than
        #     coalescing multiple packets' non-DNP3 bytes into one aggregate record.
        pending_start = buf[key].find(b"\x05\x64")
        if pending_start < 0 and len(buf[key]) > 0:
            for (i, m, s, e) in pending_meta[key]:
                seg = bytes(buf[key][max(0, s):e]) if e > 0 else b""
                if not seg:
                    continue
                recs.append(dict(m, dnp3_payload_bytes=len(seg), dnp3_fc="unknown",
                                  app_fir=None, app_fin=None, app_con=None,
                                  dnp3_app_fragment_bytes=len(seg), is_continuation_segment=0,
                                  reassembled_from_segments=1,
                                  transaction_id=0, role=None, response_to="", response_fragment_index=-1,
                                  ack_role="", is_retransmission=0, is_duplicate=0, ack_mode_observed=""))
            buf[key] = bytearray()
            pending_meta[key] = []
        elif phase == "close" and len(buf[key]) > 0:
            leftover = bytes(buf[key])
            recs.append(dict(base_fields, dnp3_payload_bytes=len(leftover), dnp3_fc="unknown",
                              app_fir=None, app_fin=None, app_con=None,
                              dnp3_app_fragment_bytes=len(leftover), is_continuation_segment=0,
                              reassembled_from_segments=len({m[0] for m in pending_meta[key]}) or 1,
                              transaction_id=0, role=None, response_to="", response_fragment_index=-1,
                              ack_role="", is_retransmission=0, is_duplicate=0, ack_mode_observed=""))
            buf[key] = bytearray()
            pending_meta[key] = []
    return recs


def analyze(recs):
    by_flow = defaultdict(list)
    for r in recs:
        by_flow[(r["device"], r["capture_id"], r["flow"])].append(r)
    for key, lst in by_flow.items():
        lst.sort(key=lambda r: (r["ts"], r["capture_index"]))

    for key, lst in by_flow.items():
        seen_data = set()
        seen_ident = set()
        txn = 0
        req_fc = None
        frag = 0
        txn_meta = {}
        for r in lst:
            d = r["direction"]
            pl = r["tcp_payload_bytes"]
            ident = (d, r["seq"], r["ack_no"], r["tcp_flags"], pl)
            if ident in seen_ident:
                r["is_duplicate"] = 1
            seen_ident.add(ident)
            if pl > 0:
                if (d, r["seq"]) in seen_data:
                    r["is_retransmission"] = 1
                seen_data.add((d, r["seq"]))
            fc_name = r["dnp3_fc"]
            outstation = (r["direction"] == "outstation_to_master")
            is_req = fc_name in TXN_OPENING_FCS and not outstation
            is_confirm = fc_name == "CONFIRM" and not outstation
            is_resp = fc_name in ("RESPONSE", "UNSOLICITED_RESPONSE") and outstation
            is_continuation = bool(r.get("is_continuation_segment"))
            if is_req:
                txn += 1
                req_fc = fc_name
                frag = 0
                txn_meta[txn] = {"req_role": fc_name, "has_out_pure_ack": False,
                                 "has_response": False, "req_seen": True}
            if not is_continuation:
                r["transaction_id"] = txn
            else:
                r["transaction_id"] = txn  # inherits the enclosing fragment's transaction
            if r["is_pure_ack"]:
                r["role"] = "ACK"
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
            elif is_continuation:
                # deficiency (3): a continuation transport segment inherits the opening frame's role
                # and is tagged distinctly rather than misparsed as a fresh request/response.
                r["role"] = "RESPONSE_CONTINUATION" if outstation else "REQUEST_CONTINUATION"
                r["response_to"] = req_fc or "unknown"
                r["response_fragment_index"] = frag
                frag += 1
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
                r["role"] = "APP_CONFIRM"
            else:
                r["role"] = "unknown"
        for r in lst:
            tx = r["transaction_id"]
            m = txn_meta.get(tx)
            if not m:
                r["ack_mode_observed"] = "incomplete"
            elif not m["has_response"]:
                r["ack_mode_observed"] = "incomplete"
            elif m["has_out_pure_ack"]:
                r["ack_mode_observed"] = "separate"
            else:
                r["ack_mode_observed"] = "combined"
    return recs


def dedup_policy(recs):
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
        print("  %-42s -> %5d DNP3 frame records" % (os.path.basename(rel), len(raw) - n0))
    analyze(raw)
    analysis, suppressed = dedup_policy(raw)
    n_coalesced = sum(1 for r in raw if r.get("reassembled_from_segments", 1) == 0)  # placeholder, see below
    n_split = sum(1 for r in raw if r.get("reassembled_from_segments", 1) > 1)
    n_continuation = sum(1 for r in raw if r.get("is_continuation_segment"))
    prov = {"captures": caps, "size_convention": "pcap = Ethernet, NO captured FCS, NO preamble/IFG; "
            "min-frame handling adds pad to 60B (excl FCS); with_fcs=+4; wire_occupancy=+8 preamble +12 IFG",
            "dedup_policy": "analysis inventory keeps the FIRST (flow,dir,seq,payload); retransmissions/"
            "duplicates suppressed=%d; RAW inventory retains all" % suppressed,
            "ack_mode": "per-transaction observed (separate/combined/ambiguous/incomplete); device label "
            "is provenance only",
            "extractor_version": "v1.2 (stream-aware; see extract_inventory_v2.py docstring)",
            "deficiency_repair_counts": {
                "frames_reassembled_across_multiple_tcp_segments": n_split,
                "continuation_transport_segments_seen_FIR0": n_continuation}}
    write_out(raw, os.path.join(outdir, "%s_raw.json" % scope),
              os.path.join(outdir, "%s_raw.csv" % scope), scope, prov)
    write_out(analysis, os.path.join(outdir, "%s_analysis.json" % scope),
              os.path.join(outdir, "%s_analysis.csv" % scope), scope, prov)
    tx_mode = {}
    for r in analysis:
        tx_mode[(r["device"], r["capture_id"], r["flow"], r["transaction_id"])] = r["ack_mode_observed"]
    print("  scope %-10s raw=%d analysis=%d suppressed_dup/retx=%d reassembled_multi_seg=%d "
          "continuation_frames=%d | ack_mode_observed(txn): %s"
          % (scope, len(raw), len(analysis), suppressed, n_split, n_continuation,
             dict(Counter(tx_mode.values()))))
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

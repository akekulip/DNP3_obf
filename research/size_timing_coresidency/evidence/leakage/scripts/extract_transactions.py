"""Transaction-level feature extraction from the six device captures.

Produces one row per DNP3 request/response transaction with an explicitly
partitioned feature set:

  size     -- everything derived from byte counts / segment counts
  timing   -- everything derived from packet timestamps
  stack    -- TCP/IP stack fingerprint (TTL, MSS, window, options, DF, TOS, dataofs)
  ackmode  -- separate-vs-combined ACK structure (categorical)
  dpi      -- DNP3 payload content (function codes, IIN, object headers)

A transaction starts at a master->outstation packet carrying payload and ends at
the packet before the next such packet. All outstation->master packets in between
belong to it (pure ACKs and data segments).

Also emits the concatenated outstation response payload (hex) per transaction so
the split / grid transforms can be applied offline downstream.

Read-only over "Traffic Trace/". Writes only under evidence/leakage/out/.
"""

import json
import os
import sys
from collections import Counter, defaultdict

import pandas as pd
from scapy.all import PcapReader, IP, TCP

PCAP_DIR = "/home/philip/Projects/DNP3/Traffic Trace"
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")

# pcap -> (device label, real-device outstation IP).  The second flow in every
# capture terminates on 10.0.0.2, a software outstation replica present in all
# six captures; it is NOT the physical device.
CAPTURES = [
    ("SEL751.pcap",   "SEL751",  "10.0.0.1"),
    ("SEL751L.pcap",  "SEL751",  "10.0.0.1"),
    ("AB1400.pcap",   "AB1400",  "10.0.0.12"),
    ("AB1400L.pcap",  "AB1400",  "10.0.0.12"),
    ("ION7550.pcap",  "ION7550", "10.0.0.11"),
    ("ION7550L.pcap", "ION7550", "10.0.0.11"),
]
TWIN_IP = "10.0.0.2"
DNP3_PORT = 20000
START_BYTES = b"\x05\x64"


def tcp_payload(pkt):
    """Payload bytes bounded by ip.len (avoids Ethernet trailer padding)."""
    ip, tcp = pkt[IP], pkt[TCP]
    n = ip.len - ip.ihl * 4 - tcp.dataofs * 4
    if n <= 0:
        return b""
    raw = bytes(tcp.payload)
    return raw[:n]


def opt_summary(tcp):
    kinds = []
    mss = wscale = None
    sackok = ts = False
    for name, val in tcp.options:
        kinds.append(str(name))
        if name == "MSS":
            mss = val
        elif name == "WScale":
            wscale = val
        elif name == "SAckOK":
            sackok = True
        elif name == "Timestamp":
            ts = True
    return {
        "opt_kinds": "|".join(kinds),
        "mss": mss,
        "wscale": wscale,
        "sackok": int(sackok),
        "tsopt": int(ts),
        "n_opts": len(kinds),
    }


def dnp3_fields(payload):
    """Minimal DNP3 link/transport/application decode of the first link frame."""
    out = {"dnp3_valid": 0, "dnp3_len": None, "dnp3_dst": None, "dnp3_src": None,
           "dnp3_fir": None, "dnp3_fin": None, "dnp3_appseq": None,
           "dnp3_fc": None, "dnp3_iin": None, "dnp3_nframes": 0,
           "dnp3_user_bytes": 0}
    if len(payload) < 13 or payload[0:2] != START_BYTES:
        return out
    out["dnp3_valid"] = 1
    out["dnp3_len"] = payload[2]
    out["dnp3_dst"] = payload[4] | (payload[5] << 8)
    out["dnp3_src"] = payload[6] | (payload[7] << 8)
    transport = payload[10]
    out["dnp3_fir"] = int(bool(transport & 0x40))
    out["dnp3_fin"] = int(bool(transport & 0x80))
    out["dnp3_appseq"] = payload[11] & 0x0F
    out["dnp3_fc"] = payload[12]
    if payload[12] == 0x81 and len(payload) >= 15:
        out["dnp3_iin"] = (payload[13] << 8) | payload[14]
    # count link frames and total user bytes across the concatenated stream
    off, nframes, user = 0, 0, 0
    n = len(payload)
    while off + 10 <= n and payload[off:off + 2] == START_BYTES:
        ln = payload[off + 2]
        ubytes = ln - 5
        if ubytes < 0:
            break
        nblocks = (ubytes + 15) // 16
        flen = 10 + ubytes + 2 * nblocks
        nframes += 1
        user += ubytes
        off += flen
    out["dnp3_nframes"] = nframes
    out["dnp3_user_bytes"] = user
    return out


def extract_capture(pcap, device, real_ip):
    path = os.path.join(PCAP_DIR, pcap)
    # group packets by flow
    flows = defaultdict(list)
    with PcapReader(path) as rd:
        for i, pkt in enumerate(rd):
            if IP not in pkt or TCP not in pkt:
                continue
            ip, tcp = pkt[IP], pkt[TCP]
            if tcp.sport != DNP3_PORT and tcp.dport != DNP3_PORT:
                continue
            if tcp.dport == DNP3_PORT:
                out_ip, out_port, mst_ip, mst_port = ip.dst, tcp.dport, ip.src, tcp.sport
                direction = "req"
            else:
                out_ip, out_port, mst_ip, mst_port = ip.src, tcp.sport, ip.dst, tcp.dport
                direction = "resp"
            key = (mst_ip, mst_port, out_ip, out_port)
            o = opt_summary(tcp)
            flows[key].append({
                "idx": i, "t": float(pkt.time), "dir": direction,
                "ttl": ip.ttl, "tos": ip.tos, "df": int(bool(ip.flags & 0x02)),
                "ipid": ip.id, "win": tcp.window, "dataofs": tcp.dataofs,
                "flags": int(tcp.flags), "payload": tcp_payload(pkt), **o,
            })

    rows = []
    payloads = {}
    for (mst_ip, mst_port, out_ip, out_port), pkts in flows.items():
        pkts.sort(key=lambda p: (p["t"], p["idx"]))
        role = "real" if out_ip == real_ip else ("twin" if out_ip == TWIN_IP else "other")
        flow_id = "%s|%s:%d>%s:%d" % (pcap, mst_ip, mst_port, out_ip, out_port)
        # handshake-derived stack facts, when the SYN-ACK is in the capture
        syn_mss = syn_win = syn_ws = None
        syn_kinds = ""
        syn_sackok = syn_ts = None
        for p in pkts:
            if p["dir"] == "resp" and (p["flags"] & 0x12) == 0x12:  # SYN+ACK
                syn_mss, syn_win, syn_ws = p["mss"], p["win"], p["wscale"]
                syn_kinds, syn_sackok, syn_ts = p["opt_kinds"], p["sackok"], p["tsopt"]
                break

        cur = None
        txn_no = 0
        prev_req_t = None
        for p in pkts:
            is_ctrl = bool(p["flags"] & 0x07)  # FIN/SYN/RST
            if p["dir"] == "req" and p["payload"] and not is_ctrl:
                if cur is not None:
                    rows.append(cur["row"]); payloads[cur["row"]["txn_id"]] = cur["resp_bytes"]
                txn_no += 1
                d = dnp3_fields(p["payload"])
                txn_id = "%s#%d" % (flow_id, txn_no)
                row = {
                    "txn_id": txn_id, "pcap": pcap, "device": device, "role": role,
                    "flow_id": flow_id, "outstation_ip": out_ip, "txn_no": txn_no,
                    "t_req": p["t"],
                    # --- size (request side) ---
                    "req_bytes": len(p["payload"]),
                    # --- stack (as seen on the request; master-side, control) ---
                    "req_ttl": p["ttl"],
                    # --- dpi (request) ---
                    "req_fc": d["dnp3_fc"], "req_appseq": d["dnp3_appseq"],
                    # --- timing ---
                    "gap_prev_req_ms": (None if prev_req_t is None
                                        else (p["t"] - prev_req_t) * 1e3),
                }
                prev_req_t = p["t"]
                cur = {"row": row, "resp_bytes": b"", "segs": [], "seg_t": [],
                       "acks": [], "resp_pkts": []}
                continue
            if cur is None:
                continue
            if p["dir"] != "resp" or is_ctrl:
                continue
            if not p["payload"]:
                cur["acks"].append(p["t"])
            else:
                cur["segs"].append(len(p["payload"]))
                cur["seg_t"].append(p["t"])
                cur["resp_bytes"] += p["payload"]
                cur["resp_pkts"].append(p)

            if len(cur["segs"]) >= 1 and "finalized" not in cur:
                pass
        if cur is not None:
            rows.append(cur["row"]); payloads[cur["row"]["txn_id"]] = cur["resp_bytes"]

        # second pass: fill response-derived fields (kept simple by re-walking)
    return rows, payloads, flows


def build():
    """Full extraction with response fields filled (single coherent pass)."""
    all_rows = []
    all_payloads = {}
    for pcap, device, real_ip in CAPTURES:
        path = os.path.join(PCAP_DIR, pcap)
        flows = defaultdict(list)
        with PcapReader(path) as rd:
            for i, pkt in enumerate(rd):
                if IP not in pkt or TCP not in pkt:
                    continue
                ip, tcp = pkt[IP], pkt[TCP]
                if tcp.sport != DNP3_PORT and tcp.dport != DNP3_PORT:
                    continue
                if tcp.dport == DNP3_PORT:
                    out_ip, out_port, mst_ip, mst_port = ip.dst, tcp.dport, ip.src, tcp.sport
                    direction = "req"
                else:
                    out_ip, out_port, mst_ip, mst_port = ip.src, tcp.sport, ip.dst, tcp.dport
                    direction = "resp"
                key = (mst_ip, mst_port, out_ip, out_port)
                o = opt_summary(tcp)
                flows[key].append({
                    "idx": i, "t": float(pkt.time), "dir": direction,
                    "ttl": ip.ttl, "tos": ip.tos, "df": int(bool(ip.flags & 0x02)),
                    "ipid": ip.id, "win": tcp.window, "dataofs": tcp.dataofs,
                    "flags": int(tcp.flags), "payload": tcp_payload(pkt), **o,
                })

        for (mst_ip, mst_port, out_ip, out_port), pkts in flows.items():
            pkts.sort(key=lambda p: (p["t"], p["idx"]))
            role = "real" if out_ip == real_ip else ("twin" if out_ip == TWIN_IP else "other")
            flow_id = "%s|%s:%d>%s:%d" % (pcap, mst_ip, mst_port, out_ip, out_port)
            syn = {"syn_mss": None, "syn_win": None, "syn_ws": None,
                   "syn_kinds": "", "syn_sackok": None, "syn_ts": None}
            for p in pkts:
                if p["dir"] == "resp" and (p["flags"] & 0x12) == 0x12:
                    syn = {"syn_mss": p["mss"], "syn_win": p["win"], "syn_ws": p["wscale"],
                           "syn_kinds": p["opt_kinds"], "syn_sackok": p["sackok"],
                           "syn_ts": p["tsopt"]}
                    break

            txns = []
            cur = None
            txn_no = 0
            prev_req_t = None
            for p in pkts:
                is_ctrl = bool(p["flags"] & 0x07)
                if p["dir"] == "req" and p["payload"] and not is_ctrl:
                    if cur is not None:
                        txns.append(cur)
                    txn_no += 1
                    cur = {"req": p, "txn_no": txn_no, "prev_gap":
                           (None if prev_req_t is None else (p["t"] - prev_req_t) * 1e3),
                           "acks": [], "segs": [], "resp": b""}
                    prev_req_t = p["t"]
                    continue
                if cur is None or p["dir"] != "resp" or is_ctrl:
                    continue
                if not p["payload"]:
                    cur["acks"].append(p)
                else:
                    cur["segs"].append(p)
                    cur["resp"] += p["payload"]
            if cur is not None:
                txns.append(cur)

            for t in txns:
                if not t["segs"]:
                    continue  # no response observed; not a usable transaction
                req = t["req"]
                dreq = dnp3_fields(req["payload"])
                dresp = dnp3_fields(t["resp"])
                seg_sizes = [len(s["payload"]) for s in t["segs"]]
                seg_ts = [s["t"] for s in t["segs"]]
                first = t["segs"][0]
                gaps = [(seg_ts[i + 1] - seg_ts[i]) * 1e3 for i in range(len(seg_ts) - 1)]
                pure_acks = [a for a in t["acks"] if a["t"] <= seg_ts[0]]
                txn_id = "%s#%d" % (flow_id, t["txn_no"])
                row = {
                    "txn_id": txn_id, "pcap": pcap, "device": device, "role": role,
                    "flow_id": flow_id, "outstation_ip": out_ip, "txn_no": t["txn_no"],
                    "t_req": req["t"],
                    # ---------------- size family ----------------
                    "sz_req_bytes": len(req["payload"]),
                    "sz_resp_bytes": sum(seg_sizes),
                    "sz_n_segments": len(seg_sizes),
                    "sz_first_seg": seg_sizes[0],
                    "sz_max_seg": max(seg_sizes),
                    "sz_min_seg": min(seg_sizes),
                    "sz_mean_seg": sum(seg_sizes) / len(seg_sizes),
                    "sz_resp_ip_bytes": sum(s["dataofs"] * 4 + 20 + len(s["payload"])
                                            for s in t["segs"]),
                    "sz_n_pure_acks": len(pure_acks),
                    # ---------------- timing family ----------------
                    "tm_req_to_first_resp_ms": (seg_ts[0] - req["t"]) * 1e3,
                    "tm_req_to_ack_ms": ((pure_acks[0]["t"] - req["t"]) * 1e3
                                         if pure_acks else None),
                    "tm_ack_to_resp_ms": ((seg_ts[0] - pure_acks[0]["t"]) * 1e3
                                          if pure_acks else None),
                    "tm_duration_ms": (seg_ts[-1] - seg_ts[0]) * 1e3,
                    "tm_mean_gap_ms": (sum(gaps) / len(gaps)) if gaps else 0.0,
                    "tm_max_gap_ms": max(gaps) if gaps else 0.0,
                    "tm_gap_prev_req_ms": t["prev_gap"],
                    # ---------------- stack family ----------------
                    "st_ttl": first["ttl"],
                    "st_tos": first["tos"],
                    "st_df": first["df"],
                    "st_win": first["win"],
                    "st_dataofs": first["dataofs"],
                    "st_n_opts": first["n_opts"],
                    "st_sackok": first["sackok"],
                    "st_tsopt": first["tsopt"],
                    "st_opt_kinds": first["opt_kinds"],
                    "st_syn_mss": syn["syn_mss"],
                    "st_syn_win": syn["syn_win"],
                    "st_syn_ws": syn["syn_ws"],
                    "st_syn_kinds": syn["syn_kinds"],
                    # ---------------- ackmode family ----------------
                    "am_separate_ack": int(len(pure_acks) > 0),
                    # ---------------- dpi family ----------------
                    "dpi_req_fc": dreq["dnp3_fc"],
                    "dpi_resp_fc": dresp["dnp3_fc"],
                    "dpi_resp_iin": dresp["dnp3_iin"],
                    "dpi_resp_nframes": dresp["dnp3_nframes"],
                    "dpi_resp_user_bytes": dresp["dnp3_user_bytes"],
                    "dpi_resp_src": dresp["dnp3_src"],
                    "dpi_resp_dst": dresp["dnp3_dst"],
                    "dpi_resp_fir": dresp["dnp3_fir"],
                    "dpi_resp_fin": dresp["dnp3_fin"],
                }
                all_rows.append(row)
                all_payloads[txn_id] = t["resp"].hex()

    df = pd.DataFrame(all_rows)
    os.makedirs(OUT_DIR, exist_ok=True)
    df.to_csv(os.path.join(OUT_DIR, "transactions.csv"), index=False)
    with open(os.path.join(OUT_DIR, "response_payloads.json"), "w") as fh:
        json.dump(all_payloads, fh)
    return df


if __name__ == "__main__":
    df = build()
    print("rows:", len(df))
    print(df.groupby(["pcap", "role", "device"]).size())
    print()
    print("segments per response:", df["sz_n_segments"].value_counts().to_dict())
    print("resp bytes by device/role:")
    print(df.groupby(["device", "role"])["sz_resp_bytes"].agg(
        ["count", "min", "max", "nunique"]))
    print()
    print("stack constants by device/role:")
    print(df.groupby(["device", "role"])[
        ["st_ttl", "st_win", "st_dataofs", "st_n_opts", "st_syn_mss"]].agg(
        lambda s: sorted(set(s.dropna().tolist()))[:5]))
    print()
    print("ack mode by device/role:", df.groupby(["device", "role"])["am_separate_ack"].mean().to_dict())

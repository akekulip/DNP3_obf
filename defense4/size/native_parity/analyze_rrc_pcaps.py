#!/usr/bin/env python3
"""analyze_rrc_pcaps.py -- examine READ vs SBO pcaps to confirm size+timing normalization.

Observer view (master-side of the outstation-edge Tofino). For each pcap it reports, for the
response direction (relay 192.168.10.7:20000 -> master), the TCP-payload segment-size histogram
(goal: [28,21] pairs), reassembles each 28+21 into 49 B and parses the DNP3 link frame, then the
request->first-response latency distribution (goal: same D4 hold). Request-direction sizes are
reported as the honest residual. Finally it compares READ and SBO against an O_count+segmentation
observer. TCP payload length is computed from headers (ip.len - ihl*4 - dataofs*4), matching the
P4 eligibility predicate. Pure analysis -- reads pcaps only.
"""
import sys, json, statistics
from collections import Counter
from scapy.all import rdpcap, IP, TCP

MASTER, RELAY, RPORT, MPORT = "192.168.10.1", "192.168.10.7", 20000, 40000

def payload_len(p):
    return p[IP].len - (p[IP].ihl * 4) - (p[TCP].dataofs * 4)

def load(path):
    reqs, resps = [], []
    for p in rdpcap(path):
        if not (p.haslayer(IP) and p.haslayer(TCP)):
            continue
        ip, tcp = p[IP], p[TCP]
        plen = payload_len(p)
        raw = bytes(tcp.payload)[:plen] if plen > 0 else b""
        rec = {"t": float(p.time), "seq": tcp.seq, "len": plen, "flags": str(tcp.flags), "raw": raw}
        if ip.src == RELAY and tcp.sport == RPORT and plen > 0:
            resps.append(rec)
        elif ip.src == MASTER and tcp.dport == RPORT and plen > 0:
            reqs.append(rec)
    reqs.sort(key=lambda r: r["t"]); resps.sort(key=lambda r: r["t"])
    return reqs, resps

def reassemble_49(resps):
    """Pair a 28 B segment with the 21 B segment at seq+28; return parsed 49 B units."""
    by_seq = {r["seq"]: r for r in resps}
    units = []
    for r in resps:
        if r["len"] == 28 and (r["seq"] + 28) in by_seq and by_seq[r["seq"] + 28]["len"] == 21:
            data = r["raw"] + by_seq[r["seq"] + 28]["raw"]
            parsed = None
            if len(data) >= 12 and data[0] == 0x05 and data[1] == 0x64:
                # link header: [05 64 len ctrl dst dst src src crc crc], app starts after 10-byte hdr + skip transport
                app = data[10:]
                if len(app) >= 3:
                    parsed = {"func": f"0x{app[1]:02x}", "iin": app[2:4].hex(),
                              "obj_group": app[4] if len(app) > 4 else None}
            units.append({"bytes": len(data), "exact49": len(data) == 49, "parsed": parsed})
    return units

def latencies(reqs, resps):
    """request -> first response segment after it (ms)."""
    out = []
    for rq in reqs:
        after = [r for r in resps if r["t"] >= rq["t"]]
        if after:
            out.append((min(after, key=lambda r: r["t"])["t"] - rq["t"]) * 1000.0)
    return out

def summarize(path, label):
    reqs, resps = load(path)
    resp_hist = Counter(r["len"] for r in resps)
    req_hist = Counter(r["len"] for r in reqs)
    units = reassemble_49(resps)
    lat = latencies(reqs, resps)
    lat_stats = {}
    if lat:
        lat_stats = {"n": len(lat), "min_ms": round(min(lat), 3), "median_ms": round(statistics.median(lat), 3),
                     "mean_ms": round(statistics.mean(lat), 3), "max_ms": round(max(lat), 3),
                     "std_ms": round(statistics.pstdev(lat), 3)}
    r = {
        "label": label, "pcap": path,
        "n_requests": len(reqs), "n_response_segments": len(resps),
        "request_size_hist": dict(sorted(req_hist.items())),
        "response_segment_hist": dict(sorted(resp_hist.items())),
        "n_28": resp_hist.get(28, 0), "n_21": resp_hist.get(21, 0),
        "reassembled_49B_units": len(units),
        "all_units_exact49": all(u["exact49"] for u in units) if units else False,
        "sample_parse": units[0]["parsed"] if units else None,
        "latency_ms": lat_stats,
    }
    return r

def verdict(a, b):
    """Compare READ (a) vs SBO (b) against an O_count+segmentation observer."""
    same_resp_seg = (a["response_segment_hist"].get(28) == b["response_segment_hist"].get(28)
                     and a["response_segment_hist"].get(21) == b["response_segment_hist"].get(21)
                     and a["n_28"] > 0 and a["n_28"] == a["n_21"] and b["n_28"] == b["n_21"])
    ta, tb = a["latency_ms"], b["latency_ms"]
    same_timing = bool(ta and tb) and abs(ta["median_ms"] - tb["median_ms"]) <= 2.0
    req_differs = set(a["request_size_hist"]) != set(b["request_size_hist"])
    return {
        "response_segmentation_identical([28,21] both)": same_resp_seg,
        "response_timing_median_within_2ms": same_timing,
        "read_median_ms": ta.get("median_ms") if ta else None,
        "sbo_median_ms": tb.get("median_ms") if tb else None,
        "residual_request_size_differs": req_differs,
        "read_request_sizes": a["request_size_hist"], "sbo_request_sizes": b["request_size_hist"],
        "O_count+seg_response_verdict": "READ == SBO" if (same_resp_seg and same_timing) else "NOT EQUAL",
    }

def main():
    read_pcap = sys.argv[1] if len(sys.argv) > 1 else "read.pcap"
    sbo_pcap = sys.argv[2] if len(sys.argv) > 2 else "sbo.pcap"
    a = summarize(read_pcap, "READ")
    b = summarize(sbo_pcap, "SBO")
    out = {"READ": a, "SBO": b, "verdict": verdict(a, b)}
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()

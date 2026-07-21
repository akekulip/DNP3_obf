#!/usr/bin/env python3
"""sel751_extract.py — extract the real SEL-751 transaction timing from SEL751.pcap.

The capture is a live SEL-751 relay (10.0.0.1:20000) polled by a master (10.0.0.3) over one DNP3/TCP
connection. For each poll transaction, extract:
  - request time / bytes            (master -> outstation, DNP3 READ)
  - pure-ACK time                   (outstation -> master, zero payload, acks the request)
  - response time / bytes           (outstation -> master, DNP3 RESPONSE)
  - native CLRT = response - pure ACK        (Formby CLRT, the device fingerprint)
  - response latency = response - request    (outstation processing time)

Emits the native CLRT distribution and a JSON schedule of per-transaction (readiness_ms, req_len,
resp_len) so the DCRN replay can drive the rig with the SEL-751's AUTHENTIC response timing. This is
what Case-A must collapse: a real ~12.9 ms-median CLRT distribution (with spread) -> a constant guard.

Usage: $RESEARCH_PYTHON sel751_extract.py <pcap> [--out 10.0.0.1] [--port 20000] [--json sched.json]
"""
import argparse
import json
import statistics as st
import sys

try:
    from scapy.all import rdpcap, IP, TCP
except Exception as e:  # pragma: no cover
    sys.stderr.write("need scapy (use $RESEARCH_PYTHON): %s\n" % e)
    sys.exit(2)


def extract(path, out_ip, port):
    pkts = rdpcap(path)
    ev = []   # (t, kind, seq, ack, plen)
    for p in pkts:
        if IP not in p or TCP not in p:
            continue
        ip, tcp = p[IP], p[TCP]
        t = float(p.time)
        plen = len(bytes(tcp.payload))
        flags = str(tcp.flags)
        if ip.dst == out_ip and tcp.dport == port and plen > 0:
            ev.append((t, "req", int(tcp.seq), int(tcp.ack), plen))
        elif ip.src == out_ip and tcp.sport == port and plen == 0 and "A" in flags:
            ev.append((t, "ack", int(tcp.seq), int(tcp.ack), 0))
        elif ip.src == out_ip and tcp.sport == port and plen > 0:
            ev.append((t, "resp", int(tcp.seq), int(tcp.ack), plen))
    ev.sort(key=lambda x: x[0])

    # walk transactions: req -> (pure ack acking req end) -> resp
    txns = []
    i = 0
    while i < len(ev):
        if ev[i][1] != "req":
            i += 1
            continue
        t_req, _, rseq, _, rlen = ev[i]
        want_ack = (rseq + rlen) & 0xffffffff
        t_ack = t_resp = resp_len = None
        j = i + 1
        while j < len(ev):
            k = ev[j]
            if k[1] == "req":
                break                       # next transaction
            if k[1] == "ack" and k[3] == want_ack and t_ack is None:
                t_ack = k[0]
            if k[1] == "resp" and t_resp is None:
                t_resp, resp_len = k[0], k[4]
                break
            j += 1
        if t_resp is not None:
            clrt = (t_resp - t_ack) * 1000.0 if t_ack is not None else None
            lat = (t_resp - t_req) * 1000.0
            txns.append({"req_len": rlen, "resp_len": resp_len,
                         "readiness_ms": round(lat, 3),
                         "native_clrt_ms": None if clrt is None else round(clrt, 3),
                         "separate_ack": t_ack is not None})
        i = j if j > i else i + 1
    return txns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--out", default="10.0.0.1")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--json")
    ap.add_argument("--limit", type=int, default=0, help="cap #transactions in the schedule (0=all)")
    a = ap.parse_args()
    txns = extract(a.pcap, a.out, a.port)
    sep = [t for t in txns if t["separate_ack"] and t["native_clrt_ms"] is not None]
    clrts = sorted(t["native_clrt_ms"] for t in sep)
    lats = sorted(t["readiness_ms"] for t in txns)
    print("=== SEL-751 real transactions: %d (separate-ACK w/ CLRT: %d) ===" % (len(txns), len(sep)))
    if clrts:
        n = len(clrts)
        print("  native CLRT (ms) : n=%d min=%.2f p25=%.2f median=%.2f p75=%.2f max=%.2f mean=%.2f"
              % (n, clrts[0], clrts[n // 4], clrts[n // 2], clrts[3 * n // 4], clrts[-1], sum(clrts) / n))
    if lats:
        n = len(lats)
        print("  response latency : n=%d min=%.2f median=%.2f max=%.2f" % (n, lats[0], lats[n // 2], lats[-1]))
    rl = set(t["req_len"] for t in txns); pl = set(t["resp_len"] for t in txns)
    print("  request lengths  : %s" % sorted(rl))
    print("  response lengths : %s" % sorted(pl))
    if a.json:
        sched = txns[:a.limit] if a.limit else txns
        json.dump({"n": len(sched), "txns": sched}, open(a.json, "w"))
        print("  schedule -> %s (%d txns)" % (a.json, len(sched)))


if __name__ == "__main__":
    main()

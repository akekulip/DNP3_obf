#!/usr/bin/env python3
"""c3_analyze_pcap.py — extract the C3 acceptance evidence from a physical-wire capture.

The C3 rig captures on the Hulk physical NIC (enp59s0f0np0). Because the two netns talk over a
VEPA-macvlan hairpin through the switch, every frame appears on that tap TWICE: once leaving for
the switch (min ts) and once returning after the switch's pipeline (max ts). This is a feature —
for an outstation->master frame, max(ts) is the arrival AT THE MASTER (post-hold), and
max(ts)-min(ts) is the on-wire hold. (min==max degrades gracefully for a non-doubled capture.)

Frames of one clean SEL-751 transaction:
  REQUEST   master->outstation, dst:20000, payload == req_len (22 B)   -> send  = min(ts)
  PURE ACK  outstation->master, src:20000, ACK, ZERO payload, ack==req_seq+req_len -> arrival = max(ts)
  RESPONSE  outstation->master, src:20000, payload == resp_len (54 B)  -> arrival = max(ts)

  CLRT = arrival(RESPONSE) - arrival(PURE ACK)            (Formby et al., NDSS 2016)
  ack_hold  = arrival(PURE ACK) - send(PURE ACK)          (the switch's ACK hold, on the wire)

Interpretation: NATIVE (forward) -> ACK returns promptly, CLRT ~= response-readiness. CASE-A ->
the switch holds the pure ACK until ~the response, so ack_hold ~= readiness and CLRT collapses to
~guard delta, WITHOUT the response bytes changing. Ordering must be request <= ack_arrival <=
resp_arrival; resets / dup-data must be zero.

Usage:
  $RESEARCH_PYTHON c3_analyze_pcap.py <pcap> [--req-len 22] [--resp-len 54] [--port 20000]
                                      [--master 10.0.1.10] [--out 10.0.2.10] [--json]
"""
import argparse
import json
import sys
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP
except Exception as e:  # pragma: no cover
    sys.stderr.write("need scapy (use $RESEARCH_PYTHON): %s\n" % e)
    sys.exit(2)


def plen(pkt):
    return len(bytes(pkt[TCP].payload)) if TCP in pkt else 0


def analyze(path, req_len, resp_len, port, master, out):
    pkts = rdpcap(path)
    # group by (direction-key, tcp.seq, payload-len, ack) -> [timestamps]  (dedupe the wire doubling)
    groups = defaultdict(list)
    resets = 0
    data_seen = defaultdict(int)     # (src,seq,len) -> count of DISTINCT timestamps for dup-data
    for p in pkts:
        if TCP not in p or IP not in p:
            continue
        tcp, ip = p[TCP], p[IP]
        t = float(p.time)
        L = plen(p)
        flags = str(tcp.flags)
        if "R" in flags:
            resets += 1
        key = (ip.src, ip.dst, tcp.sport, tcp.dport, int(tcp.seq), int(tcp.ack), L)
        groups[key].append(t)

    def collect(pred):
        """return list of (min_ts, max_ts, key) for groups whose key matches pred."""
        res = []
        for key, ts in groups.items():
            if pred(*key):
                res.append((min(ts), max(ts), key))
        return sorted(res)

    # REQUEST: master->outstation, dst port, payload==req_len
    req_g = collect(lambda s, d, sp, dp, seq, ack, L: s == master and dp == port and L == req_len)
    request = None
    req_seq = None
    if req_g:
        mn, mx, key = req_g[0]
        req_seq = key[4]
        request = {"send_ms": mn * 1000.0, "seq": req_seq}

    # RESPONSE: outstation->master, src port, payload==resp_len
    resp_g = collect(lambda s, d, sp, dp, seq, ack, L: s == out and sp == port and L == resp_len)
    response = None
    if resp_g:
        mn, mx, key = resp_g[0]
        response = {"arrival_ms": mx * 1000.0, "send_ms": mn * 1000.0,
                    "hold_ms": (mx - mn) * 1000.0, "seq": key[4], "bytes": resp_len}

    # PURE ACK: outstation->master, src port, zero payload, ack == req_seq + req_len
    pure_ack = None
    if req_seq is not None:
        want = (req_seq + req_len) & 0xffffffff
        ack_g = collect(lambda s, d, sp, dp, seq, ack, L:
                        s == out and sp == port and L == 0 and ack == want)
        # the ACK whose arrival precedes (or ~equals) the response arrival
        if ack_g:
            mn, mx, key = ack_g[0]
            pure_ack = {"arrival_ms": mx * 1000.0, "send_ms": mn * 1000.0,
                        "hold_ms": (mx - mn) * 1000.0, "ack": key[5]}

    # duplicate DATA retransmit detection: a data seq seen at >2 distinct wire times (2 = normal doubling)
    dup_data = 0
    for key, ts in groups.items():
        s, d, sp, dp, seq, ack, L = key
        if L > 0 and len(set(round(x, 6) for x in ts)) > 2:
            dup_data += 1

    clrt = ack_hold = None
    ordering_ok = False
    if pure_ack and response and request:
        clrt = response["arrival_ms"] - pure_ack["arrival_ms"]
        ack_hold = pure_ack["hold_ms"]
        ordering_ok = (request["send_ms"] <= pure_ack["arrival_ms"] + 0.05
                       and pure_ack["arrival_ms"] <= response["arrival_ms"] + 0.05)

    return {
        "pcap": path,
        "n_packets": len(pkts),
        "request": request,
        "pure_ack": pure_ack,
        "response": response,
        "clrt_ms": None if clrt is None else round(clrt, 3),
        "ack_hold_ms": None if ack_hold is None else round(ack_hold, 3),
        "ordering_ok": ordering_ok,
        "resp_bytes_ok": (response is not None and response["bytes"] == resp_len),
        "resets": resets,
        "dup_data_retransmits": dup_data,
        "clean_transport": (resets == 0 and dup_data == 0),
        "complete": (request is not None and pure_ack is not None and response is not None),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--req-len", type=int, default=22)
    ap.add_argument("--resp-len", type=int, default=54)
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--master", default="10.0.1.10")
    ap.add_argument("--out", default="10.0.2.10")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    v = analyze(a.pcap, a.req_len, a.resp_len, a.port, a.master, a.out)
    if a.json:
        print(json.dumps(v))
        return
    print("=== C3 wire analysis: %s ===" % v["pcap"])
    print("  packets              : %d" % v["n_packets"])
    print("  request  (%dB) send  : %s" % (a.req_len, v["request"]))
    print("  pure ACK             : %s" % v["pure_ack"])
    print("  response (%dB)       : %s" % (a.resp_len, v["response"]))
    print("  ACK hold (arr-send)  : %s ms   <- switch held the pure ACK this long" % v["ack_hold_ms"])
    print("  CLRT (respArr-ackArr): %s ms   <- Formby CLRT at the master" % v["clrt_ms"])
    print("  ordering req<=ack<=resp : %s" % v["ordering_ok"])
    print("  response bytes ok    : %s" % v["resp_bytes_ok"])
    print("  transport clean      : %s  (resets=%d dup_data=%d)" % (v["clean_transport"], v["resets"], v["dup_data_retransmits"]))
    print("  COMPLETE             : %s" % v["complete"])


if __name__ == "__main__":
    main()

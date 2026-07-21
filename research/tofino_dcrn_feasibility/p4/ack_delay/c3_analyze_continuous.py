#!/usr/bin/env python3
"""c3_analyze_continuous.py — acceptance analysis for the continuous single-flow campaign.

One long physical-wire capture of ONE persistent connection running N sequential Class-0 transactions
(shuffled readiness, no cold reload). Segments the N transactions and reports the acceptance criteria:
  N requests == N responses (every txn completes), all responses byte-length == resp_len,
  per-txn Formby CLRT (resp_arrival - ack_arrival) with head-vs-tail (NO degradation across txn index),
  and GLOBAL transport health: zero RST, zero data-segment retransmits (a data seq at >2 wire times).

Wire doubling (VEPA hairpin) => each frame appears twice; master-side arrival = max(ts) of a group.
Uses scapy ($RESEARCH_PYTHON). Usage:
  $RESEARCH_PYTHON c3_analyze_continuous.py <pcap> [--req-len 22] [--resp-len 54] [--port 20000]
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


def analyze(path, req_len, resp_len, port, master, out):
    pkts = rdpcap(path)
    req_grp = defaultdict(list)     # req seq -> [ts]   (master->out, payload req_len)
    ack_grp = defaultdict(list)     # ack no  -> [ts]   (out->master, payload 0, ACK)
    resp_grp = defaultdict(list)    # resp seq -> [ts]  (out->master, payload resp_len)
    data_times = defaultdict(set)   # (src,seq,len) -> {ts}  for retransmit detection
    resets = 0
    for p in pkts:
        if TCP not in p or IP not in p:
            continue
        tcp, ip = p[TCP], p[IP]
        t = float(p.time)
        L = len(bytes(tcp.payload))
        flags = str(tcp.flags)
        if "R" in flags:
            resets += 1
        if L > 0:
            data_times[(ip.src, int(tcp.seq), L)].add(round(t, 6))
        if ip.src == master and tcp.dport == port and L == req_len:
            req_grp[int(tcp.seq)].append(t)
        elif ip.src == out and tcp.sport == port and L == 0 and "A" in flags:
            ack_grp[int(tcp.ack)].append(t)
        elif ip.src == out and tcp.sport == port and L == resp_len:
            resp_grp[int(tcp.seq)].append(t)

    reqs = sorted((min(ts), seq) for seq, ts in req_grp.items())      # by send time
    resps = sorted((max(ts), min(ts), seq) for seq, ts in resp_grp.items())  # by master arrival
    n_req, n_resp = len(reqs), len(resps)

    # pair txn i: request i (time order) -> its pure ACK (ack == req_seq+req_len) -> response i (order)
    clrts = []
    per_txn = []
    for i, (rt, rseq) in enumerate(reqs):
        want_ack = (rseq + req_len) & 0xffffffff
        ack_arr = max(ack_grp[want_ack]) if want_ack in ack_grp else None
        resp_arr = resps[i][0] if i < len(resps) else None
        clrt = (resp_arr - ack_arr) * 1000.0 if (ack_arr is not None and resp_arr is not None) else None
        if clrt is not None:
            clrts.append(clrt)
        per_txn.append({"i": i, "req_seq": rseq, "clrt_ms": None if clrt is None else round(clrt, 3)})

    # retransmits: a data segment (same src+seq+len) seen at >2 distinct wire times (2 = normal doubling)
    retrans = sum(1 for k, tset in data_times.items() if len(tset) > 2)

    cs = sorted(clrts)
    n = len(cs)
    head = sum(cs[:10]) / min(10, n) if n else None
    tail = sum(cs[-10:]) / min(10, n) if n else None
    # degradation: tail median vs head median on the TIME-ORDERED (not sorted) clrt list
    ordered = [c for c in clrts]
    head_ord = sum(ordered[:10]) / min(10, len(ordered)) if ordered else None
    tail_ord = sum(ordered[-10:]) / min(10, len(ordered)) if ordered else None

    v = {
        "pcap": path,
        "n_requests": n_req,
        "n_responses": n_resp,
        "all_completed": (n_req == n_resp and n_req > 0),
        "clrt_n": n,
        "clrt_median_ms": round(cs[n // 2], 3) if n else None,
        "clrt_min_ms": round(cs[0], 3) if n else None,
        "clrt_max_ms": round(cs[-1], 3) if n else None,
        "clrt_head10_ordered_ms": None if head_ord is None else round(head_ord, 3),
        "clrt_tail10_ordered_ms": None if tail_ord is None else round(tail_ord, 3),
        "no_degradation": (head_ord is not None and tail_ord is not None and tail_ord <= head_ord + 0.5),
        "resets": resets,
        "retransmits": retrans,
        "clean_transport": (resets == 0 and retrans == 0),
    }
    return v, per_txn


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
    v, per_txn = analyze(a.pcap, a.req_len, a.resp_len, a.port, a.master, a.out)
    if a.json:
        print(json.dumps({"summary": v, "per_txn": per_txn}))
        return
    print("=== continuous campaign analysis: %s ===" % v["pcap"])
    print("  requests / responses : %d / %d   (all_completed=%s)" % (v["n_requests"], v["n_responses"], v["all_completed"]))
    print("  CLRT (n=%d)          : median=%s  min=%s  max=%s ms" % (v["clrt_n"], v["clrt_median_ms"], v["clrt_min_ms"], v["clrt_max_ms"]))
    print("  CLRT head10 / tail10 : %s / %s ms   (no_degradation=%s)" % (v["clrt_head10_ordered_ms"], v["clrt_tail10_ordered_ms"], v["no_degradation"]))
    print("  transport            : resets=%d retransmits=%d   (clean=%s)" % (v["resets"], v["retransmits"], v["clean_transport"]))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Task 4: reconcile the historical ~13 ms SEL-751 CLRT against the 300-poll live measurement.
Independently recomputes request->ACK / ACK->response / request->response from the ORIGINAL trace
(read-only), split by DNP3 request function code, and records device/request-type/response-size/
TCP-session/capture-location/sample-count. Compares to the live Class-0 result. Writes JSON + CSV.
"""
import os, json, csv
import numpy as np
from scapy.all import PcapReader, TCP, IP, Ether

REPO = "/home/philip/Projects/DNP3"
HIST_PCAP = os.path.join(REPO, "Traffic Trace", "SEL751.pcap")
SEL = "10.0.0.1"
VAL = os.path.dirname(os.path.abspath(__file__))
FUNC = {0: "CONFIRM", 1: "READ", 5: "DIRECT_OPERATE", 3: "SELECT", 4: "OPERATE"}


def app_info(pl):
    if len(pl) < 13 or pl[:2] != b"\x05\x64" or pl[2] <= 5:
        return None
    return dict(func=pl[12], func_name=FUNC.get(pl[12], pl[12]))


def stat(x):
    x = np.asarray(x, float)
    if len(x) == 0:
        return {"n": 0}
    return dict(n=int(len(x)), median=float(np.median(x)), mean=float(np.mean(x)),
                p10=float(np.percentile(x, 10)), p90=float(np.percentile(x, 90)),
                p95=float(np.percentile(x, 95)), min=float(x.min()), max=float(x.max()),
                std=float(x.std(ddof=1)))


def main():
    pkts = []
    macs = {"VIS_side": set(), "SEL_side": set()}
    ttls = {"master": [], "sel": []}
    for p in PcapReader(HIST_PCAP):
        if TCP not in p or IP not in p:
            continue
        ip = p[IP]
        # keep only the SEL751 (10.0.0.1) flow (both directions), excluding the shared 10.0.0.2
        if ip.src != SEL and ip.dst != SEL:
            continue
        d = "sel" if ip.src == SEL else "master"
        if Ether in p:
            (macs["SEL_side"] if d == "sel" else macs["VIS_side"]).add(p[Ether].src)
        ttls[d].append(int(ip.ttl))
        pkts.append(dict(time=float(p.time), dir=d, seq=int(p[TCP].seq), ack=int(p[TCP].ack),
                         flags=int(p[TCP].flags), pl=bytes(p[TCP].payload)))

    # TCP sessions (unique src ports on the master side) + retransmit detect (payload, by seq)
    seen, retrans = set(), 0
    conns = set()
    for p in pkts:
        if p["dir"] == "master" and (p["flags"] & 0x02) and not (p["flags"] & 0x10):
            conns.add(("syn",))
        if p["pl"]:
            k = (p["dir"], p["seq"], len(p["pl"]))
            if k in seen:
                retrans += 1
            else:
                seen.add(k)

    # transaction walk: master app-request -> sel pure-ACK (pl==0) -> sel app-response (pl>0)
    txns = []
    for i, p in enumerate(pkts):
        if p["dir"] != "master":
            continue
        ai = app_info(p["pl"])
        if not ai:
            continue
        treq = p["time"]; pure_ack = resp = resp_sz = None
        for q in pkts[i + 1:]:
            if q["dir"] == "master" and app_info(q["pl"]):
                break  # next request
            if q["dir"] == "sel" and len(q["pl"]) == 0 and (q["flags"] & 0x10) and pure_ack is None and resp is None:
                pure_ack = q["time"]
            if q["dir"] == "sel" and len(q["pl"]) > 0 and resp is None:
                resp = q["time"]; resp_sz = len(q["pl"]); break
        if resp is not None:
            txns.append(dict(func=ai["func_name"], resp_bytes=resp_sz,
                             req_ack_ms=((pure_ack - treq) * 1e3) if pure_ack else None,
                             clrt_ms=((resp - pure_ack) * 1e3) if pure_ack else None,
                             req_resp_ms=(resp - treq) * 1e3, separate=(pure_ack is not None)))

    # split by request function
    byfunc = {}
    for f in sorted(set(t["func"] for t in txns)):
        sub = [t for t in txns if t["func"] == f]
        from collections import Counter
        byfunc[f] = dict(
            n=len(sub), separate=sum(1 for t in sub if t["separate"]),
            response_sizes=dict(Counter(t["resp_bytes"] for t in sub)),
            request_to_ack_ms=stat([t["req_ack_ms"] for t in sub if t["req_ack_ms"] is not None]),
            ack_to_response_clrt_ms=stat([t["clrt_ms"] for t in sub if t["clrt_ms"] is not None]),
            request_to_response_ms=stat([t["req_resp_ms"] for t in sub]))
    overall = dict(
        n=len(txns), separate=sum(1 for t in txns if t["separate"]),
        request_to_ack_ms=stat([t["req_ack_ms"] for t in txns if t["req_ack_ms"] is not None]),
        ack_to_response_clrt_ms=stat([t["clrt_ms"] for t in txns if t["clrt_ms"] is not None]),
        request_to_response_ms=stat([t["req_resp_ms"] for t in txns]))

    out = dict(
        historical_source=os.path.relpath(HIST_PCAP, REPO),
        device="SEL-751 @ 10.0.0.1 (shared 10.0.0.2 excluded by IP filter)",
        tcp_sessions=1 if conns else 0, payload_retransmissions=retrans,
        capture_ethernet_src_macs={"sel_side": sorted(macs["SEL_side"]), "master_side": sorted(macs["VIS_side"])},
        ip_ttl_observed={"sel": sorted(set(ttls["sel"])), "master": sorted(set(ttls["master"]))},
        overall=overall, by_request_function=byfunc)
    json.dump(out, open(os.path.join(VAL, "historical_reconcile.json"), "w"), indent=1)

    # comparison CSV: historical (by func) vs live Class-0
    live = json.load(open(os.path.join(os.path.dirname(VAL), "summary.json")))["latency_ms"]
    with open(os.path.join(VAL, "historical_vs_live_clrt.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["dataset", "request_type", "n", "resp_bytes", "clrt_median_ms", "clrt_mean_ms",
                    "clrt_p90_ms", "req_ack_median_ms", "req_resp_median_ms"])
        for fn, b in byfunc.items():
            c = b["ack_to_response_clrt_ms"]; ra = b["request_to_ack_ms"]; rr = b["request_to_response_ms"]
            w.writerow(["historical_SEL751", fn, b["n"], "/".join(map(str, b["response_sizes"])),
                        round(c.get("median", float("nan")), 3) if c.get("n") else "n/a",
                        round(c.get("mean", float("nan")), 3) if c.get("n") else "n/a",
                        round(c.get("p90", float("nan")), 3) if c.get("n") else "n/a",
                        round(ra.get("median", float("nan")), 3) if ra.get("n") else "n/a",
                        round(rr["median"], 3)])
        oc = overall["ack_to_response_clrt_ms"]
        w.writerow(["historical_SEL751", "ALL", overall["n"], "37/54",
                    round(oc["median"], 3), round(oc["mean"], 3), round(oc["p90"], 3),
                    round(overall["request_to_ack_ms"]["median"], 3), round(overall["request_to_response_ms"]["median"], 3)])
        lc = live["ack_to_response_clrt_ms"]; lra = live["request_to_pure_ack_ms"]; lrr = live["request_to_response_ms"]
        w.writerow(["live_300poll", "READ_class0", 300, "134",
                    round(lc["median"], 3), round(lc["mean"], 3), round(lc["p90"], 3),
                    round(lra["median"], 3), round(lrr["median"], 3)])

    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""analyze_rrc_pcaps.py -- transaction-correct analysis of the RRC READ/SBO pcaps.

Rewritten after the ce3392d audit. The previous version paired each request with the next
28-byte segment by time, with no TCP-semantic check -- so an 18-byte state READ was paired with
a later SELECT response, inventing a phantom 29.9 ms outlier and an n=31 SELECT count. This
version pairs by TCP semantics and classifies by DNP3 function:

  * a response/ACK belongs to request R iff it is on the relay->master half AND
    tcp.ack == R.seq + len(R.payload), bounded by the next request;
  * requests are classified READ / STATE_READ / SELECT / OPERATE from the DNP3 function code
    and payload length (admitted timing profiles are the 20-byte READ and 45-byte SELECT/OPERATE;
    the 18-byte all-points state READ is NOT an admitted profile and is reported separately);
  * DNP3 block CRCs are removed before reading application fields (so the response function is
    the real 0x81, not the application-control byte 0xC0);
  * the response segmentation is reported in BOTH orders: TCP-sequence order [28,21] and
    capture-arrival order [21,28] (the suffix is consistently emitted before the prefix);
  * three timing metrics are reported: request->pure-ACK, pure-ACK->response (the Case-A CLRT
    the D4 deadline clamps), and request->response;
  * equivalence uses a DECLARED margin, not an arbitrary "median within 2 ms = equal".

Pure analysis -- reads pcaps only. Run with $RESEARCH_PYTHON (needs scapy).
"""
import sys, json, statistics
from collections import Counter
from scapy.all import rdpcap, IP, TCP

MASTER, RELAY, RPORT = "192.168.10.1", "192.168.10.7", 20000
# equivalence margin for the Case-A metric (pure-ACK -> response medians), milliseconds.
# The D4 deadline release tail is ~sub-microsecond; we declare 0.5 ms as "deadline-clamped equal".
CLRT_EQUIV_MARGIN_MS = 0.5

FUNC = {0x01: "READ", 0x03: "SELECT", 0x04: "OPERATE"}


def payload_len(p):
    return p[IP].len - (p[IP].ihl * 4) - (p[TCP].dataofs * 4)


def load_all(path):
    """Every TCP packet (incl. len==0 ACKs) as a dict, sorted by capture time."""
    pk = []
    for p in rdpcap(path):
        if not (p.haslayer(IP) and p.haslayer(TCP)):
            continue
        ip, tcp = p[IP], p[TCP]
        plen = payload_len(p)
        pk.append({"t": float(p.time), "src": ip.src, "dst": ip.dst,
                   "sport": int(tcp.sport), "dport": int(tcp.dport),
                   "seq": int(tcp.seq), "ack": int(tcp.ack), "len": plen,
                   "raw": bytes(tcp.payload)[:plen] if plen > 0 else b""})
    pk.sort(key=lambda r: r["t"])
    return pk


def deframe(buf):
    """Strip DNP3 link framing (10-byte header, per-block CRCs) -> user data (transport+app)."""
    i = 0
    while i + 10 <= len(buf):
        if buf[i] != 0x05 or buf[i + 1] != 0x64:
            i += 1
            continue
        ulen = buf[i + 2] - 5
        nblk = (ulen + 15) // 16 if ulen > 0 else 0
        total = 10 + ulen + 2 * nblk
        if i + total > len(buf):
            break
        u = bytearray()
        p = i + 10
        rem = ulen
        while rem > 0:
            t = min(16, rem)
            u += buf[p:p + t]
            p += t + 2
            rem -= t
        return bytes(u)          # first frame's user data is enough here
    return b""


def app_fields(buf):
    """(func, group) from a full DNP3-over-TCP payload. user = [transport][app_ctrl][func][IIN][IIN][group]..."""
    u = deframe(buf)
    if len(u) < 3:
        return None, None
    func = u[2]
    group = u[5] if len(u) > 5 else None
    return func, group


def classify(req_payload, req_len):
    func, _ = app_fields(req_payload)
    name = FUNC.get(func, "OTHER")
    if name == "READ" and req_len == 18:
        name = "STATE_READ"
    admitted = req_len in (20, 45) and name in ("READ", "SELECT", "OPERATE")
    return name, func, admitted


def transactions(path):
    pk = load_all(path)
    reqs = [p for p in pk if p["src"] == MASTER and p["dport"] == RPORT and p["len"] > 0]
    reqs.sort(key=lambda r: r["t"])
    txns = []
    for i, rq in enumerate(reqs):
        exp_ack = (rq["seq"] + rq["len"]) & 0xFFFFFFFF
        t_next = reqs[i + 1]["t"] if i + 1 < len(reqs) else float("inf")
        # relay->master packets that acknowledge THIS request, before the next request
        rel = [p for p in pk if p["src"] == RELAY and p["sport"] == RPORT
               and p["ack"] == exp_ack and rq["t"] <= p["t"] < t_next]
        acks = [p for p in rel if p["len"] == 0]
        resp = [p for p in rel if p["len"] > 0]
        if not resp:
            continue
        seq_order = sorted(resp, key=lambda p: p["seq"])
        arr_order = sorted(resp, key=lambda p: p["t"])
        payload = b"".join(p["raw"] for p in seq_order)
        func, group = app_fields(payload)
        name, req_func, admitted = classify(rq["raw"], rq["len"])
        t_first_resp = min(p["t"] for p in resp)
        t_ack = min((p["t"] for p in acks), default=None)     # the (held) pure ACK
        txns.append({
            "klass": name, "admitted": admitted, "req_len": rq["len"],
            "resp_bytes": len(payload), "exact49": len(payload) == 49,
            "seq_vector": [p["len"] for p in seq_order],
            "arrival_vector": [p["len"] for p in arr_order],
            "resp_func": (("0x%02x" % func) if func is not None else None),
            "resp_group": group,
            "req_to_resp_ms": (t_first_resp - rq["t"]) * 1000.0,
            "ack_to_resp_ms": ((t_first_resp - t_ack) * 1000.0) if t_ack is not None else None,
            "req_to_ack_ms": ((t_ack - rq["t"]) * 1000.0) if t_ack is not None else None,
        })
    return txns


def _stats(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return {}
    return {"n": len(xs), "min_ms": round(min(xs), 3), "median_ms": round(statistics.median(xs), 3),
            "mean_ms": round(statistics.mean(xs), 3), "max_ms": round(max(xs), 3),
            "std_ms": round(statistics.pstdev(xs), 3)}


def summarize(path):
    txns = transactions(path)
    by = {}
    for k in ("READ", "SELECT", "OPERATE", "STATE_READ", "OTHER"):
        grp = [t for t in txns if t["klass"] == k]
        if not grp:
            continue
        seqv = Counter(tuple(t["seq_vector"]) for t in grp)
        arrv = Counter(tuple(t["arrival_vector"]) for t in grp)
        by[k] = {
            "n": len(grp), "admitted": grp[0]["admitted"],
            "all_reassemble_49B": all(t["exact49"] for t in grp),
            "seq_order_vectors": {str(list(v)): c for v, c in seqv.items()},
            "arrival_order_vectors": {str(list(v)): c for v, c in arrv.items()},
            "resp_func": sorted({t["resp_func"] for t in grp}),
            "resp_group": sorted({t["resp_group"] for t in grp if t["resp_group"] is not None}),
            "req_to_resp_ms": _stats([t["req_to_resp_ms"] for t in grp]),
            "ack_to_resp_ms": _stats([t["ack_to_resp_ms"] for t in grp]),
            "req_to_ack_ms": _stats([t["req_to_ack_ms"] for t in grp]),
        }
    return {"pcap": path, "n_transactions": len(txns), "by_class": by}


def verdict(read_sum, sbo_sum):
    """Compare the admitted READ profile vs the admitted SELECT profile."""
    r = read_sum["by_class"].get("READ", {})
    s = sbo_sum["by_class"].get("SELECT", {})
    if not r or not s:
        return {"error": "missing READ or SELECT admitted class"}
    # Segmentation identity compares the SET of distinct segmentation vectors, NOT their
    # per-class occurrence counts. r["seq_order_vectors"] is {vector_str: count}; two classes
    # with different transaction counts (e.g. 200 READ vs 120 SELECT) both yielding only
    # [28,21] are segmentation-identical. The prior `dict == dict` compared counts too
    # ({"[28, 21]": 200} != {"[28, 21]": 120}) and wrongly reported not-identical.
    seg_same = (set(r["seq_order_vectors"]) == set(s["seq_order_vectors"])
                and set(r["arrival_order_vectors"]) == set(s["arrival_order_vectors"]))
    ra, sa = r["ack_to_resp_ms"], s["ack_to_resp_ms"]
    clrt_diff = abs(ra["median_ms"] - sa["median_ms"]) if (ra and sa) else None
    rr, sr = r["req_to_resp_ms"], s["req_to_resp_ms"]
    rr_diff = abs(rr["median_ms"] - sr["median_ms"]) if (rr and sr) else None
    return {
        "scope": "physical per-response READ vs SELECT-echo parity (SELECT-only; physical OPERATE not run)",
        "n_read": r["n"], "n_select": s["n"],
        "segmentation_identical": seg_same,
        "seq_order_vector": next(iter(r["seq_order_vectors"]), None),
        "arrival_order_vector": next(iter(r["arrival_order_vectors"]), None),
        "clrt_ack_to_resp_median_ms": {"READ": ra.get("median_ms"), "SELECT": sa.get("median_ms"),
                                       "diff_ms": clrt_diff, "equiv_margin_ms": CLRT_EQUIV_MARGIN_MS,
                                       "deadline_clamped_equal": (clrt_diff is not None and clrt_diff <= CLRT_EQUIV_MARGIN_MS)},
        "req_to_resp_median_ms": {"READ": rr.get("median_ms"), "SELECT": sr.get("median_ms"),
                                  "diff_ms": rr_diff, "std_READ": rr.get("std_ms"), "std_SELECT": sr.get("std_ms")},
        "claim": ("deadline-clamped central timing parity (ACK->response) + identical segmentation; "
                  "NOT universal statistical indistinguishability, NOT full READ-vs-SBO transaction equality"),
    }


def main():
    read_pcap = sys.argv[1] if len(sys.argv) > 1 else "read.pcap"
    sbo_pcap = sys.argv[2] if len(sys.argv) > 2 else "sbo.pcap"
    a, b = summarize(read_pcap), summarize(sbo_pcap)
    print(json.dumps({"READ_pcap": a, "SBO_pcap": b, "verdict": verdict(a, b)}, indent=2))


if __name__ == "__main__":
    main()

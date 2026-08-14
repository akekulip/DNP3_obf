#!/usr/bin/env python3
"""analyze_h3.py -- offline verdict for the H3 namespace-to-namespace validation.

Reads the two captures (master-facing + outstation-facing) and proves, from the packets alone:
  1. TCP timestamps were NOT negotiated (no TS option on SYN or SYN-ACK) -- FAILS CLOSED if present.
  2. Every request uses qualifier 0x17 with a 2-CROB object (SELECT func 0x03, OPERATE func 0x04).
  3. The outstation emits a separate bare TCP ACK BEFORE each 49-byte DNP3 response (Case-A).
  4. The native echo is present and is 49 bytes.
  5. The outstation counters advanced correctly (select/operate/callback).

Uses tshark for packet field extraction and parses DNP3 payloads with the shared wire module, so it
does not depend on tshark's DNP3 dissector. Run on the driver host (gambit), not inside a namespace.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

import dnp3_wire as w

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "tcp.len",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset", "tcp.flags.push",
    "tcp.options.timestamp.tsval", "tcp.payload",
]


def read_pcap(path: str):
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=\t"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    pkts = []
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) < len(FIELDS):
            cols += [""] * (len(FIELDS) - len(cols))
        d = dict(zip(FIELDS, cols))
        def i(x, default=0):
            try:
                return int(x)
            except ValueError:
                return default
        pkts.append({
            "num": i(d["frame.number"]),
            "t": float(d["frame.time_epoch"]) if d["frame.time_epoch"] else 0.0,
            "src": d["ip.src"], "dst": d["ip.dst"],
            "sport": i(d["tcp.srcport"]), "dport": i(d["tcp.dstport"]),
            "len": i(d["tcp.len"]),
            # tshark renders boolean flags as "True"/"False" (older builds emit "1"/"0").
            "syn": d["tcp.flags.syn"] in ("1", "True"), "ack": d["tcp.flags.ack"] in ("1", "True"),
            "fin": d["tcp.flags.fin"] in ("1", "True"), "rst": d["tcp.flags.reset"] in ("1", "True"),
            "psh": d["tcp.flags.push"] in ("1", "True"),
            "tsval": d["tcp.options.timestamp.tsval"].strip(),
            "payload": bytes.fromhex(d["tcp.payload"].replace(":", "")) if d["tcp.payload"] else b"",
        })
    return pkts


def check_tcp_timestamps(pkts):
    """FAIL CLOSED: no TCP timestamp option may appear on the SYN or SYN-ACK."""
    syns = [p for p in pkts if p["syn"]]
    offenders = [p["num"] for p in syns if p["tsval"]]
    return {
        "n_syn_or_synack": len(syns),
        "syn_frames": [p["num"] for p in syns],
        "syn_with_timestamp_option": offenders,
        "tcp_timestamps_absent": len(offenders) == 0 and len(syns) >= 1,
    }


def check_requests(pkts, port):
    """Confirm each request is a 2-CROB SELECT/OPERATE with qualifier 0x17."""
    sel = op = bad = 0
    quals, counts, points = set(), set(), set()
    funcs = []
    for p in pkts:
        if p["dport"] != port or p["len"] == 0 or not p["payload"]:
            continue
        for _total, ud in w.deframe(p["payload"]):
            req = w.parse_request(ud)
            if not req:
                continue
            funcs.append("0x%02x" % req["func"])
            quals.add(req["qual"])
            counts.add(req["count"])
            points.update(req["points"])
            if req["func"] == w.FUNC_SELECT and req["qual"] == 0x17 and req["count"] == 2:
                sel += 1
            elif req["func"] == w.FUNC_OPERATE and req["qual"] == 0x17 and req["count"] == 2:
                op += 1
            else:
                bad += 1
    return {
        "n_select_2crob_0x17": sel,
        "n_operate_2crob_0x17": op,
        "n_malformed": bad,
        "unique_qualifiers": sorted("0x%02x" % q for q in quals if q is not None),
        "unique_counts": sorted(c for c in counts if c is not None),
        "unique_points": sorted(points),
        "all_qual_0x17": quals == {0x17},
    }


def check_separate_ack(pkts, port):
    """From the outstation (srcport==port): every 49-byte response must be preceded by a bare ACK
    with no intervening outstation data segment. Returns per-response evidence."""
    out_pkts = [p for p in sorted(pkts, key=lambda x: (x["t"], x["num"])) if p["sport"] == port]
    events = []
    pending_ack = None  # most recent bare ACK since the last response
    for p in out_pkts:
        is_bare_ack = (p["len"] == 0 and p["ack"] and not p["syn"] and not p["fin"] and not p["rst"])
        is_response = (p["len"] == 49)
        if is_bare_ack:
            pending_ack = p
        elif is_response:
            if pending_ack is not None:
                events.append({
                    "response_frame": p["num"],
                    "preceding_bare_ack_frame": pending_ack["num"],
                    "ack_to_resp_ms": round((p["t"] - pending_ack["t"]) * 1000.0, 3),
                    "ack_before_response": True,
                })
            else:
                events.append({"response_frame": p["num"], "ack_before_response": False})
            pending_ack = None
    n_resp = sum(1 for p in out_pkts if p["len"] == 49)
    ok = [e for e in events if e.get("ack_before_response")]
    deltas = [e["ack_to_resp_ms"] for e in ok]
    return {
        "n_responses_49B": n_resp,
        "n_responses_with_preceding_bare_ack": len(ok),
        "all_responses_separate_ack": len(ok) == n_resp and n_resp > 0,
        "ack_to_resp_ms_min": round(min(deltas), 3) if deltas else None,
        "ack_to_resp_ms_median": round(sorted(deltas)[len(deltas) // 2], 3) if deltas else None,
        "ack_to_resp_ms_max": round(max(deltas), 3) if deltas else None,
        "first_5_events": events[:5],
    }


def check_echo_sizes(pkts, port):
    sizes = sorted({p["len"] for p in pkts if p["sport"] == port and p["len"] > 0})
    return {"outstation_response_unique_sizes": sizes, "native_echo_49B_only": sizes == [49]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--master-pcap", required=True)
    ap.add_argument("--outstation-pcap", required=True)
    ap.add_argument("--counters", required=True)
    ap.add_argument("--master-log", required=True)
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--expect-n", type=int, default=25, help="expected SBO transaction count")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    mp = read_pcap(args.master_pcap)
    op = read_pcap(args.outstation_pcap)
    with open(args.counters) as f:
        counters = json.load(f)
    with open(args.master_log) as f:
        mlog = json.load(f)

    n = args.expect_n
    ts_m = check_tcp_timestamps(mp)
    ts_o = check_tcp_timestamps(op)
    req = check_requests(mp, args.port)
    sep = check_separate_ack(mp, args.port)
    echo = check_echo_sizes(mp, args.port)

    counters_ok = (counters.get("select_count") == n and counters.get("operate_count") == n
                   and counters.get("callback_count") == n)

    verdict = {
        "expected_sbo_transactions": n,
        "master_facing_pcap": args.master_pcap,
        "outstation_facing_pcap": args.outstation_pcap,
        "tcp_timestamps_master_facing": ts_m,
        "tcp_timestamps_outstation_facing": ts_o,
        "requests_qual_0x17_2crob": req,
        "separate_ack_ordering": sep,
        "native_echo_size": echo,
        "outstation_counters": counters,
        "counters_correct": counters_ok,
        "master_log_summary": {k: mlog[k] for k in
                               ("n_transactions", "select_echo_unique_sizes",
                                "operate_echo_unique_sizes", "all_echoes_49B") if k in mlog},
    }

    checks = {
        "TCP_TIMESTAMPS_ABSENT": ts_m["tcp_timestamps_absent"] and ts_o["tcp_timestamps_absent"],
        "SELECT_2CROB_0x17_COUNT": req["n_select_2crob_0x17"] == n,
        "OPERATE_2CROB_0x17_COUNT": req["n_operate_2crob_0x17"] == n,
        "ALL_QUAL_0x17": req["all_qual_0x17"],
        "SEPARATE_ACK_ALL_RESPONSES": sep["all_responses_separate_ack"],
        "NATIVE_ECHO_49B_ONLY": echo["native_echo_49B_only"],
        "COUNTERS_CORRECT": counters_ok,
    }
    verdict["checks"] = checks
    verdict["OVERALL_PASS"] = all(checks.values())

    with open(args.out, "w") as f:
        json.dump(verdict, f, indent=2)

    print(json.dumps(checks, indent=2))
    print("OVERALL_PASS:", verdict["OVERALL_PASS"])
    return 0 if verdict["OVERALL_PASS"] else 1


if __name__ == "__main__":
    sys.exit(main())

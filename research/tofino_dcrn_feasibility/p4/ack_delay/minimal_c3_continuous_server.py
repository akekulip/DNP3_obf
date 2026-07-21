#!/usr/bin/env python3
"""minimal_c3_continuous_server.py — continuous single-flow outstation (one connection, N txns).

Accept ONE TCP connection, then run N sequential Class-0 transactions on it WITHOUT closing between
them: for each txn — quickack, recv the captured READ (verify), re-assert quickack, wait a shuffled
per-txn response-readiness interval, send the captured response in one write. Holds the connection
OPEN until killed. This is the continuous-traffic acceptance harness: it stresses whether Case-A
transaction state returns to zero every txn (no cold reload). No pydnp3.
"""
import argparse
import json
import random
import socket
import time

TCP_QUICKACK = getattr(socket, "TCP_QUICKACK", 12)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.0.2.10")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--request-file", required=True)
    ap.add_argument("--response-file", required=True)
    ap.add_argument("--n", type=int, default=120)
    ap.add_argument("--readiness-list", default="2,5,10,16,20")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--schedule-file", default=None,
                    help="JSON from sel751_extract.py: replay the REAL per-txn response latencies "
                         "(filtered to req_len/resp_len matching the payload files, in capture order)")
    a = ap.parse_args()
    expected = open(a.request_file, "rb").read()
    resp = open(a.response_file, "rb").read()
    if a.schedule_file:
        allt = json.load(open(a.schedule_file))["txns"]
        sched = [t["readiness_ms"] for t in allt
                 if t["req_len"] == len(expected) and t["resp_len"] == len(resp)][:a.n]
    else:
        base = [float(x) for x in a.readiness_list.split(",")]
        sched = [base[i % len(base)] for i in range(a.n)]
        random.Random(a.seed).shuffle(sched)      # deterministic shuffled readiness schedule
    a.n = len(sched)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(1)
    print("C3-CSERVER listening %s:%d n=%d sched(head)=%s" % (a.host, a.port, a.n, sched[:8]), flush=True)
    conn, addr = srv.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print("C3-CSERVER accepted %s" % (addr,), flush=True)

    ok = 0
    for i in range(a.n):
        conn.setsockopt(socket.IPPROTO_TCP, TCP_QUICKACK, 1)
        buf = b""
        while len(buf) < len(expected):
            d = conn.recv(len(expected) - len(buf))
            if not d:
                print("C3-CSERVER peer closed at txn %d" % i, flush=True)
                break
            buf += d
        if buf != expected:
            print("C3-CSERVER request mismatch at txn %d (got %dB)" % (i, len(buf)), flush=True)
            break
        conn.setsockopt(socket.IPPROTO_TCP, TCP_QUICKACK, 1)   # re-assert (one-shot)
        time.sleep(sched[i] / 1000.0)                          # native response-readiness (NOT the defense)
        conn.sendall(resp)
        ok += 1
    print("C3-CSERVER completed %d/%d txns" % (ok, a.n), flush=True)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()

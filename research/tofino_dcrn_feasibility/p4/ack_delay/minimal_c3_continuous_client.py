#!/usr/bin/env python3
"""minimal_c3_continuous_client.py — continuous single-flow master (one connection, N txns).

Connect ONCE, then run N request/response transactions in lockstep on the same connection: send the
captured READ, receive the exact response length, verify byte-for-byte, wait a small inter-txn gap,
repeat. Holds the connection OPEN until killed. Prints a per-txn app latency line and a final summary
(all byte-identical? degradation across txn index?). App timings are DIAGNOSTIC; the wire capture +
switch telemetry are authoritative.
"""
import argparse
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.0.2.10")
    ap.add_argument("--local", default="10.0.1.10")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--request-file", required=True)
    ap.add_argument("--response-file", required=True)
    ap.add_argument("--n", type=int, default=120)
    ap.add_argument("--gap-ms", type=float, default=30.0)
    a = ap.parse_args()
    req = open(a.request_file, "rb").read()
    expected = open(a.response_file, "rb").read()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.local, 0))
    s.connect((a.host, a.port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    lat = []
    mism = 0
    for i in range(a.n):
        t0 = time.monotonic_ns()
        s.sendall(req)
        buf = b""
        while len(buf) < len(expected):
            d = s.recv(len(expected) - len(buf))
            if not d:
                print("C3-CCLIENT peer closed at txn %d" % i, flush=True)
                break
            buf += d
        t1 = time.monotonic_ns()
        if buf != expected:
            mism += 1
        else:
            lat.append((t1 - t0) / 1e6)
        if a.gap_ms > 0:
            time.sleep(a.gap_ms / 1000.0)
    ok = len(lat)
    if ok:
        head = sum(lat[:10]) / min(10, ok)
        tail = sum(lat[-10:]) / min(10, ok)
        ls = sorted(lat)
        print("C3-CCLIENT done: %d/%d byte-identical, mism=%d | app req->resp med=%.2fms "
              "head10=%.2f tail10=%.2f (degradation if tail>>head) [DIAGNOSTIC]"
              % (ok, a.n, mism, ls[len(ls) // 2], head, tail), flush=True)
    else:
        print("C3-CCLIENT done: 0 completed, mism=%d" % mism, flush=True)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()

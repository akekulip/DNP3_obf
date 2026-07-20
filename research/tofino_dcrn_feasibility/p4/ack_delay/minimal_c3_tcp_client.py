#!/usr/bin/env python3
"""minimal_c3_tcp_client.py — single-transaction C3 master (ordinary TCP, no pydnp3).

Connect → send exactly one captured Class-0 READ → receive the exact expected response length →
verify byte-for-byte → hold the connection OPEN and idle until killed. Emits no other application
traffic. The app timestamps printed here are DIAGNOSTIC only; the authoritative timing is the wire
capture. Holding the socket open keeps TCP shutdown packets out of the capture while Case-A is armed.
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
    ap.add_argument("--response-file", required=True, help="expected response bytes (verify)")
    a = ap.parse_args()
    req = open(a.request_file, "rb").read()
    expected = open(a.response_file, "rb").read()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.local, 0))
    s.connect((a.host, a.port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    t0 = time.monotonic_ns()
    s.sendall(req)                       # exactly one captured Class-0 READ
    buf = b""
    while len(buf) < len(expected):
        d = s.recv(len(expected) - len(buf))
        if not d:
            break
        buf += d
    t1 = time.monotonic_ns()
    match = (buf == expected)
    print("C3-CLIENT resp %dB response_match=%s app_req_to_resp=%.2fms (DIAGNOSTIC ONLY)"
          % (len(buf), match, (t1 - t0) / 1e6), flush=True)

    while True:                          # hold open until killed (no close traffic while armed)
        time.sleep(1)


if __name__ == "__main__":
    main()

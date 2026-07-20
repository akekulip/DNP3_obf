#!/usr/bin/env python3
"""minimal_c3_tcp_server.py — single-transaction C3 outstation (ordinary TCP, no pydnp3).

Produces EXACTLY one clean separate-ACK transaction for the Case-A microbenchmark:
  accept → (kernel quickack pure ACK) → recv captured Class-0 READ → response-readiness delay →
  send captured SEL-751 response in one write → hold the connection OPEN and idle until killed.

The readiness delay is the outstation's native processing time (controls WHEN the response is ready
so the switch's ACK-hold is exercised) — it is NOT the defense; the Tofino performs the ACK hold.
Holding the socket open after the transaction keeps TCP shutdown packets out of the capture while the
Case-A flow is still armed (close only after the switch flow state is reset). No pydnp3, no IIN clear,
no WRITE, no keepalive, no CONFIRM, no second request.
"""
import argparse
import socket
import time

TCP_QUICKACK = getattr(socket, "TCP_QUICKACK", 12)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.0.2.10")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--request-file", required=True, help="expected captured READ bytes")
    ap.add_argument("--response-file", required=True, help="captured DNP3 response bytes to send")
    ap.add_argument("--readiness-ms", type=float, default=16.0)
    a = ap.parse_args()
    expected = open(a.request_file, "rb").read()
    resp = open(a.response_file, "rb").read()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(1)
    print("C3-SERVER listening %s:%d readiness=%.1fms exp=%dB resp=%dB"
          % (a.host, a.port, a.readiness_ms, len(expected), len(resp)), flush=True)

    conn, addr = srv.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.setsockopt(socket.IPPROTO_TCP, TCP_QUICKACK, 1)   # prompt pure ACK (before the app responds)
    print("C3-SERVER accepted %s" % (addr,), flush=True)

    buf = b""
    while len(buf) < len(expected):
        d = conn.recv(len(expected) - len(buf))
        if not d:
            break
        buf += d
    t_req = time.monotonic_ns()
    conn.setsockopt(socket.IPPROTO_TCP, TCP_QUICKACK, 1)   # re-assert (quickack is one-shot)
    match = (buf == expected)
    print("C3-SERVER recv %dB request_match=%s" % (len(buf), match), flush=True)

    # controlled native response-readiness interval (NOT the defense)
    rem_ms = a.readiness_ms - (time.monotonic_ns() - t_req) / 1e6
    if rem_ms > 0:
        time.sleep(rem_ms / 1000.0)
    conn.sendall(resp)   # exactly one controlled write
    print("C3-SERVER sent response %dB" % len(resp), flush=True)

    # hold OPEN and idle until killed — no close traffic while Case-A is armed
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()

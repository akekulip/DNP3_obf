#!/usr/bin/env python3
"""h3_outstation.py -- H3 software outstation (outstation-facing endpoint), real TCP sockets.

Stands in for the SEL-751 as a controllable Case-A separate-ACK device. It:
  * accepts 2-CROB SELECT (func 0x03) and OPERATE (func 0x04) requests with qualifier 0x17,
  * replies with the 49-byte NATIVE application echo (byte-shape-identical to the SEL-751),
  * exposes counters: select_count, operate_count, callback_count,
  * DELIBERATELY separates the TCP ACK from the application response (Case-A behaviour): it forces
    an immediate bare ACK for each received request (TCP_QUICKACK) and then waits a bounded
    application-processing delay before emitting the DNP3 response, so a pure TCP ACK always
    precedes the response on the wire.

SAFETY: this is software only. The "physical callback" for an OPERATE increments callback_count and
NOTHING ELSE -- it never drives any real output and never contacts any relay. DNP3 addrs: the
outstation answers as src=0 (outstation) to dst=1 (master).
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import socket
import struct
import sys
import time

import dnp3_wire as w

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("h3_outstation")

# TCP_QUICKACK is Linux-specific; keep a literal fallback if the constant is absent.
TCP_QUICKACK = getattr(socket, "TCP_QUICKACK", 12)


class Counters:
    def __init__(self, path: str):
        self.path = path
        self.select_count = 0
        self.operate_count = 0
        self.callback_count = 0  # increments once per OPERATE processed -- SOFTWARE ONLY
        self.select_echo_bytes = []
        self.operate_echo_bytes = []
        self.other = 0

    def dump(self):
        d = {
            "select_count": self.select_count,
            "operate_count": self.operate_count,
            "callback_count": self.callback_count,
            "select_echo_unique_sizes": sorted(set(self.select_echo_bytes)),
            "operate_echo_unique_sizes": sorted(set(self.operate_echo_bytes)),
            "unrecognised_requests": self.other,
            "note": "callback_count is a software counter only; no physical output is ever driven",
        }
        with open(self.path, "w") as f:
            json.dump(d, f, indent=2)
        return d


def handle_connection(conn: socket.socket, ctr: Counters, app_delay_s: float):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.setsockopt(socket.IPPROTO_TCP, TCP_QUICKACK, 1)
    conn.settimeout(10.0)
    transport_seq = 0
    buf = b""
    while True:
        try:
            data = conn.recv(4096)
        except socket.timeout:
            logger.info("connection idle timeout, closing")
            break
        if not data:
            break
        # Force an immediate bare ACK for the bytes just received (Case-A separate ACK). This is a
        # one-shot flag on Linux, so it is re-armed on every recv.
        conn.setsockopt(socket.IPPROTO_TCP, TCP_QUICKACK, 1)
        buf += data
        # Deframe every complete DNP3 request currently buffered.
        consumed_any = True
        while consumed_any:
            consumed_any = False
            for total, userdata in w.deframe(buf):
                req = w.parse_request(userdata)
                if req is None:
                    break
                # Bounded application-processing delay so the forced ACK is on the wire well before
                # the response -> guarantees ACK-then-response ordering.
                time.sleep(app_delay_s)
                if req["func"] == w.FUNC_SELECT:
                    ctr.select_count += 1
                    echo = w.build_echo(req["app_seq"], transport_seq)
                    ctr.select_echo_bytes.append(len(echo))
                elif req["func"] == w.FUNC_OPERATE:
                    ctr.operate_count += 1
                    # "physical callback": SOFTWARE ONLY -- increment a counter, drive nothing.
                    ctr.callback_count += 1
                    echo = w.build_echo(req["app_seq"], transport_seq)
                    ctr.operate_echo_bytes.append(len(echo))
                else:
                    ctr.other += 1
                    buf = buf[total:]
                    consumed_any = True
                    break
                transport_seq = (transport_seq + 1) & 0x3F
                conn.sendall(echo)
                ctr.dump()
                buf = buf[total:]
                consumed_any = True
                break
    conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="10.9.0.2")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--counters", required=True, help="path to write counters JSON")
    ap.add_argument("--app-delay-ms", type=float, default=5.0,
                    help="bounded application-processing delay before the response (Case-A CLRT)")
    ap.add_argument("--ready-file", default=None, help="touch this file once listening")
    args = ap.parse_args()

    ctr = Counters(args.counters)
    ctr.dump()  # write a zeroed baseline immediately

    def on_term(signum, frame):
        logger.info("SIGTERM: final counters %s", ctr.dump())
        sys.exit(0)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(4)
    logger.info("listening on %s:%d (app_delay=%.1f ms, native echo=49B, Case-A separate ACK)",
                args.bind, args.port, args.app_delay_ms)
    if args.ready_file:
        open(args.ready_file, "w").close()

    try:
        while True:
            conn, peer = srv.accept()
            logger.info("accepted %s", peer)
            handle_connection(conn, ctr, args.app_delay_ms / 1000.0)
            logger.info("connection done; counters=%s", ctr.dump())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 -- log and dump on any error so counters survive
        logger.error("outstation error: %s", e)
        ctr.dump()
    finally:
        srv.close()


if __name__ == "__main__":
    main()

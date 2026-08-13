#!/usr/bin/env python3
"""h3_master.py -- H3 software master (master-facing endpoint), real TCP sockets.

Issues N Select-Before-Operate transactions over ONE persistent connection: for each transaction it
sends a 2-CROB SELECT (func 0x03, qualifier 0x17), waits for the 49-byte echo, then sends an
IDENTICAL 2-CROB OPERATE (func 0x04, qualifier 0x17) and waits for its echo. Per-request wire
timestamps are logged. DNP3 addrs: master answers as src=1 to dst=0 (outstation).

NOTE ON CLOCKS: the application timestamps written here are supplementary. The authoritative timing
(separate-ACK ordering, ACK->response delta) comes from the pcap captures, which are all taken on
one host kernel clock. See run_h3_namespace_validation.sh.
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import time

import dnp3_wire as w

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("h3_master")


def recv_one_frame(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Receive until at least one complete DNP3 link frame is available; return its raw bytes."""
    sock.settimeout(timeout)
    buf = b""
    while True:
        d = sock.recv(4096)
        if not d:
            raise ConnectionError("outstation closed before a full frame arrived")
        buf += d
        for total, _userdata in w.deframe(buf):
            return buf[:total]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", default="10.9.0.2")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--src", default="10.9.0.1")
    ap.add_argument("--src-port", type=int, default=40000)
    ap.add_argument("--n", type=int, default=25, help="number of SELECT->OPERATE transactions")
    ap.add_argument("--log", required=True, help="path to write the per-transaction JSON log")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.bind((args.src, args.src_port))
    except OSError:
        pass
    s.settimeout(5.0)
    s.connect((args.dst, args.port))
    logger.info("connected %s -> %s:%d (%d SELECT->OPERATE SBO transactions)",
                args.src, args.dst, args.port, args.n)

    records = []
    app_seq = 0
    for i in range(args.n):
        txn = {"txn": i}
        for phase, func in (("SELECT", w.FUNC_SELECT), ("OPERATE", w.FUNC_OPERATE)):
            frame = w.build_request(func, app_seq)
            t_send = time.time()
            s.sendall(frame)
            echo = recv_one_frame(s)
            t_recv = time.time()
            txn[phase] = {
                "app_seq": app_seq,
                "func": "0x%02x" % func,
                "req_bytes": len(frame),
                "echo_bytes": len(echo),
                "send_epoch": t_send,
                "recv_epoch": t_recv,
                "rtt_ms": round((t_recv - t_send) * 1000.0, 3),
            }
            app_seq = (app_seq + 1) & 0x0F
        records.append(txn)

    s.close()
    select_sizes = sorted({t["SELECT"]["echo_bytes"] for t in records})
    operate_sizes = sorted({t["OPERATE"]["echo_bytes"] for t in records})
    summary = {
        "n_transactions": args.n,
        "n_select": sum(1 for t in records if "SELECT" in t),
        "n_operate": sum(1 for t in records if "OPERATE" in t),
        "select_echo_unique_sizes": select_sizes,
        "operate_echo_unique_sizes": operate_sizes,
        "all_echoes_49B": select_sizes == [49] and operate_sizes == [49],
        "records": records,
    }
    with open(args.log, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info("done: %d SBO txns, select_sizes=%s operate_sizes=%s all_49B=%s",
                args.n, select_sizes, operate_sizes, summary["all_echoes_49B"])


if __name__ == "__main__":
    main()

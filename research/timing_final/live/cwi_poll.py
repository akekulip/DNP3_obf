#!/usr/bin/env python3
"""cwi_poll.py — cold / warm / idle characterization poller (directive §5).

Read-only Class-0 READs (DNP3 function 1) only. The function code is asserted before every send.
No SELECT, OPERATE, DIRECT_OPERATE, WRITE, restart or configuration. Nothing is written to the relay.

CELLS
  C1  new TCP connection, ONE read, close.            isolates connection-cold cost
  C2  one connection, polls 1..P.                     how the cold effect decays with poll ordinal
  C3  one connection, absolute-cadence steady state.   the steady distribution and its tail
  C4  one connection, idle S seconds, then poll.       whether idleness re-creates the cold state

ABSOLUTE CADENCE (this is the fix, not a detail)
  Polls fire at t0 + k*period against a monotonic clock. The v1 harness slept for a fixed interval
  AFTER each response, which makes a protected arm slower than a native arm by exactly the hold —
  that is the confound that made campaign A's arms incomparable (300.4 ms native vs 400.5 ms
  protected). Never sleep relative to the response.

OUTPUT
  A JSON sidecar of per-poll labels. The pcap is authoritative for timing; the sidecar exists so
  each transaction can be joined to its experimental condition via (src_port, dnp3 app sequence).
"""
import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dnp3_crc import append_crc

MASTER_LINK, OUTSTATION_LINK = 1, 0        # verified on the wire 2026-07-25


def read_frame(app_seq):
    """Class-0 READ addressed to the physical relay: dst link 0, src link 1."""
    data = bytes([0xC0, 0xC0 | (app_seq & 0x0F), 0x01, 0x1E, 0x03, 0x01, 0x01, 0x00, 0x07, 0x00])
    assert data[2] == 0x01, "refusing to send: application function code is not READ(1)"
    hdr = bytes([0x05, 0x64, 0x0F, 0xC4,
                 OUTSTATION_LINK & 0xFF, (OUTSTATION_LINK >> 8) & 0xFF,
                 MASTER_LINK & 0xFF, (MASTER_LINK >> 8) & 0xFF])
    return append_crc(hdr) + append_crc(data)


def connect(src_ip, dst_ip, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind((src_ip, 0))
    s.settimeout(timeout)
    s.connect((dst_ip, 20000))
    return s, s.getsockname()[1]


def one_poll(sock, app_seq):
    """Send one READ, wait for the response. Returns (ok, nbytes, func, app_rtt_ms)."""
    t0 = time.monotonic()
    sock.sendall(read_frame(app_seq))
    got = b""
    try:
        while len(got) < 4:
            d = sock.recv(512)
            if not d:
                break
            got += d
    except socket.timeout:
        pass
    dt = (time.monotonic() - t0) * 1000.0
    func = got[12] if len(got) > 12 else 0
    return (func == 0x81), len(got), func, dt


def main():
    ap = argparse.ArgumentParser(description="cold/warm/idle characterization poller")
    ap.add_argument("--cell", choices=["C1", "C2", "C3", "C4"], required=True)
    ap.add_argument("--connections", type=int, default=30, help="C1/C2: number of TCP connections")
    ap.add_argument("--polls", type=int, default=5, help="C2: polls per connection; C3: total polls")
    ap.add_argument("--trials", type=int, default=20, help="C4: trials per idle interval")
    ap.add_argument("--idle-s", type=float, default=1.0, help="C4: idle seconds before each poll")
    ap.add_argument("--period-ms", type=float, default=400.0, help="absolute inter-poll period")
    ap.add_argument("--src-ip", default="192.168.10.1")
    ap.add_argument("--dst-ip", default="192.168.10.7")
    ap.add_argument("--sidecar", default=None)
    a = ap.parse_args()

    period = a.period_ms / 1000.0
    labels, ok_total, n_total = [], 0, 0

    def record(conn_id, sport, ordinal, idle_before, app_seq, res):
        nonlocal ok_total, n_total
        ok, nb, func, rtt = res
        ok_total += 1 if ok else 0
        n_total += 1
        labels.append(dict(cell=a.cell, connection_id=conn_id, src_port=sport,
                           poll_ordinal=ordinal, idle_before_s=idle_before,
                           dnp3_app_seq=app_seq & 0x0F, treatment="native",
                           app_rtt_ms=round(rtt, 3), resp_bytes=nb,
                           dnp3_func=func, answered=ok))
        print("  %s conn=%-3d ord=%-3d idle=%-5.1f seq=0x%02X rx=%3dB func=0x%02x app_rtt=%7.2fms%s"
              % (a.cell, conn_id, ordinal, idle_before, 0xC0 | (app_seq & 0x0F), nb, func, rtt,
                 "" if ok else "   <-- NO DNP3 RESPONSE"))

    try:
        if a.cell == "C1":
            for c in range(a.connections):
                s, sp = connect(a.src_ip, a.dst_ip)
                record(c, sp, 1, 0.0, c, one_poll(s, c))
                s.close()
                time.sleep(0.25)                     # let the close settle; not a measured interval

        elif a.cell == "C2":
            for c in range(a.connections):
                s, sp = connect(a.src_ip, a.dst_ip)
                t0 = time.monotonic()
                for k in range(a.polls):
                    target = t0 + k * period          # ABSOLUTE, not relative to the response
                    now = time.monotonic()
                    if target > now:
                        time.sleep(target - now)
                    record(c, sp, k + 1, 0.0, k, one_poll(s, k))
                s.close()
                time.sleep(0.25)

        elif a.cell == "C3":
            s, sp = connect(a.src_ip, a.dst_ip)
            t0 = time.monotonic()
            for k in range(a.polls):
                target = t0 + k * period
                now = time.monotonic()
                if target > now:
                    time.sleep(target - now)
                record(0, sp, k + 1, 0.0, k, one_poll(s, k))
            s.close()

        elif a.cell == "C4":
            s, sp = connect(a.src_ip, a.dst_ip)
            for k in range(3):                        # warm the connection out of the cold state
                one_poll(s, k)
                time.sleep(period)
            for t in range(a.trials):
                time.sleep(a.idle_s)                  # the idle interval IS the treatment
                record(0, sp, t + 1, a.idle_s, t, one_poll(s, t))
            s.close()
    except KeyboardInterrupt:
        print("\ninterrupted; writing partial sidecar")
    except Exception as e:
        print("FATAL: %s: %s" % (type(e).__name__, e))
        return 2

    path = a.sidecar or ("cwi_%s.labels.json" % a.cell)
    json.dump(dict(cell=a.cell, period_ms=a.period_ms, idle_s=a.idle_s,
                   master_link=MASTER_LINK, outstation_link=OUTSTATION_LINK,
                   polls=labels), open(path, "w"), indent=2)
    print("DONE  %s: %d/%d answered with DNP3 RESPONSE (func 129); labels -> %s"
          % (a.cell, ok_total, n_total, path))
    return 0 if ok_total == n_total else 1


if __name__ == "__main__":
    sys.exit(main())

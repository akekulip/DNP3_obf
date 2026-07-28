#!/usr/bin/env python3
"""poll.py — drive the physical SEL-751 through the inline Tofino, native or protected.

MODES
  --mode native      send READs only.  Nothing holds the response, so you measure the relay's
                     true CLRT (relay pure-ACK -> DNP3 response).
  --mode protected   send each READ, then IMMEDIATELY inject K blocker tokens.  The tokens
                     starve the response's low-priority queue until the data-plane deadline
                     t_ack + G, so the observed CLRT becomes G.

WHY THE ORDER MATTERS (protected mode)
  A token is accepted only if its `gen` byte matches the current transaction generation, and
  that generation is written by the READ itself (the DNP3 application-control byte).  Tokens
  injected BEFORE the READ therefore carry a stale generation and self-terminate on their first
  loopback pass.  Tokens must also be circulating before the relay's response arrives, which is
  1-5 ms after the READ -- hence "send, then inject, with nothing in between".

SAFETY
  The only DNP3 bytes this program transmits are Class-0 READ (function 1) frames; the function
  code is asserted before every send.  No WRITE, no SELECT/OPERATE, no cold restart, no time sync.
  Blocker tokens use ethertype 0x88C1, which the P4 parser FORCES to ROLE_BLOCK -- they are
  internal to the switch and can never egress to a host port.

  Protected mode needs root (AF_PACKET raw socket).  Native mode does not.
"""
import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dnp3_crc import append_crc

ETYPE_TOKEN = 0x88C1
ROLE_BLOCK = 1
DST_INTERNAL = "020000000001"
SRC_TOKEN = "020000000b0c"


def read_frame(appseq):
    """Class-0 READ, addressed to the live relay: dst link address 0, src (master) 1."""
    data = bytes([0xC0, 0xC0 | (appseq & 0x0F), 0x01, 0x1E, 0x03, 0x01, 0x01, 0x00, 0x07, 0x00])
    assert data[2] == 0x01, "refusing to send: application function code is not READ(1)"
    hdr = bytes([0x05, 0x64, 0x0F, 0xC4, 0x00, 0x00, 0x01, 0x00])
    return append_crc(hdr) + append_crc(data)


def build_token(gen, budget, slot=0, pad_to=60):
    ib = struct.pack("!BBBI", ROLE_BLOCK, slot & 0xFF, gen & 0xFF, budget & 0xFFFFFFFF)
    f = bytes.fromhex(DST_INTERNAL) + bytes.fromhex(SRC_TOKEN) + struct.pack("!H", ETYPE_TOKEN) + ib
    return f + b"\x00" * max(0, pad_to - len(f))


def main():
    ap = argparse.ArgumentParser(description="live DNP3 poll of the SEL-751 through the Tofino")
    ap.add_argument("--mode", choices=["native", "protected"], required=True)
    ap.add_argument("--n", type=int, default=20, help="measured polls")
    ap.add_argument("--warmup", type=int, default=1,
                    help="unmeasured warm-up polls first (the cold poll is a big outlier)")
    ap.add_argument("--k", type=int, default=64, help="blocker reservoir depth (>=64 required)")
    ap.add_argument("--budget", type=int, default=2000000, help="token pass budget (fail-open bound)")
    ap.add_argument("--gap", type=float, default=0.4, help="seconds between polls")
    ap.add_argument("--src-ip", default="192.168.10.1")
    ap.add_argument("--dst-ip", default="192.168.10.7")
    ap.add_argument("--iface", default="enp59s0f0np0")
    a = ap.parse_args()

    protected = (a.mode == "protected")
    raw = None
    if protected:
        if os.geteuid() != 0:
            sys.exit("FATAL: --mode protected needs root (AF_PACKET). Re-run with sudo.")
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        raw.bind((a.iface, 0))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind((a.src_ip, 0))
    s.settimeout(5.0)
    try:
        s.connect((a.dst_ip, 20000))
    except Exception as e:
        sys.exit("FATAL: could not connect to %s:20000 (%s).\n"
                 "  Check the relay leg is up and the Tofino is forwarding." % (a.dst_ip, e))
    print("MODE=%s  %s -> %s:20000  K=%s" % (a.mode, a.src_ip, a.dst_ip, a.k if protected else "-"))

    ok = 0
    for i in range(a.warmup + a.n):
        gen = 0xC0 | (i & 0x0F)
        t0 = time.monotonic()
        s.sendall(read_frame(i))
        if protected:
            tok = build_token(gen, a.budget)
            for _ in range(a.k):
                raw.send(tok)
        got = b""
        try:
            while len(got) < 4:
                d = s.recv(256)
                if not d:
                    break
                got += d
        except socket.timeout:
            pass
        dt = (time.monotonic() - t0) * 1000.0
        func = got[12] if len(got) > 12 else 0
        if func == 0x81:
            ok += 1
        print("%-6s %2d gen=0x%02X rx=%3dB rtt=%7.2fms func=0x%02x%s"
              % ("warmup" if i < a.warmup else "poll", i, gen, len(got), dt, func,
                 "" if func == 0x81 else "   <-- NO DNP3 RESPONSE"))
        time.sleep(a.gap)

    s.close()
    if raw:
        raw.close()
    print("DONE  %d/%d polls answered with DNP3 RESPONSE (func 129)" % (ok, a.warmup + a.n))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

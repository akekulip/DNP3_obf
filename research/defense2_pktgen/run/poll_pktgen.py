#!/usr/bin/env python3
"""poll_pktgen.py — drive the physical SEL-751 through the inline Tofino (pktgen variant).

Unlike the host-seeded runner, this variant injects NO blocker tokens from the host. The switch
generates the K=64 blocker reservoir itself, triggered by the READ, via the Tofino-1 packet
generator (trigger_recirc_pattern). The client therefore only ever sends legitimate DNP3
Class-0 READ frames in BOTH modes.

MODES (the client behaviour is identical; the difference is entirely in-switch)
  --mode native      send READs while the pktgen app is DISABLED  -> the relay's true CLRT.
  --mode protected   send READs while the pktgen app is ENABLED   -> each READ triggers one
                     in-switch 64-token burst that holds the response to t_ack + G.

  Enable/disable the pktgen app in the setup (dnp3_timing_normalizer_pktgen_setup.py). This runner
  does not touch the switch and does NOT require root in either mode — the raw-socket 0x88C1
  injection that the host-seeded runner needed is gone.

SAFETY
  The only DNP3 bytes this program transmits are Class-0 READ (function 1) frames; the function
  code is asserted before every send. No WRITE, no SELECT/OPERATE, no cold restart, no time sync.
"""
import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dnp3_crc import append_crc


def read_frame(appseq):
    """Class-0 READ, addressed to the live relay: dst link address 0, src (master) 1."""
    data = bytes([0xC0, 0xC0 | (appseq & 0x0F), 0x01, 0x1E, 0x03, 0x01, 0x01, 0x00, 0x07, 0x00])
    assert data[2] == 0x01, "refusing to send: application function code is not READ(1)"
    hdr = bytes([0x05, 0x64, 0x0F, 0xC4, 0x00, 0x00, 0x01, 0x00])
    return append_crc(hdr) + append_crc(data)


def main():
    ap = argparse.ArgumentParser(description="live DNP3 poll of the SEL-751 through the Tofino (pktgen variant)")
    ap.add_argument("--mode", choices=["native", "protected"], required=True,
                    help="label only; protection is controlled in-switch, not by this client")
    ap.add_argument("--n", type=int, default=20, help="measured polls")
    ap.add_argument("--warmup", type=int, default=1,
                    help="unmeasured warm-up polls first (the cold poll is a big outlier)")
    ap.add_argument("--gap", type=float, default=0.4, help="seconds between polls")
    ap.add_argument("--src-ip", default="192.168.10.1")
    ap.add_argument("--dst-ip", default="192.168.10.7")
    a = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind((a.src_ip, 0))
    s.settimeout(5.0)
    try:
        s.connect((a.dst_ip, 20000))
    except Exception as e:
        sys.exit("FATAL: could not connect to %s:20000 (%s).\n"
                 "  Check the relay leg is up and the Tofino is forwarding." % (a.dst_ip, e))
    print("MODE=%s  %s -> %s:20000  (blockers generated in-switch; no host injection)"
          % (a.mode, a.src_ip, a.dst_ip))

    ok = 0
    for i in range(a.warmup + a.n):
        gen = 0xC0 | (i & 0x0F)
        t0 = time.monotonic()
        s.sendall(read_frame(i))
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
    print("DONE  %d/%d polls answered with DNP3 RESPONSE (func 129)" % (ok, a.warmup + a.n))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

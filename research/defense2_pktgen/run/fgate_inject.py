#!/usr/bin/env python3
# Functional-gate controlled DNP3 injector (READ-ONLY). Sends a caller-specified
# sequence of Class-0 READ app-sequence values so idempotency (duplicate gen) and
# fresh-vs-duplicate arming can be tested precisely. Safety: only function-code-1
# READ frames are ever transmitted (asserted before every send).
import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dnp3_crc import append_crc


def read_frame(appseq):
    data = bytes([0xC0, 0xC0 | (appseq & 0x0F), 0x01, 0x1E, 0x03, 0x01, 0x01, 0x00, 0x07, 0x00])
    assert data[2] == 0x01, "refusing: not a READ(1)"
    hdr = bytes([0x05, 0x64, 0x0F, 0xC4, 0x00, 0x00, 0x01, 0x00])
    return append_crc(hdr) + append_crc(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gens", required=True, help="comma-separated app-seq values, e.g. 5 or 5,5 or 5,6,7")
    ap.add_argument("--gap", type=float, default=0.3, help="seconds between sends")
    ap.add_argument("--src-ip", default="192.168.10.1")
    ap.add_argument("--dst-ip", default="192.168.10.7")
    a = ap.parse_args()
    gens = [int(x) for x in a.gens.split(",") if x != ""]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind((a.src_ip, 0))
    s.settimeout(5.0)
    s.connect((a.dst_ip, 20000))
    for g in gens:
        t0 = time.monotonic()
        s.sendall(read_frame(g))
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
        print("sent gen=0x%02X rx=%dB rtt=%.2fms func=0x%02x" % (0xC0 | (g & 0x0F), len(got), dt, func))
        time.sleep(a.gap)
    s.close()


if __name__ == "__main__":
    main()

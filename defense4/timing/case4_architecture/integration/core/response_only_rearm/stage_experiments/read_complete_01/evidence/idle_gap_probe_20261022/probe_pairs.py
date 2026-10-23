"""Idle-gap ICMP probe (Philip, 2026-10-22): from Vision's parent address to the relay through the production switch
program. 60 pairs: echo A after >= 200 ms idle, echo B ~100 us behind it (its reply lands on a busy receive path).
Raw ICMP socket (root via the harness's sudo python3; unprivileged ICMP is disabled on Vision). Sends only; the
timestamps used are tcpdump's on enp59s0f0np0 (request at the transmit tap, reply at the receive tap).
  sudo -n python3 -I probe_pairs.py SRC DST"""
import os
import socket
import struct
import sys
import time


def checksum(data):
    data += b'\0' * (len(data) % 2)
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff


def echo(ident, seq):
    payload = b'idle-gap-probe-20261022'
    head = struct.pack('!BBHHH', 8, 0, 0, ident, seq)
    return struct.pack('!BBHHH', 8, 0, checksum(head + payload), ident, seq) + payload


src, dst = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.bind((src, 0))
ident = os.getpid() & 0xffff
for k in range(60):
    time.sleep(0.2)
    s.sendto(echo(ident, 2 * k), (dst, 0))
    t = time.perf_counter() + 100e-6
    while time.perf_counter() < t:
        pass
    s.sendto(echo(ident, 2 * k + 1), (dst, 0))
time.sleep(0.5)
print('sent 60 pairs, ident %d' % ident)

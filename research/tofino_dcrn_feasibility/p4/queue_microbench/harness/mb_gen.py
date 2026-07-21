#!/usr/bin/env python3
"""
mb_gen.py — queue_microbench host packet generator (run on HULK, sends into dp9).

Emits 64 B UDP frames whose UDP dst-port selects the switch's size-state / pad / role class
(queue_microbench.p4 mb_classify const table). The switch pads/holds/queues them; capture the
result on Vision with mb_capture.sh and analyse with mb_parse.py.

Base frame is exactly 64 B on the wire (14 Eth + 20 IPv4 + 8 UDP + 22 payload). The payload
embeds MAGIC(4) + seq(4) + tx_ns(8) + filler(6) so the parser can measure loss, reordering,
and (with a synced or single-host clock) residence time.

Classification dports (must match queue_microbench.p4):
  20001 ACK_S1  (pad->S1)     20002 RESP_S2 (pad->S2)
  20003 SPLIT_S1(pad->S1)     20004 SPLIT_S2(pad->S2)
  20005 PRE_S1  (preserve)    20006 PRE_S2  (preserve, but base<S2 so stays base — see note)
  any other dport -> fail-open (transparent forward), used for background load.

Mode dports (chosen by the harness, complements the control-plane pat_state):
  v1    (equal-sized): use 20005 (PRE_S1, PAD_NONE) so reals stay 64 B like the chaff.
  final (size order):  alternate 20001 (pad S1->128) and 20002 (pad S2->256).

Usage examples (see run_matrix.sh for the full plan-4 matrix):
  # a. one isolated marked packet (sparse first-packet)
  sudo python3 mb_gen.py --iface enp1s0f0 --dports 20001 --count 1
  # 1/10 ms stream, final mode alternating S1/S2
  sudo python3 mb_gen.py --iface enp1s0f0 --dports 20001 20002 --count 200 --interval-ms 10
  # small bursts of 4
  sudo python3 mb_gen.py --iface enp1s0f0 --dports 20001 --count 40 --burst 4 --interval-ms 50
  # background load on a non-classified port (fail-open path)
  sudo python3 mb_gen.py --iface enp1s0f0 --dports 30000 --count 100000 --interval-ms 0.1
"""
import argparse
import time
import struct

from scapy.all import Ether, IP, UDP, Raw, sendp   # scapy (project standard)

MAGIC = b"MBQ1"
DST_MAC = "00:11:22:33:44:55"   # arbitrary; switch steers by P4, not L2 learning
SRC_MAC = "00:aa:bb:cc:dd:ee"
SRC_IP  = "10.0.9.9"            # arbitrary; classification is by UDP dport only
DST_IP  = "10.0.8.8"
BASE_WIRE = 64                  # keep every emitted frame 64 B so on-switch pad hits the target


def build_frame(dport, seq):
    tx_ns = time.time_ns()
    body = MAGIC + struct.pack("!I", seq & 0xFFFFFFFF) + struct.pack("!Q", tx_ns)
    # pad payload so wire == 64 B: 14+20+8 = 42 header -> 22 payload bytes
    body = body + b"\x00" * (22 - len(body))
    return Ether(dst=DST_MAC, src=SRC_MAC) / IP(src=SRC_IP, dst=DST_IP) / \
        UDP(sport=40000, dport=dport) / Raw(load=body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True, help="Hulk NIC facing dp9")
    ap.add_argument("--dports", type=int, nargs="+", required=True,
                    help="one or more UDP dports; cycled per packet (e.g. 20001 20002 for final)")
    ap.add_argument("--count", type=int, default=1, help="total frames to send")
    ap.add_argument("--interval-ms", type=float, default=10.0, help="inter-frame gap (ms)")
    ap.add_argument("--burst", type=int, default=1, help="frames per burst (sent back-to-back)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    interval = args.interval_ms / 1000.0
    seq = 0
    sent = 0
    print("mb_gen: iface=%s dports=%s count=%d interval=%.3f ms burst=%d"
          % (args.iface, args.dports, args.count, args.interval_ms, args.burst))
    if args.dry_run:
        f = build_frame(args.dports[0], 0)
        print("  sample frame wire len = %d B (target 64)" % len(bytes(f)))
        return

    t0 = time.time()
    while sent < args.count:
        burst = []
        for _ in range(min(args.burst, args.count - sent)):
            dport = args.dports[seq % len(args.dports)]
            burst.append(build_frame(dport, seq))
            seq += 1
        # send a burst back-to-back, then wait the inter-burst gap
        sendp(burst, iface=args.iface, verbose=False)
        sent += len(burst)
        if sent < args.count and interval > 0:
            time.sleep(interval)
    dt = time.time() - t0
    print("mb_gen: sent %d frames in %.3f s (%.1f pps)" % (sent, dt, sent / dt if dt else 0))


if __name__ == "__main__":
    main()

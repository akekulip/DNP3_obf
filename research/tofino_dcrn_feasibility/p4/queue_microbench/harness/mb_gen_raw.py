#!/usr/bin/env python3
"""mb_gen_raw.py — dependency-free (stdlib AF_PACKET) queue_microbench generator for HULK.

Same 64 B frame format as mb_gen.py (so mb_parse.py is unchanged): 14 Eth + 20 IPv4 + 8 UDP +
22 payload, payload = MAGIC('MBQ1') + seq(4, !I) + tx_ns(8, !Q) + filler(6). UDP dst-port picks
the switch's size-state/pad/role class. Runs on Hulk (Vision/scapy unavailable); needs root
(AF_PACKET SOCK_RAW) -> run under sudo.

Usage:
  sudo python3 mb_gen_raw.py --iface enp59s0f0np0 --dports 20001 --count 1                 # sparse 1
  sudo python3 mb_gen_raw.py --iface enp59s0f0np0 --dports 20001 --count 40000 --interval-ms 0   # backlog
  sudo python3 mb_gen_raw.py --iface enp59s0f0np0 --dports 20001 --count 200 --interval-ms 200    # 5 Hz
"""
import argparse, socket, struct, time

MAGIC   = b"MBQ1"
DST_MAC = bytes.fromhex("001122334455")
SRC_MAC = bytes.fromhex("00aabbccddee")
SRC_IP  = socket.inet_aton("10.0.9.9")
DST_IP  = socket.inet_aton("10.0.8.8")

def ip_csum(hdr):
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i+1]
    s = (s >> 16) + (s & 0xFFFF); s += (s >> 16)
    return (~s) & 0xFFFF

def build(dport, seq, tx_ns):
    payload = MAGIC + struct.pack("!I", seq & 0xFFFFFFFF) + struct.pack("!Q", tx_ns)
    payload = payload + b"\x00" * (22 - len(payload))            # -> 22 B
    udp_len = 8 + len(payload)                                    # 30
    udp = struct.pack("!HHHH", 40000, dport, udp_len, 0) + payload
    total_len = 20 + len(udp)                                     # 50
    ip = bytearray(struct.pack("!BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, 17, 0)) + SRC_IP + DST_IP
    c = ip_csum(ip); ip[10] = (c >> 8) & 0xFF; ip[11] = c & 0xFF
    eth = DST_MAC + SRC_MAC + struct.pack("!H", 0x0800)
    return eth + bytes(ip) + udp                                  # 14+20+8+22 = 64

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--dports", type=int, nargs="+", required=True)
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--interval-ms", type=float, default=10.0)
    ap.add_argument("--burst", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if a.dry_run:
        f = build(a.dports[0], 0, 0)
        print("sample wire len = %d B (target 64)" % len(f)); return

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    interval = a.interval_ms / 1000.0
    seq = sent = 0
    t0 = time.time()
    while sent < a.count:
        n = min(a.burst, a.count - sent)
        for _ in range(n):
            s.send(build(a.dports[seq % len(a.dports)], seq, time.time_ns()))
            seq += 1
        sent += n
        if sent < a.count and interval > 0:
            time.sleep(interval)
    dt = time.time() - t0
    print("mb_gen_raw: sent %d frames in %.3f s (%.1f pps) dports=%s"
          % (sent, dt, sent / dt if dt else 0, a.dports))

if __name__ == "__main__":
    main()

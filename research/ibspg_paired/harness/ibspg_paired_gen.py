#!/usr/bin/env python3
"""ibspg_part9_gen.py — synthetic marked-frame generator for the Part 9 controlled-drain test.

Runs on a host (raw AF_PACKET, stdlib only). Emits IBSPG frames:
  Ethernet(dst,src,etype) + ibspg(role,slot,gen,seq)

  role         ethertype  meaning
  ------------ ---------- ---------------------------------------------------------------
  blocker      0x88C1     internal blocker token; seq = P4 pass-BUDGET (hard safety bound)
  held         0x88C0     the REAL packet to hold; seq = UNIQUE packet_id (0,1,2,... FIFO id)
  drain-match  0x88C0     matched drain (slot+gen must equal the armed slot+gen)
  drain-unrel  0x88C0     unrelated drain (wrong slot) — negative control
  arm          0x88C0     arm slot: set reg_active=1, reg_gen, clear reg_drain

Held frames each carry a distinct seq (= packet_id) so the verifier can check count, FIFO order,
duplicates, and full-frame byte identity of the released copies.

Examples:
  sudo python3 ibspg_part9_gen.py --iface IF --role arm         --slot 0 --gen 7
  sudo python3 ibspg_part9_gen.py --iface IF --role blocker     --slot 0 --gen 7 --count 1 --budget 200000
  sudo python3 ibspg_part9_gen.py --iface IF --role held        --slot 0 --gen 7 --count 32 --id-start 1
  sudo python3 ibspg_part9_gen.py --iface IF --role drain-match --slot 0 --gen 7
  sudo python3 ibspg_part9_gen.py --iface IF --role drain-unrel --slot 9 --gen 7
"""
import argparse
import socket
import struct
import time

ETYPE_REAL = 0x88C0
ETYPE_TOKEN = 0x88C1
DST_MAC = bytes.fromhex("020000000001")
SRC_REAL = bytes.fromhex("020000000000")[:5] + b"\x0a"   # 02:00:00:00:00:0A
SRC_TOKEN = bytes.fromhex("020000000B0C")                # 02:00:00:00:0B:0C (private blocker marker)

ROLE = {"blocker": 1, "resp": 2, "held": 2, "drain-match": 3, "drain-unrel": 4, "arm": 6, "ack": 7}


def build(role_name, slot, gen, seq, pad_to=60, dst=None, src=None):
    d_src, etype = (SRC_TOKEN, ETYPE_TOKEN) if role_name == "blocker" else (SRC_REAL, ETYPE_REAL)
    dmac = dst if dst is not None else DST_MAC
    smac = src if src is not None else d_src
    ib = struct.pack("!BBBI", ROLE[role_name], slot & 0xFF, gen & 0xFF, seq & 0xFFFFFFFF)  # 7 bytes
    frame = dmac + smac + struct.pack("!H", etype) + ib
    if len(frame) < pad_to:
        frame += b"\x00" * (pad_to - len(frame))
    return frame


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--role", required=True, choices=list(ROLE.keys()))
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--gen", type=int, default=7)
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--interval-ms", type=float, default=0.0)
    ap.add_argument("--id-start", type=int, default=1, help="held: first packet_id (seq); ids increment")
    ap.add_argument("--budget", type=int, default=0, help="blocker pass-budget (seq). HARD ring bound.")
    ap.add_argument("--pad-to", type=int, default=60, help="frame size; vary to test size-independence")
    ap.add_argument("--dst-mac", default=None, help="dest MAC hex (12 chars); e.g. real NIC MAC of the egress host")
    ap.add_argument("--src-mac", default=None, help="src MAC hex (12 chars); neutral MAC avoids source-pruning")
    a = ap.parse_args()
    dst = bytes.fromhex(a.dst_mac) if a.dst_mac else None
    src = bytes.fromhex(a.src_mac) if a.src_mac else None

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    gap = a.interval_ms / 1000.0
    for i in range(a.count):
        if a.role == "blocker" and a.budget > 0:
            seq = a.budget
        elif a.role in ("held", "resp", "ack"):
            seq = a.id_start + i           # unique packet_id per held/ack/resp frame
        else:
            seq = 0                         # arm/drain: seq unused
        s.send(build(a.role, a.slot, a.gen, seq, a.pad_to, dst, src))
        if gap > 0:
            time.sleep(gap)
    s.close()
    print("SENT role=%s slot=%d gen=%d count=%d budget=%d id-start=%d pad=%d iface=%s"
          % (a.role, a.slot, a.gen, a.count, a.budget, a.id_start, a.pad_to, a.iface))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ibspg_gen.py — synthetic marked-frame generator for the IBSPG microbench.

Runs on a host (raw AF_PACKET, stdlib only — the proven mb_gen_raw.py pattern).
Emits IBSPG microbench frames:  Ethernet(dst,src,etype) + ibspg(role,slot,gen,seq).

  role   ethertype   src MAC                 meaning
  ------ ----------- ---------------------- ----------------------------------
  blocker 0x88C1     02:00:00:00:0B:0C       internal blocker token (private marker)
  held    0x88C0     02:00:00:00:00:0A       the REAL packet to hold in Q_HOLD
  drain-match  0x88C0 02:00:00:00:00:0A      matched drain (slot+gen)
  drain-unrel  0x88C0 02:00:00:00:00:0A      unrelated drain (wrong slot/gen)
  arm     0x88C0     02:00:00:00:00:0A       arm slot: set reg_gen, clear reg_drain

Usage:
  sudo python3 ibspg_gen.py --iface IF --role blocker --slot 0 --gen 7 --count 100
  sudo python3 ibspg_gen.py --iface IF --role held    --slot 0 --gen 7 --count 1
  sudo python3 ibspg_gen.py --iface IF --role drain-match --slot 0 --gen 7 --count 1
"""
import argparse, socket, struct, time

ETYPE_REAL  = 0x88C0
ETYPE_TOKEN = 0x88C1
DST_MAC   = bytes.fromhex("020000000001")
SRC_REAL  = bytes.fromhex("020000000000")[:5] + b"\x0a"   # 02:00:00:00:00:0A
SRC_TOKEN = bytes.fromhex("020000000B0C")                  # 02:00:00:00:0B:0C  (private marker)

ROLE = {"blocker": 1, "held": 2, "drain-match": 3, "drain-unrel": 4, "arm": 6}


def build(role_name, slot, gen, seq):
    if role_name == "blocker":
        src, etype = SRC_TOKEN, ETYPE_TOKEN
    else:
        src, etype = SRC_REAL, ETYPE_REAL
    role = ROLE[role_name]
    # For blocker tokens, seq carries the P4 pass-budget (HARD SAFETY BOUND): the token
    # is dropped after `seq` internal loops, so a ring cannot storm the switch.
    ib = struct.pack("!BBBI", role, slot & 0xFF, gen & 0xFF, seq & 0xFFFFFFFF)  # 7 bytes
    frame = DST_MAC + src + struct.pack("!H", etype) + ib
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--role", required=True, choices=list(ROLE.keys()))
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--gen", type=int, default=7)
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--interval-ms", type=float, default=0.0)
    ap.add_argument("--seq-start", type=int, default=0)
    ap.add_argument("--budget", type=int, default=0,
                    help="blocker pass-budget (seq); 0 = use seq-start+i. HARD BOUND for the ring.")
    a = ap.parse_args()

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    gap = a.interval_ms / 1000.0
    for i in range(a.count):
        seq = a.budget if (a.role == "blocker" and a.budget > 0) else (a.seq_start + i)
        s.send(build(a.role, a.slot, a.gen, seq))
        if gap > 0:
            time.sleep(gap)
    s.close()
    print("SENT role=%s slot=%d gen=%d count=%d budget=%d iface=%s"
          % (a.role, a.slot, a.gen, a.count, a.budget, a.iface))


if __name__ == "__main__":
    main()

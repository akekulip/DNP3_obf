#!/usr/bin/env python3
"""ibspg_p12_gen.py — scenario injector for the Part 12 HOLD_RESPONSE trial.

Runs ON HULK (raw AF_PACKET, stdlib only, python3.8+). Emits IBSPG frames:

    Ethernet(dst48, src48, etype16) + ibspg(role8, slot8, gen8, seq32)

    role  name    ethertype  seq field means
    ----  ------  ---------  -------------------------------------------------
    1     BLOCK   0x88C1     pass BUDGET (decremented per loopback pass in P4)
    2     RESP    0x88C0     unique packet_id (0,1,2,... FIFO id) — held frame
    6     ARM     0x88C0     unused (0)
    7     ACK     0x88C0     GUARD INTERVAL G in NANOSECONDS  <-- Part 12 change

The Part 12 P4 (ibspg_hold_response.p4) forwards the ACK immediately and arms
deadline = t_ack + G, where G is read straight out of the ACK's seq field. Only
the RESPONSE is held. So a G sweep is a pure host-side parameter — no
control-plane write per trial.

WHY A --scenario FLAG AND NOT ONE ROLE PER INVOCATION (deviation from Part 11).
Part 11's trial fired one ssh + one generator process per role. Part 12 measures
an ACK->response interval against a millisecond-scale G, so the ACK->RESPONSE
spacing must be controlled locally, in ONE process on Hulk, instead of inheriting
ssh round-trip jitter. The whole scenario is therefore injected by a single run.

SCENARIOS
  normal         ARM, K blockers, ACK carrying G, then RESPONSE after
                 --resp-delay-ms. Deadline arms; release is caused by the
                 deadline.
  stale-ack      as normal, but the ACK carries a generation != the armed
                 generation. Must NOT arm the deadline (ctr_ack_bypass).
                 Release then happens only by blocker budget exhaustion.
  unrelated-ack  as normal, but the ACK carries slot != 0. Same expectation.
  no-ack         no ACK at all. Fail-open (budget) path only.

CAPTURE DISCIPLINE. Do NOT run tcpdump on the injection interface — it fights
with the AF_PACKET inject. The injected frames are deterministic and are
RECONSTRUCTED by ibspg_p12_verify.py from the `spec` string printed below, which
is exactly what Part 11 did.

SUDO. A raw AF_PACKET socket without root raises PermissionError; a swallowed
one looks like a silent no-inject trial. This script fails LOUDLY (exit 2).

Examples:
  sudo python3 ibspg_p12_gen.py --iface enp59s0f0np0 --scenario normal \\
       --k 64 --g-ms 20 --budget 2000000 --resp-delay-ms 2 --gen 7 --runid p12
  sudo python3 ibspg_p12_gen.py --iface enp59s0f0np0 --scenario stale-ack --k 64
"""
import argparse
import json
import socket
import struct
import sys
import time

ETYPE_REAL = 0x88C0
ETYPE_TOKEN = 0x88C1

ROLE_BLOCK = 1
ROLE_RESP = 2
ROLE_ARM = 6
ROLE_ACK = 7

# Defaults reproduced from the Part 11 harness (proven on silicon):
#   real NIC MAC of Vision so the forwarded ACK / released RESPONSE are accepted,
#   neutral src so i40e source-pruning does not drop the reflected frames.
DEFAULT_DST_HOST = "3cfdfecc5dc0"        # Vision enp59s0f0np0
DEFAULT_SRC_NEUTRAL = "02000000000a"     # 02:00:00:00:00:0a
DEFAULT_DST_INTERNAL = "020000000001"    # ARM/BLOCK never leave the switch
DEFAULT_SRC_TOKEN = "020000000b0c"       # private blocker marker

SCENARIOS = ("normal", "stale-ack", "unrelated-ack", "no-ack")

# The P4 expiry test is a 32-bit wrapping subtraction read through its sign bit,
# so it is only valid while |now - deadline| < 2^31 ns.
MAX_G_NS = 2 ** 31 - 1


def build(role, slot, gen, seq, pad_to, dst_hex, src_hex, etype):
    """One IBSPG frame. Identical layout to ibspg_paired_gen.py's build()."""
    ib = struct.pack("!BBBI", role & 0xFF, slot & 0xFF, gen & 0xFF, seq & 0xFFFFFFFF)
    frame = bytes.fromhex(dst_hex) + bytes.fromhex(src_hex) + struct.pack("!H", etype) + ib
    if len(frame) < pad_to:
        frame += b"\x00" * (pad_to - len(frame))
    return frame


def open_raw(iface):
    """Raw AF_PACKET socket bound to iface. Fails loudly, never silently."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    except AttributeError:
        sys.stderr.write("FATAL: AF_PACKET is Linux-only; run this on Hulk.\n")
        sys.exit(2)
    except PermissionError as e:
        sys.stderr.write(
            "FATAL: raw AF_PACKET socket denied (%s). This script MUST run as root "
            "(sudo). Without it nothing is injected and the trial silently reads "
            "all-zero counters.\n" % e)
        sys.exit(2)
    except OSError as e:
        sys.stderr.write("FATAL: could not create raw socket: %s\n" % e)
        sys.exit(2)
    try:
        s.bind((iface, 0))
    except OSError as e:
        sys.stderr.write("FATAL: could not bind raw socket to iface %r: %s\n" % (iface, e))
        sys.exit(2)
    return s


def send_all(sock, frames, gap_s=0.0):
    for f in frames:
        sock.send(f)
        if gap_s > 0:
            time.sleep(gap_s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--scenario", default="normal", choices=list(SCENARIOS))
    ap.add_argument("--k", type=int, default=64, help="blocker reservoir size (Part 9: K>=64)")
    ap.add_argument("--budget", type=int, default=2000000,
                    help="blocker pass budget (seq). Fail-open watchdog bound; must be >=1. "
                         "Sized so a NEGATIVE scenario finishes inside the trial wait.")
    ap.add_argument("--g-ms", type=float, default=20.0, help="guard interval G in milliseconds")
    ap.add_argument("--g-ns", type=int, default=None, help="G in ns; overrides --g-ms if given")
    ap.add_argument("--gen", type=int, default=7, help="armed generation")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--nack", type=int, default=1, help="ACK frames (0 = none)")
    ap.add_argument("--nresp", type=int, default=1, help="RESPONSE frames to hold")
    ap.add_argument("--resp-id-start", type=int, default=1, help="first RESPONSE packet_id (seq)")
    ap.add_argument("--resp-delay-ms", type=float, default=2.0,
                    help="ACK -> RESPONSE spacing. For a deadline-caused release this must be "
                         "well under G, or the response arrives after the deadline already passed.")
    ap.add_argument("--arm-settle-ms", type=float, default=50.0,
                    help="pause after the blockers so the reservoir is looping before the ACK")
    ap.add_argument("--blocker-gap-ms", type=float, default=0.0, help="inter-blocker spacing")
    ap.add_argument("--ack-gen", type=int, default=None,
                    help="override the ACK generation (stale-ack default: armed gen - 1)")
    ap.add_argument("--ack-slot", type=int, default=None,
                    help="override the ACK slot (unrelated-ack default: 9)")
    ap.add_argument("--pad-to", type=int, default=60, help="frame size in bytes")
    ap.add_argument("--dst-mac", default=DEFAULT_DST_HOST, help="dst MAC of ACK/RESP (host NIC)")
    ap.add_argument("--src-mac", default=DEFAULT_SRC_NEUTRAL, help="src MAC of ACK/RESP (neutral)")
    ap.add_argument("--internal-dst-mac", default=DEFAULT_DST_INTERNAL, help="dst MAC of ARM/BLOCK")
    ap.add_argument("--blocker-src-mac", default=DEFAULT_SRC_TOKEN, help="src MAC of BLOCK tokens")
    ap.add_argument("--runid", default="p12")
    a = ap.parse_args()

    # ---- validate before touching the wire -------------------------------
    g_ns = a.g_ns if a.g_ns is not None else int(round(a.g_ms * 1e6))
    if g_ns < 0 or g_ns > MAX_G_NS:
        sys.stderr.write("FATAL: G=%d ns out of range; the P4 sign-bit expiry test is only "
                         "valid for 0 <= G < 2^31 ns (~2.147 s).\n" % g_ns)
        sys.exit(2)
    if a.budget < 1:
        sys.stderr.write("FATAL: --budget must be >= 1 (seq==0 terminates a blocker on its "
                         "first pass, so the reservoir would never form).\n")
        sys.exit(2)
    if a.budget > 0xFFFFFFFF:
        sys.stderr.write("FATAL: --budget must fit in 32 bits.\n")
        sys.exit(2)
    if a.k < 0 or a.nack < 0 or a.nresp < 0:
        sys.stderr.write("FATAL: --k/--nack/--nresp must be >= 0.\n")
        sys.exit(2)

    # ---- scenario -> ACK qualification fields -----------------------------
    ack_gen = a.gen
    ack_slot = a.slot
    nack = a.nack
    if a.scenario == "stale-ack":
        ack_gen = (a.gen - 1) & 0xFF
    elif a.scenario == "unrelated-ack":
        ack_slot = 9
    elif a.scenario == "no-ack":
        nack = 0
    if a.ack_gen is not None:
        ack_gen = a.ack_gen & 0xFF
    if a.ack_slot is not None:
        ack_slot = a.ack_slot & 0xFF

    sock = open_raw(a.iface)

    t0 = time.time()
    t_ack = None
    t_resp = None

    # 1) ARM the synthetic slot (sets reg_gen + reg_active, clears reg_deadline)
    send_all(sock, [build(ROLE_ARM, a.slot, a.gen, 0, a.pad_to,
                          a.internal_dst_mac, DEFAULT_SRC_NEUTRAL, ETYPE_REAL)])

    # 2) blocker reservoir on Q_BLOCK (qid7, HIGH)
    if a.k > 0:
        send_all(sock,
                 [build(ROLE_BLOCK, a.slot, a.gen, a.budget, a.pad_to,
                        a.internal_dst_mac, a.blocker_src_mac, ETYPE_TOKEN)] * a.k,
                 a.blocker_gap_ms / 1000.0)
        if a.arm_settle_ms > 0:
            time.sleep(a.arm_settle_ms / 1000.0)

    # 3) the ACK — forwarded immediately by the P4; arms the deadline iff it qualifies
    if nack > 0:
        t_ack = time.time()
        send_all(sock, [build(ROLE_ACK, ack_slot, ack_gen, g_ns, a.pad_to,
                              a.dst_mac, a.src_mac, ETYPE_REAL)] * nack)

    # 4) the RESPONSE(s) — held on Q_RESP (qid1, LOW) until the reservoir empties
    if a.resp_delay_ms > 0:
        time.sleep(a.resp_delay_ms / 1000.0)
    if a.nresp > 0:
        t_resp = time.time()
        send_all(sock, [build(ROLE_RESP, a.slot, a.gen, a.resp_id_start + i, a.pad_to,
                              a.dst_mac, a.src_mac, ETYPE_REAL) for i in range(a.nresp)])

    sock.close()

    # The verifier reconstructs every injected frame from this spec — it is the
    # single source of truth for what went on the wire.
    spec = ",".join([
        "nack=%d" % nack,
        "nresp=%d" % a.nresp,
        "ack_seq=%d" % g_ns,
        "ack_gen=%d" % ack_gen,
        "ack_slot=%d" % ack_slot,
        "resp_id_start=%d" % a.resp_id_start,
        "gen=%d" % a.gen,
        "slot=%d" % a.slot,
        "dst=%s" % a.dst_mac,
        "src=%s" % a.src_mac,
        "pad=%d" % a.pad_to,
    ])
    out = {
        "runid": a.runid,
        "scenario": a.scenario,
        "iface": a.iface,
        "k": a.k,
        "budget": a.budget,
        "g_ns": g_ns,
        "g_ms": g_ns / 1e6,
        "gen": a.gen,
        "slot": a.slot,
        "ack_gen": ack_gen,
        "ack_slot": ack_slot,
        "nack": nack,
        "nresp": a.nresp,
        "resp_id_start": a.resp_id_start,
        "resp_delay_ms": a.resp_delay_ms,
        "arm_settle_ms": a.arm_settle_ms,
        "pad": a.pad_to,
        # host-side wall clock, CONTEXT ONLY — the measurement is the on-chip
        # timestamp pair read by ibspg_p12_read.py, never these.
        "host_t_ack_s": (None if t_ack is None else round(t_ack - t0, 6)),
        "host_t_resp_s": (None if t_resp is None else round(t_resp - t0, 6)),
        "spec": spec,
    }
    print("P12GEN " + json.dumps(out))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
queue_microbench_trace_setup.py — bring-up sketch for queue_microbench_trace_v1.p4
(Level-1 trace-driven SIZE-normalization: map 13 DNP3-derived input sizes -> ONE 128 B state).

DRY-RUN BY DEFAULT and OFF-SWITCH SAFE: running this with no flags (or --dry-run) imports NO
SDE / bfrt_grpc and connects to NOTHING — it only prints the intended bring-up plan and the
trace-replay frame format. The actual grpc apply lives behind --apply and lazily imports
bfrt_grpc AFTER the dry-run early-return, exactly like queue_microbench_setup.py. This script
does NOT restart bf_switchd. It is SEPARATE from the loaded queue_microbench and the frozen
dcrn_defense1/2.

What it configures (control-plane only; the P4 datapath is fixed):
  1. install the 13-entry size_class_pad table: input_size_class -> pad_dNN action (each action
     pads to 128 B). Unknown sizes hit the const default (pad_none) -> fail open.
  2. seed telemetry_enable (A/B gate; DEFAULT 0 = OFF) and run_id (control-plane run epoch).
  3. ONE real high-priority queue (QID_REAL_S1) on the observe port; frames release DIRECTLY
     (no metronome, no recirc hold, no external cover — those do not exist in this program).

bfrt names below were read off the COMPILED bfrt.json (local bf-p4c 9.13.1), not guessed:
  pipe.Ingress.size_class_pad   key hdr.trace_replay.input_size_class   action Ingress.pad_dNN
  pipe.Ingress.run_id_reg       key $REGISTER_INDEX   data Ingress.run_id_reg.f1
  pipe.Ingress.telemetry_enable key $REGISTER_INDEX   data Ingress.telemetry_enable.f1
  pipe.Ingress.ctr_*            key $COUNTER_INDEX     data $COUNTER_SPEC_PKTS

===============================================================================================
TRACE-REPLAY FRAME FORMAT  (what the host generator must send; Level-1 = synthetic, no live
                            TCP/DNP3 required — labels are MEASUREMENT-ONLY and carry no
                            security claim)
===============================================================================================
On-wire layout (all multi-byte fields NETWORK byte order), physical size = input_size + 19:

  ┌──────────────── ethernet_h (14 B) ─────────────────┐
  | dst_addr(6) | src_addr(6) | ether_type(2)=0x88B7   |   <- 0x88B7 selects the replay parser
  ├──────────── trace_replay_h (R = 19 B) ─────────────┤
  | run_id(2)          measurement                     |
  | seq(4)             measurement                     |
  | device_label(1)    measurement                     |
  | operation_label(1) measurement                     |
  | direction(1)       measurement                     |
  | input_size_class(1)  === DATAPATH KEY ===          |   <- one of {60,62,66,74,76,88,89,
  | transaction_id(2)  measurement                     |      91,101,103,108,115,120}
  | ack_mode(1)        measurement                     |
  | orig_ethertype(2)  restored onto the delivered fr. |   <- e.g. 0x0800 so the 128 B frame
  | tx_tstamp(4)       measurement                     |      looks like a normal IPv4 frame
  ├──────────────── body (input_size - 14 B) ──────────┤
  | opaque filler (the DNP3-derived payload stand-in)  |   <- length = input_size - 14
  └────────────────────────────────────────────────────┘

HOW THE HOST SETS input_size_class: pick the DNP3-derived frame size S from the 13-set, write
S into the 1-byte input_size_class field, and make the BODY exactly (S - 14) bytes. The physical
frame is then S + 19 bytes. The switch strips the 19 B replay header and adds delta = 128 - S
bytes of pad, so EVERY class leaves as EXACTLY 128 B:
      output = (S + 19) - 19 + (128 - S) = 128.
Delivered frame = ethernet(14) | pad(128-S) | body(S-14) = 128 B. (Pad precedes the body; the
body is the implicit deparser residual, always last. Level-1 makes no payload-semantics claim.)

build_trace_frame() below constructs exactly this layout (struct only, no scapy dep) so a
generator can `from queue_microbench_trace_setup import build_trace_frame`.
===============================================================================================
Usage:  python3 queue_microbench_trace_setup.py                 # dry-run plan + frame format
        python3 queue_microbench_trace_setup.py --telemetry     # dry-run, telemetry A-side on
        python3 queue_microbench_trace_setup.py --print-frames   # + a sample frame per class
        python3 queue_microbench_trace_setup.py --apply          # ON-SWITCH apply (needs SDE)
Author: Philip
"""
import sys
import struct
import argparse

# bfrt_grpc lives only on the switch SDE; imported lazily inside apply() AFTER the dry-run
# early-return, so dry-run runs on any host off-switch.
SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"

PROG = "queue_microbench_trace_v1"

# ── constants that MUST match queue_microbench_trace_v1.p4 ──
ETHERTYPE_TRACE = 0x88B7
REPLAY_HDR_LEN  = 19          # R (bytes)
ETH_LEN         = 14
TARGET_SIZE     = 128
QID_REAL_S1     = 1           # the one real high-priority queue
PORT_HULK       = 9           # dp9 generator (testbed map)
PORT_OBSERVE    = 9           # dp9 hairpin observe (Vision/dp8 down); off-switch -> not load-bearing

# input_size_class -> table action name (delta = 128 - size, decomposed to power-of-2 pads).
SIZE_TO_ACTION = {
    60: "Ingress.pad_d68", 62: "Ingress.pad_d66", 66: "Ingress.pad_d62",
    74: "Ingress.pad_d54", 76: "Ingress.pad_d52", 88: "Ingress.pad_d40",
    89: "Ingress.pad_d39", 91: "Ingress.pad_d37", 101: "Ingress.pad_d27",
    103: "Ingress.pad_d25", 108: "Ingress.pad_d20", 115: "Ingress.pad_d13",
    120: "Ingress.pad_d8",
}
INPUT_SIZES = sorted(SIZE_TO_ACTION)


def build_trace_frame(input_size_class, seq=0, run_id=0, device_label=0, operation_label=0,
                      direction=0, transaction_id=0, ack_mode=0, orig_ethertype=0x0800,
                      tx_tstamp=0, dst_mac=b"\x02\x00\x00\x00\x00\x02",
                      src_mac=b"\x02\x00\x00\x00\x00\x01", fill=b"\x00"):
    """Build one trace-replay frame of the exact physical size (input_size_class + 19 B).

    The switch normalizes it to EXACTLY 128 B. This function IS the executable frame-format
    spec; a generator can import and call it. Returns raw bytes.
    """
    if input_size_class not in SIZE_TO_ACTION:
        raise ValueError("input_size_class %r not in the 13-set %s (would fail open)"
                         % (input_size_class, INPUT_SIZES))
    eth = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_TRACE)                     # 14 B
    replay = struct.pack("!H I B B B B H B H I",                                     # 19 B
                         run_id & 0xFFFF, seq & 0xFFFFFFFF,
                         device_label & 0xFF, operation_label & 0xFF, direction & 0xFF,
                         input_size_class & 0xFF, transaction_id & 0xFFFF, ack_mode & 0xFF,
                         orig_ethertype & 0xFFFF, tx_tstamp & 0xFFFFFFFF)
    body_len = input_size_class - ETH_LEN                                            # S - 14
    body = (fill * body_len)[:body_len]
    frame = eth + replay + body
    assert len(frame) == input_size_class + REPLAY_HDR_LEN, "physical size mismatch"
    return frame


def print_plan(args):
    print("=" * 88)
    print("queue_microbench_trace_v1 bring-up plan  (DRY-RUN — nothing applied, no switch contact)")
    print("=" * 88)
    te = 1 if args.telemetry else 0
    print("\n[1] size_class_pad — install 13 exact entries (input_size_class -> pad action):")
    print("    %-18s %-6s %-16s %-9s %-9s" % ("key input_size", "delta", "action", "body=S-14", "out"))
    for s in INPUT_SIZES:
        print("    %-18d %-6d %-16s %-9d %-9d" % (s, TARGET_SIZE - s, SIZE_TO_ACTION[s],
                                                  s - ETH_LEN, TARGET_SIZE))
    print("    default_action = Ingress.pad_none  (unsupported size -> fail open, ctr_unsupported)")
    print("\n[2] registers (seed via $REGISTER_INDEX=0):")
    print("    pipe.Ingress.telemetry_enable.f1 = %d   (%s; A/B gate, default 0)"
          % (te, "ON" if te else "OFF"))
    print("    pipe.Ingress.run_id_reg.f1       = %d   (control-plane run epoch)" % args.run_id)
    print("\n[3] queues / release path:")
    print("    ONE real high-priority queue QID_REAL_S1=%d on dp%d (observe)." % (QID_REAL_S1, PORT_OBSERVE))
    print("    Release is DIRECT (single ingress pass). Structurally OFF (not in this program):")
    print("      metronome = OFF   external cover/chaff = OFF   recirculation hold = OFF")
    print("    No TM shaper needed — this is a SIZE experiment, not a timing one.")
    print("\n[4] counters (read via $COUNTER_INDEX=0, $COUNTER_SPEC_PKTS):")
    print("    ctr_released  ctr_failopen  ctr_unsupported  ctr_digest_emit")
    print("\nCapture on Hulk (dp9 hairpin, inbound only) and check every frame is 128 B:")
    print("    tcpdump -i <hulk_if> -Q in -w cap.pcap 'ether proto 0x88b7 or ip'")


def print_frames():
    print("\n[frame-format check] one sample frame per class (physical size = S + 19 -> 128 B out):")
    for s in INPUT_SIZES:
        f = build_trace_frame(s, seq=s)
        print("    S=%-4d  physical=%-4d B  (eth14 + replay19 + body%-3d)  -> switch -> 128 B"
              % (s, len(f), s - ETH_LEN))


def apply_on_switch(args):
    """ON-SWITCH apply. Lazily imports bfrt_grpc so dry-run needs no SDE. NOT run off-switch."""
    sys.path.insert(0, SDE_PY + "/tofino")   # bfrt_grpc lives under the tofino subdir
    sys.path.insert(0, SDE_PY)
    import bfrt_grpc.client as gc  # noqa: E402  (SDE-only)

    interface = gc.ClientInterface("localhost:50052", client_id=0, device_id=0)
    bi = interface.bfrt_info_get(PROG)
    interface.bind_pipeline_config(PROG)
    tgt = gc.Target(device_id=0, pipe_id=0xFFFF)

    # [0] bring up dp9 (Hulk generator + hairpin observe) at 25G — the cold reload reset the ports.
    port_tbl = bi.table_get("$PORT")
    pk = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", PORT_OBSERVE)])]
    pd = [port_tbl.make_data([gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                              gc.DataTuple("$FEC", str_val="BF_FEC_TYP_RS"),
                              gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
                              gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_NONE"),
                              gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
    try:    port_tbl.entry_add(tgt, pk, pd)
    except Exception: port_tbl.entry_mod(tgt, pk, pd)
    print("  port dp%d up (25G RS-FEC, hairpin observe)." % PORT_OBSERVE)

    # [1] size_class_pad entries are COMPILE-TIME `const entries` in the P4 (fixed corpus mapping):
    #     the 13 size_class -> pad-delta rows + the pad_none default are baked in, so there is NOTHING
    #     to install at runtime (attempting entry_add on a const-entries table returns Write Error).
    print("  size_class_pad: 13 entries are compiled-in const (no runtime install).")

    # [2] seed telemetry_enable + run_id.
    def _seed_reg(name, field, val):
        r = bi.table_get(name)
        k = [r.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])]
        dd = [r.make_data([gc.DataTuple(field, val)])]
        try:    r.entry_add(tgt, k, dd)
        except Exception: r.entry_mod(tgt, k, dd)
    _seed_reg("pipe.Ingress.telemetry_enable", "Ingress.telemetry_enable.f1", 1 if args.telemetry else 0)
    _seed_reg("pipe.Ingress.run_id_reg", "Ingress.run_id_reg.f1", args.run_id)
    print("  telemetry_enable = %d, run_id = %d seeded." % (1 if args.telemetry else 0, args.run_id))

    # [3] queue: direct release uses QID_REAL_S1 with default TM config; no shaper needed.
    #     (Port bring-up / strict-priority is the operator's standard step and is intentionally
    #     left out here — a size experiment does not depend on TM scheduling.)
    print("  queue: QID_REAL_S1=%d on dp%d (default TM config; direct release)." % (QID_REAL_S1, PORT_OBSERVE))
    print("apply complete.")


def parse_args():
    ap = argparse.ArgumentParser(description="queue_microbench_trace_v1 bring-up (dry-run default)")
    ap.add_argument("--apply", action="store_true", help="apply on the switch (needs SDE); default is dry-run")
    ap.add_argument("--dry-run", action="store_true", help="print the plan only (default behaviour)")
    ap.add_argument("--telemetry", action="store_true", help="seed telemetry_enable=1 (A-side); default 0")
    ap.add_argument("--run-id", dest="run_id", type=int, default=1, help="run epoch seeded into run_id_reg")
    ap.add_argument("--print-frames", action="store_true", help="also print a sample frame per class")
    return ap.parse_args()


def main():
    args = parse_args()
    print_plan(args)
    if args.print_frames:
        print_frames()
    if not args.apply:
        print("\n[dry-run] no switch contact, nothing applied. Re-run with --apply on the switch.")
        return
    print("\n[apply] connecting to local bf_switchd grpc ...")
    apply_on_switch(args)


if __name__ == "__main__":
    main()

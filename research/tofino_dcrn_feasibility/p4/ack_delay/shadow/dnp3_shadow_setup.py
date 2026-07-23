#!/usr/bin/env python3
"""
dnp3_shadow_setup.py — bring-up controller for dnp3_shadow.p4 (PASSIVE DNP3 shadow classifier).

DRY-RUN BY DEFAULT. Running this script without --run prints the planned bfrt writes and exits
WITHOUT importing bfrt and WITHOUT connecting to the switch. It touches NOTHING on the shared
Tofino. Loading dnp3_shadow on the switch is a GATED action (GATE 1 of
research/END_TO_END_IMPLEMENTATION_PLAN.md); --run is provided for that later, authorized step only.

What a real (--run) bring-up would do — mirrors defense1_setup.py, but the shadow is smaller:
  1. host ports up: dp8 (Vision/master) and dp9 (Hulk/outstation) @ 25G RS-FEC, LPBK_NONE, ENABLE.
  2. seed reg_shadow_enable[0] = 1 (digests ON). This is the measurement A/B gate ONLY; forwarding
     is unconditional and identical whether it is 0 or 1. Use --shadow-enable 0 for the "off" arm.
  NO recirculation, NO queue shaper, NO fc_allowlist, NO arming — the shadow neither holds nor
  synthesizes anything. It is a transparent bump-in-the-wire that only observes.

Names CONFIRMED against the local compiled out/bfrt.json (bf-p4c 9.13.1), not guessed:
    register : pipe.ShadowIngress.reg_shadow_enable  (key $REGISTER_INDEX; data ShadowIngress.reg_shadow_enable.f1)
    counter  : pipe.ShadowIngress.class_ctr          (per-class packet counts; read with a SyncCounters op)
    digest   : ShadowIngressDeparser.shadow_digest    (match the collector by this INSTANCE name, not the struct type)
Names taken VERBATIM from defense1_setup.py (fixed bfrt/SDE tables) and to CONFIRM at first --run:
    $PORT ($DEV_PORT/$SPEED/$FEC/$AUTO_NEGOTIATION/$LOOPBACK_MODE/$PORT_ENABLE).

Usage:
    python3.8 dnp3_shadow_setup.py                    # DRY-RUN: print plan, no import, no connect (default)
    python3.8 dnp3_shadow_setup.py --shadow-enable 0  # DRY-RUN plan with the A/B "off" arm
    python3.8 dnp3_shadow_setup.py --run              # REAL bring-up (ON-SWITCH, GATED — do not run before GATE 1)
Author: Philip
"""
import sys
import argparse

# SDE python path (present on the switch only; imported lazily so the default dry-run runs off-switch).
SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"

# ── topology (testbed.md) ──
PROG = "dnp3_shadow"
PORT_VISION, PORT_HULK = 8, 9          # dp8 master, dp9 outstation

# ── measurement A/B gate (confirmed name in out/bfrt.json) ──
REG_SHADOW_ENABLE = "pipe.ShadowIngress.reg_shadow_enable"
REG_DATA_FIELD    = "ShadowIngress.reg_shadow_enable.f1"


def parse_args():
    ap = argparse.ArgumentParser(description="dnp3_shadow (passive DNP3 shadow classifier) bring-up.")
    ap.add_argument("--run", action="store_true",
                    help="actually connect to the switch and apply (GATED — GATE 1). Default is dry-run.")
    ap.add_argument("--shadow-enable", type=int, choices=[0, 1], default=1,
                    help="seed reg_shadow_enable[0] (1 = digests on, default; 0 = A/B off arm). Forwarding is unaffected.")
    return ap.parse_args()


def print_plan(args):
    """Human-readable plan (default path — no bfrt import, no connection, switch untouched)."""
    print("=== dnp3_shadow_setup PLAN (DRY-RUN, no switch contact) ===")
    print("  program bind        : %s" % PROG)
    print("  1. $PORT up         : dp%d Vision + dp%d Hulk @ BF_SPEED_25G / BF_FEC_TYP_RS, LPBK_NONE, ENABLE"
          % (PORT_VISION, PORT_HULK))
    print("  2. reg_shadow_enable: %s[$REGISTER_INDEX=0] <- %d  (data %s)"
          % (REG_SHADOW_ENABLE, args.shadow_enable, REG_DATA_FIELD))
    print("     (measurement A/B gate ONLY; forwarding is unconditional and byte/order identical either way)")
    print("  NOT configured      : no recirc, no queue shaper, no fc_allowlist, no arming — the shadow")
    print("                        forwards every frame unchanged (dp8<->dp9) and only observes.")
    print("  Digest collector    : match ShadowIngressDeparser.shadow_digest by digest_id (instance name)")
    print("  Per-class counter   : pipe.ShadowIngress.class_ctr (read with operations_execute SyncCounters)")
    print("  Capture on Vision   : tcpdump -i enp59s0f0np0 'tcp port 20000'")
    print("=== end plan (nothing was sent to the switch) ===")


def bring_up(args, gc):
    """Real bring-up (only reached with --run). gc = bfrt_grpc.client."""
    print("=== dnp3_shadow_setup ===  program=%s  shadow_enable=%d" % (PROG, args.shadow_enable))

    iface = gc.ClientInterface("localhost:50052", client_id=2, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi  = iface.bfrt_info_get(PROG)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    # ── 1. host ports up: dp8 Vision, dp9 Hulk ──
    port_tbl = bi.table_get("$PORT")
    for dp, lbl in [(PORT_VISION, "Vision/master"), (PORT_HULK, "Hulk/outstation")]:
        key  = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
        data = [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_RS"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
            gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_NONE"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
        try:    port_tbl.entry_add(tgt, key, data)
        except Exception: port_tbl.entry_mod(tgt, key, data)
    print("  host ports up: dp%d Vision, dp%d Hulk" % (PORT_VISION, PORT_HULK))

    # ── 2. seed the measurement A/B gate (constructor already cold-seeds it to 1; this makes the
    #        arm explicit and lets --shadow-enable flip it for the off arm) ──
    reg = bi.table_get(REG_SHADOW_ENABLE)
    reg.entry_add(tgt,
        [reg.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
        [reg.make_data([gc.DataTuple(REG_DATA_FIELD, args.shadow_enable)])])
    print("  reg_shadow_enable[0] = %d (digests %s)" % (args.shadow_enable, "ON" if args.shadow_enable else "OFF"))

    print("shadow up. Capture on Vision: tcpdump -i enp59s0f0np0 'tcp port 20000'")


def main():
    args = parse_args()
    if not args.run:
        print_plan(args)          # DEFAULT: dry-run, no import, no connect
        return
    # Import bfrt only for a real (gated) run — keeps the default dry-run usable off-switch.
    sys.path.insert(0, SDE_PY + "/tofino")
    sys.path.insert(0, SDE_PY)
    import bfrt_grpc.client as gc
    bring_up(args, gc)


if __name__ == "__main__":
    main()

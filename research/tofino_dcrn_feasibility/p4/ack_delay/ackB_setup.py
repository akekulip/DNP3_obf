#!/usr/bin/env python3
"""
ackA_setup.py — Case-A (ACK_DELAY_REDUCE_CLRT) bring-up controller for dcrn_ackA.p4.
Run ON THE SWITCH (decps@10.10.54.15) after bf_switchd is up with the dcrn_ackA program
(launch_ackA.sh). Reuses dcrn_setup.py's bfrt_grpc connection idiom.

Two modes (via --mode):
  forward  — C2 transparent-forwarding config: ports dp8/dp9 up, recirc on dp68, QID_HOLD
             shaper, registers seeded, and NO arming (fc_allowlist EMPTY) so every DNP3 frame
             fail-opens/forwards. Use this to prove byte-identical dp8<->dp9 forwarding.
  case-a   — Case-A enforcement config: identical port/recirc/queue/seed setup PLUS
             fc_allowlist = READ(0x01) -> arm. The fixed ordering guard (GUARD_PASSES) is
             COMPILED INTO dcrn_ackA.p4 (=4 passes); there is NO runtime target table for
             Case A (unlike Case B / dcrn_setup.py's bounded_target).

  --dry-run   print the planned bfrt writes and exit WITHOUT importing bfrt or connecting
              (runs off-switch — useful to review the plan locally).
  --seed-full force a full per-flow register reset (65536 entries x 6 regs, slow). Default OFF:
              --init-mode=cold + the P4 constructor (Register<...>(SIZE, 0)) already zero-seed
              every cell on load, so only the small global reg_held_count is re-seeded by default.

Name provenance — ALL of the following were CONFIRMED against the compiled
  build_ackA_9.13.1/bfrt.json (local), not guessed:
    tables  : pipe.DcrnIngress.fc_allowlist  (key hdr.dnp3_app.func_code; action DcrnIngress.fc_allow / NoAction)
    registers: pipe.DcrnIngress.{reg_gen,reg_armed,reg_req_tick,reg_ack_seen,reg_resp_seen,
               reg_ack_gone,reg_held_count}  (key $REGISTER_INDEX; data DcrnIngress.<reg>.f1)
  This resolves the ".f1" data-field name that dcrn_setup.py flagged as confirm-at-M0.

Names still taken VERBATIM from dcrn_setup.py / the co-resident bring-up (fixed bfrt/SDE tables,
  not program-specific) and to CONFIRM on the switch at first run:
    $PORT ($DEV_PORT/$SPEED/$FEC/$AUTO_NEGOTIATION/$LOOPBACK_MODE/$PORT_ENABLE),
    tf1.pktgen.port_cfg (dev_port / recirculation_enable),
    tf1.tm.queue.sched_shaping + tf1.tm.queue.sched_cfg (pg_id / pg_queue; unit/provisioning/
      max_rate/max_burst_size; scheduling_enable/max_rate_enable),
    and the dp68 PG_ID/PG_PORT_NR/QID_HOLD -> pg_queue mapping (== HW-unknown #1, the pacing
      question). If the shaper does not pace the recirc loop, this mapping is the prime suspect.

Usage:
    python3.8 ackA_setup.py --mode forward           # C2 transparent forwarding
    python3.8 ackA_setup.py --mode case-a            # Case-A fixed-guard enforcement
    python3.8 ackA_setup.py --mode forward --dry-run # print plan only (works off-switch)
Author: Philip
"""
import sys
import argparse

# SDE python path (present on the switch only; imported lazily so --dry-run runs off-switch).
SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"

# ── topology (testbed.md) ──
PROG = "dcrn_ackB"
PORT_VISION, PORT_HULK, PORT_RECIRC = 8, 9, 68     # dp8 master, dp9 outstation, dp68 recirc

# ── dp68 hold-queue shaper (verbatim mapping from dcrn_setup.py / co-resident bring-up) ──
PG_ID, PG_PORT_NR, QID_HOLD = 17, 0, 5
HOLD_LOOP_PPS = 10000                              # ~100 us/pass (co-resident program caps at 100000 = ~10 us/pass)

# ── allowlist: routine solicited READ only (case-a); EMPTY in forward mode ──
FC_READ = 0x01

# ── Case-A registers. Data field CONFIRMED = DcrnIngress.<reg>.f1 (build_ackA_9.13.1/bfrt.json) ──
# Hardened build (FIX 1/2/4): reg_held_count REMOVED (FIX4 -> per-flow binary flow_has_held_ack);
# reg_gen/reg_req_tick/reg_ack_seen removed; reg_expected_ack (FIX1) + flow_has_held_ack added.
# All registers are constructor cold-seeded on --init-mode=cold, so the default path seeds nothing
# global; --seed-full walks the per-flow set below.
REG_PERFLOW = ["reg_armed", "reg_expected_ack", "reg_ack_seen", "reg_deadline"]  # 65536 entries
REG_GLOBAL  = ["reg_held_count"]                   # Case B occupancy watermark (inc@hold/dec@release)
REG_SIZE_PERFLOW = 65536


def parse_args():
    ap = argparse.ArgumentParser(description="Case-B (dcrn_ackB) bring-up controller.")
    ap.add_argument("--mode", choices=["forward", "case-b"], default="forward",
                    help="forward = transparent native baseline; case-b = ACK-relative response-delay enforcement")
    ap.add_argument("--gi-ms", type=float, default=60.0, help="B1_FIXED target gap G_i in ms (default 60)")
    ap.add_argument("--bounded-band", default=None,
                    help="B2_COMMON_BOUNDED: 'lo,hi' ms -> install a device-independent bounded target "
                         "distribution across the 256 buckets (walked by the global txn counter). Depends "
                         "on NOTHING device-specific (IP/size/pcap/native-CLRT/ACK-mode). Overrides --gi-ms.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print planned bfrt writes and exit (no import, no connect)")
    ap.add_argument("--seed-full", action="store_true",
                    help="also zero every per-flow register cell (slow; constructor already cold-seeds)")
    return ap.parse_args()


def print_plan(args):
    """Human-readable plan for --dry-run (no bfrt import / no connection)."""
    print("=== ackA_setup PLAN (dry-run, no switch contact) ===")
    print("  program bind        : %s" % PROG)
    print("  mode                : %s" % args.mode)
    print("  1. $PORT up         : dp%d Vision + dp%d Hulk @ BF_SPEED_25G / BF_FEC_TYP_RS, LPBK_NONE, ENABLE"
          % (PORT_VISION, PORT_HULK))
    print("  2. recirc on        : tf1.pktgen.port_cfg dev_port=%d recirculation_enable=True" % PORT_RECIRC)
    print("  3. hold-queue shaper: tf1.tm.queue.sched_{shaping,cfg} pg_id=%d pg_queue=%d "
          "(=PG_PORT_NR*8+QID_HOLD) unit=PPS max_rate=%d [pacing = HW-unknown #1]"
          % (PG_ID, PG_PORT_NR * 8 + QID_HOLD, HOLD_LOOP_PPS))
    print("  4. seed registers   : global %s [index 0]=0%s"
          % (REG_GLOBAL, ("; + FULL per-flow reset %s x %d cells" % (REG_PERFLOW, REG_SIZE_PERFLOW))
             if args.seed_full else " (per-flow left to the cold constructor; --seed-full to force)"))
    if args.mode == "case-b":
        print("  5. fc_allowlist ADD : hdr.dnp3_app.func_code=0x%02x (READ) -> DcrnIngress.fc_allow (arm)" % FC_READ)
        print("     Case-A guard     : GUARD_PASSES=4 is COMPILED IN (no runtime target table)")
    else:
        print("  5. fc_allowlist DEL : ensure EMPTY (remove READ if present) -> nothing arms -> all forward")
    print("  Capture on Vision   : tcpdump -i enp59s0f0np0 'tcp port 20000'")
    print("=== end plan ===")


def bring_up(args, gc):
    """Real bring-up. gc = bfrt_grpc.client (imported by main only for non-dry-run)."""
    print("=== ackB_setup ===  program=%s  mode=%s  G_i=%.1fms" % (PROG, args.mode, args.gi_ms))

    # ── connect (shared bfrt client boilerplate, from dcrn_setup.py) ──
    iface = gc.ClientInterface("localhost:50052", client_id=2, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi   = iface.bfrt_info_get(PROG)
    tgt  = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)        # TM tables are pipe-specific

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

    # ── 2. recirculation on dp68 (NO pktgen — dcrn_ackA synthesizes nothing) ──
    pc = bi.table_dict["tf1.pktgen.port_cfg"]
    pc.entry_mod(tgt, [pc.make_key([gc.KeyTuple("dev_port", PORT_RECIRC)])],
        [pc.make_data([gc.DataTuple("recirculation_enable", bool_val=True)])])
    print("  dp%d: recirculation on" % PORT_RECIRC)

    # ── 3. dp68 hold-loop shaper (self-clock churn control) ──
    q_shape = bi.table_get("tf1.tm.queue.sched_shaping")
    q_cfg   = bi.table_get("tf1.tm.queue.sched_cfg")
    pgq = PG_PORT_NR * 8 + QID_HOLD
    q_shape.entry_mod(tgt0,
        [q_shape.make_key([gc.KeyTuple("pg_id", PG_ID), gc.KeyTuple("pg_queue", pgq)])],
        [q_shape.make_data([gc.DataTuple("unit", str_val="PPS"),
                            gc.DataTuple("provisioning", str_val="UPPER"),
                            gc.DataTuple("max_rate", val=HOLD_LOOP_PPS),
                            gc.DataTuple("max_burst_size", val=16384)])])
    q_cfg.entry_mod(tgt0,
        [q_cfg.make_key([gc.KeyTuple("pg_id", PG_ID), gc.KeyTuple("pg_queue", pgq)])],
        [q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True),
                          gc.DataTuple("max_rate_enable", bool_val=True)])])
    print("  hold-loop cap: dp%d qid%d (pg_queue=%d) max_rate=%d PPS  [pacing = HW-unknown #1]"
          % (PORT_RECIRC, QID_HOLD, pgq, HOLD_LOOP_PPS))

    # ── 4. seed registers to 0. Constructor cold-seeds on --init-mode=cold; we always reset the
    #        tiny global reg_held_count, and per-flow only with --seed-full (65536 x 6 = slow). ──
    for reg in REG_GLOBAL:
        t = bi.table_get("pipe.DcrnIngress.%s" % reg)
        t.entry_add(tgt,
            [t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
            [t.make_data([gc.DataTuple("DcrnIngress.%s.f1" % reg, 0)])])
    if args.seed_full:
        for reg in REG_PERFLOW:
            t = bi.table_get("pipe.DcrnIngress.%s" % reg)
            for i in range(REG_SIZE_PERFLOW):
                t.entry_add(tgt,
                    [t.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                    [t.make_data([gc.DataTuple("DcrnIngress.%s.f1" % reg, 0)])])
        print("  registers seeded: global %s + FULL per-flow %s" % (REG_GLOBAL, REG_PERFLOW))
    else:
        print("  registers seeded: global %s (per-flow cold-seeded by P4 constructor)" % REG_GLOBAL)

    # ── 5. fc_allowlist: forward -> EMPTY (nothing arms); case-a -> READ (0x01) arms ──
    fca  = bi.table_get("pipe.DcrnIngress.fc_allowlist")
    fkey = [fca.make_key([gc.KeyTuple("hdr.dnp3_app.func_code", FC_READ)])]
    fdat = [fca.make_data([], "DcrnIngress.fc_allow")]
    if args.mode == "case-b":
        try:    fca.entry_add(tgt, fkey, fdat)
        except Exception: fca.entry_mod(tgt, fkey, fdat)
        print("  fc_allowlist: FC 0x%02x (READ) -> arm; all else bypass." % FC_READ)
        # ── 6. bounded_target: 256 buckets walked by the global txn counter (device-independent). ──
        #        B1_FIXED = every bucket the same G_i. B2_COMMON_BOUNDED = a bounded distribution.
        TICK_US = 65.536
        bt = bi.table_get("pipe.DcrnIngress.bounded_target")
        if args.bounded_band:
            import random
            lo, hi = (float(x) for x in args.bounded_band.split(","))
            rnd = random.Random(1)                       # deterministic, reproducible; NOT device-derived
            gis = [rnd.uniform(lo, hi) for _ in range(256)]
            for idx in range(256):
                gt = int(round(gis[idx] * 1000.0 / TICK_US))
                k = [bt.make_key([gc.KeyTuple("meta.bkt_idx", idx)])]
                d = [bt.make_data([gc.DataTuple("gi", gt)], "DcrnIngress.set_deadline")]
                try:    bt.entry_add(tgt, k, d)
                except Exception: bt.entry_mod(tgt, k, d)
            print("  bounded_target: 256 buckets ~U[%.1f,%.1f]ms [B2_COMMON_BOUNDED, device-independent, seed=1]"
                  % (lo, hi))
        else:
            gi_ticks = int(round(args.gi_ms * 1000.0 / TICK_US))
            for idx in range(256):
                k = [bt.make_key([gc.KeyTuple("meta.bkt_idx", idx)])]
                d = [bt.make_data([gc.DataTuple("gi", gi_ticks)], "DcrnIngress.set_deadline")]
                try:    bt.entry_add(tgt, k, d)
                except Exception: bt.entry_mod(tgt, k, d)
            print("  bounded_target: 256 buckets x G_i=%d ticks (%.1fms) [B1_FIXED uniform]" % (gi_ticks, args.gi_ms))
    else:
        try:    fca.entry_del(tgt, fkey)      # ensure empty -> nothing arms -> transparent forward
        except Exception: pass
        print("  fc_allowlist: EMPTY (no arming) -> every frame fail-opens/forwards (transparent)")

    print("ackB up (mode=%s, G_i=%.1fms). Capture: tcpdump -i enp59s0f0np0 'tcp port 20000'" % (args.mode, args.gi_ms))


def main():
    args = parse_args()
    if args.dry_run:
        print_plan(args)
        return
    # Import bfrt only for a real run (keeps --dry-run usable off-switch).
    sys.path.insert(0, SDE_PY + "/tofino")
    sys.path.insert(0, SDE_PY)
    import bfrt_grpc.client as gc
    bring_up(args, gc)


if __name__ == "__main__":
    main()

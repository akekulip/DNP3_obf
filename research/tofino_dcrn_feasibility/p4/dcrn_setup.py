#!/usr/bin/env python3
"""
dcrn_setup.py — DCRN (Dual-Case Release-Time Normalizer) bring-up (run ON the switch, per reload).

Sequence (build spec Part 5):
  1. host ports dp8 (Vision, master) / dp9 (Hulk, outstation) up at 25G,
  2. recirculation enabled on dp68 (pipe-0 internal recirc port; NO pktgen — DCRN never
     synthesizes packets),
  3. TM max_rate PPS shaper on dp68's hold queue (self-clock churn control),
  4. registers re-seeded to 0 (the P4 constructor already cold-seeds them),
  5. fc_allowlist: READ (0x01) only,
  6. bounded_target: 256 Di (ticks) under a deterministic seed, each asserted <= rto_cap_ticks.

Policy (P0_NATIVE / P1_FIXED / P2_BOUNDED) via --policy or the POLICY constant.

Capture on Vision:  tcpdump -i enp59s0f0np0 'tcp port 20000'

Usage:  python3.8 dcrn_setup.py                      # POLICY default (P2_BOUNDED)
        python3.8 dcrn_setup.py --policy P1_FIXED
        python3.8 dcrn_setup.py --policy P0_NATIVE
        python3.8 dcrn_setup.py --dry-run

--------------------------------------------------------------------------------------------
UNCOMPILED companion to dcrn.p4 — the first bf-p4c compile + this bring-up run is milestone M1.
Known control-plane confirm-at-M0 items (do NOT trust these strings from memory):
  * register-table data-field name for a Register<> write. Below uses "<Ctrl>.<reg>.f1"; the
    exact field is read off the compiled bf-rt.json at M0. Register RE-SEED here is OPTIONAL and
    guarded by SEED_REGISTERS — the P4 constructor (Register<...>(SIZE, 0)) already cold-seeds,
    so M1/M2 run correctly even if this string needs adjustment.
  * TM shaper table names are taken VERBATIM from a co-resident program's working bring-up code
    (tf1.tm.queue.sched_shaping / tf1.tm.queue.sched_cfg); pg_id/pg_queue for dp68 likewise.
  * match-table key/data field names (hdr.dnp3_app.func_code, meta.bkt_idx, di) follow the P4
    source; confirm against bf-rt.json at M0 if entry_add rejects a field name.
Grounding: connection/$PORT/pktgen/TM/mirror bfrt idioms and the ClientInterface/bfrt_info_get
  boilerplate are adapted from a co-resident program's working bring-up code on this shared switch.
Author: Philip
"""
import sys
import argparse

SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE_PY + "/tofino")
sys.path.insert(0, SDE_PY)
import bfrt_grpc.client as gc

# ── topology (build spec / testbed.md) ──
PORT_VISION, PORT_HULK, PORT_RECIRC = 8, 9, 68     # dp8 master, dp9 outstation, dp68 recirc

# ── dp68 hold-queue shaper (verbatim mapping from the reference bring-up code) ──
PG_ID, PG_PORT_NR, QID_HOLD = 17, 0, 5
HOLD_LOOP_PPS = 10000                               # ~100 us/pass (a co-resident program caps at 100000 = ~10 us/pass)

# ── BOUNDED calibration (build spec Part 6). tick = global_tstamp[47:16] = 65536 ns ──
TICK_NS       = 65536
RTO_CAP_MS    = 150                                 # RTO-safe cap (Vision RTO ~211 ms [M]; re-measure kernel-6.8 at M5)
DLOW_MS       = 32                                  # target band low
DHIGH_MS      = 42                                  # target band high
FIXED_MS      = 33                                  # P1_FIXED single calibrated target
SEED          = 20260718                            # deterministic; NEVER reset per device/session/rep
NUM_BUCKETS   = 256                                 # bounded_target size = txn low-8-bit index space

RTO_CAP_TICKS = int(RTO_CAP_MS * 1_000_000 / TICK_NS)
DLOW_T        = int(DLOW_MS   * 1_000_000 / TICK_NS)
DHIGH_T       = int(DHIGH_MS  * 1_000_000 / TICK_NS)
FIXED_T       = int(FIXED_MS  * 1_000_000 / TICK_NS)

# ── allowlist: routine solicited READ only, initially (fail-open bypass for all else) ──
FC_READ = 0x01

SEED_REGISTERS = False   # constructor cold-seeds; flip on once the .f1 field name is confirmed at M0
REG_NAMES = ["reg_deadline", "reg_req_tstamp", "reg_ack_seen", "reg_txn", "reg_held_count"]


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", choices=["P0_NATIVE", "P1_FIXED", "P2_BOUNDED"], default="P2_BOUNDED")
    ap.add_argument("--dry-run", action="store_true")
    return ap.parse_args()


def bounded_values(policy):
    """Return the 256 Di (ticks) for bounded_target, or None for P0_NATIVE (no arming)."""
    if policy == "P0_NATIVE":
        return None
    if policy == "P1_FIXED":
        vals = [FIXED_T] * NUM_BUCKETS
    else:  # P2_BOUNDED — one deterministic sequence, device-independent, never per-device reset
        import numpy as np
        rng = np.random.default_rng(SEED)
        vals = [int(rng.integers(DLOW_T, DHIGH_T + 1)) for _ in range(NUM_BUCKETS)]
    for v in vals:
        assert v <= RTO_CAP_TICKS, "Di %d ticks exceeds RTO cap %d — refuse to install" % (v, RTO_CAP_TICKS)
    return vals


def main():
    args = parse_args()
    print("=== DCRN bring-up ===  policy=%s" % args.policy)
    print("  target band: Dlow=%d ms (%d t)  Dhigh=%d ms (%d t)  RTO cap=%d ms (%d t)"
          % (DLOW_MS, DLOW_T, DHIGH_MS, DHIGH_T, RTO_CAP_MS, RTO_CAP_TICKS))
    if args.dry_run:
        vals = bounded_values(args.policy)
        print("  [DRY-RUN] no writes. bounded_target = %s" % ("<none, P0>" if vals is None else vals[:8] + ["..."]))
        return

    # ── connect (shared bfrt client boilerplate) ──
    iface = gc.ClientInterface("localhost:50052", client_id=2, device_id=0, notifications=None)
    iface.bind_pipeline_config("dcrn")
    bi   = iface.bfrt_info_get("dcrn")
    tgt  = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)        # TM tables are pipe-specific

    # ── 1. host ports up: dp8 Vision, dp9 Hulk (standard $PORT fields) ──
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

    # ── 2. recirculation on dp68 (NO pktgen — DCRN synthesizes nothing) ──
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
    print("  hold-loop cap: dp%d qid%d max_rate=%d PPS" % (PORT_RECIRC, QID_HOLD, HOLD_LOOP_PPS))

    # ── 4. (optional) re-seed registers to 0. Constructor already cold-seeds; enable once the
    #        register data-field name is confirmed against bf-rt.json at M0. ──
    if SEED_REGISTERS:
        for reg in REG_NAMES:
            t = bi.table_get("pipe.DcrnIngress.%s" % reg)
            # single-slot globals: index 0 only; per-flow 64k: loop range(65536) if a full reset is wanted
            n = 1 if reg in ("reg_txn", "reg_held_count") else 65536
            for i in range(n):
                t.entry_add(tgt,
                    [t.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                    [t.make_data([gc.DataTuple("DcrnIngress.%s.f1" % reg, 0)])])
        print("  registers re-seeded to 0")
    else:
        print("  registers: cold-seeded by P4 constructor (re-seed disabled; confirm .f1 at M0)")

    # ── 5. fc_allowlist: READ (0x01) only ──
    fca = bi.table_get("pipe.DcrnIngress.fc_allowlist")
    fkey = [fca.make_key([gc.KeyTuple("hdr.dnp3_app.func_code", FC_READ)])]
    fdat = [fca.make_data([], "DcrnIngress.fc_allow")]
    try:    fca.entry_add(tgt, fkey, fdat)
    except Exception: fca.entry_mod(tgt, fkey, fdat)
    print("  fc_allowlist: FC 0x%02x (READ) -> arm; all else bypass" % FC_READ)

    # ── 6. bounded_target: 256 Di (or none for P0_NATIVE) ──
    vals = bounded_values(args.policy)
    bt = bi.table_get("pipe.DcrnIngress.bounded_target")
    if vals is None:
        print("  bounded_target: P0_NATIVE — fc_allowlist left EMPTY instead (nothing arms)")
        # P0: make sure nothing arms — remove the READ allow entry just installed
        try: fca.entry_del(tgt, fkey)
        except Exception: pass
    else:
        for i in range(NUM_BUCKETS):
            bkey = [bt.make_key([gc.KeyTuple("meta.bkt_idx", i)])]
            bdat = [bt.make_data([gc.DataTuple("di", vals[i])], "DcrnIngress.set_deadline")]
            try:    bt.entry_add(tgt, bkey, bdat)
            except Exception: bt.entry_mod(tgt, bkey, bdat)
        print("  bounded_target: %d Di installed (seed=%d), min=%d max=%d ticks"
              % (NUM_BUCKETS, SEED, min(vals), max(vals)))

    print("DCRN up (policy=%s). Capture on Vision: tcpdump -i enp59s0f0np0 'tcp port 20000'" % args.policy)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
queue_microbench_setup.py — Phase-4 TM microbenchmark bring-up (run ON the switch, per reload).

Configures the size-labelled Traffic-Manager queue + scheduler microbench (queue_microbench.p4).
It is a SEPARATE program from the frozen dcrn_defense1/2.p4 and REPLACES gridcloak on the shared
chip via a gated bf_switchd swap (gridcloak claims all 4 pipes — see QUEUE_MICROBENCH_REVIEW.md
"Rollback"). This script does NOT restart bf_switchd; run it AFTER the (approved) reload.

What it does (staged; mode + mechanism chosen here, NO P4 recompile):
  1. host ports dp9 (Hulk/generator) + dp8 (Vision/observe) up at 25G,
  2. recirc + pktgen enabled on dp68 (pipe-0 internal recirc port, no cable),
  3. pktgen PERIODIC metronome app: one 64 B MB_METRO tick every tau on dp68,
  4. dp68 hold-loop shaper CAP (churn control for the recirc-hold, GridCloak B3),
  5. size-labelled TM queues on dp8: REAL_S1/CHAFF_S1/REAL_S2/CHAFF_S2, real HIGH- vs
     chaff LOW-priority per state; (shaper mode) a per-REAL-queue PPS rate R,
  6. seed mech_reg (PKTGEN metronome vs SHAPER) + install the size-pattern P into pat_state,
  7. optional mirror tap (sid=2) -> dp8 for timing measurement.

Modes / mechanisms (control-plane only):
  --mode  v1     : P = [S1] every slot, chaff pad NONE  -> EQUAL-sized (isolate TM timing).
  --mode  final  : P = [S1,S2] alternating, chaff padded to state -> size ORDER + timing.
  --mech  pktgen : reals recirc-HELD, released one per tau tick in pattern order (metronome).
  --mech  shaper : reals go straight to the per-state REAL queue paced by rate R (TM shaper).

Reuse provenance (cited file:line): the connection / $PORT / pktgen / TM / mirror bfrt idioms
follow this project's proven dcrn_setup.py and GridCloak Mechanism C
(/home/philip/Projects/GridCloak/p4/gc_switch_setup_c.py):
  - port bring-up            gc_switch_setup_c.py:92-104
  - pktgen port_cfg (dp68)   gc_switch_setup_c.py:106-111
  - pktgen template+app_cfg  gc_switch_setup_c.py:113-143  (timer_nanosec is an ACTION field;
                             pktgen prepends 6 B into the eth dst-MAC -> ethertype at buf[6:8],
                             pkt_len = wire-6)
  - mirror $mirror.cfg       gc_switch_setup_c.py:145-156
  - TM sched_shaping+cfg     gc_switch_setup_c.py:163-177 (Target(pipe_id=0); pg_queue=port_nr*8+qid)

Real bfrt names below were read off the COMPILED bfrt.json (local bf-p4c 9.13.1), not guessed:
  pipe.Ingress.mech_reg   key $REGISTER_INDEX  data Ingress.mech_reg.f1
  pipe.Ingress.pat_state  key meta.pat_lo      action Ingress.set_slot_state(st, chaff_pad)
  pipe.Ingress.ctr_*      key $COUNTER_INDEX    data $COUNTER_SPEC_PKTS

CONFIRM-ON-SWITCH items (do NOT trust from memory — flagged, guarded):
  * The dp8 REAL/CHAFF queue (pg_id, pg_port_nr) mapping. GridCloak only TM-shaped dp68's
    hold queue; the dp8 per-state queues are NEW. `pg_queue = pg_port_nr*8 + qid` holds, but the
    (pg_id, pg_port_nr) for dp8 must be read from the switch's port->PG map at bring-up
    (bfrt tf1.tm.port.* / the SDE port map). Defaults below are a FORMULA guess, guarded by
    --skip-dp8-queues so the metronome path (which does not need dp8 TM shaping) runs regardless.
  * The exact strict-priority field name/enum on tf1.tm.queue.sched_cfg (real HIGH vs chaff LOW).
    GridCloak did not exercise per-queue strict priority. Written below as best-known; if entry_mod
    rejects the field, drop it (metronome mode does not depend on it) and confirm at review time.

Usage:  python3.8 queue_microbench_setup.py --mode v1    --mech pktgen               # PRIMARY
        python3.8 queue_microbench_setup.py --mode final --mech pktgen --tau-ms 10
        python3.8 queue_microbench_setup.py --mode final --mech shaper --rate-pps 100
        python3.8 queue_microbench_setup.py --dry-run --mode final --mech pktgen
Author: Philip
"""
import sys
import struct
import argparse

SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE_PY + "/tofino")
sys.path.insert(0, SDE_PY)
import bfrt_grpc.client as gc

PROG = "queue_microbench"

# ── topology (testbed.md / queue_microbench.p4) ──
# Vision (dp8) is DOWN; OBSERVE HAIRPINS to dp9 so Hulk both generates (ingress dp9) and
# captures the shaped output (egress dp9). Matches queue_microbench.p4 PORT_OBSERVE = 9w9.
PORT_HULK, PORT_OBSERVE, PORT_RECIRC = 9, 9, 68     # dp9 gen + hairpin observe; dp68 recirc

# ── internal encap constants (must match queue_microbench.p4) ──
ETHERTYPE_MB = 0x88B6
MB_METRO     = 1        # is_tick value the P4 treats as a metronome tick
S1, S2       = 1, 2     # size states
PAD_NONE, PAD_S1, PAD_S2 = 0, 1, 2
MECH_PKTGEN, MECH_SHAPER = 0, 1

# ── size-labelled TM queues (must match queue_microbench.p4 QID_*) ──
QID_REAL_S1, QID_CHAFF_S1, QID_REAL_S2, QID_CHAFF_S2, QID_HOLD = 1, 2, 3, 4, 6

# ── pktgen metronome ──
PKTGEN_HDR   = 6                 # pktgen prepends 6 B into the eth dst-MAC
TICK_WIRE    = 64                # 64 B base tick; P4 pads chaff cover to slot target (128/256)
PG_ID_RECIRC = 17                # dp68 port-group id (GridCloak value; dp68 unchanged)
PG_PORT_NR_RECIRC = 0
TICK_APP_ID  = 1                 # distinct pktgen app id
HOLD_LOOP_PPS = 100000           # cap recirc-hold churn (GridCloak B3 fix); ~10 us/pass
OBSERVE_MIRROR_SID = 2           # timing tap (gridcloak uses 1 -> use 2)

# ── dp9 REAL/CHAFF queue port-group mapping — READ from switch tf1.tm.port.cfg (dev_port=9) ──
#    Confirmed on switch 2026-07-22: dp9 -> pg_id=2, pg_port_nr=1
#    (dp8 -> pg2/nr0, dp68 -> pg17/nr0, the last matching GridCloak's known-good value).
PG_ID_OBSERVE      = 2           # dp9 port-group id (read, not guessed)
PG_PORT_NR_OBSERVE = 1           # dp9 port-nr in pg -> pg_queue = pg_port_nr*8 + qid = 8+qid


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["v1", "final"], default="v1")
    ap.add_argument("--mech", choices=["pktgen", "shaper"], default="pktgen")
    ap.add_argument("--tau-ms", type=float, default=10.0, help="metronome slot period (ms)")
    ap.add_argument("--rate-pps", type=int, default=100,
                    help="shaper-mode per-REAL-queue rate R (pps); <~1200 reproduces GridCloak B1 starvation")
    ap.add_argument("--skip-dp8-queues", action="store_true",
                    help="skip the dp8 REAL/CHAFF TM queue config (pg map unconfirmed); metronome runs without it")
    ap.add_argument("--dry-run", action="store_true")
    return ap.parse_args()


def pattern_entries(mode):
    """Return the ordered size-state list P as pat_state entries: pat_lo -> (state, chaff_pad).
       v1:    all 8 slots -> S1, no chaff pad  (equal-sized).
       final: alternate S1,S2 (|P|=2), chaff padded to the slot's target size."""
    if mode == "v1":
        return [(i, S1, PAD_NONE) for i in range(8)]
    # final: S1,S2,S1,S2,... over the low 3 bits
    out = []
    for i in range(8):
        if i % 2 == 0:
            out.append((i, S1, PAD_S1))
        else:
            out.append((i, S2, PAD_S2))
    return out


def tick_template():
    """64 B MB_METRO tick. pktgen prepends 6 B into the eth dst-MAC, so the template buffer
       supplies wire byte 6 onward: buf[6:8]=ethertype, then the 6 B mb header at buf[8:14]."""
    buf = bytearray(TICK_WIRE - PKTGEN_HDR)          # 58 bytes
    buf[6] = (ETHERTYPE_MB >> 8) & 0xFF              # ethertype hi  (wire byte 12)
    buf[7] = ETHERTYPE_MB & 0xFF                     # ethertype lo  (wire byte 13)
    buf[8] = MB_METRO                                # mb.is_tick    (wire byte 14)
    buf[9] = 0                                       # mb.state      (P4 overwrites per slot)
    buf[10] = 0                                      # mb.role
    buf[11] = 0                                      # mb.seq
    struct.pack_into('!H', buf, 12, 0x0800)          # mb.orig_ethertype
    return bytes(buf)


def _u16(v): return v & 0xFFFF
def _u32(v): return v & 0xFFFFFFFF


def main():
    args = parse_args()
    tau_ns = int(args.tau_ms * 1_000_000)
    print("=== queue_microbench bring-up ===")
    print("  mode=%s  mech=%s  tau=%.3f ms (%d ns)  rate_R=%d pps"
          % (args.mode, args.mech, args.tau_ms, tau_ns, args.rate_pps))
    print("  P = %s" % ([("S%d" % s, "pad%s" % ("N" if p == 0 else p))
                        for (_, s, p) in pattern_entries(args.mode)][:4] + ["..."]))
    if args.dry_run:
        print("  [DRY-RUN] no writes.")
        return

    # ── connect (shared bfrt client boilerplate; dcrn_setup.py:107-111) ──
    iface = gc.ClientInterface("localhost:50052", client_id=2, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi   = iface.bfrt_info_get(PROG)
    tgt  = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)          # TM tables are pipe-specific

    # ── 1. host ports up (gc_switch_setup_c.py:92-104) ──
    port_tbl = bi.table_get("$PORT")
    # dp9 is BOTH generator and hairpin observe (Vision/dp8 down) -> bring it up once.
    for dp, lbl in [(PORT_HULK, "Hulk/gen+observe (dp9 hairpin)")]:
        key  = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
        data = [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_RS"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
            gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_NONE"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
        try:    port_tbl.entry_add(tgt, key, data)
        except Exception: port_tbl.entry_mod(tgt, key, data)
    print("  host port up: dp%d Hulk (gen + hairpin observe)" % PORT_HULK)

    # ── 2. recirc + pktgen on dp68 (gc_switch_setup_c.py:106-111) ──
    pc = bi.table_dict["tf1.pktgen.port_cfg"]
    pc.entry_mod(tgt, [pc.make_key([gc.KeyTuple("dev_port", PORT_RECIRC)])],
        [pc.make_data([gc.DataTuple("pktgen_enable", bool_val=True),
                       gc.DataTuple("recirculation_enable", bool_val=True)])])
    print("  dp%d: recirc + pktgen on" % PORT_RECIRC)

    # ── 3. write metronome tick template + arm the PERIODIC slot clock
    #        (gc_switch_setup_c.py:113-143). Only needed for the pktgen mechanism, but harmless
    #        to arm always; the P4 only recirc-holds reals when mech_reg == PKTGEN. ──
    pb = bi.table_dict["tf1.pktgen.pkt_buffer"]
    tpl = tick_template()
    for s in range(0, len(tpl), 128):
        chunk = tpl[s:s+128]
        pb.entry_mod(tgt, [pb.make_key([gc.KeyTuple("pkt_buffer_offset", s),
                                        gc.KeyTuple("pkt_buffer_size", len(chunk))])],
            [pb.make_data([gc.DataTuple("buffer", int_arr_val=list(chunk))])])
    ac = bi.table_dict["tf1.pktgen.app_cfg"]
    flds = [
        gc.DataTuple("timer_nanosec", val=_u32(tau_ns)),          # period = tau (ACTION field)
        gc.DataTuple("pkt_len", val=_u16(TICK_WIRE - PKTGEN_HDR)),
        gc.DataTuple("pkt_buffer_offset", val=_u16(0)),
        gc.DataTuple("pipe_local_source_port", val=_u32(PORT_RECIRC)),
        gc.DataTuple("increment_source_port", bool_val=False),
        gc.DataTuple("batch_count_cfg", val=_u16(0)),             # 1 batch / fire
        gc.DataTuple("packets_per_batch_cfg", val=_u16(0)),       # 1 packet / batch
        gc.DataTuple("ibg", val=_u32(0)), gc.DataTuple("ibg_jitter", val=_u32(0)),
        gc.DataTuple("ipg", val=_u32(0)), gc.DataTuple("ipg_jitter", val=_u32(0)),
    ]
    def _arm(enable):
        ac.entry_mod(tgt, [ac.make_key([gc.KeyTuple("app_id", TICK_APP_ID)])],
            [ac.make_data(flds + [gc.DataTuple("app_enable", bool_val=enable)], "trigger_timer_periodic")])
    # The metronome belongs to the pktgen mechanism ONLY. In shaper mode DISABLE it: otherwise the
    # periodic tick becomes chaff cover on the hairpin OBSERVE port (dp9) and pollutes the pure
    # TM-shaper cadence measurement (the mechanism actually under test).
    if args.mech == "pktgen":
        _arm(False); _arm(True)
        print("  metronome ARMED: periodic %d ns on dp%d (app %d), %d B tick"
              % (tau_ns, PORT_RECIRC, TICK_APP_ID, TICK_WIRE))
    else:
        _arm(False)
        print("  metronome DISABLED (shaper arm: dp9 carries only TM-shaper output under test)")

    # ── 4. dp68 hold-loop shaper CAP (gc_switch_setup_c.py:163-177; GridCloak B3) ──
    q_shape = bi.table_get("tf1.tm.queue.sched_shaping")
    q_cfg   = bi.table_get("tf1.tm.queue.sched_cfg")
    pgq_hold = PG_PORT_NR_RECIRC * 8 + QID_HOLD
    q_shape.entry_mod(tgt0,
        [q_shape.make_key([gc.KeyTuple("pg_id", PG_ID_RECIRC), gc.KeyTuple("pg_queue", pgq_hold)])],
        [q_shape.make_data([gc.DataTuple("unit", str_val="PPS"),
                            gc.DataTuple("provisioning", str_val="UPPER"),
                            gc.DataTuple("max_rate", val=HOLD_LOOP_PPS),
                            gc.DataTuple("max_burst_size", val=16384)])])
    q_cfg.entry_mod(tgt0,
        [q_cfg.make_key([gc.KeyTuple("pg_id", PG_ID_RECIRC), gc.KeyTuple("pg_queue", pgq_hold)])],
        [q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True),
                          gc.DataTuple("max_rate_enable", bool_val=True)])])
    print("  hold-loop cap: dp%d qid%d max_rate=%d PPS" % (PORT_RECIRC, QID_HOLD, HOLD_LOOP_PPS))

    # ── 5. size-labelled TM queues on dp8 (REAL high-prio, CHAFF low-prio, per state).
    #        CONFIRM (pg_id, pg_port_nr) for dp8 on switch; guarded by --skip-dp8-queues. ──
    if args.skip_dp8_queues:
        print("  dp8 REAL/CHAFF queues: SKIPPED (--skip-dp8-queues); metronome paces via pktgen+recirc")
    else:
        # strict priority: real queues > chaff queues (highest numeric = strongest, per SDE enum).
        # The priority field name/enum is a CONFIRM-ON-SWITCH item (see header).
        prio = {QID_REAL_S1: "PRIO_7", QID_CHAFF_S1: "PRIO_1",
                QID_REAL_S2: "PRIO_7", QID_CHAFF_S2: "PRIO_1"}
        for qid in (QID_REAL_S1, QID_CHAFF_S1, QID_REAL_S2, QID_CHAFF_S2):
            pgq = PG_PORT_NR_OBSERVE * 8 + qid
            cfg = [gc.DataTuple("scheduling_enable", bool_val=True)]
            # best-known strict-priority field; if rejected, comment out and rely on default DWRR.
            try:
                cfg2 = cfg + [gc.DataTuple("min_priority", str_val=prio[qid])]
                q_cfg.entry_mod(tgt0,
                    [q_cfg.make_key([gc.KeyTuple("pg_id", PG_ID_OBSERVE), gc.KeyTuple("pg_queue", pgq)])],
                    [q_cfg.make_data(cfg2)])
            except Exception:
                q_cfg.entry_mod(tgt0,
                    [q_cfg.make_key([gc.KeyTuple("pg_id", PG_ID_OBSERVE), gc.KeyTuple("pg_queue", pgq)])],
                    [q_cfg.make_data(cfg)])
        print("  dp8 queues: REAL_S1=%d/REAL_S2=%d (high) CHAFF_S1=%d/CHAFF_S2=%d (low)"
              % (QID_REAL_S1, QID_REAL_S2, QID_CHAFF_S1, QID_CHAFF_S2))

        # shaper mechanism: pace each REAL queue at rate R (this is the arm that GridCloak B1
        # found STARVES below ~1200 pps; the microbench measures whether it paces a sparse frame).
        if args.mech == "shaper":
            for qid in (QID_REAL_S1, QID_REAL_S2):
                pgq = PG_PORT_NR_OBSERVE * 8 + qid
                q_shape.entry_mod(tgt0,
                    [q_shape.make_key([gc.KeyTuple("pg_id", PG_ID_OBSERVE), gc.KeyTuple("pg_queue", pgq)])],
                    [q_shape.make_data([gc.DataTuple("unit", str_val="PPS"),
                                        gc.DataTuple("provisioning", str_val="UPPER"),
                                        gc.DataTuple("max_rate", val=args.rate_pps),
                                        gc.DataTuple("max_burst_size", val=16384)])])
                q_cfg.entry_mod(tgt0,
                    [q_cfg.make_key([gc.KeyTuple("pg_id", PG_ID_OBSERVE), gc.KeyTuple("pg_queue", pgq)])],
                    [q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True),
                                      gc.DataTuple("max_rate_enable", bool_val=True)])])
            print("  shaper: REAL queues paced at R=%d pps (below ~1200 reproduces GridCloak B1)"
                  % args.rate_pps)

    # ── 6a. seed mech_reg (bfrt name from compiled bfrt.json) ──
    mech_val = MECH_PKTGEN if args.mech == "pktgen" else MECH_SHAPER
    mreg = bi.table_get("pipe.Ingress.mech_reg")
    mreg_data = [gc.DataTuple("Ingress.mech_reg.f1", mech_val)]
    mkey = [mreg.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])]
    try:    mreg.entry_add(tgt, mkey, [mreg.make_data(mreg_data)])
    except Exception: mreg.entry_mod(tgt, mkey, [mreg.make_data(mreg_data)])
    print("  mech_reg seeded = %d (%s)" % (mech_val, args.mech))

    # ── 6b. install the size-pattern P into pat_state (this table IS the ordered list) ──
    pt = bi.table_get("pipe.Ingress.pat_state")
    for (lo, st, pad) in pattern_entries(args.mode):
        pkey = [pt.make_key([gc.KeyTuple("meta.pat_lo", lo)])]
        pdat = [pt.make_data([gc.DataTuple("st", st), gc.DataTuple("chaff_pad", pad)],
                             "Ingress.set_slot_state")]
        try:    pt.entry_add(tgt, pkey, pdat)
        except Exception: pt.entry_mod(tgt, pkey, pdat)
    print("  pat_state: P installed for mode=%s (|P|=%d over 8 slots)"
          % (args.mode, 1 if args.mode == "v1" else 2))

    # ── 7. mirror tap -> dp8 for timing measurement (gc_switch_setup_c.py:145-156) ──
    #    OFF unless the P4 sets ig_dprsr_md.mirror_type; kept configured so a tap variant can use it.
    mir = bi.table_get("$mirror.cfg")
    mrkey = [mir.make_key([gc.KeyTuple("$sid", OBSERVE_MIRROR_SID)])]
    mrdat = [mir.make_data([
        gc.DataTuple("$direction", str_val="INGRESS"),
        gc.DataTuple("$ucast_egress_port", val=PORT_OBSERVE),
        gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
        gc.DataTuple("$session_enable", bool_val=True),
        gc.DataTuple("$max_pkt_len", val=16384)], "$normal")]
    try:    mir.entry_add(tgt, mrkey, mrdat)
    except Exception: mir.entry_mod(tgt, mrkey, mrdat)
    print("  mirror session %d -> dp%d configured (off unless P4 arms mirror_type)"
          % (OBSERVE_MIRROR_SID, PORT_OBSERVE))

    print("queue_microbench up (mode=%s mech=%s). Capture on Hulk (dp9 hairpin, inbound only):" % (args.mode, args.mech))
    print("  tcpdump -i enp59s0f0np0 -Q in -w cap.pcap 'ether proto 0x88b6 or udp'")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ibspg_setup.py — one-time static TM configuration for the IBSPG microbench.

Runs on the switch against the loaded ibspg_mb program (bfruntime localhost:50052).
Installs ALL config once; performs NO per-transaction operation. Idempotent.

  - bring host ports up (dp9, dp11) at 25G RS-FEC
  - enable recirc on the loopback port L (dp68)
  - set Q_BLOCK (pg_l,qb)=HIGH  and  Q_HOLD (pg_l,qh)=LOW  strict priority, with readback verify
  - optional Q_BLOCK max-rate shaper (variant C)  via --block-shape-pps

Prints one JSON line:  IBSPGSETUP {...}  (strict_priority_verified: true/false is the key field)
"""
import sys, json, argparse
import bfrt_grpc.client as gc

PROG = "ibspg_mb"


def pnorm(v):
    if v is None:
        return None
    s = str(v).upper()
    if s == "HIGH":
        return 7
    if s == "LOW":
        return 0
    try:
        return int(s)
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-l", type=int, default=68)
    ap.add_argument("--pg-l", type=int, default=17)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--qb", type=int, default=7)          # Q_BLOCK qid (HIGH)
    ap.add_argument("--qh", type=int, default=1)          # Q_HOLD  qid (LOW)
    ap.add_argument("--host-ports", default="9,11")
    ap.add_argument("--block-shape-pps", type=int, default=0)   # 0 = no shaper
    ap.add_argument("--mac-loopback", action="store_true",
                    help="put PORT_L in BF_LPBK_MAC_NEAR (physical-loopback variant)")
    a = ap.parse_args()
    hp = [int(x) for x in a.host_ports.split(",") if x != ""]
    out = {}

    iface = gc.ClientInterface("localhost:50052", client_id=30, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi   = iface.bfrt_info_get(PROG)
    tgt  = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)

    # 1. host ports up
    port_tbl = bi.table_get("$PORT")
    up = []
    for dp in hp:
        key  = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
        data = [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_RS"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
            gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_NONE"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
        try:
            port_tbl.entry_add(tgt, key, data)
        except Exception:
            try:
                port_tbl.entry_mod(tgt, key, data)
            except Exception as e:
                out["port_%d_err" % dp] = str(e)
        up.append(dp)
    out["host_ports_up"] = up

    # 1b. physical MAC-near loopback on PORT_L (delete + re-add; a live entry rejects
    #     the mode change). Idiom from dp8_loopback.py.
    if a.mac_loopback:
        try:
            lk = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", a.port_l)])]
            try:
                port_tbl.entry_del(tgt, lk)
            except Exception:
                pass
            port_tbl.entry_add(tgt, lk, [port_tbl.make_data([
                gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
                gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
                gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
            out["mac_loopback_L"] = a.port_l
        except Exception as e:
            out["mac_loopback_err"] = str(e)

    # 2. recirc on loopback L
    try:
        pc = bi.table_dict["tf1.pktgen.port_cfg"]
        pc.entry_mod(tgt, [pc.make_key([gc.KeyTuple("dev_port", a.port_l)])],
            [pc.make_data([gc.DataTuple("pktgen_enable", bool_val=True),
                           gc.DataTuple("recirculation_enable", bool_val=True)])])
        out["recirc_on"] = a.port_l
    except Exception as e:
        out["recirc_err"] = str(e)

    # 3. strict priority on L: Q_BLOCK=HIGH, Q_HOLD=LOW  (+ mandatory readback)
    q_cfg = bi.table_get("tf1.tm.queue.sched_cfg")

    def set_pri(qid, want):
        pgq = a.pg_l_nr * 8 + qid
        qkey = q_cfg.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])
        got = None
        err = None
        try:
            q_cfg.entry_mod(tgt0, [qkey], [q_cfg.make_data([
                gc.DataTuple("scheduling_enable", bool_val=True),
                gc.DataTuple("min_priority", str_val=want)])])
            for d, _ in q_cfg.entry_get(tgt0, [qkey], {"from_hw": False}):
                got = d.to_dict().get("min_priority")
        except Exception as e:
            err = str(e)
        return got, err

    gb, eb = set_pri(a.qb, "HIGH")
    gh, eh = set_pri(a.qh, "LOW")
    out["Q_BLOCK_pri"] = {"want": "HIGH", "got": gb, "err": eb}
    out["Q_HOLD_pri"]  = {"want": "LOW",  "got": gh, "err": eh}
    ok = (eb is None and eh is None and pnorm(gb) == 7 and pnorm(gh) == 0 and pnorm(gb) > pnorm(gh))
    out["strict_priority_verified"] = bool(ok)

    # 4. optional Q_BLOCK shaper (variant C)
    if a.block_shape_pps > 0:
        try:
            q_shape = bi.table_get("tf1.tm.queue.sched_shaping")
            pgq = a.pg_l_nr * 8 + a.qb
            skey = q_shape.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])
            q_shape.entry_mod(tgt0, [skey], [q_shape.make_data([
                gc.DataTuple("unit", str_val="PPS"),
                gc.DataTuple("provisioning", str_val="UPPER"),
                gc.DataTuple("max_rate", val=a.block_shape_pps),
                gc.DataTuple("max_burst_size", val=16384)])])
            qkey = q_cfg.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])
            q_cfg.entry_mod(tgt0, [qkey], [q_cfg.make_data([
                gc.DataTuple("scheduling_enable", bool_val=True),
                gc.DataTuple("max_rate_enable", bool_val=True)])])
            out["block_shape_pps"] = a.block_shape_pps
        except Exception as e:
            out["shape_err"] = str(e)

    print("IBSPGSETUP " + json.dumps(out))


if __name__ == "__main__":
    main()

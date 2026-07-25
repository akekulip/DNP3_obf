#!/usr/bin/env python3
"""ibspg_part9_setup.py — static config + per-trial reset for the Part 9 controlled-drain program.

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052). The control plane may
ONLY: load/configure-static-priority, bring up ports, reset counters/registers between trials, and
read evidence. It MUST NOT perform the transaction-time release (that is a data-plane DRAIN packet).

Modes:
  --config   : one-time static setup — host ports up (dp9,dp11), dp8 MAC-near loopback, strict
               priority Q_BLOCK=HIGH / Q_HOLD=LOW (with mandatory max_priority readback verify),
               Q_BLOCK shaping left disabled. Idempotent.
  --reset    : per-trial — zero the named state + timestamp registers and clear the named counters.
  (both may be given together: --config --reset)

Register/counter names are args so this is independent of exact P4 field names.
Prints one JSON line:  PART9SETUP {...}
"""
import argparse
import json
import bfrt_grpc.client as gc


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
    ap.add_argument("--prog", default="ibspg_controlled_drain")
    ap.add_argument("--config", action="store_true")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--port-l", type=int, default=8)
    ap.add_argument("--pg-l", type=int, default=2)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--qb", type=int, default=7)     # Q_BLOCK qid
    ap.add_argument("--qa", type=int, default=5)      # Q_ACK   qid (Part 11)
    ap.add_argument("--qh", type=int, default=1)      # Q_RESP/Q_HOLD qid
    ap.add_argument("--ack-pri", default="3", help="Q_ACK max_priority (between HIGH=7 and LOW=0)")
    ap.add_argument("--paired", action="store_true", help="configure 3 levels: Q_BLOCK>Q_ACK>Q_RESP")
    ap.add_argument("--host-ports", default="9,11")
    ap.add_argument("--regs", default="")
    ap.add_argument("--counters", default="")
    ap.add_argument("--reg-prefix", default="pipe.Ingress.")
    ap.add_argument("--ctr-prefix", default="pipe.Ingress.")
    a = ap.parse_args()

    iface = gc.ClientInterface("localhost:50052", client_id=62, device_id=0, notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    out = {"prog": a.prog}

    if a.config:
        # host ports up
        port_tbl = bi.table_get("$PORT")
        up = []
        for dp in [int(x) for x in a.host_ports.split(",") if x]:
            key = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
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
                    out["port_%d_err" % dp] = str(e)[:80]
            up.append(dp)
        out["host_ports_up"] = up

        # dp8 MAC-near loopback (delete + re-add; a live entry rejects the mode change)
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
            out["mac_loopback_err"] = str(e)[:80]

        # strict priority: max_priority is the arbitration field among backlogged queues (Part 3 fix)
        q_cfg = bi.table_get("tf1.tm.queue.sched_cfg")

        def set_pri(qid, want):
            pgq = a.pg_l_nr * 8 + qid
            qkey = q_cfg.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])
            got = err = None
            try:
                q_cfg.entry_mod(tgt0, [qkey], [q_cfg.make_data([
                    gc.DataTuple("scheduling_enable", bool_val=True),
                    gc.DataTuple("min_priority", str_val=want),
                    gc.DataTuple("max_priority", str_val=want)])])
                for d, _ in q_cfg.entry_get(tgt0, [qkey], {"from_hw": False}):
                    got = d.to_dict().get("max_priority")
            except Exception as e:
                err = str(e)[:80]
            return got, err

        gb, eb = set_pri(a.qb, "HIGH")
        gh, eh = set_pri(a.qh, "LOW")
        out["Q_BLOCK_pri"] = {"want": "HIGH", "got_max_priority": gb, "err": eb}
        out["Q_HOLD_pri"] = {"want": "LOW", "got_max_priority": gh, "err": eh}
        if a.paired:
            ga, ea = set_pri(a.qa, a.ack_pri)
            out["Q_ACK_pri"] = {"want": a.ack_pri, "got_max_priority": ga, "err": ea}
            # 3-level structural ordering: Q_BLOCK > Q_ACK > Q_RESP
            out["strict_priority_verified"] = bool(
                eb is None and eh is None and ea is None
                and pnorm(gb) is not None and pnorm(ga) is not None and pnorm(gh) is not None
                and pnorm(gb) > pnorm(ga) > pnorm(gh))
        else:
            out["strict_priority_verified"] = bool(
                eb is None and eh is None and pnorm(gb) == 7 and pnorm(gh) == 0 and pnorm(gb) > pnorm(gh))

    if a.reset:
        rz = {}
        for nm in [x for x in a.regs.split(",") if x]:
            try:
                t = bi.table_get(a.reg_prefix + nm)
                k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
                data = None
                for fn in ("Ingress.%s.f1" % nm, "%s.f1" % nm, "f1"):
                    try:
                        data = t.make_data([gc.DataTuple(fn, 0)])
                        break
                    except Exception:
                        continue
                t.entry_mod(tgt, [k], [data])
                rz[nm] = 0
            except Exception as e:
                rz[nm] = "ERR:" + str(e)[:60]
        out["regs_reset"] = rz
        cz = {}
        for nm in [x for x in a.counters.split(",") if x]:
            try:
                t = bi.table_get(a.ctr_prefix + nm)
                k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])
                t.entry_mod(tgt, [k], [t.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])])
                cz[nm] = 0
            except Exception as e:
                cz[nm] = "ERR:" + str(e)[:60]
        out["counters_reset"] = cz

    print("PART9SETUP " + json.dumps(out))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""oracle_sched_ctl.py — scheduling + priority control for the finite-backlog oracle (Part 3).

Runs on the switch against the loaded program. Toggles Q_BLOCK/Q_HOLD scheduling (to preload a
finite backlog while disabled, then release), sets max_priority for the A/B/A configs, and resets
the trace event counter between trials.

  --disable-both     : both queues scheduling_enable=false (freeze; preload backlog)
  --enable-both      : both queues scheduling_enable=true in ONE entry_mod (minimize enable-order bias)
  --set-pri B H      : Q_BLOCK.max_priority=B, Q_HOLD.max_priority=H  (HIGH|LOW)
  --reset-trace      : zero reg_event_ctr + reg_overflow (fresh trial)
  --readback         : print sched_cfg for both queues
"""
import sys, json, argparse
import bfrt_grpc.client as gc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", required=True)
    ap.add_argument("--pg-l", type=int, required=True)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--qb", type=int, default=7)
    ap.add_argument("--qh", type=int, default=1)
    ap.add_argument("--disable-both", action="store_true")
    ap.add_argument("--enable-both", action="store_true")
    ap.add_argument("--set-pri", nargs=2, metavar=("BLOCK", "HOLD"))
    ap.add_argument("--reset-trace", action="store_true")
    ap.add_argument("--readback", action="store_true")
    a = ap.parse_args()

    iface = gc.ClientInterface("localhost:50052", client_id=70, device_id=0, notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    tgtall = gc.Target(device_id=0, pipe_id=0xffff)
    q_cfg = bi.table_get("tf1.tm.queue.sched_cfg")
    kb = q_cfg.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", a.pg_l_nr * 8 + a.qb)])
    kh = q_cfg.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", a.pg_l_nr * 8 + a.qh)])
    out = {}

    if a.set_pri:
        b, h = a.set_pri
        q_cfg.entry_mod(tgt0, [kb], [q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True),
                                                      gc.DataTuple("max_priority", str_val=b)])])
        q_cfg.entry_mod(tgt0, [kh], [q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True),
                                                      gc.DataTuple("max_priority", str_val=h)])])
        out["set_pri"] = {"Q_BLOCK": b, "Q_HOLD": h}

    if a.disable_both:
        d = q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=False)])
        q_cfg.entry_mod(tgt0, [kb, kh], [d, d])   # one call, both queues
        out["disabled"] = ["Q_BLOCK", "Q_HOLD"]

    if a.enable_both:
        d = q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True)])
        q_cfg.entry_mod(tgt0, [kb, kh], [d, d])   # one call, both queues -> near-simultaneous release
        out["enabled"] = ["Q_BLOCK", "Q_HOLD"]

    if a.reset_trace:
        for rn in ("reg_event_ctr", "reg_overflow"):
            try:
                t = bi.table_get("pipe.Ingress." + rn)
                k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
                # write 0 to the register's data field(s)
                flds = [f for f in t.info.data_field_name_list_get()] if hasattr(t, "info") else []
                data = None
                for fn in ("Ingress.%s.f1" % rn, "%s.f1" % rn):
                    try:
                        data = t.make_data([gc.DataTuple(fn, 0)]); break
                    except Exception:
                        pass
                if data is None:
                    data = t.make_data([gc.DataTuple("f1", 0)])
                t.entry_mod(tgtall, [k], [data])
                out[rn] = "reset0"
            except Exception as e:
                out[rn + "_err"] = str(e)

    if a.readback or not out:
        for lbl, k in (("Q_BLOCK", kb), ("Q_HOLD", kh)):
            for d, _ in q_cfg.entry_get(tgt0, [k], {"from_hw": True}):
                dd = d.to_dict()
                out[lbl] = {"sched": dd.get("scheduling_enable"), "max_priority": dd.get("max_priority"),
                            "dwrr": dd.get("dwrr_weight")}

    print("ORACLE_SCHED " + json.dumps(out))


if __name__ == "__main__":
    main()

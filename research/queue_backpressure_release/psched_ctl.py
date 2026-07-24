#!/usr/bin/env python3
"""psched_ctl.py — enable/disable a TM queue's scheduling (P-SCHED demonstration, Part 5).

Runs on the switch against the loaded program. Toggles Q_HOLD (pg_l, pg_l_nr*8+qh)
scheduling_enable via tf1.tm.queue.sched_cfg, with readback. This is the ONLY lever that
holds an enqueued packet queue-resident on TF1 without recirculation — and it is
control-plane only (the point of the demonstration).

  python3 psched_ctl.py --prog ibspg_mb_physL --pg-l 2 --qh 1 --action disable
  python3 psched_ctl.py --prog ibspg_mb_physL --pg-l 2 --qh 1 --action enable
"""
import sys, json, argparse
import bfrt_grpc.client as gc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", required=True)
    ap.add_argument("--pg-l", type=int, default=2)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--qh", type=int, default=1)
    ap.add_argument("--action", required=True, choices=["enable", "disable"])
    a = ap.parse_args()

    iface = gc.ClientInterface("localhost:50052", client_id=51, device_id=0, notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    q_cfg = bi.table_get("tf1.tm.queue.sched_cfg")
    pgq = a.pg_l_nr * 8 + a.qh
    key = q_cfg.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])
    want = (a.action == "enable")
    q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data([
        gc.DataTuple("scheduling_enable", bool_val=want)])])
    got = None
    for d, _ in q_cfg.entry_get(tgt0, [key], {"from_hw": False}):
        got = d.to_dict().get("scheduling_enable")
    print("PSCHED %s Q_HOLD(pg=%d,pgq=%d) scheduling_enable set=%s readback=%s"
          % (a.action, a.pg_l, pgq, want, got))


if __name__ == "__main__":
    main()

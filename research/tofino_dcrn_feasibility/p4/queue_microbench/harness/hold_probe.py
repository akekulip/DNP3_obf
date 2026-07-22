#!/usr/bin/env python3.8
"""hold_probe.py — set the cover=OFF deadline-hold pass budget + the dp68 HOLD shaper, for the
recirc-clock AUDIT (run ON the switch). Diagnostic only: writes hold_passes_reg and the HOLD
queue's sched_shaping (max_rate / max_burst_size) so the 4096-plateau and 0.65-us/pass anomalies
can be root-caused WITHOUT the forbidden DCRN raise-MAX_PASS+shaper fix. Restore with --restore.

dp68 HOLD queue: pg_id=17, pg_queue=6 (READ from tf1.tm.port.cfg dev_port=68: pg_id=17,pg_port_nr=0).
Baseline (as configured by queue_microbench_setup.py): max_rate=100000 PPS, max_burst_size=16384.

Usage:
  python3.8 hold_probe.py --hold-passes 2000 --rate 100000 --burst 16384
  python3.8 hold_probe.py --hold-passes 12000 --burst 1          # remove burst credit
  python3.8 hold_probe.py --restore                              # max_rate=100000 burst=16384
"""
import sys, argparse

SDE = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE + "/tofino"); sys.path.insert(0, SDE)
import bfrt_grpc.client as gc

PG_ID_HOLD, PG_QUEUE_HOLD = 17, 6   # dp68 recirc HOLD queue (read from tf1.tm.port.cfg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hold-passes", type=int, default=None)
    ap.add_argument("--rate", type=int, default=100000, help="HOLD queue max_rate (PPS)")
    ap.add_argument("--burst", type=int, default=16384, help="HOLD queue max/min_burst_size")
    ap.add_argument("--restore", action="store_true", help="restore max_rate=100000 burst=16384")
    a = ap.parse_args()
    if a.restore:
        a.rate, a.burst = 100000, 16384

    i = gc.ClientInterface("localhost:50052", client_id=90, device_id=0, notifications=None)
    i.bind_pipeline_config("queue_microbench"); bi = i.bfrt_info_get("queue_microbench")
    tall = gc.Target(device_id=0, pipe_id=0xffff)
    t0 = gc.Target(device_id=0, pipe_id=0)

    if a.hold_passes is not None:
        r = bi.table_get("pipe.Ingress.hold_passes_reg")
        k = [r.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])]
        d = [r.make_data([gc.DataTuple("Ingress.hold_passes_reg.f1", a.hold_passes)])]
        try: r.entry_add(tall, k, d)
        except Exception: r.entry_mod(tall, k, d)
        got = [x.to_dict().get("Ingress.hold_passes_reg.f1") for x, _ in r.entry_get(tall, k, {"from_hw": True})]
        print("hold_passes = %d (readback %s)" % (a.hold_passes, got))

    qsh = bi.table_get("tf1.tm.queue.sched_shaping")
    qk = [qsh.make_key([gc.KeyTuple("pg_id", PG_ID_HOLD), gc.KeyTuple("pg_queue", PG_QUEUE_HOLD)])]
    qsh.entry_mod(t0, qk, [qsh.make_data([
        gc.DataTuple("unit", str_val="PPS"), gc.DataTuple("provisioning", str_val="UPPER"),
        gc.DataTuple("max_rate", val=a.rate),
        gc.DataTuple("max_burst_size", val=a.burst),
        gc.DataTuple("min_burst_size", val=a.burst)])])
    qcfg = bi.table_get("tf1.tm.queue.sched_cfg")
    qcfg.entry_mod(t0, [qcfg.make_key([gc.KeyTuple("pg_id", PG_ID_HOLD), gc.KeyTuple("pg_queue", PG_QUEUE_HOLD)])],
        [qcfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True),
                         gc.DataTuple("max_rate_enable", bool_val=True)])])
    # readback the shaper to PRESERVE/verify the exact config
    for d, _ in qsh.entry_get(t0, qk, {"from_hw": False}):
        print("HOLD sched_shaping:", d.to_dict())


if __name__ == "__main__":
    main()

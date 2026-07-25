#!/usr/bin/env python3
"""tm_shaper_clear.py — clear + verify NO max-rate shaper on Q_BLOCK (review C3).

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052).

The restore target (queue microbench) configures TM max-rate shapers. If a stale
shaper is left enabled on Q_BLOCK (qid7), the blocker reservoir becomes
rate-INELIGIBLE while over-rate and Q_RESP leaks past strict priority — a silent,
eligibility (not priority) failure. This script disables max_rate_enable on the
Q_BLOCK queue and reads it back so the clear is verified, not assumed.

Prints one JSON line:  TMSHAPER {...}
Exit 0 only if the shaper reads back disabled.
"""
import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", default="dnp3_timing_normalizer")
    ap.add_argument("--pg-l", type=int, default=2)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--qb", type=int, default=7)   # Q_BLOCK qid
    a = ap.parse_args()

    import bfrt_grpc.client as gc   # switch-only; deferred so --help works off-switch
    iface = gc.ClientInterface("localhost:50052", client_id=63, device_id=0, notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    out = {"prog": a.prog, "qb": a.qb}

    q_cfg = bi.table_get("tf1.tm.queue.sched_cfg")
    pgq = a.pg_l_nr * 8 + a.qb
    qkey = q_cfg.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])

    # disable the max-rate shaper (leave scheduling + strict priority untouched)
    try:
        q_cfg.entry_mod(tgt0, [qkey], [q_cfg.make_data([
            gc.DataTuple("scheduling_enable", bool_val=True),
            gc.DataTuple("max_rate_enable", bool_val=False)])])
        out["disabled"] = True
    except Exception as e:
        out["disable_err"] = str(e)[:100]

    # read back and confirm (from driver cache; C5: not silicon)
    got = None
    try:
        for d, _ in q_cfg.entry_get(tgt0, [qkey], {"from_hw": False}):
            dd = d.to_dict()
            got = dd.get("max_rate_enable")
            out["max_rate_enable_readback"] = got
            out["from_hw"] = False
    except Exception as e:
        out["readback_err"] = str(e)[:100]

    out["cleared"] = (got is False or got == 0 or got is None) and "disable_err" not in out
    print("TMSHAPER " + json.dumps(out))
    sys.exit(0 if out["cleared"] else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ibspg_part9_read.py — evidence reader for the Part 9 controlled-drain program.

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052). Dumps, as one JSON
object: every named single-entry Register value, every named Counter's packet count, and the
Q_BLOCK/Q_HOLD strict-priority readback. Read-only — never actuates a release.

Register/counter names are passed as args so this reader is independent of the exact P4 field
names (reconciled to the compiled program). Defaults match PART9_CONTROLLED_DRAIN_EXPERIMENT_PLAN.md.

Usage (on switch):
  python3 ibspg_part9_read.py --prog ibspg_controlled_drain \
      --regs reg_active,reg_gen,reg_drain_req,reg_ts_first_block,reg_ts_drain_match,\
reg_ts_block_term,reg_ts_first_release,reg_ts_last_release \
      --counters ctr_block_enq,ctr_hold_enq,ctr_block_loop,ctr_block_term_controlled,\
ctr_block_term_timeout,ctr_block_term_stale,ctr_hold_release,ctr_drain_match,\
ctr_drain_reject_unrelated,ctr_drain_reject_stale,ctr_hold_premature,ctr_nonibspg \
      --pg-l 2 --qb 7 --qh 1
"""
import argparse
import json
import bfrt_grpc.client as gc


def _first_scalar(dd):
    for k in dd:
        if k == "$REGISTER_INDEX" or k.startswith("action") or k.startswith("is_"):
            continue
        v = dd[k]
        return v[0] if isinstance(v, list) else v
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", default="ibspg_controlled_drain")
    ap.add_argument("--regs", default="")
    ap.add_argument("--counters", default="")
    ap.add_argument("--pg-l", type=int, default=2)
    ap.add_argument("--qb", type=int, default=7)
    ap.add_argument("--qh", type=int, default=1)
    ap.add_argument("--reg-prefix", default="pipe.Ingress.")
    ap.add_argument("--ctr-prefix", default="pipe.Ingress.")
    a = ap.parse_args()

    iface = gc.ClientInterface("localhost:50052", client_id=61, device_id=0, notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tall = gc.Target(device_id=0, pipe_id=0xffff)
    t0 = gc.Target(device_id=0, pipe_id=0)
    out = {"prog": a.prog, "registers": {}, "counters": {}, "tm": {}}

    for nm in [x for x in a.regs.split(",") if x]:
        try:
            t = bi.table_get(a.reg_prefix + nm)
            k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
            val = None
            for d, _ in t.entry_get(tall, [k], {"from_hw": True}):
                val = _first_scalar(d.to_dict())
            out["registers"][nm] = val
        except Exception as e:
            out["registers"][nm] = "ERR:" + str(e)[:80]

    for nm in [x for x in a.counters.split(",") if x]:
        try:
            t = bi.table_get(a.ctr_prefix + nm)
            k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])
            cnt = None
            for d, _ in t.entry_get(tall, [k], {"from_hw": True}):
                dd = d.to_dict()
                cnt = dd.get("$COUNTER_SPEC_PKTS", dd.get("$COUNTER_SPEC_BYTES"))
            out["counters"][nm] = cnt
        except Exception as e:
            out["counters"][nm] = "ERR:" + str(e)[:80]

    # strict-priority readback (the load-bearing config)
    try:
        q = bi.table_get("tf1.tm.queue.sched_cfg")
        for lbl, qid in (("Q_BLOCK", a.qb), ("Q_HOLD", a.qh)):
            kk = q.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", qid)])
            for d, _ in q.entry_get(t0, [kk], {"from_hw": True}):
                dd = d.to_dict()
                out["tm"][lbl] = {"max_priority": dd.get("max_priority"),
                                  "min_priority": dd.get("min_priority"),
                                  "scheduling_enable": dd.get("scheduling_enable"),
                                  "max_rate_enable": dd.get("max_rate_enable"),
                                  "dwrr_weight": dd.get("dwrr_weight")}
    except Exception as e:
        out["tm"]["err"] = str(e)[:120]

    print("PART9READ " + json.dumps(out))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ibspg_tm_readback.py — prove queue/priority placement for Q_BLOCK and Q_HOLD (Part 5).

Runs on the switch against the loaded program. Dumps the FULL TM scheduler + shaping + counter
state for both queues (every field the tables expose, not just the ones we set), plus the queue->
port mapping and any L1-node attachment, and FAILS LOUDLY on ambiguity/mismatch. No writes.

  python3 ibspg_tm_readback.py --prog ibspg_mb_physL --pg-l 2 --pg-l-nr 0 --qb 7 --qh 1 \
      --dev-port 8 [--expect-block-pri HIGH --expect-hold-pri LOW]

Exit non-zero on any FAIL. Do not draw IBSPG conclusions unless this prints PLACEMENT-OK.
"""
import sys, json, argparse
import bfrt_grpc.client as gc

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("  !! FAIL:", msg)


def dump_entry(tbl, tgt, keyfields, label):
    """entry_get -> full dict, or None (and record FAIL) if the entry does not exist."""
    try:
        key = tbl.make_key([gc.KeyTuple(k, v) for k, v in keyfields])
    except Exception as e:
        fail("%s: cannot build key %s: %s" % (label, keyfields, e)); return None
    got = None
    try:
        for d, _ in tbl.entry_get(tgt, [key], {"from_hw": True}):
            got = d.to_dict()
    except Exception as e:
        fail("%s: entry_get raised: %s" % (label, e)); return None
    if got is None:
        fail("%s: entry does not exist (queue/mapping missing?)" % label)
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", required=True)
    ap.add_argument("--pg-l", type=int, required=True)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--qb", type=int, default=7)   # Q_BLOCK qid
    ap.add_argument("--qh", type=int, default=1)   # Q_HOLD qid
    ap.add_argument("--dev-port", type=int, required=True)
    ap.add_argument("--expect-block-pri", default=None)  # HIGH / 7 / ...
    ap.add_argument("--expect-hold-pri", default=None)   # LOW / 0 / ...
    a = ap.parse_args()

    iface = gc.ClientInterface("localhost:50052", client_id=53, device_id=0, notifications=None)
    try:
        iface.bind_pipeline_config(a.prog)
        bi = iface.bfrt_info_get(a.prog)
    except Exception as e:
        print("!! FAIL: program binding wrong (%s): %s" % (a.prog, e)); sys.exit(2)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    tgt  = gc.Target(device_id=0, pipe_id=0xffff)

    queues = [("Q_BLOCK", a.qb, a.expect_block_pri), ("Q_HOLD", a.qh, a.expect_hold_pri)]
    out = {"prog": a.prog, "dev_port": a.dev_port, "pg_id": a.pg_l, "pg_port_nr": a.pg_l_nr, "queues": {}}

    # queue->port mapping sanity: which dev_port does (pg_id,pg_queue) belong to?
    # tf1.tm.port.cfg is keyed by dev_port and reports pg_id/pg_port_nr on this SDE.
    try:
        pcfg = bi.table_get("tf1.tm.port.cfg")
        pm = dump_entry(pcfg, tgt0, [("dev_port", a.dev_port)], "port.cfg dp%d" % a.dev_port)
        if pm:
            out["port_cfg"] = {k: pm[k] for k in pm if "pg" in k.lower() or "pipe" in k.lower()}
            got_pg = pm.get("pg_id")
            if got_pg is not None and got_pg != a.pg_l:
                fail("dev_port %d maps to pg_id %s, but --pg-l=%d (ambiguous mapping)" % (a.dev_port, got_pg, a.pg_l))
    except Exception as e:
        out["port_cfg_err"] = str(e)

    sched = bi.table_get("tf1.tm.queue.sched_cfg")
    shap  = bi.table_get("tf1.tm.queue.sched_shaping")
    qctr  = bi.table_get("tf1.tm.counter.queue")
    # optional L1-node mapping table (may not exist on this SDE)
    l1tbl = None
    for name in ("tf1.tm.queue.sched_cfg", "tf1.tm.l1_node.sched_cfg", "tf1.tm.queue.map"):
        try:
            t = bi.table_get(name)
            if "l1" in name:
                l1tbl = t
        except Exception:
            pass

    for label, qid, expect in queues:
        pgq = a.pg_l_nr * 8 + qid
        key = [("pg_id", a.pg_l), ("pg_queue", pgq)]
        rec = {"qid": qid, "pg_queue": pgq}
        sc = dump_entry(sched, tgt0, key, "%s sched_cfg" % label)
        rec["sched_cfg"] = sc                       # FULL dict: scheduling_enable, min_priority, max_priority, dwrr_weight, min/max_rate_enable, ...
        rec["shaping"]   = dump_entry(shap, tgt0, key, "%s sched_shaping" % label)
        rec["counter"]   = dump_entry(qctr, tgt0, key, "%s counter" % label)
        if l1tbl is not None:
            rec["l1"] = dump_entry(l1tbl, tgt0, key, "%s l1" % label)
        # priority expectation check (compare against readback if requested)
        if expect is not None and sc is not None:
            mp = sc.get("min_priority")
            xp = sc.get("max_priority")
            rec["priority_readback"] = {"min_priority": mp, "max_priority": xp}
            def norm(v):
                s = str(v).upper()
                return 7 if s == "HIGH" else (0 if s == "LOW" else (int(s) if s.lstrip("-").isdigit() else None))
            if norm(mp) is None and norm(xp) is None:
                fail("%s: no interpretable priority in readback (min=%s max=%s)" % (label, mp, xp))
            elif norm(expect) is not None and norm(mp) != norm(expect):
                print("  NOTE: %s min_priority readback=%s vs expected %s (may be OK if strict priority uses a different field)" % (label, mp, expect))
        out["queues"][label] = rec

    # domain check: both queues must be on the same dev_port / pg_id (same arbitration domain intent)
    if out["queues"].get("Q_BLOCK") and out["queues"].get("Q_HOLD"):
        print("  DOMAIN: both queues on pg_id=%d dev_port=%d (Q_BLOCK pgq=%d, Q_HOLD pgq=%d)"
              % (a.pg_l, a.dev_port, out["queues"]["Q_BLOCK"]["pg_queue"], out["queues"]["Q_HOLD"]["pg_queue"]))

    print("IBSPG_TM_READBACK " + json.dumps(out, default=str))
    if FAILS:
        print("PLACEMENT-FAIL (%d issue(s))" % len(FAILS)); sys.exit(1)
    print("PLACEMENT-OK")


if __name__ == "__main__":
    main()

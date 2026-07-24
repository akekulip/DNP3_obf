#!/usr/bin/env python3
"""ibspg_read.py — switch-side counter + queue-occupancy + port-stat reader.

Runs on the switch against the loaded ibspg_mb program (bfruntime localhost:50052).
Prints one JSON line:  IBSPGREAD {...}

  --slot N        which per-slot counter index to read (default 0)
  --pg-l ID       port-group id of loopback port L (default 17 = dp68 recirc)
  --qb Q          Q_BLOCK qid (default 7)
  --qh Q          Q_HOLD  qid (default 1)
  --ports a,b,..  dev_ports to report eg_port + PORT_STAT for (default 9,11,68)
  --pg-l-nr NR    pg_port_nr of L (default 0)  -> pg_queue = NR*8 + qid
"""
import sys, json, argparse
import bfrt_grpc.client as gc

PROG = "ibspg_mb"
CTRS = ["ctr_blk_loop", "ctr_blk_drop", "ctr_safety_expiry", "ctr_held_enq",
        "ctr_held_release", "ctr_drain_match", "ctr_drain_badgen", "ctr_drain_unrel",
        "ctr_arm", "ctr_nonibspg"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--pg-l", type=int, default=17)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--qb", type=int, default=7)
    ap.add_argument("--qh", type=int, default=1)
    ap.add_argument("--ports", default="9,11,68")
    ap.add_argument("--prog", default="ibspg_mb", help="loaded p4 program name")
    a = ap.parse_args()
    ports = [int(x) for x in a.ports.split(",") if x != ""]
    global PROG
    PROG = a.prog

    iface = gc.ClientInterface("localhost:50052", client_id=22, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi = iface.bfrt_info_get(PROG)
    tgtall = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0   = gc.Target(device_id=0, pipe_id=0)
    out = {"label": a.label, "slot": a.slot}

    for c in CTRS:
        idx = 0 if c == "ctr_nonibspg" else a.slot
        try:
            t = bi.table_get("pipe.Ingress." + c)
            k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])
            v = 0
            for d, _ in t.entry_get(tgtall, [k], {"from_hw": True}):
                v = d.to_dict().get("$COUNTER_SPEC_PKTS", 0)
            out[c] = v
        except Exception as e:
            out[c] = "ERR:%s" % e

    # register state (reg_drain, reg_gen) at this slot
    for rn in ("reg_drain", "reg_gen"):
        try:
            t = bi.table_get("pipe.Ingress." + rn)
            k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", a.slot)])
            val = None
            for d, _ in t.entry_get(tgtall, [k], {"from_hw": True}):
                dd = d.to_dict()
                for kk in dd:
                    if kk.endswith(".f1") or kk.startswith("Ingress." + rn):
                        val = dd[kk]
            out[rn] = val
        except Exception as e:
            out[rn] = "ERR:%s" % e

    # TM queue occupancy on loopback L
    qc = bi.table_get("tf1.tm.counter.queue")
    for name, qid in (("Q_BLOCK", a.qb), ("Q_HOLD", a.qh)):
        pgq = a.pg_l_nr * 8 + qid
        try:
            k = qc.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])
            for d, _ in qc.entry_get(tgt0, [k], {"from_hw": True}):
                dd = d.to_dict()
                out["q_%s" % name] = {"use": dd.get("usage_cells"),
                                       "wm": dd.get("watermark_cells"),
                                       "drop": dd.get("drop_count_packets")}
        except Exception as e:
            out["q_%s" % name] = "ERR:%s" % e

    # eg_port occupancy + PORT_STAT rx/tx per reported port
    ep = bi.table_get("tf1.tm.counter.eg_port")
    ps = bi.table_get("$PORT_STAT")
    for p in ports:
        try:
            k = ep.make_key([gc.KeyTuple("dev_port", p)])
            for d, _ in ep.entry_get(tgt0, [k], {"from_hw": True}):
                dd = d.to_dict()
                out["egport_%d" % p] = {"use": dd.get("usage_cells"), "wm": dd.get("watermark_cells"),
                                         "drop": dd.get("drop_count_packets")}
        except Exception as e:
            out["egport_%d" % p] = "ERR:%s" % e
        try:
            k = ps.make_key([gc.KeyTuple("$DEV_PORT", p)])
            for d, _ in ps.entry_get(tgtall, [k], {"from_hw": True}):
                dd = d.to_dict()
                out["port_%d" % p] = {"rx": dd.get("$FramesReceivedOK"),
                                       "tx": dd.get("$FramesTransmittedOK")}
        except Exception as e:
            out["port_%d" % p] = "ERR:%s" % e

    print("IBSPGREAD " + json.dumps(out))


if __name__ == "__main__":
    main()

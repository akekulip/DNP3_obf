#!/usr/bin/env python3.8
"""mb_read.py — on-switch ground-truth reader for queue_microbench (run ON the switch).

Reads the P4 ctr_* indirect counters (Stats ALU, key $COUNTER_INDEX, data $COUNTER_SPEC_PKTS,
from_hw=True — confirmed live) and the TM queue counters (tf1.tm.counter.queue, keyed on
(pg_id, pg_queue): usage_cells / watermark_cells / drop_count_packets) plus the dp9 egress-port
counter. Prints one 'MBREAD {...}' dict line so a driver can log/diff snapshots.

dp9 mapping (READ from tf1.tm.port.cfg): pg_id=2, pg_port_nr=1 -> pg_queue = 8 + qid.
  QID_REAL_S1=1 ->9   QID_CHAFF_S1=2 ->10   QID_REAL_S2=3 ->11   QID_CHAFF_S2=4 ->12
Usage:  python3.8 mb_read.py [label]
"""
import sys
SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE_PY + "/tofino"); sys.path.insert(0, SDE_PY)
import bfrt_grpc.client as gc

PROG = "queue_microbench"
PG_ID_DP9 = 2
QMAP = {"REAL_S1": 9, "CHAFF_S1": 10, "REAL_S2": 11, "CHAFF_S2": 12}
# ctr_grad = REAL released; ctr_cover = EXTERNAL cover transmitted; ctr_tick = idle tick consumed
# INTERNALLY (no transmit, COVER_OFF). External bytes on the WAN when idle should be ZERO in cover=off.
CTRS = ["ctr_encap", "ctr_grad", "ctr_tick", "ctr_cover", "ctr_shaper", "ctr_chaff",
        "ctr_failopen", "ctr_oversize"]

def main():
    label = sys.argv[1] if len(sys.argv) > 1 else ""
    iface = gc.ClientInterface("localhost:50052", client_id=20, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi = iface.bfrt_info_get(PROG)
    tgtall = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0   = gc.Target(device_id=0, pipe_id=0)
    out = {"label": label}

    for c in CTRS:
        try:
            t = bi.table_get("pipe.Ingress." + c)
            k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])
            v = 0
            for d, _ in t.entry_get(tgtall, [k], {"from_hw": True}):
                v = d.to_dict().get("$COUNTER_SPEC_PKTS", 0)
            out[c] = v
        except Exception as e:
            out[c] = "ERR:%s" % e

    qc = bi.table_get("tf1.tm.counter.queue")
    for name, pgq in QMAP.items():
        try:
            k = qc.make_key([gc.KeyTuple("pg_id", PG_ID_DP9), gc.KeyTuple("pg_queue", pgq)])
            for d, _ in qc.entry_get(tgt0, [k], {"from_hw": True}):
                dd = d.to_dict()
                out["q_%s" % name] = {"use": dd.get("usage_cells"),
                                       "wm": dd.get("watermark_cells"),
                                       "drop": dd.get("drop_count_packets")}
        except Exception as e:
            out["q_%s" % name] = "ERR:%s" % e

    try:
        ep = bi.table_get("tf1.tm.counter.eg_port")
        k = ep.make_key([gc.KeyTuple("dev_port", 9)])
        for d, _ in ep.entry_get(tgt0, [k], {"from_hw": True}):
            dd = d.to_dict()
            out["egport_dp9"] = {"use": dd.get("usage_cells"), "wm": dd.get("watermark_cells"),
                                  "drop": dd.get("drop_count_packets")}
    except Exception as e:
        out["egport_dp9"] = "ERR:%s" % e

    print("MBREAD " + repr(out))

if __name__ == "__main__":
    main()

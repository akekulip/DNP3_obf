#!/usr/bin/env python3
"""
shadow_read_counters.py — read the shadow classifier's on-switch telemetry via bfrt and print
JSON. Runs ON THE SWITCH (SDE python), bound to the dnp3_shadow program. Read-only: it syncs and
reads counters/registers/port state; it never writes classification state.

Emits:
  class_counts   : per-class packet Counter (pipe.ShadowIngress.class_ctr), synced from HW
  shadow_enable  : reg_shadow_enable[0] (measurement A/B gate)
  ports          : dp8/dp9 $PORT status ($PORT_UP/$SPEED/$FEC/$PORT_ENABLE)
  port_stats     : dp8/dp9 $PORT_STAT (RX/TX frame counters, dropped, errors)
Usage:  python3.8 shadow_read_counters.py            # after the replay, to snapshot telemetry
"""
import sys, json

SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE_PY + "/tofino"); sys.path.insert(0, SDE_PY)
import bfrt_grpc.client as gc

PROG = "dnp3_shadow"
PORT_VISION, PORT_HULK = 8, 9
CLASS_NAMES = {0: "NON_DNP3", 1: "DNP3_READ", 2: "PURE_ACK", 3: "DNP3_RESP",
               4: "TCP_FIN", 5: "TCP_RST", 6: "LINK_OTHER", 7: "MALFORMED"}


def main():
    out = {"program": PROG}
    iface = gc.ClientInterface("localhost:50052", client_id=7, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi = iface.bfrt_info_get(PROG)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    # ---- per-class packet counter (sync from HW first) ----
    try:
        ctr = bi.table_get("pipe.ShadowIngress.class_ctr")
        try:
            ctr.operations_execute(tgt, "SyncCounters")
        except Exception as e:
            out["counter_sync_warning"] = str(e)
        counts = {}
        for idx in range(8):
            k = ctr.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])
            for d, _ in ctr.entry_get(tgt, [k], {"from_hw": False}):
                dd = d.to_dict()
                pkts = dd.get("$COUNTER_SPEC_PKTS", 0)
                counts["%d_%s" % (idx, CLASS_NAMES[idx])] = pkts
        out["class_counts"] = counts
    except Exception as e:
        out["class_counts_error"] = str(e)

    # ---- measurement A/B gate ----
    try:
        reg = bi.table_get("pipe.ShadowIngress.reg_shadow_enable")
        for d, _ in reg.entry_get(tgt, [reg.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])], {"from_hw": True}):
            out["shadow_enable"] = d.to_dict()
    except Exception as e:
        out["shadow_enable_error"] = str(e)

    # ---- port status + stats for dp8/dp9 ----
    ports = {}; pstats = {}
    try:
        pt = bi.table_get("$PORT")
        for dp in (PORT_VISION, PORT_HULK):
            try:
                for d, _ in pt.entry_get(tgt, [pt.make_key([gc.KeyTuple("$DEV_PORT", dp)])], {"from_hw": False}):
                    dd = d.to_dict()
                    ports["dp%d" % dp] = {kk: dd.get(kk) for kk in
                                          ("$PORT_UP", "$SPEED", "$FEC", "$PORT_ENABLE", "$LOOPBACK_MODE")}
            except Exception as e:
                ports["dp%d" % dp] = {"error": str(e)}
        out["ports"] = ports
    except Exception as e:
        out["ports_error"] = str(e)
    try:
        ps = bi.table_get("$PORT_STAT")
        for dp in (PORT_VISION, PORT_HULK):
            try:
                for d, _ in ps.entry_get(tgt, [ps.make_key([gc.KeyTuple("$DEV_PORT", dp)])], {"from_hw": True}):
                    dd = d.to_dict()
                    pstats["dp%d" % dp] = {kk: dd.get(kk) for kk in dd
                                           if any(t in kk for t in ("Frames", "Octets", "Drop", "Error", "Discard"))}
            except Exception as e:
                pstats["dp%d" % dp] = {"error": str(e)}
        out["port_stats"] = pstats
    except Exception as e:
        out["port_stats_error"] = str(e)

    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()

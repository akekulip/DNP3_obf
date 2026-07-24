#!/usr/bin/env python3
"""lane_probe.py — temporary link-layer probe for ANY switch lane/dev_port, for the on-site
substitution tests. Runs on the CURRENTLY LOADED program (default queue_microbench); touches only
the $PORT manager for one dev_port at the verified 25 G RS-FEC config. No shadow, no traffic.

Usage:  python3.8 lane_probe.py <baseline|add|read|remove> <dev_port> [program]
  e.g.  python3.8 lane_probe.py add 9         # enable dp9 (lane 15/1) at 25G RS AN
        python3.8 lane_probe.py read 9
        python3.8 lane_probe.py remove 9
Always `remove` after each test to restore the empty microbench $PORT.
"""
import sys, json
SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE_PY + "/tofino"); sys.path.insert(0, SDE_PY)
import bfrt_grpc.client as gc

cmd = sys.argv[1]
DP = int(sys.argv[2])
PROG = sys.argv[3] if len(sys.argv) > 3 else "queue_microbench"
i = gc.ClientInterface("localhost:50052", client_id=22, device_id=0, notifications=None)
i.bind_pipeline_config(PROG)
bi = i.bfrt_info_get(PROG); tgt = gc.Target(device_id=0, pipe_id=0xffff)
pt = bi.table_get("$PORT")

def pstate(dp):
    try:
        for d, _ in pt.entry_get(tgt, [pt.make_key([gc.KeyTuple("$DEV_PORT", dp)])], {"from_hw": False}):
            dd = d.to_dict()
            return {k: dd.get(k) for k in ("$PORT_UP","$SPEED","$FEC","$PORT_ENABLE","$LOOPBACK_MODE","$RX_PRSNT","$RX_SIG_OK")}
    except Exception as e:
        return {"absent_or_err": str(e)}

def list_ports():
    out = []
    try:
        for d, k in pt.entry_get(tgt, [], {"from_hw": False}):
            out.append(k.to_dict().get("$DEV_PORT"))
    except Exception as e:
        out = ["scan_err:" + str(e)]
    return out

if cmd == "baseline":
    print(json.dumps({"program": PROG, "configured_ports": list_ports(), "dp%d" % DP: pstate(DP)}, indent=1, default=str))
elif cmd == "add":
    st = pstate(DP)
    if not st.get("absent_or_err"):
        print(json.dumps({"STOP": "dp%d already present in $PORT (conflict)" % DP, "dp%d" % DP: st})); sys.exit(2)
    d = [pt.make_data([gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                       gc.DataTuple("$FEC", str_val="BF_FEC_TYP_RS"),
                       gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
                       gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_NONE"),
                       gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
    pt.entry_add(tgt, [pt.make_key([gc.KeyTuple("$DEV_PORT", DP)])], d)
    print(json.dumps({"added": "dp%d 25G RS PM_AN_DEFAULT LPBK_NONE ENABLE" % DP,
                      "other_ports_after_add": list_ports()}, indent=1, default=str))
elif cmd == "read":
    out = {"dp%d" % DP: pstate(DP)}
    try:
        ps = bi.table_get("$PORT_STAT")
        for d, _ in ps.entry_get(tgt, [ps.make_key([gc.KeyTuple("$DEV_PORT", DP)])], {"from_hw": True}):
            dd = d.to_dict()
            out["stats"] = {k: dd.get(k) for k in dd
                if any(t in k.lower() for t in ("frames","error","drop","fec","signal","fault","pcs","align"))}
    except Exception as e:
        out["stats_err"] = str(e)
    print(json.dumps(out, indent=1, default=str))
elif cmd == "remove":
    err = None
    try:
        pt.entry_del(tgt, [pt.make_key([gc.KeyTuple("$DEV_PORT", DP)])])
    except Exception as e:
        err = str(e)
    print(json.dumps({"del_err": err, "dp%d_after_remove" % DP: pstate(DP), "configured_ports": list_ports()}, indent=1, default=str))

#!/usr/bin/env python3
"""Read-only $PORT inventory: dump every configured dev_port + fields. NO WRITES."""
import sys
import bfrt_grpc.client as gc

PROGRAM = "defense4_rrc_bor_unified12"
GRPC = "localhost:50052"

iface = gc.ClientInterface(grpc_addr=GRPC, client_id=99, device_id=0)
iface.bind_pipeline_config(PROGRAM)
bi = iface.bfrt_info_get(PROGRAM)
tdev = gc.Target(device_id=0, pipe_id=0xffff)

port = bi.table_get("$PORT")
rows = []
for d, k in port.entry_get(tdev, [], {"from_hw": False}):
    kd = k.to_dict(); dd = d.to_dict()
    dp = kd["$DEV_PORT"]["value"]
    rows.append((dp, dd.get("$SPEED"), dd.get("$PORT_UP",{}) if isinstance(dd.get("$PORT_UP"),dict) else dd.get("$PORT_UP"),
                 dd.get("$PORT_ENABLE"), dd.get("$LOOPBACK_MODE"), dd.get("$FEC")))
rows.sort()
print("=== configured $PORT entries (dev_port, speed, up, enable, loopback, fec) ===")
for r in rows:
    dp = r[0]; pipe = dp >> 7; local = dp & 0x7f
    print("dp%-3d pipe%d local%-3d  speed=%s up=%s en=%s lpbk=%s fec=%s" %
          (dp, pipe, local, r[1], r[2], r[3], r[4], r[5]))
cfg = sorted(dp for (dp,*_) in rows)
print("\nconfigured dev_ports:", cfg)
# pipe-0 dev_ports currently configured
p0 = [dp for dp in cfg if (dp>>7)==0]
print("pipe-0 configured:", p0)
try:
    iface._tear_down_stream()
except Exception:
    pass

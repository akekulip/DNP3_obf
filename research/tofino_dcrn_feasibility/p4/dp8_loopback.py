#!/usr/bin/env python3.8
"""dp8_loopback.py — put dp8 (the powered-off Vision leg) into MAC-near loopback.

Single-host DCRN end-to-end test helper (switch + Hulk only, Vision off): dp8 becomes a
hairpin so a frame DCRN forwards to dp8 loops straight back into dp8 ingress. The request
then ARMs on the dp8/dir0 pass and the response is HELD on its dp9/dir1 pass — a full
request->response round trip with DCRN's hold, all returning to Hulk.

Run AFTER dcrn_setup.py each reload (dcrn_setup re-creates dp8 as BF_LPBK_NONE). Deletes and
re-adds dp8 with the loopback set at creation (mode changes on a live entry are often rejected);
forces FEC none / AN off since dp8 has no live link partner. Grounded in dcrn_setup.py's own
bfrt idiom.
"""
import sys
SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE_PY + "/tofino")
sys.path.insert(0, SDE_PY)
import bfrt_grpc.client as gc

DP8 = 8

iface = gc.ClientInterface("localhost:50052", client_id=3, device_id=0, notifications=None)
iface.bind_pipeline_config("dcrn")
bi  = iface.bfrt_info_get("dcrn")
tgt = gc.Target(device_id=0, pipe_id=0xffff)
port = bi.table_get("$PORT")

key = [port.make_key([gc.KeyTuple("$DEV_PORT", DP8)])]
try:
    port.entry_del(tgt, key)          # remove the NONE-loopback entry dcrn_setup added
except Exception:
    pass
data = [port.make_data([
    gc.DataTuple("$SPEED",            str_val="BF_SPEED_25G"),
    gc.DataTuple("$FEC",              str_val="BF_FEC_TYP_NONE"),
    gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
    gc.DataTuple("$LOOPBACK_MODE",    str_val="BF_LPBK_MAC_NEAR"),
    gc.DataTuple("$PORT_ENABLE",      bool_val=True)])]
port.entry_add(tgt, key, data)
print("dp8 -> BF_LPBK_MAC_NEAR, enabled (FEC none, AN off)")

try:
    for d, k in port.entry_get(tgt, key, {"from_hw": True}):
        dd = d.to_dict()
        print("dp8 status: PORT_UP=%s ENABLE=%s SPEED=%s LOOPBACK=%s"
              % (dd.get("$PORT_UP"), dd.get("$PORT_ENABLE"), dd.get("$SPEED"), dd.get("$LOOPBACK_MODE")))
except Exception as e:
    print("status read skipped:", type(e).__name__, str(e)[:60])

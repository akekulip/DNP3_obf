#!/usr/bin/env python3
"""Replay the $PORT table of a saved snapshot after a cold start. Runs on the switch host.

Writes only $PORT entries (speed, FEC, auto-negotiation, enable), exactly the attributes the snapshot recorded; a port that already exists
is left alone. Usage: restore_ports.py PROGRAM SNAPSHOT.json[.gz] [--apply]   (without --apply it only prints what it would do)"""
import argparse
import gzip
import json
import os
import sys
import time

sde = os.environ.get("SDE_INSTALL", "/home/decps/Downloads/bf-sde-9.13.2/install")
sys.path.insert(0, sde + "/lib/python3.8/site-packages/tofino")
import bfrt_grpc.client as gc  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("program")
ap.add_argument("snapshot")
ap.add_argument("--apply", action="store_true")
ap.add_argument("--wait", type=float, default=30.0)
a = ap.parse_args()
opener = gzip.open if a.snapshot.endswith(".gz") else open
snap = json.load(opener(a.snapshot, "rt"))
spec = {}
for e in snap["tables"]["$PORT"]["entries"]:
    d = e["data"]
    if d.get("$PORT_ENABLE"):
        spec[e["key"]["$DEV_PORT"]["value"]] = (d["$SPEED"], d["$FEC"], d["$AUTO_NEGOTIATION"])
print("snapshot ports to restore:", len(spec), sorted(spec))
iface = gc.ClientInterface("localhost:50052", client_id=111, device_id=0)
try:
    iface.bind_pipeline_config(a.program)
    bi = iface.bfrt_info_get(a.program)
    t = bi.table_get("$PORT")
    tdev = gc.Target(device_id=0, pipe_id=0xffff)
    for dp, (speed, fec, an) in sorted(spec.items()):
        key = [t.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
        exists = False
        try:
            exists = any(True for _ in t.entry_get(tdev, key, {"from_hw": False}))
        except Exception:
            pass
        if exists:
            print("dp%d exists, left alone" % dp)
            continue
        print("dp%d %s %s %s" % (dp, speed, fec, an), "ADD" if a.apply else "(dry run)")
        if a.apply:
            t.entry_add(tdev, key, [t.make_data([gc.DataTuple("$SPEED", str_val=speed), gc.DataTuple("$FEC", str_val=fec),
                                                 gc.DataTuple("$AUTO_NEGOTIATION", str_val=an), gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
    if a.apply:
        time.sleep(a.wait)
    for dp in sorted(spec):
        for r, _ in t.entry_get(tdev, [t.make_key([gc.KeyTuple("$DEV_PORT", dp)])], {"from_hw": True}):
            x = r.to_dict()
            if x.get("$PORT_UP") or dp in (8, 9, 10, 11, 64):
                print("dp%d enable=%s up=%s speed=%s" % (dp, x.get("$PORT_ENABLE"), x.get("$PORT_UP"), x.get("$SPEED")))
finally:
    iface.tear_down_stream()

#!/usr/bin/env python3
"""Read-only snapshot of every table of the loaded program, including traffic-manager, replication, mirror and packet-generator state.

Runs on the switch host (needs bfrt_grpc). It only calls entry_get and default_entry_get; it never writes, loads or restarts anything.
Usage: live_snapshot.py PROGRAM_NAME OUT.json
"""
import argparse
import json
import os
import sys
import time

sde = os.environ.get("SDE_INSTALL", "/home/decps/Downloads/bf-sde-9.13.2/install")
sys.path.insert(0, sde + "/lib/python3.8/site-packages/tofino")
import bfrt_grpc.client as gc  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("program")
ap.add_argument("output")
a = ap.parse_args()
client = gc.ClientInterface("localhost:50052", client_id=110, device_id=0)
result = {"program": a.program, "time_ns": time.time_ns(), "read_only": True, "tables": {}, "errors": {}}
try:
    client.bind_pipeline_config(a.program)
    bi = client.bfrt_info_get(a.program)
    target = gc.Target(device_id=0, pipe_id=0xffff)
    for name in sorted(bi.table_dict):
        table = bi.table_get(name)
        item = {}
        try:
            item["entries"] = [{"key": k.to_dict() if k else None, "data": d.to_dict() if d else None}
                               for d, k in table.entry_get(target, flags={"from_hw": False})]
        except Exception as exc:                      # many fixed-function tables refuse a bulk read; keep the reason
            item["entries_error"] = str(exc)[:200]
        try:
            item["default"] = [d.to_dict() for d, _ in table.default_entry_get(target, flags={"from_hw": False}) if d]
        except Exception as exc:
            item["default_error"] = str(exc)[:200]
        result["tables"][name] = item
finally:
    client.tear_down_stream()
with open(a.output, "w") as out:
    json.dump(result, out, indent=1, default=lambda v: v.hex() if isinstance(v, bytes) else str(v))
print("tables:", len(result["tables"]), "->", a.output)

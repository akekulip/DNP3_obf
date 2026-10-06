#!/usr/bin/env python3
"""Read-only snapshot of a program's tables and relevant fixed-function state."""
import argparse
import json
import os
import sys
import time

sde = os.environ.get("SDE_INSTALL", "/home/decps/Downloads/bf-sde-9.13.2/install")
sys.path.insert(0, sde + "/lib/python3.8/site-packages/tofino")
import bfrt_grpc.client as gc

p = argparse.ArgumentParser()
p.add_argument("program")
p.add_argument("output")
a = p.parse_args()
client = gc.ClientInterface("localhost:50052", client_id=109, device_id=0)
result = {"program": a.program, "time_ns": time.time_ns(), "tables": {}}
try:
    client.bind_pipeline_config(a.program)
    bi = client.bfrt_info_get(a.program)
    target = gc.Target(device_id=0, pipe_id=0xffff)
    names = sorted(n for n in bi.table_dict if n.startswith("pipe.") or n in (
        "$PORT", "$mirror.cfg", "$PKTGEN_APPLICATION_CFG", "pktgen.app_cfg"))
    for name in names:
        table = bi.table_get(name)
        item = {}
        try:
            item["entries"] = [{"key": key.to_dict() if key else None,
                                "data": data.to_dict()}
                               for data, key in table.entry_get(target, flags={"from_hw": False})]
        except Exception as exc:
            item["entries_error"] = str(exc)
        try:
            item["default"] = [data.to_dict() for data, _ in
                               table.default_entry_get(target, flags={"from_hw": False})]
        except Exception as exc:
            item["default_error"] = str(exc)
        result["tables"][name] = item
finally:
    client.tear_down_stream()
with open(a.output, "w") as out:
    json.dump(result, out, indent=2, default=lambda v: v.hex() if isinstance(v, bytes) else str(v))
print("Snapshot:", a.program, len(result["tables"]), "tables", a.output)
for name, item in result["tables"].items():
    if name == "$PORT":
        for entry in item.get("entries", []):
            d = entry["data"]
            print(entry["key"], {k: d.get(k) for k in ("$SPEED", "$PORT_UP", "$PORT_ENABLE", "$LOOPBACK_MODE")})

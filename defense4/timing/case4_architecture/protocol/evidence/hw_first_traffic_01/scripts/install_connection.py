#!/usr/bin/env python3
"""Install one case4_response_path connection slot via response_path_cp.py's Registry,
backed by real BFRT writes. Runs on the switch host."""
import os
import sys

sde = os.environ.get("SDE_INSTALL", "/home/decps/Downloads/bf-sde-9.13.2/install")
sys.path.insert(0, sde + "/lib/python3.8/site-packages/tofino")
sys.path.insert(0, "/tmp")
import bfrt_grpc.client as gc  # noqa: E402
from response_path_cp import Registry, Endpoint  # noqa: E402

PROGRAM = "case4_response_path"
iface = gc.ClientInterface("localhost:50052", client_id=115, device_id=0)
iface.bind_pipeline_config(PROGRAM)
bi = iface.bfrt_info_get(PROGRAM)
target = gc.Target(device_id=0, pipe_id=0xffff)


def add(table, key_dict, action, data_dict):
    t = bi.table_get(table)
    key = t.make_key([gc.KeyTuple(k, v) for k, v in key_dict.items()])
    data = t.make_data([gc.DataTuple(k, v) for k, v in data_dict.items()], action)
    t.entry_add(target, [key], [data])
    print("ADD", table, key_dict, action, data_dict)


def delete(table, key_dict):
    t = bi.table_get(table)
    key = t.make_key([gc.KeyTuple(k, v) for k, v in key_dict.items()])
    t.entry_del(target, [key])
    print("DEL", table, key_dict)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--master-ip", required=True)
    ap.add_argument("--master-port", type=int, required=True)
    ap.add_argument("--master-dev-port", type=int, required=True)
    ap.add_argument("--outstation-ip", required=True)
    ap.add_argument("--outstation-port", type=int, required=True)
    ap.add_argument("--outstation-dev-port", type=int, required=True)
    ap.add_argument("--slot", type=int, default=0)
    a = ap.parse_args()

    reg = Registry()
    master = Endpoint(ip=a.master_ip, port=a.master_port, dev_port=a.master_dev_port)
    outstation = Endpoint(ip=a.outstation_ip, port=a.outstation_port, dev_port=a.outstation_dev_port)
    try:
        rows = reg.install(a.slot, outstation, master, add, delete, pad_enable=True)
        print("installed", len(rows), "rows for slot", a.slot)
    finally:
        iface.tear_down_stream()

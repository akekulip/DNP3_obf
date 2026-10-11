#!/usr/bin/env python3
"""Set connection slot 0 of case4_response_path on the switch. Runs on the switch host.

  switch_slot.py vepa --master-port P [--enable 0|1] [--no-forwarding]
  switch_slot.py relay

Clears Egress.conn, Egress.odd_ip_t and Ingress.forwarding, then installs one slot through
response_path_cp.Registry (deployed next to this file). `vepa` is the software endpoint pair that
shares dev_port 9 (master 192.168.10.61:P, outstation 192.168.10.62:20000); `relay` is the rig's
normal slot (Vision 192.168.10.1:54321, SEL-751 192.168.10.7:20000, dev_ports 9 and 64).
--enable 0 writes the padding policy off: the transport mapper still arms and translates.
--no-forwarding leaves Ingress.forwarding empty (the forwarding-off control).
Prints the three tables read back from hardware as one JSON line."""
import argparse
import json
import os
import sys

sde = os.environ.get('SDE_INSTALL', '/home/decps/Downloads/bf-sde-9.13.2/install')
sys.path.insert(0, sde + '/lib/python3.8/site-packages/tofino')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bfrt_grpc.client as gc  # noqa: E402
from response_path_cp import Registry, Endpoint  # noqa: E402

PROGRAM = 'case4_response_path'
TABLES = ('Egress.conn', 'Egress.odd_ip_t', 'Ingress.forwarding')

ap = argparse.ArgumentParser()
ap.add_argument('which', choices=('vepa', 'relay'))
ap.add_argument('--master-port', type=int)
ap.add_argument('--enable', type=int, choices=(0, 1), default=1)
ap.add_argument('--no-forwarding', action='store_true')
a = ap.parse_args()
if a.which == 'vepa':
    if a.master_port is None:
        ap.error('vepa needs --master-port')
    outstation, master = Endpoint('192.168.10.62', 20000, 9), Endpoint('192.168.10.61', a.master_port, 9)
else:
    outstation, master = Endpoint('192.168.10.7', 20000, 64), Endpoint('192.168.10.1', 54321, 9)

iface = gc.ClientInterface('localhost:50052', client_id=125, device_id=0)
try:
    iface.bind_pipeline_config(PROGRAM)
    bi = iface.bfrt_info_get(PROGRAM)
    tg = gc.Target(device_id=0, pipe_id=0xffff)

    def table(name):
        return bi.table_get('pipe.' + name)

    def add(name, key, action, data):
        t = table(name)
        t.entry_add(tg, [t.make_key([gc.KeyTuple(k, v) for k, v in key.items()])],
                    [t.make_data([gc.DataTuple(k, v) for k, v in data.items()], action)])

    def delete(name, key):
        t = table(name)
        t.entry_del(tg, [t.make_key([gc.KeyTuple(k, v) for k, v in key.items()])])

    for name in TABLES:
        t = table(name)
        keys = [k for _, k in t.entry_get(tg, flags={'from_hw': False})]
        if keys:
            t.entry_del(tg, keys)
    rows = Registry().plan(0, outstation, master, pad_enable=bool(a.enable))
    for r in rows:
        if a.no_forwarding and r.table == 'Ingress.forwarding':
            continue
        add(r.table, r.key_dict, r.action, r.data_dict)
    out = {'which': a.which, 'master_port': master.port, 'enable': a.enable, 'no_forwarding': a.no_forwarding}
    for name in TABLES:
        out[name] = [{'key': {k: v['value'] for k, v in key.to_dict().items()},
                      'data': {k: v for k, v in data.to_dict().items() if k != 'is_default_entry'}}
                     for data, key in table(name).entry_get(tg, flags={'from_hw': True})]
    print(json.dumps(out))
finally:
    iface.tear_down_stream()

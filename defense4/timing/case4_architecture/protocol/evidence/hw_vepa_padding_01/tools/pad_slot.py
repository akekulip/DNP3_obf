"""Swap connection slot 0 of case4_response_path between the relay tuple and the VEPA endpoint tuple.
Usage: pad_slot.py {relay|vepa} {install|remove}   Uses response_path_cp (deployed copy in /tmp)."""
import sys
SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE + '/lib/python3.8/site-packages/tofino'); sys.path.insert(0, '/tmp')
import bfrt_grpc.client as gc
from response_path_cp import Registry, Endpoint
which, op = sys.argv[1], sys.argv[2]
EP = {'relay': (Endpoint('192.168.10.7', 20000, 64), Endpoint('192.168.10.1', 54321, 9)),
      'vepa': (Endpoint('192.168.10.62', 20000, 9), Endpoint('192.168.10.61', 54400, 9))}
o, m = EP[which]
iface = gc.ClientInterface('localhost:50052', client_id=125, device_id=0)
iface.bind_pipeline_config('case4_response_path')
bi = iface.bfrt_info_get('case4_response_path')
tg = gc.Target(device_id=0, pipe_id=0xffff)
def add(table, key, action, data):
    t = bi.table_get('pipe.' + table)
    t.entry_add(tg, [t.make_key([gc.KeyTuple(k, v) for k, v in key.items()])], [t.make_data([gc.DataTuple(k, v) for k, v in data.items()], action)])
    print('ADD', table, key, action, data)
def delete(table, key):
    t = bi.table_get('pipe.' + table)
    t.entry_del(tg, [t.make_key([gc.KeyTuple(k, v) for k, v in key.items()])]); print('DEL', table, key)
reg = Registry()
try:
    if op == 'install':
        print(len(reg.install(0, o, m, add, delete, pad_enable=True)), 'rows installed for', which)
    else:   # rebuild the registry's view, then retire; the caller asserts the connection is closed
        for r in reg.plan(0, o, m, True): delete(r.table, r.key_dict)
finally:
    iface.tear_down_stream()

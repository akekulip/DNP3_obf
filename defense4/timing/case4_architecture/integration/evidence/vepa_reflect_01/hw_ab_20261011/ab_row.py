import sys
SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE + '/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc
op, mac = sys.argv[1], int(sys.argv[2], 16)
iface = gc.ClientInterface('localhost:50052', client_id=123, device_id=0)
iface.bind_pipeline_config('xpipe_reflect_probe')
bi = iface.bfrt_info_get('xpipe_reflect_probe')
tg = gc.Target(device_id=0, pipe_id=0xffff)
t = bi.table_get('pipe.Ingress.fwd_mac')
k = t.make_key([gc.KeyTuple('ig.ingress_port', 9), gc.KeyTuple('hdr.eth.dst', mac)])
if op == 'del':
    t.entry_del(tg, [k])
else:
    t.entry_add(tg, [k], [t.make_data([gc.DataTuple('port', 9), gc.DataTuple('do_mir', 0), gc.DataTuple('sid', 0)], 'Ingress.go_reflect')])
print(op, hex(mac), 'rows now:', len(list(t.entry_get(tg, flags={'from_hw': True}))))
iface.tear_down_stream()

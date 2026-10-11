"""Controls for the VEPA slot. Usage: pad_ctl.py enable {0|1} | fwd {del|add}"""
import sys
SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE + '/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc
iface = gc.ClientInterface('localhost:50052', client_id=126, device_id=0)
iface.bind_pipeline_config('case4_response_path')
bi = iface.bfrt_info_get('case4_response_path')
tg = gc.Target(device_id=0, pipe_id=0xffff)
try:
    if sys.argv[1] == 'enable':
        t = bi.table_get('pipe.Egress.conn')
        k = t.make_key([gc.KeyTuple('hdr.ip.src', 0xC0A80A3E), gc.KeyTuple('hdr.ip.dst', 0xC0A80A3D),
                        gc.KeyTuple('hdr.tcp.sport', 20000), gc.KeyTuple('hdr.tcp.dport', 54400)])
        t.entry_mod(tg, [k], [t.make_data([gc.DataTuple('idx', 0), gc.DataTuple('enable', int(sys.argv[2]))], 'Egress.fwd_conn')])
        for d, kk in t.entry_get(tg, [k], {'from_hw': True}): print('fwd_conn now', d.to_dict())
    else:
        t = bi.table_get('pipe.Ingress.forwarding')
        k = t.make_key([gc.KeyTuple('ig.ingress_port', 9)])
        if sys.argv[2] == 'del': t.entry_del(tg, [k])
        else: t.entry_add(tg, [k], [t.make_data([gc.DataTuple('port', 9)], 'Ingress.route')])
        print('forwarding rows:', [(kk.to_dict(), d.to_dict()) for d, kk in t.entry_get(tg, flags={'from_hw': True})])
finally:
    iface.tear_down_stream()

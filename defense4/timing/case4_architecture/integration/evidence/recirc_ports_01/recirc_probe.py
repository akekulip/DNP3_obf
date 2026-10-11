"""Recirculation test with xpipe_reflect_probe. Usage: recirc_probe.py set PORT | read | lpbk PORT MODE
set PORT: fwd[9] -> PORT (through egress), fwd[PORT] -> 9. Any frame from dev 9 then returns only if PORT loops back."""
import sys, json
SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE + '/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc
iface = gc.ClientInterface('localhost:50052', client_id=128, device_id=0)
iface.bind_pipeline_config('xpipe_reflect_probe')
bi = iface.bfrt_info_get('xpipe_reflect_probe')
tg = gc.Target(device_id=0, pipe_id=0xffff)
try:
    if sys.argv[1] == 'set':
        port = int(sys.argv[2]); t = bi.table_get('pipe.Ingress.fwd')
        keys = [k for _, k in t.entry_get(tg, flags={'from_hw': False})]
        if keys: t.entry_del(tg, keys)
        for src, dst in ((9, port), (port, 9)):
            t.entry_add(tg, [t.make_key([gc.KeyTuple('ig.ingress_port', src)])],
                        [t.make_data([gc.DataTuple('port', dst), gc.DataTuple('do_mir', 0), gc.DataTuple('sid', 0)], 'Ingress.go_egress')])
        print('fwd 9 ->', port, '->', 9)
    elif sys.argv[1] == 'lpbk':
        t = bi.table_get('$PORT'); k = t.make_key([gc.KeyTuple('$DEV_PORT', int(sys.argv[2]))])
        t.entry_mod(tg, [k], [t.make_data([gc.DataTuple('$LOOPBACK_MODE', str_val=sys.argv[3])])])
        for d, _ in t.entry_get(tg, [k], {'from_hw': False}): print(sys.argv[2], d.to_dict().get('$LOOPBACK_MODE'))
    else:
        out = {}
        for name in ('pipe.Ingress.arr_ig', 'pipe.Egress.arr_eg'):
            t = bi.table_get(name); nz = {}
            for d, k in t.entry_get(tg, flags={'from_hw': True}):
                v = [x for a, x in d.to_dict().items() if a.endswith('.f1')][0]
                if any(v): nz[k.to_dict()['$REGISTER_INDEX']['value']] = v
            out[name.split('.')[-1]] = nz
        pt = bi.table_get('$PORT_STAT')
        for d, _ in pt.entry_get(tg, [pt.make_key([gc.KeyTuple('$DEV_PORT', 9)])], {'from_hw': True}):
            dd = d.to_dict(); out['dev9'] = {'rx': dd['$FramesReceivedOK'], 'tx': dd['$FramesTransmittedOK']}
        print(json.dumps(out))
finally:
    iface.tear_down_stream()

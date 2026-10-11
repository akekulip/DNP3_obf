import sys, json
SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE + '/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc
iface = gc.ClientInterface('localhost:50052', client_id=127, device_id=0)
iface.bind_pipeline_config('response_only')
bi = iface.bfrt_info_get('response_only')
tg = gc.Target(device_id=0, pipe_id=0xffff)
names = sorted(bi.table_dict)
if len(sys.argv) > 1 and sys.argv[1] == 'list':
    print([n for n in names if not n.startswith('$') and not n.startswith('tf1.')])
else:
    for n in names:
        t = bi.table_get(n)
        ty = t.info.type_get() if hasattr(t.info, 'type_get') else ''
        if 'COUNTER' in str(ty) and not n.startswith('tf1'):
            nz = {}
            for d, k in t.entry_get(tg, flags={'from_hw': True}):
                dd = d.to_dict(); v = dd.get('$COUNTER_SPEC_PKTS', 0)
                if v: nz[list(k.to_dict().values())[0]['value']] = v
            print(n, nz)
    pt = bi.table_get('$PORT')
    for dp in (68, 69, 70, 71, 196, 197, 198, 199):
        try:
            for d, k in pt.entry_get(tg, [pt.make_key([gc.KeyTuple('$DEV_PORT', dp)])], {'from_hw': False}):
                dd = d.to_dict(); print('port', dp, {x: dd.get(x) for x in ('$PORT_ENABLE', '$PORT_UP', '$LOOPBACK_MODE', '$SPEED', '$IS_VALID')})
        except Exception as e:
            print('port', dp, 'ERR', str(e).replace('\n', ' ')[:100])
iface.tear_down_stream()

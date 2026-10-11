import sys, json
SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE + '/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc
iface = gc.ClientInterface('localhost:50052', client_id=122, device_id=0)
iface.bind_pipeline_config('xpipe_reflect_probe')
bi = iface.bfrt_info_get('xpipe_reflect_probe')
tg = gc.Target(device_id=0, pipe_id=0xffff)
out = {}
for name in ['pipe.Ingress.arr_ig', 'pipe.Egress.arr_eg']:
    t = bi.table_get(name)
    for d, k in t.entry_get(tg, [t.make_key([gc.KeyTuple('$REGISTER_INDEX', 9)])], {'from_hw': True}):
        out[name] = d.to_dict()
pt = bi.table_get('$PORT_STAT')
for d, k in pt.entry_get(tg, [pt.make_key([gc.KeyTuple('$DEV_PORT', 9)])], {'from_hw': True}):
    dd = d.to_dict()
    out['port9'] = {k: v for k, v in dd.items() if k in ('$FramesReceivedAll', '$FramesTransmittedAll', '$FramesReceivedOK', '$FramesTransmittedOK', '$FramesTransmittedUnicast', '$FramesReceivedUnicast', '$FrameswithanyError', '$FramesDroppedBufferFull')}
print(json.dumps(out, default=str))
iface.tear_down_stream()

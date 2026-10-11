"""Read case4_response_path observability: outcome counter (all 32), slot-0 mapper registers, dev 9/64 port stats.
Usage: pad_counters.py [SLOT]   prints one JSON line. Read-only."""
import sys, json
SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE + '/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc
slot = int(sys.argv[1]) if len(sys.argv) > 1 else 0
P = 'case4_response_path'
iface = gc.ClientInterface('localhost:50052', client_id=124, device_id=0)
iface.bind_pipeline_config(P)
bi = iface.bfrt_info_get(P)
tg = gc.Target(device_id=0, pipe_id=0xffff)
out = {'outcome': {}, 'regs': {}, 'ports': {}}
t = bi.table_get('pipe.Egress.outcome')
for d, k in t.entry_get(tg, flags={'from_hw': True}):
    v = d.to_dict().get('$COUNTER_SPEC_PKTS', 0)
    if v: out['outcome'][k.to_dict()['$COUNTER_INDEX']['value']] = v
for r in ('mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend'):
    rt = bi.table_get('pipe.Egress.' + r)
    for d, k in rt.entry_get(tg, [rt.make_key([gc.KeyTuple('$REGISTER_INDEX', slot)])], {'from_hw': True}):
        out['regs'][r] = {kk: vv for kk, vv in d.to_dict().items() if kk.startswith('Egress.')}
pt = bi.table_get('$PORT_STAT')
for dp in (9, 64):
    for d, k in pt.entry_get(tg, [pt.make_key([gc.KeyTuple('$DEV_PORT', dp)])], {'from_hw': True}):
        dd = d.to_dict(); out['ports'][dp] = {'rx': dd['$FramesReceivedOK'], 'tx': dd['$FramesTransmittedOK']}
print(json.dumps(out, default=str))
iface.tear_down_stream()

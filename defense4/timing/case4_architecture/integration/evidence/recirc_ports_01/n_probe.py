import sys, json
SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE + '/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc
iface = gc.ClientInterface('localhost:50052', client_id=127, device_id=0)
iface.bind_pipeline_config('response_only')
bi = iface.bfrt_info_get('response_only')
tg = gc.Target(device_id=0, pipe_id=0xffff)
out = {}
for n in ('p0.n_Ingress.counter', 'p0.r_Egress.outcome', 'p1.t_Ingress.outcome_count', 'p1.t_Ingress.outcomes'):
    t = bi.table_get(n); nz = {}
    try:
        for d, k in t.entry_get(tg, flags={'from_hw': True}):
            dd = d.to_dict(); kv = list(k.to_dict().values())[0]['value']
            v = dd.get('$COUNTER_SPEC_PKTS')
            if v is None:
                v = [x for a, x in dd.items() if a.endswith('.f1')]
                v = v[0] if v else None
                v = v if (v and any(v)) else 0
            if v: nz[kv] = v
    except Exception as e:
        nz = 'ERR ' + str(e).replace('\n', ' ')[:120]
    out[n] = nz
print(json.dumps(out))
iface.tear_down_stream()

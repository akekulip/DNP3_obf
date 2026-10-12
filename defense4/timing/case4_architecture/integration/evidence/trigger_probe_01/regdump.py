import sys, json
SDE='/home/decps/Downloads/bf-sde-9.13.2/install'
sys.path.insert(0, SDE+'/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc
iface=gc.ClientInterface('localhost:50052',client_id=141,device_id=0)
iface.bind_pipeline_config('response_only')
bi=iface.bfrt_info_get('response_only')
tg=gc.Target(device_id=0,pipe_id=0xffff)
out={}
for n in ('gen_alloc_reg','op_gen_alloc_reg','cur_epoch_reg','ack_commit_gen_reg','op_done_reg','resp_done_reg','quarantine_reg','t0_reg','op_t0_reg','ack_done_reg'):
    try:
        t=bi.table_get('p1.t_Ingress.'+n); vals=[]
        for d,k in t.entry_get(tg,flags={'from_hw':True}):
            dd=d.to_dict(); v=[x for a,x in dd.items() if a.endswith('.f1')]
            v=v[0] if v else None
            vals.append(v)
        flat=[]
        for v in vals:
            flat.extend(v if isinstance(v,list) else [v])
        nz=[x for x in flat if x not in (0,4294967295,None)]
        out[n]={'n':len(flat),'nonzero_sample':nz[:6],'max':max(flat) if flat else None,'min':min(flat) if flat else None}
    except Exception as e:
        out[n]='ERR '+str(e).replace('\n',' ')[:80]
print(json.dumps(out))
iface.tear_down_stream()

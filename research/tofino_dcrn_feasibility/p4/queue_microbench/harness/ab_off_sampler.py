import sys, time, json
SDE="/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0,SDE+"/tofino"); sys.path.insert(0,SDE)
import bfrt_grpc.client as gc
N=int(sys.argv[1]); secs=float(sys.argv[2])
i=gc.ClientInterface("localhost:50052",client_id=17,device_id=0,notifications=None)
i.bind_pipeline_config("queue_microbench"); bi=i.bfrt_info_get("queue_microbench")
t=gc.Target(device_id=0,pipe_id=0xffff)
cg=bi.table_get("pipe.Ingress.ctr_grad"); lh=bi.table_get("pipe.Ingress.last_hold_reg")
ck=[cg.make_key([gc.KeyTuple("$COUNTER_INDEX",0)])]; lk=[lh.make_key([gc.KeyTuple("$REGISTER_INDEX",0)])]
def rd():
    g=0
    for d,_ in cg.entry_get(t,ck,{"from_hw":True}): g=d.to_dict().get("$COUNTER_SPEC_PKTS",0)
    h=0
    for d,_ in lh.entry_get(t,lk,{"from_hw":True}):
        v=d.to_dict().get("Ingress.last_hold_reg.f1"); h=max(v) if isinstance(v,list) else v
    return g,h
holds=[]; pg,_=rd(); t_end=time.time()+secs
while len(holds)<N and time.time()<t_end:
    g,h=rd()
    if g>pg:
        holds.append(h/1e6)   # ms
        pg=g
    time.sleep(0.03)
holds.sort()
def pct(x,p):
    if not x: return float('nan')
    k=(len(x)-1)*p/100.0; lo=int(k); hi=min(lo+1,len(x)-1); return x[lo]+(x[hi]-x[lo])*(k-lo)
import statistics as st
print(json.dumps({"n":len(holds),"p50":round(pct(holds,50),4),"p95":round(pct(holds,95),4),
   "p99":round(pct(holds,99),4),"mean":round(st.mean(holds),4) if holds else 0,
   "std":round(st.pstdev(holds),4) if len(holds)>1 else 0,
   "min":round(min(holds),4) if holds else 0,"max":round(max(holds),4) if holds else 0}))

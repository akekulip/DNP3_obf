import sys
SDE="/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0,SDE+"/tofino"); sys.path.insert(0,SDE)
import bfrt_grpc.client as gc
i=gc.ClientInterface("localhost:50052",client_id=int(sys.argv[1]),device_id=0,notifications=None)
i.bind_pipeline_config("queue_microbench"); bi=i.bfrt_info_get("queue_microbench")
r=bi.table_get("pipe.Ingress.last_hold_reg"); t=gc.Target(device_id=0,pipe_id=0xffff)
for d,_ in r.entry_get(t,[r.make_key([gc.KeyTuple("$REGISTER_INDEX",0)])],{"from_hw":True}):
    v=d.to_dict().get("Ingress.last_hold_reg.f1"); print(max(v) if isinstance(v,list) else v)

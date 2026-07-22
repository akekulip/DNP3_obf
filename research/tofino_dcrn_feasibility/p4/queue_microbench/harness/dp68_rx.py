import sys
SDE="/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0,SDE+"/tofino"); sys.path.insert(0,SDE)
import bfrt_grpc.client as gc
i=gc.ClientInterface("localhost:50052",client_id=int(sys.argv[1]),device_id=0,notifications=None)
i.bind_pipeline_config("queue_microbench"); bi=i.bfrt_info_get("queue_microbench")
t=gc.Target(device_id=0,pipe_id=0xffff)
ps=bi.table_get("$PORT_STAT")
for d,_ in ps.entry_get(t,[ps.make_key([gc.KeyTuple("$DEV_PORT",68)])],{"from_hw":True}):
    print(d.to_dict().get("$FramesReceivedOK",0))

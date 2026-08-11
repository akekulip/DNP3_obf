import sys
sys.path.insert(0,"/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino")
sys.path.insert(0,"/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages")
import bfrt_grpc.client as gc
iface=gc.ClientInterface("localhost:50052",client_id=88,device_id=0); iface.bind_pipeline_config("defense4_timing")
bi=iface.bfrt_info_get("defense4_timing"); tgt=gc.Target(device_id=0,pipe_id=0xffff)
tp=bi.table_get("Ingress.tbl_params")
ROLE_ARM,ROLE_RESP,ROLE_ACK=6,2,7; DIR_MASTER,DIR_OUT=0,1
MODE_D4,D_A,D_R=4,4,10
entries=[(ROLE_ARM,DIR_MASTER),(ROLE_ACK,DIR_OUT),(ROLE_RESP,DIR_OUT)]
for role,dr in entries:
    try:
        tp.entry_add(tgt,[tp.make_key([gc.KeyTuple("m.role",role),gc.KeyTuple("m.dir",dr)])],
            [tp.make_data([gc.DataTuple("mode",MODE_D4),gc.DataTuple("d_a",D_A),gc.DataTuple("d_r",D_R)],"Ingress.set_params")])
    except Exception as e:
        # entry may exist -> mod
        try: tp.entry_mod(tgt,[tp.make_key([gc.KeyTuple("m.role",role),gc.KeyTuple("m.dir",dr)])],
            [tp.make_data([gc.DataTuple("mode",MODE_D4),gc.DataTuple("d_a",D_A),gc.DataTuple("d_r",D_R)],"Ingress.set_params")])
        except Exception as e2: print("  write",(role,dr),"err",repr(e2)[:60])
print("=== tbl_params readback (D4: mode=4, d_a=4, d_r=10) ===")
for d,k in tp.entry_get(tgt,flags={"from_hw":True}):
    kd=k.to_dict(); dd=d.to_dict()
    print("  role=%s dir=%s -> mode=%s d_a=%s d_r=%s"%(
        kd.get("m.role",{}).get("value"),kd.get("m.dir",{}).get("value"),
        dd.get("mode"),dd.get("d_a"),dd.get("d_r")))
print("CONFIGURED ON SILICON: unified timing core tbl_params written + read back from hardware")

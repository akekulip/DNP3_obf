import sys, time
sys.path.insert(0,"/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino")
sys.path.insert(0,"/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages")
import bfrt_grpc.client as gc
PROG="combined_pgen"; P=68; ACT="trigger_timer_one_shot"
iface=gc.ClientInterface("localhost:50052",client_id=95,device_id=0); iface.bind_pipeline_config(PROG)
bi=iface.bfrt_info_get(PROG); tgt=gc.Target(device_id=0,pipe_id=0xffff)
def tbl(n): return bi.table_get(n)
u16=lambda x:bytes([(x>>8)&0xFF,x&0xFF]); u32=lambda x:bytes([(x>>24)&0xFF,(x>>16)&0xFF,(x>>8)&0xFF,x&0xFF])
MSS=lambda v:bytes([2,4,(v>>8)&0xFF,v&0xFF]); TS=bytes([8,10]+[0]*8); WS=bytes([3,3,7]); SACK=bytes([4,2]); NOP=bytes([1])
def frame(sport,dport,flags,opts=b"",payload=b""):
    doff=(20+len(opts))//4
    tcp=u16(sport)+u16(dport)+u32(100)+u32(1024)+bytes([doff<<4,flags])+u16(8192)+u16(0)+u16(0)+opts
    body=tcp+payload; ipt=20+len(body)
    ip=bytes([0x45,0])+u16(ipt)+u16(0)+u16(0x4000)+bytes([64,6])+u16(0)+bytes([10,0,0,2])+bytes([10,0,0,9])
    return bytes.fromhex("020000000001")+bytes.fromhex("0200000000bc")+u16(0x0800)+ip+body
FIX=[
 ("HANDSHAKE: SEL751 full SYN",        frame(44000,20000,0x02,MSS(1460)+SACK+TS+WS+NOP), 1),
 ("HANDSHAKE: SEL751 full SYN-ACK",    frame(20000,44000,0x12,MSS(1460)+NOP+WS+NOP+NOP+SACK+NOP+NOP+TS), 3),
 ("ACK-MODE: outstation pure ACK",     frame(20000,44000,0x10), 12),
 ("ACK-MODE: outstation response",     frame(20000,44000,0x18,b"",b"\x05\x64\x1f\x44"+b"\x00"*40), 0),
]
def rd():
    t=tbl("pipe.Ingress.ctr")
    try: t.operations_execute(tgt,"Sync")
    except: pass
    v={}
    for d in t.entry_get(tgt,flags={"from_hw":True}): v[d[1].to_dict()["$COUNTER_INDEX"]["value"]]=d[0].to_dict().get("$COUNTER_SPEC_PKTS",0)
    return v
pc=tbl("tf1.pktgen.port_cfg"); pc.entry_mod(tgt,[pc.make_key([gc.KeyTuple("dev_port",P)])],[pc.make_data([gc.DataTuple("pktgen_enable",bool_val=True)])])
pb=tbl("tf1.pktgen.pkt_buffer"); ac=tbl("tf1.pktgen.app_cfg")
def fire(fr):
    ac.entry_mod(tgt,[ac.make_key([gc.KeyTuple("app_id",0)])],[ac.make_data([gc.DataTuple("app_enable",bool_val=False)],ACT)])
    pb.entry_mod(tgt,[pb.make_key([gc.KeyTuple("pkt_buffer_offset",0),gc.KeyTuple("pkt_buffer_size",len(fr))])],[pb.make_data([gc.DataTuple("buffer",bytearray(fr))])])
    ac.entry_mod(tgt,[ac.make_key([gc.KeyTuple("app_id",0)])],[ac.make_data([gc.DataTuple("timer_nanosec",1000),gc.DataTuple("pkt_len",len(fr)),gc.DataTuple("pkt_buffer_offset",0),gc.DataTuple("pipe_local_source_port",P),gc.DataTuple("increment_source_port",bool_val=False),gc.DataTuple("batch_count_cfg",0),gc.DataTuple("packets_per_batch_cfg",0),gc.DataTuple("ipg",0),gc.DataTuple("ibg",0),gc.DataTuple("app_enable",bool_val=True)],ACT)])
    time.sleep(0.6)
prev=rd(); npass=0
print(f"{'CASE':36s} EXPECT GOT")
for name,fr,exp in FIX:
    fire(fr); cur=rd(); dl={i:cur.get(i,0)-prev.get(i,0) for i in set(cur)|set(prev) if cur.get(i,0)-prev.get(i,0)}
    ok=dl=={exp:1}; npass+=ok; print(f"{name:36s} idx{exp:<3d} {dl}  {'PASS' if ok else 'FAIL'}"); prev=cur
ac.entry_mod(tgt,[ac.make_key([gc.KeyTuple("app_id",0)])],[ac.make_data([gc.DataTuple("app_enable",bool_val=False)],ACT)])
print(f"COMBINED ASIC: {npass}/{len(FIX)} (handshake + ACK-mode both live on one program)")

import sys, time
sys.path.insert(0, "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino")
sys.path.insert(0, "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages")
import bfrt_grpc.client as gc
PROG="handshake_pgen"; P=68; ACT="trigger_timer_one_shot"
iface = gc.ClientInterface("localhost:50052", client_id=98, device_id=0)
iface.bind_pipeline_config(PROG); bi = iface.bfrt_info_get(PROG)
tgt = gc.Target(device_id=0, pipe_id=0xffff)
def tbl(n): return bi.table_get(n)
u16=lambda x: bytes([(x>>8)&0xFF,x&0xFF]); u32=lambda x: bytes([(x>>24)&0xFF,(x>>16)&0xFF,(x>>8)&0xFF,x&0xFF])
def frame(opts, flags, src_syn=True, payload=b""):
    tflags = flags
    doff=(20+len(opts))//4
    sport,dport=(44000,20000) if src_syn else (20000,44000)
    tcp=u16(sport)+u16(dport)+u32(1000)+u32(7)+bytes([doff<<4,tflags])+u16(8192)+u16(0)+u16(0)+opts
    body=tcp+payload; ipt=20+len(body)
    ip=bytes([0x45,0])+u16(ipt)+u16(0)+u16(0x4000)+bytes([64,6])+u16(0)+bytes([10,0,0,9])+bytes([10,0,0,2])
    return bytes.fromhex("020000000001")+bytes.fromhex("0200000000bc")+u16(0x0800)+ip+body
MSS=lambda v: bytes([2,4,(v>>8)&0xFF,v&0xFF]); TS=bytes([8,10]+[0]*8); WS=bytes([3,3,7]); SACK=bytes([4,2]); NOP=bytes([1]); EOL=bytes([0])
FIX=[  # (name, frame, expected_ctr_index)
 ("01 SEL751 full SYN do10",       frame(MSS(1460)+SACK+TS+WS+NOP, 0x02), 1),
 ("02 ION7550 MSS-only SYN do6",   frame(MSS(1460), 0x02), 1),
 ("03 AB1400 MSS1478 clamp",       frame(MSS(1478)+NOP+NOP+NOP+EOL, 0x02), 2),
 ("04 SYN no MSS (failopen)",      frame(TS+NOP+NOP, 0x02), 6),
 ("05 SYN MD5 2nd opt (security)", frame(MSS(1460)+bytes([19,18])+bytes(16)+NOP+NOP, 0x02), 9),
 ("06 SYN-ACK MSS-only do6",       frame(MSS(1460), 0x12, src_syn=False), 3),
 ("07 established ACK+TS (leak)",  frame(NOP+NOP+TS, 0x10, src_syn=False, payload=bytes.fromhex("0564")), 7),
 ("08 data_offset 13 unsupported", frame(MSS(1460)+TS+WS+NOP*18, 0x02), 11),
]
def read_ctr():
    t=tbl("pipe.Ingress.ctr"); 
    try: t.operations_execute(tgt,"Sync")
    except: pass
    v={}
    for d in t.entry_get(tgt, flags={"from_hw":True}):
        v[d[1].to_dict()["$COUNTER_INDEX"]["value"]]=d[0].to_dict().get("$COUNTER_SPEC_PKTS",0)
    return v
pc=tbl("tf1.pktgen.port_cfg"); pc.entry_mod(tgt,[pc.make_key([gc.KeyTuple("dev_port",P)])],[pc.make_data([gc.DataTuple("pktgen_enable",bool_val=True)])])
pb=tbl("tf1.pktgen.pkt_buffer"); ac=tbl("tf1.pktgen.app_cfg")
def fire(fr):
    ac.entry_mod(tgt,[ac.make_key([gc.KeyTuple("app_id",0)])],[ac.make_data([gc.DataTuple("app_enable",bool_val=False)],ACT)])
    pb.entry_mod(tgt,[pb.make_key([gc.KeyTuple("pkt_buffer_offset",0),gc.KeyTuple("pkt_buffer_size",len(fr))])],[pb.make_data([gc.DataTuple("buffer",bytearray(fr))])])
    ac.entry_mod(tgt,[ac.make_key([gc.KeyTuple("app_id",0)])],[ac.make_data([
        gc.DataTuple("timer_nanosec",1000),gc.DataTuple("pkt_len",len(fr)),gc.DataTuple("pkt_buffer_offset",0),
        gc.DataTuple("pipe_local_source_port",P),gc.DataTuple("increment_source_port",bool_val=False),
        gc.DataTuple("batch_count_cfg",0),gc.DataTuple("packets_per_batch_cfg",0),gc.DataTuple("ipg",0),gc.DataTuple("ibg",0),
        gc.DataTuple("app_enable",bool_val=True)],ACT)])
    time.sleep(0.6)
prev=read_ctr(); npass=0
print(f"{'CASE':34s} {'EXPECT':7s} {'GOT':18s} RES")
for name,fr,exp in FIX:
    fire(fr); cur=read_ctr()
    delta={i:cur.get(i,0)-prev.get(i,0) for i in set(cur)|set(prev) if cur.get(i,0)-prev.get(i,0)}
    ok = delta==({exp:1})
    npass+= 1 if ok else 0
    print(f"{name:34s} idx {exp:<3d} {str(delta):18s} {'PASS' if ok else 'FAIL'}")
    prev=cur
ac.entry_mod(tgt,[ac.make_key([gc.KeyTuple("app_id",0)])],[ac.make_data([gc.DataTuple("app_enable",bool_val=False)],ACT)])
print(f"ASIC MATRIX: {npass}/{len(FIX)} classifications correct on silicon")

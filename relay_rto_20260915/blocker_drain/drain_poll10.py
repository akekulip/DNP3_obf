import bfrt_grpc.client as gc, time, sys
DUR=float(sys.argv[1]); OUT=sys.argv[2]
i = gc.ClientInterface("localhost:50052", client_id=int(sys.argv[3]), device_id=0)
i.bind_pipeline_config("defense4_rrc_bor_unified12")
b = i.bfrt_info_get("defense4_rrc_bor_unified12")
tgt = gc.Target(device_id=0, pipe_id=0xffff); st=b.table_get("$PORT_STAT")
k10 = st.make_key([gc.KeyTuple("$DEV_PORT", 10)])
rows=[]; t_end=time.time()+DUR
while time.time()<t_end:
    t=time.time()
    for d,_ in st.entry_get(tgt,[k10],{"from_hw":True}):
        rows.append((t, dict(d.to_dict()).get("$FramesTransmittedOK")))
with open(OUT,"w") as f:
    for t,v in rows: f.write("%.6f %d\n" % (t,v))
print("samples=%d" % len(rows))

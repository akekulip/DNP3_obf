import bfrt_grpc.client as gc, sys, json
i = gc.ClientInterface("localhost:50052", client_id=int(sys.argv[1]), device_id=0)
i.bind_pipeline_config("defense4_rrc_bor_unified12")
b = i.bfrt_info_get("defense4_rrc_bor_unified12")
tgt = gc.Target(device_id=0, pipe_id=0xffff); st = b.table_get("$PORT_STAT")
out={}
for dp in (8,10,64,9):
    k = st.make_key([gc.KeyTuple("$DEV_PORT", dp)])
    for d,_ in st.entry_get(tgt,[k],{"from_hw":True}):
        dd=dict(d.to_dict())
        out[dp]={"tx_frames":dd.get("$FramesTransmittedOK"),
                 "tx_octets":dd.get("$OctetsTransmittedwithoutError") or dd.get("$OctetsTransmittedTotal"),
                 "rx_frames":dd.get("$FramesReceivedOK")}
print(json.dumps(out))

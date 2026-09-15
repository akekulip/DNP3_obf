"""Clear the epsilon registers, or read them together with the two deadlines."""
import bfrt_grpc.client as gc, sys, json
MODE = sys.argv[1]
i = gc.ClientInterface("localhost:50052", client_id=int(sys.argv[2]), device_id=0)
i.bind_pipeline_config("epsilon_candidate")
b = i.bfrt_info_get("epsilon_candidate")
tgt = gc.Target(device_id=0, pipe_id=0xffff)

def reg(name):
    return b.table_get(name)

def rd(t, idx):
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
    t.operations_execute(tgt, "Sync")
    for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
        dd = dict(d.to_dict())
        for kk, v in dd.items():
            if isinstance(v, list) and v:
                return int(v[0])
    return None

def wr(t, idx, val):
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
    fname = [f for f in t.info.data_field_name_list_get() if "f1" in f][0]
    t.entry_add(tgt, [k], [t.make_data([gc.DataTuple(fname, val)])])

ef, bl = reg("Ingress.reg_ep_expiry_first"), reg("Ingress.reg_ep_block_last")
if MODE == "clear":
    for t in (ef, bl):
        for idx in (0, 1):
            wr(t, idx, 0)
    print("cleared")
else:
    out = {
        "deadline_ack": rd(reg("Ingress.reg_deadline"), 0),
        "deadline_resp": rd(reg("Ingress.reg_tresp"), 0),
        "expiry_first_ack": rd(ef, 0), "expiry_first_resp": rd(ef, 1),
        "block_last_ack": rd(bl, 0), "block_last_resp": rd(bl, 1),
    }
    print(json.dumps(out))

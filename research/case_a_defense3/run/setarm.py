"""Set D and the reservoir arm state for one campaign block, and clear the
transaction state so the next READ arms fresh. Nothing else is touched: ports,
queues, priorities, session, mirror, K and the budget all stay as configured."""
import json, sys
sys.path.insert(0, "/home/decps/d3")
import bfrt_grpc.client as gc
d_ms = float(sys.argv[1]); arm = int(sys.argv[2])
PROG = "case_a_defense3_fixed_ack_delay"
iface = gc.ClientInterface("localhost:50052", client_id=int(sys.argv[3]) if len(sys.argv) > 3 else 20,
                           device_id=0, notifications=None)
iface.bind_pipeline_config(PROG)
bi = iface.bfrt_info_get(PROG)
tgt = gc.Target(device_id=0, pipe_id=0xffff)
p0 = gc.Target(device_id=0, pipe_id=0)

# D on the 256 ns tick grid, low byte zero so the ARMED marker survives dl_cand = now + D
ticks = int(round(d_ms * 1e6 / 256.0))
word = (ticks << 8) & 0xFFFFFF00
out = {"d_ms": d_ms, "d_ticks": ticks, "d_word": word, "d_realized_ns": word}
t = bi.table_get("tbl_params")
for act in ("Ingress.set_params", "set_params"):
    try:
        t.default_entry_set(tgt, t.make_data([gc.DataTuple("d_ticks", word),
                                             gc.DataTuple("read_len", 18),
                                             gc.DataTuple("budget", 18000)], act))
        out["d_written"] = True
        break
    except Exception as e:
        out["d_err"] = str(e)[:80]
for item in t.default_entry_get(tgt, {"from_hw": True}):
    d = item[0] if isinstance(item, tuple) else item
    out["d_readback"] = d.to_dict().get("d_ticks")

# clear ONLY the per-transaction state, so the first READ of the block arms fresh
n = 0
for r in ("reg_tag", "reg_deadline", "reg_ack_rel", "reg_ts_first_block",
          "reg_ts_last_block", "reg_ts_ack_arm", "reg_ts_block_term",
          "reg_ts_last_term", "reg_ts_ack_release"):
    tb = bi.table_get(r)
    for fld in ("f1", "Ingress." + r + ".f1"):
        try:
            tb.entry_mod(tgt, [tb.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
                         [tb.make_data([gc.DataTuple(fld, 0)])]); n += 1; break
        except Exception:
            pass
out["state_regs_zeroed"] = n
for nm, c in (("ctr_fresh", 17), ("ctr_deq", 8)):
    tb = bi.table_get(nm)
    for i in range(c):
        try:
            tb.entry_mod(tgt, [tb.make_key([gc.KeyTuple("$COUNTER_INDEX", i)])],
                         [tb.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0),
                                        gc.DataTuple("$COUNTER_SPEC_BYTES", 0)])])
        except Exception:
            pass

# the reservoir arm: this is the ONLY thing that distinguishes the observationally
# native arm from a treatment arm
ac = bi.table_get("tf1.pktgen.app_cfg")
ac.entry_mod(p0, [ac.make_key([gc.KeyTuple("app_id", 1)])],
             [ac.make_data([gc.DataTuple("app_enable", bool_val=bool(arm))])])
for d, _ in ac.entry_get(p0, [ac.make_key([gc.KeyTuple("app_id", 1)])], {"from_hw": True}):
    dd = d.to_dict()
    out["app1"] = {k: dd.get(k) for k in ("app_enable", "trigger_counter", "pkt_counter")}
print("SETARM " + json.dumps(out, default=str))

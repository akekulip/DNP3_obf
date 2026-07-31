"""Set D and the reservoir arm state for one campaign block, and clear the
transaction state so the next READ arms fresh. Nothing else is touched: ports,
queues, priorities, session, mirror, K and the budget all stay as configured.

CORRECTIONS.md §2.2/§3.2/§4.2: the program defaults to the FINAL repaired build; D is
validated and written through the ONE parameter authority (control/parameter_policy.py),
not written to tbl_params directly; and the per-block counter reset comes from the shared
counter map (control/counter_map.py) so CF_BLOCK_REJECT (index 17) is included.
"""
import json, os, sys
sys.path.insert(0, "/home/decps/d3")
# the shared control modules are staged flat on the switch (and live under ../control in
# the repo); accept either layout.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in ("/home/decps/d3/control", "/home/decps/d3",
           os.path.join(_HERE, "..", "control")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import bfrt_grpc.client as gc
import parameter_policy
import counter_map

d_ms = float(sys.argv[1]); arm = int(sys.argv[2])
# FINAL repaired build is the default (CORRECTIONS.md §2.2). D3_PROG overrides for an
# explicit historical-control run.
PROG = os.environ.get("D3_PROG", "case_a_defense3")
iface = gc.ClientInterface("localhost:50052", client_id=int(sys.argv[3]) if len(sys.argv) > 3 else 20,
                           device_id=0, notifications=None)
iface.bind_pipeline_config(PROG)
bi = iface.bfrt_info_get(PROG)
tgt = gc.Target(device_id=0, pipe_id=0xffff)
p0 = gc.Target(device_id=0, pipe_id=0)

out = {"prog": PROG, "d_ms": d_ms}

# D through the single parameter authority: validate, then write via the gated writer.
# A read-only block (arm==0, no ACK ever arrives) declares itself so the small-H case is
# admissible; an armed block is a real hold and D must sit inside D_max.
pol = parameter_policy.evaluate(d_ms, read_only_trial=(arm == 0))
out["policy_ok"] = pol["ok"]
out["policy"] = {k: pol[k] for k in ("d_realized_ms", "d_word", "H_ms", "D_max_ms", "reasons")}
if not pol["ok"]:
    # fail closed: a rejected parameter set must NOT silently become a campaign row.
    out["error"] = "parameter policy REJECTED D=%.3f ms: %s" % (d_ms, "; ".join(pol["reasons"]))
    print("SETARM " + json.dumps(out, default=str))
    sys.exit(3)
t = bi.table_get("tbl_params")
try:
    out["d_written_action"] = parameter_policy.write_params(t, tgt, pol, gc)
    out["d_written"] = True
except Exception as e:
    out["d_err"] = str(e)[:120]
    print("SETARM " + json.dumps(out, default=str))
    sys.exit(3)
for item in t.default_entry_get(tgt, {"from_hw": True}):
    d = item[0] if isinstance(item, tuple) else item
    out["d_readback"] = d.to_dict().get("d_ticks")

# clear ONLY the per-transaction state, so the first READ of the block arms fresh.
# reg_failopen (R2's note) is included; its absence on a non-R2 build is tolerated.
n = 0
for r in ("reg_tag", "reg_deadline", "reg_ack_rel", "reg_ts_first_block",
          "reg_ts_last_block", "reg_ts_ack_arm", "reg_ts_block_term",
          "reg_ts_last_term", "reg_ts_ack_release", "reg_failopen"):
    try:
        tb = bi.table_get(r)
    except Exception:
        continue          # not in this build
    for fld in ("f1", "Ingress." + r + ".f1"):
        try:
            tb.entry_mod(tgt, [tb.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
                         [tb.make_data([gc.DataTuple(fld, 0)])]); n += 1; break
        except Exception:
            pass
out["state_regs_zeroed"] = n

# counter reset ranges from the shared map (CORRECTIONS.md §4.2): ctr_fresh 0..17
# (CF_BLOCK_REJECT included), ctr_deq 0..7.
for nm, rng in (("ctr_fresh", counter_map.fresh_reset_range()),
                ("ctr_deq", counter_map.deq_reset_range())):
    tb = bi.table_get(nm)
    for i in rng:
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

#!/usr/bin/env python3
# AUTHORED FOR THE SILICON CAMPAIGN — switch-side evidence reader (read-only).
"""read_pktgen.py — read the pktgen HW counters, P4 counters, and timing registers
for the request-triggered pktgen Defense-2 program. Read-only; never configures.

Run on the switch:
  PYTHONPATH=$SP:$SP/tofino python3.8 read_pktgen.py            # print one JSON line
  PYTHONPATH=$SP:$SP/tofino python3.8 read_pktgen.py --zero     # zero P4 counters + registers first

Prints:  PKTGENREAD {...}
"""
import argparse
import json
import bfrt_grpc.client as gc

PROG = "dnp3_timing_normalizer_pktgen"

# P4 ingress counters (Stats ALU) — index 0, need SyncCounters before read.
CTRS = [
    "ctr_arm", "ctr_arm_clone", "ctr_pktgen_admit", "ctr_pktgen_drop",
    "ctr_block_enq", "ctr_block_loop", "ctr_ack_arm", "ctr_ack_bypass",
    "ctr_resp_enq", "ctr_resp_release",
    "ctr_block_term_deadline", "ctr_block_term_timeout", "ctr_block_term_stale",
    "ctr_release_deadline", "ctr_release_fail_open",
    "ctr_response_actually_held", "ctr_response_zero_hold",
    "ctr_response_before_deadline", "ctr_response_at_or_after_deadline",
]
# timing/state registers — read live (from_hw=True).
REGS = [
    "reg_native_clrt", "reg_protection", "reg_deadline", "reg_tag",
    "reg_ts_ack_arm", "reg_ts_first_resp_release", "reg_ts_block_term", "reg_ts_first_block",
]


def read_counter(bi, tgt, nm):
    try:
        t = bi.table_get("pipe.Ingress." + nm)
        try:
            t.operations_execute(tgt, "SyncCounters")
        except Exception:
            pass
        k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])
        for d, _ in t.entry_get(tgt, [k], {"from_hw": False}):
            return d.to_dict().get("$COUNTER_SPEC_PKTS")
    except Exception as e:
        return "ERR:" + str(e)[:50]
    return None


def read_register(bi, tgt, nm):
    try:
        t = bi.table_get("pipe.Ingress." + nm)
        k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
        for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
            dd = d.to_dict()
            # register value field is the non-index data field (name varies by SDE);
            # take the first list/int value that is not the index key.
            for key, val in dd.items():
                if key.startswith("$"):
                    continue
                if isinstance(val, list):
                    return val[0] if val else None
                return val
    except Exception as e:
        return "ERR:" + str(e)[:50]
    return None


def read_pktgen_app(bi, tgt, app_id):
    try:
        t = bi.table_get("tf1.pktgen.app_cfg")
        k = t.make_key([gc.KeyTuple("app_id", app_id)])
        for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
            dd = d.to_dict()
            return {x: dd.get(x) for x in
                    ["app_enable", "trigger_counter", "batch_counter", "pkt_counter"]}
    except Exception as e:
        return {"err": str(e)[:60]}
    return {}


def zero_state(bi, tgt, out):
    zc = {}
    for nm in CTRS:
        try:
            t = bi.table_get("pipe.Ingress." + nm)
            t.entry_mod(tgt, [t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])],
                        [t.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])])
            zc[nm] = 0
        except Exception as e:
            zc[nm] = "ERR:" + str(e)[:40]
    # ctr_bypass is a size-2 counter (idx0 = bypass-forward, idx1 = bad-port drop)
    try:
        t = bi.table_get("pipe.Ingress.ctr_bypass")
        for idx in (0, 1):
            t.entry_mod(tgt, [t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])],
                        [t.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])])
        zc["ctr_bypass"] = 0
    except Exception as e:
        zc["ctr_bypass"] = "ERR:" + str(e)[:40]
    out["counters_zeroed"] = zc
    # reset the pktgen HW counters (trigger/batch/pkt) on app_id 1
    try:
        a = bi.table_get("tf1.pktgen.app_cfg")
        a.entry_mod(tgt, [a.make_key([gc.KeyTuple("app_id", 1)])],
                    [a.make_data([gc.DataTuple("trigger_counter", 0),
                                  gc.DataTuple("batch_counter", 0),
                                  gc.DataTuple("pkt_counter", 0)])])
        out["pktgen_counters_zeroed"] = True
    except Exception as e:
        out["pktgen_counters_zeroed"] = "ERR:" + str(e)[:50]
    zr = {}
    for nm in REGS:
        try:
            t = bi.table_get("pipe.Ingress." + nm)
            k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
            data = None
            for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
                dd = d.to_dict()
                for key in dd:
                    if not key.startswith("$"):
                        data = t.make_data([gc.DataTuple(key, 0)])
                        break
                break
            if data is not None:
                t.entry_mod(tgt, [k], [data])
                zr[nm] = 0
        except Exception as e:
            zr[nm] = "ERR:" + str(e)[:40]
    out["registers_zeroed"] = zr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zero", action="store_true", help="zero P4 counters + registers, then read")
    ap.add_argument("--app-id", type=int, default=1)
    ap.add_argument("--client-id", type=int, default=80)
    a = ap.parse_args()

    iface = gc.ClientInterface("localhost:50052", client_id=a.client_id, device_id=0, notifications=None)
    iface.bind_pipeline_config(PROG)
    bi = iface.bfrt_info_get(PROG)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)

    out = {}
    if a.zero:
        zero_state(bi, tgt, out)

    out["pktgen_app"] = read_pktgen_app(bi, tgt, a.app_id)
    out["counters"] = {nm: read_counter(bi, tgt, nm) for nm in CTRS}
    # ctr_bypass size-2: idx0 = ROLE_BYPASS forwarded, idx1 = port_ok==0 bad-port drop
    try:
        t = bi.table_get("pipe.Ingress.ctr_bypass")
        try:
            t.operations_execute(tgt, "SyncCounters")
        except Exception:
            pass
        for idx in (0, 1):
            for d, _ in t.entry_get(tgt, [t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])], {"from_hw": False}):
                out["counters"]["ctr_bypass[%d]" % idx] = d.to_dict().get("$COUNTER_SPEC_PKTS")
    except Exception as e:
        out["counters"]["ctr_bypass_err"] = str(e)[:40]
    out["registers"] = {nm: read_register(bi, tgt0, nm) for nm in REGS}
    print("PKTGENREAD " + json.dumps(out))


if __name__ == "__main__":
    main()

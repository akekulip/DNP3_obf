#!/usr/bin/env python3
"""p13_guard.py — set / read the guard interval G on the Part 13 DNP3 classifier.

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052).

Part 12 carried G in the packet (`hdr.ib.seq` of the ACK), which was a TEST_ONLY shortcut. The
Part 13 classifier takes G from a control-plane table instead — `tbl_guard`, a keyless table whose
default action `set_guard(g_ns)` supplies the value — because a real pure TCP ACK has nowhere to
carry it. This is the deployment-shaped path: G is policy, set once, not per packet.

The Part 11 control-plane script (`ibspg_paired_setup.py`) is still used unchanged for ports, TM
strict priority and register/counter reset; this only adds the one thing it cannot know about.

  --set-g-ms 20    set the guard interval and read it back
  --read           read the current value only

Prints one JSON line: P13GUARD {...}
"""
import argparse
import json
import sys

import bfrt_grpc.client as gc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", default="ibspg_dnp3")
    ap.add_argument("--table", default="pipe.Ingress.tbl_guard")
    ap.add_argument("--action", default="Ingress.set_guard")
    ap.add_argument("--param", default="g")   # verified against the P4: action set_guard(bit<32> g)
    ap.add_argument("--set-g-ms", type=float, default=None)
    ap.add_argument("--read", action="store_true")
    a = ap.parse_args()

    iface = gc.ClientInterface("localhost:50052", client_id=64, device_id=0, notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    out = {"prog": a.prog, "table": a.table}

    try:
        t = bi.table_get(a.table)
    except Exception as e:
        print("P13GUARD " + json.dumps({"error": "table_get failed: %s" % str(e)[:120]}))
        sys.exit(1)

    if a.set_g_ms is not None:
        g_ns = int(round(a.set_g_ms * 1e6))
        out["requested_g_ns"] = g_ns
        # the sign-bit deadline test is only valid while G < 2^31 ns (~2.147 s)
        if not (0 <= g_ns < (1 << 31)):
            print("P13GUARD " + json.dumps({"error": "G out of range for the sign-bit test",
                                            "g_ns": g_ns}))
            sys.exit(2)
        # TICK ALIGNMENT (review D / packed-state JOIN C): the packed deadline word carries the
        # armed marker in bit 0, so G MUST have a zero low byte (256 ns tick granularity). A G with
        # a non-zero low byte carries into / corrupts the armed marker at `now_word + G`. Round DOWN
        # to the tick boundary and report if the request was not already aligned.
        g_ticks_ns = g_ns & 0xFFFFFF00
        if g_ticks_ns != g_ns:
            out["tick_aligned_from"] = g_ns
        g_ns = g_ticks_ns
        out["g_ns"] = g_ns
        wrote = None
        for pname in (a.param, "g_ns", "guard_ns", "val"):
            try:
                t.default_entry_set(tgt, t.make_data([gc.DataTuple(pname, g_ns)], a.action))
                wrote = pname
                break
            except Exception as e:
                out.setdefault("tried", {})[pname] = str(e)[:70]
        if wrote is None:
            print("P13GUARD " + json.dumps(out) + " ERROR: no accepted parameter name")
            sys.exit(3)
        out["wrote_param"] = wrote

    # always read back — a write that is not verified is not a configuration
    try:
        got = None
        for d, _k in t.default_entry_get(tgt, {"from_hw": False}):
            dd = d.to_dict()
            got = {k: v for k, v in dd.items() if not k.startswith("$") and k != "action_name"}
            out["action_name"] = dd.get("action_name")
        out["readback"] = got
        if a.set_g_ms is not None and got:
            vals = [v for v in got.values() if isinstance(v, int)]
            out["verified"] = bool(vals and vals[0] == out["g_ns"])   # aligned value, not the pre-tick request
    except Exception as e:
        out["readback_error"] = str(e)[:120]

    print("P13GUARD " + json.dumps(out))


if __name__ == "__main__":
    main()

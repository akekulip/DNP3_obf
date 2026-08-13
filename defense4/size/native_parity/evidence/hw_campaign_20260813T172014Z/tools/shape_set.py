#!/usr/bin/env python3
"""shape_set.py <0|1> -- toggle the RRC size carve (tbl_params.shape_enable) on the loaded
unified program via the proven rrc.set_shape_enable RMW (device target 0xffff, timing preserved).
shape=1 -> responses split [28,21] via PRE; shape=0 -> native pass-through (no replicas)."""
import sys, os, importlib.util
import bfrt_grpc.client as gc

CASEA = "/home/decps/d4_build/control/defense4_caseA_setup.py"
RRC = "/home/decps/rrc_bor_build/control/defense4_rrc_setup.py"
PROGRAM = "defense4_rrc_bor_unified12"
os.environ["D4_CASEA_SETUP"] = CASEA

def _load(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

def main():
    on = int(sys.argv[1])
    rrc = _load("rrc", RRC)
    d3 = rrc._load_d3()
    iface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0)
    iface.bind_pipeline_config(PROGRAM)
    bi = iface.bfrt_info_get(PROGRAM)
    tdev = gc.Target(device_id=0, pipe_id=0xffff)
    chk = d3.Checks(); out = {}
    ok = rrc.set_shape_enable(bi, tdev, chk, out, on=bool(on), d3=d3, strict=True)
    print("shape_set on=%d ok=%s tbl_params=%s" % (on, ok, out.get("tbl_params")))
    print("RESULT: %s" % ("PASS" if chk.n_fail == 0 else "FAIL"))
    try: iface._tear_down_stream()
    except Exception: pass
    sys.exit(0 if chk.n_fail == 0 else 2)

if __name__ == "__main__":
    main()

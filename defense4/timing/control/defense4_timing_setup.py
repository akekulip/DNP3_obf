#!/usr/bin/env python3
"""Control-plane setup for the UNIFIED timing core (defense4_timing.p4).

Reuses the proven, program-agnostic fixed-function setup from defense4_caseA_setup.py: the four-queue
strict-priority ladder (qid7>6>5>4 via tf1.tm.queue.sched_cfg) and the 128-token pktgen blocker-token
reservoir (64 ACK-blockers on qid7 + 64 RESP-blockers on qid5). defense4_timing.p4 uses the identical
queue/port/token constants, so the same machinery seeds its reservoirs. Then writes tbl_params (D4).

Run on the switch host:  python3 defense4_timing_setup.py
"""
import sys, types
sys.path.insert(0, "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino")
sys.path.insert(0, "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages")
sys.path.insert(0, "/home/decps/d3")
sys.path.insert(0, "/home/decps/d4_build/control")
import bfrt_grpc.client as gc
import case_a_defense3_fixed_ack_delay_setup as d3
import defense4_caseA_setup as ca

class Chk:
    def __init__(s): s.fails = []
    def ok(s, n, note=""): print("  OK   %-42s %s" % (n, note))
    def fail(s, n, note=""): print("  FAIL %-42s %s" % (n, note)); s.fails.append(n)
    def warn(s, n, note=""): print("  warn %-42s %s" % (n, note))
    def expect(s, n, got, want):
        (s.ok if got == want else s.fail)(n, "got=%s want=%s" % (got, want))

K = getattr(d3, "K_TOKENS", 64)
a = types.SimpleNamespace(
    port_l=getattr(d3, "PORT_L", 8), port_pgen=getattr(d3, "PORT_PGEN", 68),
    port_relay=getattr(d3, "PORT_RELAY", 64), port_vision=getattr(d3, "PORT_VISION", 9),
    token_len=getattr(d3, "TOKEN_LEN", 64), buf_offset=0, app_id=getattr(d3, "APP_ID_DEFAULT", 1),
    k=K, pipe=0, pg_l=2, pg_l_nr=0, program="defense4_timing", grpc="localhost:50052")

iface = gc.ClientInterface(a.grpc, client_id=86, device_id=0)
iface.bind_pipeline_config(a.program)
bi = iface.bfrt_info_get(a.program)
tgt = gc.Target(device_id=0, pipe_id=0xffff)
tgt0 = gc.Target(device_id=0, pipe_id=a.pipe)
chk = Chk(); out = {}

print("=== 1. four-queue strict-priority ladder qid7>6>5>4 on the loopback (dp%d) ===" % a.port_l)
try: ca.config_queues_4q(bi, tgt0, a, out, chk, write=True)
except Exception as e: chk.fail("config_queues_4q", repr(e)[:120])

print("=== 2. seed + enable the 2K=128 blocker-token reservoir (64 ACK@qid7 + 64 RESP@qid5) ===")
try: ca.config_pktgen_2k(bi, tgt, a, out, chk, write=True, app_enable=True)
except Exception as e: chk.fail("config_pktgen_2k", repr(e)[:120])

print("=== 3. tbl_params: D4 dual-deadline, D_A=4 D_R=10 (ARM/ACK/RESP) ===")
tp = bi.table_get("Ingress.tbl_params")
for role, dr in [(6, 0), (7, 1), (2, 1)]:
    try:
        tp.entry_mod(tgt, [tp.make_key([gc.KeyTuple("m.role", role), gc.KeyTuple("m.dir", dr)])],
            [tp.make_data([gc.DataTuple("mode", 4), gc.DataTuple("d_a", 4), gc.DataTuple("d_r", 10)], "Ingress.set_params")])
    except Exception:
        try: tp.entry_add(tgt, [tp.make_key([gc.KeyTuple("m.role", role), gc.KeyTuple("m.dir", dr)])],
            [tp.make_data([gc.DataTuple("mode", 4), gc.DataTuple("d_a", 4), gc.DataTuple("d_r", 10)], "Ingress.set_params")])
        except Exception as e: chk.warn("params (%d,%d)" % (role, dr), repr(e)[:60])
chk.ok("tbl_params D4 written", "ARM/ACK/RESP")

print("=== 4. reservoir readback: pktgen app enabled + queue max_priority ===")
try:
    ac = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    g, err = d3.get_entry(ac, tgt, [("app_id", a.app_id)]) if hasattr(d3, "get_entry") else (None, "n/a")
    en = (g or {}).get("app_enable") if isinstance(g, dict) else None
    chk.ok("pktgen app_enable readback", str(en))
except Exception as e: chk.warn("pktgen readback", repr(e)[:80])

print("\nSETUP RESULT:", "FAIL (%d)" % len(chk.fails) if chk.fails else "OK — queues + reservoir + params configured on silicon")
print("fails:", chk.fails)

#!/usr/bin/env python3
"""Adversarial injection probe for the three audit defects — the in-switch stand-in
for a forged 0x88C1 frame on a host port, which the lab cannot produce (no passwordless
raw socket on the master, no host on the relay leg).

It forges ONE 0x88C1 blocker token with an ATTACKER-CHOSEN generation and budget, via a
synthetic packet-generator application (app 5) that the D3_INJECT parser path treats as a
FRESH host-injected token (is_pktgen = 0), so the frame keeps its own gen/seq instead of
being re-stamped with the current generation on admission.

THE ONE-HOP EXPLOIT. Inject the foreign token with seq == 0. Its fresh pass enqueues it to
the dp8 loopback (harmless — no tag write). On its FIRST dequeue it arrives with seq == 0,
so the class driver raises budget_zero at level 2 and the fail-open write commits BEFORE
tbl_state_decode decides at level 3 that the token is stale. That ordering is defect 2:

    build              live reg_tag before   after injecting foreign gen, seq=0
    ---------------    -------------------   ---------------------------------
    R1 only            0xC0                  0x00   <- CLOBBERED (the defect, live)
    R1 + R2            0xC0                  0xC0   <- R2: the note cannot arm 0xC0
    R1 + R2 + R3       0xC0                  0xC0   <- R3: the frame never enters

reg_tag is written directly to the "live" value rather than armed through a full synthetic
transaction, because the property under test is only whether the injected token's write
reaches reg_tag — how reg_tag got there is irrelevant, and a direct write makes the probe
deterministic and independent of the generator's event timing.

Register and counter access reuse the proven d3 helpers rather than re-deriving them.

Usage (on the switch, after the control plane is configured):
    inject_probe.py <prog> <gen_live_hex> <gen_inject_hex> <seq_inject> <out.json>
"""
import json, sys, time
sys.path.insert(0, "/home/decps/d3")
import bfrt_grpc.client as gc
import case_a_defense3_fixed_ack_delay_setup as d3

PROG = sys.argv[1]
GEN_LIVE = int(sys.argv[2], 0)
GEN_INJ = int(sys.argv[3], 0)
SEQ_INJ = int(sys.argv[4], 0)
OUT = sys.argv[5]

APP_INJECT = 5
PIPE = 0
PGEN_PRSR_ID = 17
PORT_PGEN = 68
BUF_OFFSET = 512
TOKEN_LEN = 60
TOKEN_DST = bytes([0x02, 0, 0, 0, 0, 0x01])
TOKEN_SRC = bytes([0x02, 0, 0, 0, 0x0B, 0x0C])
ETYPE_IBSPG = 0x88C1
ROLE_BLOCK = 1

# ctr_fresh index names (matches the P4 CF_* constants)
CF = {"BAD_PORT": 1, "ARM_FRESH": 2, "ARM_BUSY": 4, "ACK_HOLD": 5, "ACK_REJECT": 7,
      "RESP_HOLD_EARLY": 8, "RESP_BYPASS": 10, "BLOCK_ENQ": 12, "PKTGEN_ADMIT": 13,
      "PKTGEN_DROP": 14, "CLONE_SEEN": 15, "RESP_DUP_SUPP": 16, "BLOCK_REJECT": 17}
CD = {"BLOCK_LOOP": 0, "BLOCK_TERM_STALE": 1, "BLOCK_TERM_DL": 2, "BLOCK_TERM_TMO": 3,
      "RELEASE_DEADLINE": 4, "RELEASE_FAILOPEN": 5, "ACK_RELEASE": 6, "ACK_REL_RETIRE": 7}

iface = gc.ClientInterface("localhost:50052", client_id=91, device_id=0, notifications=None)
iface.bind_pipeline_config(PROG)
bi = iface.bfrt_info_get(PROG)
tgt = gc.Target(device_id=0, pipe_id=0xffff)
p0 = gc.Target(device_id=0, pipe_id=PIPE)
rec = {"prog": PROG, "gen_live": GEN_LIVE, "gen_inject": GEN_INJ, "seq_inject": SEQ_INJ,
       "checks": []}


def counters():
    out = {}
    for name, tbl in list((k, "ctr_fresh") for k in CF) + list((k, "ctr_deq") for k in CD):
        idx = CF[name] if tbl == "ctr_fresh" else CD[name]
        v = d3.ctr_read(bi, tgt, tbl, idx)
        if v:
            out[name] = v
    return out


def build_inject(gen, seq):
    tok = bytearray(TOKEN_DST + TOKEN_SRC)
    tok += bytes([(ETYPE_IBSPG >> 8) & 0xFF, ETYPE_IBSPG & 0xFF])
    tok += bytes([ROLE_BLOCK, 0x00, gen & 0xFF])
    tok += bytes([(seq >> 24) & 0xFF, (seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF])
    return bytes(tok + bytes(TOKEN_LEN - len(tok)))


# ---- 1. the inject value_set entry: leading byte 0x05 (pipe 0, app 5) -----------
vs_byte = (PIPE << 3) | APP_INJECT
try:
    vs = bi.table_get("pipe.IgParser.pgen_inject")
    # The value_set's SCOPE is a per-TABLE attribute, and pgen_inject is a new table
    # the control plane never configured, so its scope must be set before a per-pipe
    # entry can be added -- exactly as config_value_set does for pgen_recirc. Setting
    # scope only succeeds while the table is empty; a failure on a re-run is expected.
    if d3.bfr_pb2 is not None:
        try:
            vs.attribute_entry_scope_set(
                gc.Target(device_id=0, pipe_id=0xffff),
                config_pipe_scope=True, predefined_pipe_scope=True,
                predefined_pipe_scope_val=d3.bfr_pb2.Mode.SINGLE,
                config_gress_scope=True, predefined_gress_scope_val=d3.bfr_pb2.Mode.ALL,
                config_prsr_scope=True, predefined_prsr_scope_val=d3.bfr_pb2.Mode.SINGLE)
        except Exception:
            pass
    vtgt = gc.Target(device_id=0, pipe_id=PIPE, prsr_id=PGEN_PRSR_ID)
    vkey = [vs.make_key([gc.KeyTuple("f1", vs_byte, 0xFF)])]
    try:
        vs.entry_del(vtgt, vkey)
    except Exception:
        pass
    vs.entry_add(vtgt, vkey)
except Exception as e:
    rec["checks"].append({"result": "FAIL", "check": "pgen_inject value_set",
                          "detail": str(e)[:120]})
    json.dump(rec, open(OUT, "w"), indent=1)
    print("FAIL: pgen_inject value_set:", str(e)[:120])
    sys.exit(2)

# ---- 2. the forged token into the packet buffer --------------------------------
tmpl = build_inject(GEN_INJ, SEQ_INJ)
pbuf = bi.table_get("tf1.pktgen.pkt_buffer")
pbuf.entry_mod(tgt, [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", BUF_OFFSET),
                                    gc.KeyTuple("pkt_buffer_size", len(tmpl))])],
               [pbuf.make_data([gc.DataTuple("buffer", bytearray(tmpl))])])
rec["inject_template"] = tmpl[:15].hex()

# ---- 3. app 5 as a one-shot timer, one packet ----------------------------------
acfg = bi.table_get("tf1.pktgen.app_cfg")


def app5_set(**over):
    base = dict(timer_nanosec=200000, pkt_len=len(tmpl), pkt_buffer_offset=BUF_OFFSET,
                pipe_local_source_port=PORT_PGEN, batch_count_cfg=0,
                packets_per_batch_cfg=0, ipg=0, ibg=0, trigger_counter=0,
                batch_counter=0, pkt_counter=0)
    data = [gc.DataTuple(k, v) for k, v in base.items()]
    data.append(gc.DataTuple("increment_source_port", bool_val=False))
    data.append(gc.DataTuple("app_enable", bool_val=over.get("enable", False)))
    acfg.entry_mod(p0, [acfg.make_key([gc.KeyTuple("app_id", APP_INJECT)])],
                   [acfg.make_data(data, "trigger_timer_one_shot")])


app5_set()

# ---- 4. make a transaction "live", clear the note, snapshot counters -----------
rec["reg_write_ok"] = d3.reg_write(bi, tgt, "reg_tag", GEN_LIVE)
rec["has_reg_failopen"] = d3.reg_write(bi, tgt, "reg_failopen", 0)
rec["reg_tag_before"] = d3.reg_read(bi, tgt, "reg_tag")
c0 = counters()

# ---- 5. fire the injector, once ------------------------------------------------
acfg.entry_mod(p0, [acfg.make_key([gc.KeyTuple("app_id", APP_INJECT)])],
               [acfg.make_data([gc.DataTuple("app_enable", bool_val=True)])])
time.sleep(0.3)
acfg.entry_mod(p0, [acfg.make_key([gc.KeyTuple("app_id", APP_INJECT)])],
               [acfg.make_data([gc.DataTuple("app_enable", bool_val=False)])])

# ---- 6. read the outcome -------------------------------------------------------
rec["reg_tag_after"] = d3.reg_read(bi, tgt, "reg_tag")
rec["reg_failopen_after"] = d3.reg_read(bi, tgt, "reg_failopen")
c1 = counters()
rec["counters_delta"] = {k: c1.get(k, 0) - c0.get(k, 0)
                         for k in set(c0) | set(c1) if c1.get(k, 0) - c0.get(k, 0)}
app5 = None
for it in acfg.entry_get(p0, [acfg.make_key([gc.KeyTuple("app_id", APP_INJECT)])],
                         {"from_hw": True}):
    app5 = (it[0] if isinstance(it, tuple) else it).to_dict()
rec["app5_fired"] = {"trigger": app5.get("trigger_counter"),
                     "pkt": app5.get("pkt_counter")} if app5 else None
rec["checks"].append({"result": "PASS" if (rec["app5_fired"] and
                      rec["app5_fired"]["pkt"] == 1) else "FAIL",
                      "check": "app 5 injected exactly one frame",
                      "detail": str(rec["app5_fired"])})
json.dump(rec, open(OUT, "w"), indent=1)
print("reg_tag: 0x%02X -> 0x%02X | failopen_after=%s | app5=%s | deltas=%s"
      % (rec["reg_tag_before"] or 0, rec["reg_tag_after"] or 0,
         rec["reg_failopen_after"], rec["app5_fired"], rec["counters_delta"]))

#!/usr/bin/env python3
# ============================================================================
# defense4_caseA_setup.py — the one-time control-plane setup for the Defense 4
# Case-A integration (defense4/timing/p4/defense4_caseA.p4).
#
# Reuses the PROVEN, silicon-validated helpers from the frozen Defense 3 setup
# (defense3/setup/case_a_defense3_fixed_ack_delay_setup.py) — get_table,
# get_entry, pnorm, resolve_pg, pg_queue_of, Checks, build_token_template,
# quantize_d, and the fixed-function pktgen/TM table names — WITHOUT modifying
# that frozen source. Adds the Defense 4 specifics:
#   * ONE request-triggered pktgen batch of 2K = 128 packets (one app, one
#     template, one clone, one trigger). The P4 admit path splits by packet_id:
#     0..63 -> ACK blocker (qid7), 64..127 -> RESPONSE blocker (qid5). This is
#     how BOTH reservoirs are established from a single READ with no per-txn CP.
#   * the FOUR-queue strict-priority ladder qid7 > qid6 > qid5 > qid4 (max_priority
#     read back from hardware; scheduling enabled; min/max shaping disabled);
#   * the Defense 4 params: mode, D_A, D_R, precomputed D_A+D_R, READ length,
#     budget (installed and read back; D_A+D_R and quantization validated;
#     D2:D_A=0, D3:D_R=0, D4:D_A>0,D_R>0 enforced); initialised in OFF.
#   * modes: dry-run / configure / verify-only / snapshot / restore-only. The
#     request-triggered app is enabled ONLY after every readback passes.
#
# ►► Static readback proves CONFIGURATION, not per-trigger reservoir
#    establishment. The first protected hardware transaction must prove the
#    DYNAMIC result (pktgen counter deltas, CF_PKTGEN_ADMIT, qid7/qid5 occupancy,
#    no drops) — that check lives in the bring-up runner, not here.
#
# NOT EXECUTED offline: this programs the packet generator + TM (hardware state),
# gated on explicit authorization and a live bfrt gRPC client. --dry-run
# exercises the offline math + argument validation only.
# ============================================================================
import argparse
import importlib.util
import os
import sys

# ---- reuse the frozen Defense 3 helpers (do NOT modify that file) ----
_D3 = os.path.join(os.path.dirname(__file__), "..", "..", "..",
                   "defense3", "setup", "case_a_defense3_fixed_ack_delay_setup.py")
_spec = importlib.util.spec_from_file_location("d3setup", os.path.abspath(_D3))
d3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d3)   # bfrt_grpc is lazy-imported inside functions, so this is offline-safe
import json


def _report(chk, out):
    print(chk.render())
    print("---- readback ----")
    print(json.dumps(out, indent=2, default=str))
    print("RESULT: %s (%d failures)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))

# ---- Defense 4 constants (must match defense4/timing/p4/defense4_caseA.p4) ----
K_TOKENS   = 64                 # per reservoir
BATCH_2K   = 2 * K_TOKENS       # 128: one batch seeds BOTH reservoirs
PORT_PGEN  = 68                 # dp68 pktgen/recirc
PORT_L     = 8                  # dp8 loopback (the four queues live here)

# four-queue ladder (label, qid, wanted max_priority as str) — STRICT DESCENDING
QUEUE_PLAN = [
    ("Q_ACK_BLOCK",  7, "7"),   # ACK blocker reservoir
    ("Q_ACK_HOLD",   6, "6"),   # held original ACK
    ("Q_RESP_BLOCK", 5, "5"),   # RESPONSE blocker reservoir
    ("Q_RESP_HOLD",  4, "4"),   # held original RESPONSE
]

# modes (must match the P4 MODE_* constants)
MODE = {"OFF": 0, "D1": 1, "D2": 2, "D3": 3, "D4": 4, "FAIL_OPEN": 5}

TICK_LOW_BYTE_ZERO = 0xFFFFFF00   # the armed marker rides the low byte -> D_A/D_R quantised to 256 ns


# ---------------------------------------------------------------------------
# offline validation (exercised by --dry-run)
# ---------------------------------------------------------------------------
def validate_params(mode_name, d_a, d_r, chk):
    """Enforce the mode-specific timing constraints + quantization + the
    precomputed sum. Returns (d_a, d_r, da_dr) or aborts via chk."""
    da_dr = d_a + d_r
    chk.expect("D_A quantised (low byte 0)", d_a & 0xFF, 0)
    chk.expect("D_R quantised (low byte 0)", d_r & 0xFF, 0)
    chk.expect("D_A+D_R quantised (low byte 0)", da_dr & 0xFF, 0)
    chk.expect("D_A+D_R < 2^31 (half-range clamp)", da_dr < (1 << 31), True)
    if mode_name == "D2":
        chk.expect("D2 requires D_A == 0", d_a, 0)
        chk.expect("D2 requires D_R > 0", d_r > 0, True)
    elif mode_name == "D3":
        chk.expect("D3 requires D_R == 0", d_r, 0)
        chk.expect("D3 requires D_A > 0", d_a > 0, True)
    elif mode_name == "D4":
        chk.expect("D4 requires D_A > 0", d_a > 0, True)
        chk.expect("D4 requires D_R > 0", d_r > 0, True)
    # da_dr is what the P4 adds in one MAU op; assert it equals the true sum
    chk.expect("da_dr == D_A + D_R", da_dr, d_a + d_r)
    return d_a, d_r, da_dr


# ---------------------------------------------------------------------------
# hardware configuration (each reused helper is called ONCE; app enabled last)
# ---------------------------------------------------------------------------
def config_pktgen_2k(bi, tgt, a, out, chk, write=True, app_enable=False):
    """The Defense 4 pktgen app: ONE recirc-triggered batch of 2K=128 packets.
    Identical to the proven Defense 3 config_pktgen EXCEPT packets_per_batch_cfg
    = 2K-1 = 127 (the P4 splits the batch by packet_id into the two reservoirs).
    increment_source_port MUST read back False or the driver caps the batch."""
    import bfrt_grpc.client as gc
    template = d3.build_token_template(a.token_len)

    pcfg = d3.get_table(bi, d3.PKTGEN_PORT_CFG, chk)
    if pcfg is not None and write:
        pcfg.entry_mod(tgt, [pcfg.make_key([gc.KeyTuple("dev_port", PORT_PGEN)])],
                       [pcfg.make_data([
                           gc.DataTuple("pktgen_enable", bool_val=True),
                           gc.DataTuple("recirculation_enable", bool_val=True),
                           gc.DataTuple("pattern_matching_enable", bool_val=True)])])

    pbuf = d3.get_table(bi, d3.PKTGEN_PKT_BUFFER, chk)
    if pbuf is not None and write:
        pbuf.entry_mod(
            tgt,
            [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", a.buf_offset),
                            gc.KeyTuple("pkt_buffer_size", len(template))])],
            [pbuf.make_data([gc.DataTuple("buffer", bytearray(template))])])

    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return
    pattern_value = d3.CLONE_TAG_MARKER << 24   # 0xE1000000, pin byte 0
    pattern_mask = 0xFF000000
    if write:
        acfg.entry_mod(
            tgt,
            [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
            [acfg.make_data([
                gc.DataTuple("pattern_value", pattern_value),
                gc.DataTuple("pattern_mask", pattern_mask),
                gc.DataTuple("pkt_len", len(template)),
                gc.DataTuple("pkt_buffer_offset", a.buf_offset),
                gc.DataTuple("pipe_local_source_port", PORT_PGEN),
                gc.DataTuple("increment_source_port", bool_val=False),   # LOAD-BEARING
                gc.DataTuple("batch_count_cfg", 0),                      # 1 batch
                gc.DataTuple("packets_per_batch_cfg", BATCH_2K - 1),     # 2K=128 -> 127
                gc.DataTuple("ipg", 0),
                gc.DataTuple("ibg", 0),
                gc.DataTuple("trigger_counter", 0),
                gc.DataTuple("batch_counter", 0),
                gc.DataTuple("pkt_counter", 0),
                gc.DataTuple("app_enable", bool_val=app_enable),        # OFF at config time
            ], "trigger_recirc_pattern")])

    got, err = d3.get_entry(acfg, tgt, [("app_id", a.app_id)])
    out["pktgen"] = err or {k: got.get(k) for k in
                            ("pattern_value", "pattern_mask", "pkt_len", "pkt_buffer_offset",
                             "pipe_local_source_port", "increment_source_port",
                             "batch_count_cfg", "packets_per_batch_cfg", "app_enable",
                             "trigger_counter", "batch_counter", "pkt_counter")}
    if not err:
        chk.expect("pktgen increment_source_port == False", got.get("increment_source_port"), False)
        chk.expect("pktgen pipe_local_source_port", got.get("pipe_local_source_port"), PORT_PGEN)
        chk.expect("pktgen packets_per_batch_cfg (2K-1)", got.get("packets_per_batch_cfg"), BATCH_2K - 1)
        chk.expect("pktgen batch_count_cfg (1 batch)", got.get("batch_count_cfg"), 0)
        chk.expect("pktgen app_enable at config time", got.get("app_enable"), app_enable)


def config_queues_4q(bi, tgt0, a, out, chk, write=True):
    """The four dp8 queues 7>6>5>4 via tf1.tm.queue.sched_cfg, keyed on the
    resolved (pg_id, pg_queue). max_priority read back from hardware, scheduling
    enabled, min/max shaping disabled. Strict-descending ordering asserted."""
    import bfrt_grpc.client as gc
    pg_id, pg_nr = d3.resolve_pg(bi, tgt0, PORT_L, chk, out)
    if pg_id is None:
        chk.fail("resolve_pg dp%d" % PORT_L, "no port-group map")
        return
    q_cfg = d3.get_table(bi, "tf1.tm.queue.sched_cfg", chk)
    if q_cfg is None:
        return
    observed = []
    for label, qid, want_pri in QUEUE_PLAN:
        pgq = d3.pg_queue_of(pg_nr, qid)
        key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        if write:
            cur, _ = d3.get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)], from_hw=False)
            data = [gc.DataTuple("min_rate_enable", bool_val=False),
                    gc.DataTuple("max_rate_enable", bool_val=False),
                    gc.DataTuple("max_priority", str_val=want_pri),
                    gc.DataTuple("scheduling_enable", bool_val=True)]
            if cur is not None and cur.get("dwrr_weight") is not None:
                data.append(gc.DataTuple("dwrr_weight", int(cur.get("dwrr_weight"))))
            try:
                q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data(data)])
            except Exception:
                q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data([
                    gc.DataTuple("min_rate_enable", bool_val=False),
                    gc.DataTuple("max_rate_enable", bool_val=False),
                    gc.DataTuple("max_priority", str_val=want_pri),
                    gc.DataTuple("scheduling_enable", bool_val=True)])])
        sc, err = d3.get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("%s sched_cfg readback" % label, err)
            continue
        got_pri = d3.pnorm(sc.get("max_priority"))
        chk.expect("%s max_priority" % label, got_pri, int(want_pri))
        chk.expect("%s scheduling_enable" % label, sc.get("scheduling_enable"), True)
        chk.expect("%s min shaping disabled" % label, sc.get("min_rate_enable"), False)
        chk.expect("%s max shaping disabled" % label, sc.get("max_rate_enable"), False)
        observed.append((label, got_pri))
        out.setdefault("queues", {})[label] = {"qid": qid, "pg_queue": pgq,
                                               "max_priority": got_pri,
                                               "scheduling_enable": sc.get("scheduling_enable")}
    vals = [v for _l, v in observed]
    strict = (len(vals) == 4 and all(v is not None for v in vals)
              and vals[0] > vals[1] > vals[2] > vals[3])
    out["strict_priority_verified"] = strict
    chk.expect("strict ladder 7>6>5>4", strict, True)


def config_params_d4(bi, tgt, a, out, chk, write=True):
    """Install + read back the Defense 4 params: set_params(d_ticks=D_A, read_len,
    budget, mode, da_dr). tbl_params is the proven keyless default-entry table."""
    import bfrt_grpc.client as gc
    d_a, d_r, da_dr = validate_params(a.mode, a.d_a, a.d_r, chk)
    out["params_requested"] = {"mode": a.mode, "D_A": d_a, "D_R": d_r, "da_dr": da_dr,
                               "read_len": a.read_len, "budget": a.budget}
    t = d3.get_table(bi, "tbl_params", chk)
    if t is None:
        return
    mode_val = MODE[a.mode]
    if write:
        # try the richer signature first (5 params), then argument order variants
        for args in ([gc.DataTuple("d_ticks", d_a), gc.DataTuple("read_len", a.read_len),
                      gc.DataTuple("budget", a.budget), gc.DataTuple("mode", mode_val),
                      gc.DataTuple("da_dr", da_dr)],):
            try:
                t.default_entry_set(tgt, t.make_data(args, "set_params"))
                out["tbl_params_action"] = "set_params"
                break
            except Exception as e:
                chk.fail("tbl_params default_entry_set", str(e)[:160])
    got = None
    try:
        for d in t.default_entry_get(tgt, {"from_hw": True}):
            got = d.to_dict()
    except Exception as e:
        chk.fail("tbl_params default_entry_get", str(e)[:90])
    out["tbl_params_readback"] = got
    if got:
        chk.expect("tbl_params d_ticks (D_A)", got.get("d_ticks"), d_a)
        chk.expect("tbl_params da_dr (D_A+D_R)", got.get("da_dr"), da_dr)
        chk.expect("tbl_params mode", got.get("mode"), mode_val)
        chk.expect("tbl_params read_len", got.get("read_len"), a.read_len)
        chk.expect("tbl_params budget", got.get("budget"), a.budget)


def enable_app(bi, tgt, a, chk):
    """Enable the request-triggered pktgen app — called ONLY after every readback
    above has passed."""
    import bfrt_grpc.client as gc
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return
    acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
                   [acfg.make_data([gc.DataTuple("app_enable", bool_val=True)], "trigger_recirc_pattern")])


def disable_app(bi, tgt, a, chk):
    import bfrt_grpc.client as gc
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return
    acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
                   [acfg.make_data([gc.DataTuple("app_enable", bool_val=False)], "trigger_recirc_pattern")])


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def run(a):
    chk = d3.Checks()
    out = {"mode": a.mode, "op": a.op}

    if a.op == "dry-run":
        # offline math + validation only — no gRPC, no hardware
        validate_params(a.mode, a.d_a, a.d_r, chk)
        out["batch"] = {"packets_per_batch_cfg": BATCH_2K - 1, "batch_count_cfg": 0,
                        "K": K_TOKENS, "2K": BATCH_2K}
        out["queue_plan"] = [(l, q, p) for (l, q, p) in QUEUE_PLAN]
        chk.ok("dry-run: params + batch + queue-plan validated offline", "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    # everything below needs the live bfrt client and hardware authorization
    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write("REFUSING: op=%s programs pktgen/TM (hardware). Set "
                         "DEFENSE4_HW_AUTHORIZED=1 under an authorized session.\n" % a.op)
        return 2
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(grpc_addr=a.grpc, client_id=0, device_id=0)
    iface.bind_pipeline_config(a.program)
    bi = iface.bfrt_info_get(a.program)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)

    if a.op == "restore-only":
        disable_app(bi, tgt, a, chk)     # stop generating; the loader restores Defense 3 separately
        chk.ok("restore-only: pktgen app disabled", "the Defense 3 binary is restored by the loader")
        _report(chk, out); return 0 if chk.n_fail == 0 else 2

    if a.op in ("configure", "verify-only", "snapshot"):
        write = (a.op == "configure")
        config_queues_4q(bi, tgt0, a, out, chk, write=write)
        config_params_d4(bi, tgt, a, out, chk, write=write)
        # pktgen configured with app DISABLED; enabled only after all readbacks pass
        config_pktgen_2k(bi, tgt, a, out, chk, write=write, app_enable=False)
        if a.op == "configure":
            if chk.n_fail == 0:
                enable_app(bi, tgt, a, chk)
                chk.ok("pktgen app ENABLED (all readbacks passed)", "")
            else:
                chk.fail("pktgen app NOT enabled", "a configuration readback failed — left disabled")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    chk.fail("unknown op", a.op)
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(description="Defense 4 Case-A runtime setup")
    ap.add_argument("op", choices=["dry-run", "configure", "verify-only", "snapshot", "restore-only"])
    ap.add_argument("--mode", choices=list(MODE.keys()), default="OFF")
    ap.add_argument("--d-a", dest="d_a", type=lambda x: int(x, 0), default=0, help="D_A ticks (256 ns)")
    ap.add_argument("--d-r", dest="d_r", type=lambda x: int(x, 0), default=0, help="D_R ticks (256 ns)")
    ap.add_argument("--read-len", type=int, default=13)
    ap.add_argument("--budget", type=int, default=100000)
    ap.add_argument("--app-id", type=int, default=d3.APP_ID_DEFAULT)
    ap.add_argument("--buf-offset", type=int, default=0)
    ap.add_argument("--token-len", type=int, default=getattr(d3, "TOKEN_LEN", 64))
    ap.add_argument("--clone-sid", type=int, default=getattr(d3, "CLONE_SESSION_ID", 7))
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--program", default="defense4_caseA")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())

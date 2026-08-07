#!/usr/bin/env python3
# ============================================================================
# defense4_caseA_setup.py — the one-time control-plane setup for the Defense 4
# Case-A integration (defense4/timing/p4/defense4_caseA.p4).
#
# Reuses the PROVEN, silicon-validated helpers + config functions from the frozen
# Defense 3 setup (defense3/setup/case_a_defense3_fixed_ack_delay_setup.py) —
# WITHOUT modifying that frozen source — for the shared fixed-function state:
# tbl_session, the dp68 mirror session, the parser value_set, the pktgen port
# flags/template/source-port, dp8 speed + port-shaper safety, and register/counter
# clearing. It ADDS the Defense 4 specifics:
#   * ONE request-triggered pktgen batch of 2K=128 (batch_count_cfg=0,
#     packets_per_batch_cfg=127) — the P4 splits by packet_id: 0..63 -> ACK
#     blocker (qid7), 64..127 -> RESPONSE blocker (qid5). Both reservoirs from a
#     single READ, no per-transaction control-plane action;
#   * the FOUR-queue strict-priority ladder qid7 > qid6 > qid5 > qid4 (max_priority
#     read back from hardware; scheduling enabled; min/max shaping disabled);
#   * the Defense 4 params mode/D_A/D_R/(D_A+D_R)/read_len/budget (installed and
#     read back; the P4 stores D_A and D_A+D_R, so effective D_R is verified as
#     da_dr - D_A — no extra P4 parameter). D2:D_A=0, D3:D_R=0, D4:both>0 enforced;
#   * reg_tresp added to the cleared-register set;
#   * op semantics: OFF/FAIL_OPEN -> pktgen DISABLED; D1..D4 -> pktgen enabled ONLY
#     after every readback passes, then an explicit enabled-state readback;
#     verify-only checks the EXPECTED enabled state for the mode; snapshot writes the
#     actual pre-change pktgen/mirror/port/qid7-6-5-4 TM state to JSON; restore-only
#     consumes that JSON and restores the fixed-function state.
#
# ►► Static readback proves CONFIGURATION, not per-trigger reservoir establishment.
#    The first protected READ proves the DYNAMIC result (pktgen deltas,
#    CF_PKTGEN_ADMIT, qid7/qid5 occupancy, no drops) in the bring-up runner.
#
# --dry-run is offline (no gRPC). Every hardware op refuses without
# DEFENSE4_HW_AUTHORIZED=1 and a live bfrt gRPC client.
# ============================================================================
import argparse
import importlib.util
import json
import os
import sys

# Resolve the frozen Defense 3 setup module. When staged on the switch it is a SIBLING
# in the same directory; in the repo it is at ../../../defense3/setup/. Honor an explicit
# override first, then the co-located sibling, then the repo-relative path.
_HERE = os.path.dirname(os.path.abspath(__file__))
_D3NAME = "case_a_defense3_fixed_ack_delay_setup.py"
_D3CANDS = [os.environ.get("D4_D3SETUP", ""),
            os.path.join(_HERE, _D3NAME),
            os.path.abspath(os.path.join(_HERE, "..", "..", "..", "defense3", "setup", _D3NAME))]
_D3PATH = next((p for p in _D3CANDS if p and os.path.isfile(p)), _D3CANDS[-1])
_spec = importlib.util.spec_from_file_location("d3setup", _D3PATH)
d3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d3)     # bfrt_grpc lazy-imported inside functions -> import is offline-safe

# ---- Defense 4 constants (must match defense4/timing/p4/defense4_caseA.p4) ----
K_TOKENS = 64
BATCH_2K = 2 * K_TOKENS          # 128: one batch seeds BOTH reservoirs
PORT_L   = getattr(d3, "PORT_L", 8)
PORT_PGEN = getattr(d3, "PORT_PGEN", 68)

QUEUE_PLAN = [                    # (label, qid, wanted max_priority str) STRICT DESCENDING
    ("Q_ACK_BLOCK",  7, "7"),
    ("Q_ACK_HOLD",   6, "6"),
    ("Q_RESP_BLOCK", 5, "5"),
    ("Q_RESP_HOLD",  4, "4"),
]
MODE = {"OFF": 0, "D1": 1, "D2": 2, "D3": 3, "D4": 4, "FAIL_OPEN": 5}
PKTGEN_ENABLED_MODES = {"D1", "D2", "D3", "D4"}   # OFF / FAIL_OPEN keep pktgen DISABLED
# ctr_fresh (CF_*) indices — mirror defense3/control/counter_map.py, verified by d3's
# own map assertion at setup time. Only the two the bring-up scores are named here.
CF_PKTGEN_ADMIT = 13
CF_PKTGEN_DROP  = 14
# reg_tresp is the Defense 4 addition to the frozen Defense 3 REGS_ZERO set
REGS_ZERO_D4 = tuple(getattr(d3, "REGS_ZERO", ())) + ("reg_tresp",)


def _report(chk, out):
    print(chk.render())
    print("---- readback ----")
    print(json.dumps(out, indent=2, default=str))
    print("RESULT: %s (%d failures)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))


# ---------------------------------------------------------------------------
# offline validation (exercised by --dry-run)
# ---------------------------------------------------------------------------
def validate_params(mode_name, d_a, d_r, chk):
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
    # the P4 stores D_A and D_A+D_R; effective D_R is derived, never a 2nd P4 param
    chk.expect("effective D_R == da_dr - D_A", da_dr - d_a, d_r)
    return d_a, d_r, da_dr


# ---------------------------------------------------------------------------
# B2 — parameter handling with the proven quantization authority (real ms units)
# ---------------------------------------------------------------------------
def resolve_delays(a, chk=None):
    """Resolve D_A and D_R to the P4 deadline WORDS (nanoseconds, low byte zero).

    The P4 addend `d_ticks`/`da_dr` is the delay in NANOSECONDS quantised to the 256 ns
    grid (word = ticks<<8; e.g. 2 ms -> 1,999,872). Prefer millisecond input via the
    proven d3.quantize_d authority; a raw --d-a/--d-r is accepted as an already-encoded
    word (ns) for expert use. Returns (da_word, dr_word, dadr_word, breakdown)."""
    def one(ms, word_raw, name):
        if ms is not None:
            q = d3.quantize_d(float(ms))          # enforces low-byte-zero + <=40 ms clamp
            q["source"] = "ms"; q["name"] = name
            return q["word"], q
        # raw word path: must already be a valid ns word with a zero low byte
        w = int(word_raw)
        return w, {"name": name, "source": "word", "requested_ms": w / 1e6,
                   "word": w, "word_hex": "0x%08X" % w, "ticks": w >> 8,
                   "realized_ns": w, "realized_ms": w / 1e6,
                   "quantization_error_ns": 0, "low_byte_zero": (w & 0xFF) == 0}
    da_word, qa = one(getattr(a, "d_a_ms", None), a.d_a, "D_A")
    dr_word, qr = one(getattr(a, "d_r_ms", None), a.d_r, "D_R")
    dadr = da_word + dr_word
    poll_ms = getattr(a, "poll_ms", 400.0)
    try:
        H = d3.failopen_horizon(a.budget)
        H_ms = H["horizon_ms"] if isinstance(H, dict) else float(H)
    except Exception:
        H_ms = None
    breakdown = {
        "D_A": qa, "D_R": qr,
        "da_dr_word": dadr, "da_dr_hex": "0x%08X" % dadr,
        "da_dr_realized_ms": dadr / 1e6,
        "poll_interval_ms": poll_ms,
        "da_dr_vs_poll": "%.3f ms of %.1f ms poll (%.1f%%)" % (dadr / 1e6, poll_ms, 100.0 * (dadr / 1e6) / poll_ms),
        "failopen_horizon_ms": H_ms,
        "da_dr_vs_horizon": (None if H_ms is None else "%.3f ms vs H=%.3f ms" % (dadr / 1e6, H_ms)),
    }
    if chk is not None:
        chk.expect("D_A word low byte 0", da_word & 0xFF, 0)
        chk.expect("D_R word low byte 0", dr_word & 0xFF, 0)
        chk.expect("da_dr low byte 0", dadr & 0xFF, 0)
        chk.expect("da_dr < 2^31 (modular half-range)", dadr < (1 << 31), True)
        chk.expect("da_dr < poll interval (no poll overlap)", (dadr / 1e6) < poll_ms, True)
    return da_word, dr_word, dadr, breakdown


def txn_active(bi, tgt):
    """True if a transaction is in flight (reg_tag != TAG_INACTIVE). set-policy /
    clear-evidence refuse while this holds, so live transaction state is never disturbed."""
    try:
        v = d3.reg_read(bi, tgt, getattr(d3, "REG_TAG", "reg_tag"))
        return int(v) != getattr(d3, "TAG_INACTIVE", 0)
    except Exception:
        return True   # fail safe: if we cannot read the tag, assume active and refuse


def clear_evidence_only(bi, tgt, chk):
    """Clear ONLY counters and sparse evidence-timestamp registers at a campaign boundary.
    Does NOT touch reg_tag, reg_deadline, reg_tresp, reg_ack_rel or the session trackers."""
    n = 0
    for i in range(32):
        try:
            d3.ctr_zero(bi, tgt, "ctr_fresh", i); n += 1
        except Exception:
            break
    for i in range(16):
        try:
            d3.ctr_zero(bi, tgt, "ctr_deq", i)
        except Exception:
            break
    for r in ("reg_ts_first_block", "reg_ts_ack_arm", "reg_ts_block_term", "reg_ts_ack_release"):
        try:
            d3.reg_write(bi, tgt, r, 0, chk=None)
        except Exception:
            pass
    chk.ok("evidence cleared (counters + ts regs only)", "reg_tag/deadlines/trackers untouched")


# ---------------------------------------------------------------------------
# Defense 4 specifics (the shared fixed-function state reuses d3.* functions)
# ---------------------------------------------------------------------------
def config_pktgen_2k(bi, tgt, a, out, chk, write=True, app_enable=False):
    """Defense 4 pktgen app: ONE recirc-triggered batch of 2K=128 (the P4 splits
    it by packet_id). Same proven idiom as d3.config_pktgen except packets_per_batch
    = 2K-1 = 127. increment_source_port MUST read back False (else the driver caps)."""
    import bfrt_grpc.client as gc
    template = d3.build_token_template(a.token_len)
    pcfg = d3.get_table(bi, d3.PKTGEN_PORT_CFG, chk)
    if pcfg is not None and write:
        pcfg.entry_mod(tgt, [pcfg.make_key([gc.KeyTuple("dev_port", a.port_pgen)])],
                       [pcfg.make_data([gc.DataTuple("pktgen_enable", bool_val=True),
                                        gc.DataTuple("recirculation_enable", bool_val=True),
                                        gc.DataTuple("pattern_matching_enable", bool_val=True)])])
    pbuf = d3.get_table(bi, d3.PKTGEN_PKT_BUFFER, chk)
    if pbuf is not None and write:
        pbuf.entry_mod(tgt,
                       [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", a.buf_offset),
                                       gc.KeyTuple("pkt_buffer_size", len(template))])],
                       [pbuf.make_data([gc.DataTuple("buffer", bytearray(template))])])
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return
    if write:
        acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
                       [acfg.make_data([
                           gc.DataTuple("pattern_value", d3.CLONE_TAG_MARKER << 24),
                           gc.DataTuple("pattern_mask", 0xFF000000),
                           gc.DataTuple("pkt_len", len(template)),
                           gc.DataTuple("pkt_buffer_offset", a.buf_offset),
                           gc.DataTuple("pipe_local_source_port", a.port_pgen),
                           gc.DataTuple("increment_source_port", bool_val=False),
                           gc.DataTuple("batch_count_cfg", 0),
                           gc.DataTuple("packets_per_batch_cfg", BATCH_2K - 1),  # 127
                           gc.DataTuple("ipg", 0), gc.DataTuple("ibg", 0),
                           gc.DataTuple("trigger_counter", 0), gc.DataTuple("batch_counter", 0),
                           gc.DataTuple("pkt_counter", 0),
                           gc.DataTuple("app_enable", bool_val=app_enable)],
                          "trigger_recirc_pattern")])
    got, err = d3.get_entry(acfg, tgt, [("app_id", a.app_id)])
    out["pktgen"] = err or {k: got.get(k) for k in
                            ("pattern_value", "pattern_mask", "pkt_len", "pkt_buffer_offset",
                             "pipe_local_source_port", "increment_source_port",
                             "batch_count_cfg", "packets_per_batch_cfg", "app_enable")}
    if not err:
        chk.expect("pktgen increment_source_port == False", got.get("increment_source_port"), False)
        chk.expect("pktgen packets_per_batch_cfg (2K-1)", got.get("packets_per_batch_cfg"), BATCH_2K - 1)
        chk.expect("pktgen batch_count_cfg (1 batch)", got.get("batch_count_cfg"), 0)
        chk.expect("pktgen app_enable at config time", got.get("app_enable"), app_enable)


def _q_cfg_read(bi, tgt0, a, chk):
    """Return {label: sched_cfg dict} for the four queues (resolved pg_id/pg_queue)."""
    pg_id, pg_nr = d3.resolve_pg(bi, tgt0, a.port_l, chk, {})
    q_cfg = d3.get_table(bi, "tf1.tm.queue.sched_cfg", chk)
    res = {}
    if pg_id is None or q_cfg is None:
        return None, None, res, q_cfg
    for label, qid, _p in QUEUE_PLAN:
        pgq = d3.pg_queue_of(pg_nr, qid)
        sc, err = d3.get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        res[label] = {"pg_queue": pgq, "qid": qid, "err": err,
                      "max_priority": (None if err else sc.get("max_priority")),
                      "min_rate_enable": (None if err else sc.get("min_rate_enable")),
                      "max_rate_enable": (None if err else sc.get("max_rate_enable")),
                      "scheduling_enable": (None if err else sc.get("scheduling_enable")),
                      "dwrr_weight": (None if err else sc.get("dwrr_weight"))}
    return pg_id, pg_nr, res, q_cfg


def config_queues_4q(bi, tgt0, a, out, chk, write=True):
    import bfrt_grpc.client as gc
    pg_id, pg_nr, _res, q_cfg = _q_cfg_read(bi, tgt0, a, chk)
    if pg_id is None or q_cfg is None:
        chk.fail("resolve dp%d queues" % a.port_l, "no port-group map / sched_cfg")
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
            chk.fail("%s sched_cfg readback" % label, err); continue
        got_pri = d3.pnorm(sc.get("max_priority"))
        chk.expect("%s max_priority" % label, got_pri, int(want_pri))
        chk.expect("%s scheduling_enable" % label, sc.get("scheduling_enable"), True)
        chk.expect("%s min shaping disabled" % label, sc.get("min_rate_enable"), False)
        chk.expect("%s max shaping disabled" % label, sc.get("max_rate_enable"), False)
        observed.append((label, got_pri))
        out.setdefault("queues", {})[label] = {"qid": qid, "pg_queue": pgq, "max_priority": got_pri}
    vals = [v for _l, v in observed]
    strict = (len(vals) == 4 and all(v is not None for v in vals)
              and vals[0] > vals[1] > vals[2] > vals[3])
    out["strict_priority_verified"] = strict
    chk.expect("strict ladder 7>6>5>4", strict, True)


def config_params_d4(bi, tgt, a, out, chk, write=True):
    import bfrt_grpc.client as gc
    # B2: resolve delays to P4 words (ns) via the quantization authority + print realized units
    d_a, d_r, da_dr, breakdown = resolve_delays(a, chk)
    validate_params(a.mode, d_a, d_r, chk)
    out["params_realized"] = breakdown
    out["params_requested"] = {"mode": a.mode, "D_A_word": d_a, "D_R_word": d_r, "da_dr_word": da_dr,
                               "D_A_ms": breakdown["D_A"]["realized_ms"],
                               "D_R_ms": breakdown["D_R"]["realized_ms"],
                               "read_len": a.read_len, "budget": a.budget}
    t = d3.get_table(bi, "tbl_params", chk)
    if t is None:
        return
    mode_val = MODE[a.mode]
    if write:
        try:
            t.default_entry_set(tgt, t.make_data(
                [gc.DataTuple("d_ticks", d_a), gc.DataTuple("read_len", a.read_len),
                 gc.DataTuple("budget", a.budget), gc.DataTuple("mode", mode_val),
                 gc.DataTuple("da_dr", da_dr)], "set_params"))
        except Exception as e:
            chk.fail("tbl_params default_entry_set", str(e)[:160])
    got = None
    try:
        for item in t.default_entry_get(tgt, {"from_hw": True}):
            d = item[0] if isinstance(item, tuple) else item   # yields (data, key) tuples
            if d is not None:
                got = d.to_dict()
    except Exception as e:
        chk.fail("tbl_params default_entry_get", str(e)[:90])
    out["tbl_params_readback"] = got
    if got:
        chk.expect("tbl_params d_ticks (D_A)", got.get("d_ticks"), d_a)
        chk.expect("tbl_params da_dr (D_A+D_R)", got.get("da_dr"), da_dr)
        chk.expect("effective D_R (da_dr - D_A)", got.get("da_dr", 0) - got.get("d_ticks", 0), d_r)
        chk.expect("tbl_params mode", got.get("mode"), mode_val)
        chk.expect("tbl_params read_len", got.get("read_len"), a.read_len)
        chk.expect("tbl_params budget", got.get("budget"), a.budget)


def clear_state(bi, tgt, chk):
    """Zero the Defense 4 register/counter state (reg_deadline, reg_tresp, reg_ack_rel,
    reg_exp_*, reg_session_port, reg_ts_*, reg_failopen) + reg_tag -> TAG_INACTIVE."""
    for r in REGS_ZERO_D4:
        d3.reg_write(bi, tgt, r, 0, chk=chk)
    try:
        d3.reg_write(bi, tgt, "reg_failopen", 0, chk=chk)
    except Exception:
        pass
    d3.reg_write(bi, tgt, getattr(d3, "REG_TAG", "reg_tag"), getattr(d3, "TAG_INACTIVE", 0), chk=chk)
    for i in range(32):
        try:
            d3.ctr_zero(bi, tgt, "ctr_fresh", i)
        except Exception:
            break
    for i in range(16):
        try:
            d3.ctr_zero(bi, tgt, "ctr_deq", i)
        except Exception:
            break
    chk.ok("state cleared", "regs=%s + reg_tag=INACTIVE; counters zeroed" % (REGS_ZERO_D4,))


def app_enable_set(bi, tgt, a, value, chk):
    import bfrt_grpc.client as gc
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        return
    acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
                   [acfg.make_data([gc.DataTuple("app_enable", bool_val=value)], "trigger_recirc_pattern")])
    got, err = d3.get_entry(acfg, tgt, [("app_id", a.app_id)])
    if not err:
        chk.expect("pktgen app_enable readback == %s" % value, got.get("app_enable"), value)


def snapshot_state(bi, tgt, tgt0, a, chk):
    """Capture actual pre-change pktgen / mirror / port / qid7-6-5-4 TM state -> JSON."""
    import bfrt_grpc.client as gc
    snap = {"note": "Defense 4 pre-change fixed-function snapshot for rollback"}
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is not None:
        g, e = d3.get_entry(acfg, tgt, [("app_id", a.app_id)])
        snap["pktgen_app"] = e or {k: g.get(k) for k in
                                   ("app_enable", "packets_per_batch_cfg", "batch_count_cfg",
                                    "pkt_len", "pkt_buffer_offset", "pipe_local_source_port",
                                    "increment_source_port", "pattern_value", "pattern_mask")}
    pcfg = d3.get_table(bi, d3.PKTGEN_PORT_CFG, chk)
    if pcfg is not None:
        g, e = d3.get_entry(pcfg, tgt, [("dev_port", a.port_pgen)])
        snap["pktgen_port"] = e or g
    mtbl = d3.get_table(bi, "$mirror.cfg", chk)
    if mtbl is not None:
        g, e = d3.get_entry(mtbl, tgt, [("$sid", a.clone_sid)])
        snap["mirror"] = e or g
    _pg, _nr, qres, _q = _q_cfg_read(bi, tgt0, a, chk)
    snap["queues"] = qres
    with open(a.snapshot_out, "w") as f:
        json.dump(snap, f, indent=2, default=str)
    chk.ok("snapshot written", a.snapshot_out)
    return snap


def restore_from_snapshot(bi, tgt, tgt0, a, chk):
    """Consume the snapshot JSON and restore the fixed-function state (pktgen app
    disabled + prior batch, queues to prior max_priority). The Defense 3 BINARY is
    restored by the loader/rollback script, not here."""
    import bfrt_grpc.client as gc
    if not os.path.exists(a.snapshot_out):
        chk.fail("restore: snapshot missing", a.snapshot_out); return
    snap = json.load(open(a.snapshot_out))
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    ps = snap.get("pktgen_app") or {}
    if acfg is not None and isinstance(ps, dict) and "app_enable" in ps:
        acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
                       [acfg.make_data([gc.DataTuple("app_enable", bool_val=bool(ps.get("app_enable")))],
                                       "trigger_recirc_pattern")])
        chk.ok("restore pktgen app_enable", str(ps.get("app_enable")))
    _pg, _nr, _q, q_cfg = _q_cfg_read(bi, tgt0, a, chk)
    qs = snap.get("queues") or {}
    if q_cfg is not None and isinstance(qs, dict):
        pg_id, pg_nr = d3.resolve_pg(bi, tgt0, a.port_l, chk, {})
        for label, rec in qs.items():
            mp = rec.get("max_priority") if isinstance(rec, dict) else None
            if mp is None:
                continue
            pgq = rec.get("pg_queue")
            key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
            try:
                q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data(
                    [gc.DataTuple("max_priority", str_val=str(d3.pnorm(mp)))])])
            except Exception as e:
                chk.warn("restore %s max_priority" % label, str(e)[:90])
        chk.ok("restore queues to snapshot max_priority", "")


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def read_evidence(bi, tgt, tgt0, a):
    """READ-ONLY switch-side evidence for the bring-up. Reuses the frozen D3 read
    primitives. watermark_cells is LATCHED and one-way: watermark>0 proves the queue
    WAS occupied (the correct signal for 'qid populated / held'); usage_cells is not
    reasoned from (d3 note: reads 0 even when demonstrably queued). Works on any loaded
    build, so a --op evidence-dump against live Defense 3 also plumbing-tests the reader."""
    import bfrt_grpc.client as gc  # noqa: F401
    ev = {}
    # pktgen app emission counters (pkt_counter delta == 2K == 128 for a D4 seed)
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG)
    if acfg is not None:
        g, err = d3.get_entry(acfg, tgt, [("app_id", a.app_id)])
        ev["pktgen"] = err or {"pkt_counter": g.get("pkt_counter"),
                               "batch_counter": g.get("batch_counter"),
                               "trigger_counter": g.get("trigger_counter"),
                               "app_enable": g.get("app_enable")}
    # ctr_fresh: the admit/drop classification the P4 charges on the reservoir split
    ev["cf_pktgen_admit"] = d3.ctr_read(bi, tgt, "ctr_fresh", CF_PKTGEN_ADMIT)
    ev["cf_pktgen_drop"] = d3.ctr_read(bi, tgt, "ctr_fresh", CF_PKTGEN_DROP)
    # TM per-queue watermark + drops for all four queues qid7/6/5/4 on the loopback pg
    qc = d3.get_table(bi, d3.TM_QUEUE_COUNTER)
    pg_id, pg_nr = d3.resolve_pg(bi, tgt0, a.port_l, d3.Checks(), {})
    ev["queues"] = {}
    if qc is not None and pg_id is not None:
        for (label, qid, _p) in QUEUE_PLAN:
            pgq = d3.pg_queue_of(pg_nr, qid)
            g, err = d3.get_entry(qc, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
            ev["queues"]["qid%d" % qid] = err or {
                "label": label,
                "watermark_cells": g.get("watermark_cells"),
                "drop_count_packets": g.get("drop_count_packets"),
            }
    return ev


def run(a):
    chk = d3.Checks()
    out = {"mode": a.mode, "op": a.op, "pktgen_should_be_enabled": a.mode in PKTGEN_ENABLED_MODES}

    if a.op == "dry-run":
        d_a, d_r, da_dr, breakdown = resolve_delays(a, chk)
        validate_params(a.mode, d_a, d_r, chk)
        out["params_realized"] = breakdown
        out["batch"] = {"packets_per_batch_cfg": BATCH_2K - 1, "K": K_TOKENS, "2K": BATCH_2K}
        out["queue_plan"] = [(l, q, p) for (l, q, p) in QUEUE_PLAN]
        out["regs_zeroed"] = REGS_ZERO_D4
        chk.ok("dry-run: params/batch/queues/reg-set validated offline", "")
        _report(chk, out); return 0 if chk.n_fail == 0 else 2

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

    if a.op == "evidence-dump":
        ev = read_evidence(bi, tgt, tgt0, a)
        # machine-readable single line the runner greps, plus the human report
        print("EVIDENCE " + json.dumps(ev, default=str))
        out["evidence"] = ev
        chk.ok("evidence-dump read (read-only)", "")
        _report(chk, out); return 0

    if a.op == "snapshot":
        snapshot_state(bi, tgt, tgt0, a, chk)
        _report(chk, out); return 0 if chk.n_fail == 0 else 2

    if a.op == "restore-only":
        restore_from_snapshot(bi, tgt, tgt0, a, chk)
        _report(chk, out); return 0 if chk.n_fail == 0 else 2

    want_enabled = a.mode in PKTGEN_ENABLED_MODES

    if a.op == "verify-only":
        d3.config_session(bi, tgt, a, out, chk, write=False)
        d3.config_mirror(bi, tgt, a, out, chk, write=False)
        d3.config_value_set(bi, a, out, chk, write=False)
        config_queues_4q(bi, tgt0, a, out, chk, write=False)
        config_params_d4(bi, tgt, a, out, chk, write=False)
        config_pktgen_2k(bi, tgt, a, out, chk, write=False, app_enable=False)
        # verify the EXPECTED enabled state for the selected mode (not always disabled)
        acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
        if acfg is not None:
            g, e = d3.get_entry(acfg, tgt, [("app_id", a.app_id)])
            if not e:
                chk.expect("pktgen app_enable matches mode (%s)" % a.mode, g.get("app_enable"), want_enabled)
        _report(chk, out); return 0 if chk.n_fail == 0 else 2

    if a.op == "set-policy":
        # B1: change ONLY mode + delays (+ pktgen enable). Refuse while a transaction is
        # active so live reg_tag/deadlines/trackers are never disturbed. No ports, no
        # template, no queue priorities, no clear.
        if txn_active(bi, tgt):
            chk.fail("set-policy refused", "a transaction is active (reg_tag != INACTIVE)")
            _report(chk, out); return 2
        config_params_d4(bi, tgt, a, out, chk, write=True)
        if chk.n_fail == 0:
            app_enable_set(bi, tgt, a, want_enabled, chk)
            chk.ok("policy set: mode=%s pktgen=%s" % (a.mode, "on" if want_enabled else "off"), "")
        else:
            chk.fail("policy NOT applied", "a params readback failed")
        _report(chk, out); return 0 if chk.n_fail == 0 else 2

    if a.op == "clear-evidence":
        # B1: clear counters + sparse ts registers only, and only while inactive.
        if txn_active(bi, tgt):
            chk.fail("clear-evidence refused", "a transaction is active (reg_tag != INACTIVE)")
            _report(chk, out); return 2
        clear_evidence_only(bi, tgt, chk)
        _report(chk, out); return 0 if chk.n_fail == 0 else 2

    # `initialize` (canonical one-time campaign boundary) and `configure` (back-compat alias)
    # do the same full fixed-function + queues + pktgen + clean-state setup.
    if a.op in ("initialize", "configure"):
        # dp8 speed + port-shaper safety first (proven D3 checks)
        d3.assert_dp8_speed(bi, tgt, tgt0, a, out, chk, pre=True)
        d3.config_ports(bi, tgt, a, out, chk, write=True)
        # d3.disarm_port_shaper expects a list of (name, target) tuples, not bare Targets
        d3.disarm_port_shaper(bi, [("pipe0", tgt0), ("device", tgt)], a, out, chk, write=True)
        # the protected session, mirror, value-set (reused D3 config)
        d3.config_session(bi, tgt, a, out, chk, write=True)
        d3.config_mirror(bi, tgt, a, out, chk, write=True)
        d3.config_value_set(bi, a, out, chk, write=True)
        # four queues + params + clean state + pktgen (app DISABLED at config time)
        config_queues_4q(bi, tgt0, a, out, chk, write=True)
        config_params_d4(bi, tgt, a, out, chk, write=True)
        clear_state(bi, tgt, chk)
        config_pktgen_2k(bi, tgt, a, out, chk, write=True, app_enable=False)
        # ENABLE the app ONLY for D1..D4 and ONLY after every readback passed
        if chk.n_fail == 0 and want_enabled:
            app_enable_set(bi, tgt, a, True, chk)
            chk.ok("pktgen ENABLED for mode %s (all readbacks passed)" % a.mode, "")
        elif want_enabled:
            chk.fail("pktgen NOT enabled", "a readback failed — left DISABLED (safe)")
        else:
            app_enable_set(bi, tgt, a, False, chk)   # OFF/FAIL_OPEN: explicitly disabled
            chk.ok("pktgen DISABLED for mode %s (bypass)" % a.mode, "")
        _report(chk, out); return 0 if chk.n_fail == 0 else 2

    chk.fail("unknown op", a.op)
    _report(chk, out); return 2


def main(argv=None):
    ap = argparse.ArgumentParser(description="Defense 4 Case-A runtime setup")
    ap.add_argument("op", choices=["dry-run", "initialize", "set-policy", "clear-evidence",
                                   "configure", "verify-only", "snapshot",
                                   "restore-only", "evidence-dump"])
    ap.add_argument("--mode", choices=list(MODE.keys()), default="OFF")
    # B2: prefer millisecond input (quantised via d3.quantize_d); raw --d-a/--d-r is an
    # already-encoded deadline WORD in ns (low byte zero) for expert use.
    ap.add_argument("--d-a-ms", dest="d_a_ms", type=float, default=None)
    ap.add_argument("--d-r-ms", dest="d_r_ms", type=float, default=None)
    ap.add_argument("--poll-ms", dest="poll_ms", type=float, default=400.0)
    ap.add_argument("--d-a", dest="d_a", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--d-r", dest="d_r", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--read-len", type=int, default=getattr(d3, "READ_LEN_DEFAULT", 13))
    ap.add_argument("--budget", type=int, default=getattr(d3, "BUDGET_DEFAULT", 100000))
    ap.add_argument("--k", type=int, default=K_TOKENS)
    # shared fixed-function args (defaults from the frozen Defense 3 module)
    ap.add_argument("--relay-ip", default=getattr(d3, "RELAY_IP_DEFAULT", "192.168.10.7"))
    ap.add_argument("--master-ip", default=getattr(d3, "MASTER_IP_DEFAULT", "192.168.10.1"))
    ap.add_argument("--app-id", type=int, default=getattr(d3, "APP_ID_DEFAULT", 1))
    ap.add_argument("--pipe", type=int, default=0)
    ap.add_argument("--buf-offset", type=int, default=0)
    ap.add_argument("--token-len", type=int, default=getattr(d3, "TOKEN_LEN", 64))
    ap.add_argument("--clone-sid", type=int, default=getattr(d3, "CLONE_SID", 7))
    ap.add_argument("--mirror-max-len", type=int, default=128)
    ap.add_argument("--port-l", type=int, default=PORT_L)
    ap.add_argument("--port-vision", type=int, default=getattr(d3, "PORT_VISION", 9))
    ap.add_argument("--port-relay", type=int, default=getattr(d3, "PORT_RELAY", 64))
    ap.add_argument("--port-pgen", type=int, default=PORT_PGEN)
    ap.add_argument("--pg-l", type=int, default=2)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--drain-s", type=float, default=0.5)
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--snapshot-out", default="/home/decps/d4_build/d4_snapshot.json")
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--program", default="defense4_caseA")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())

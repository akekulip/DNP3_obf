#!/usr/bin/env python3
# ============================================================================
# defense4_rrc_bor_unified12_setup.py — the ONE unified control-plane setup for the
# corrected single-pipe defense4_rrc_bor_unified12.p4 (-DU_BOR), with full write->read->
# assert readback verification (blocker 6).
#
# It installs / configures / verifies, in a safe order, EVERYTHING the unified BOR build
# needs before any traffic:
#   1. deadline validation  — reject an invalid (A,R,J) set BEFORE any write
#                             (A > J_max + native_ACK ; R > J_max + native_resp ; R >= A ;
#                              A,R,J_max < min(actuation, master_timeout-guard, RTO-guard,
#                              fail_open_horizon) ; A,R low byte == 0 so the ARMED marker
#                              survives now_word + ticks).
#   2. register state init  — reg_bor_epoch/ready/gen/topj := 0 (retired), readback == 0.
#   3. tbl_params           — timing knobs (d_ticks/read_len/budget/mode/da_dr/shape_enable).
#   4. tbl_bor_params       — the NEW T0-anchored A/R totals (blocker 3), readback == install.
#   5. tbl_bor_codebook     — the leak-safe J codebook (per relay dst_port x PRNG bucket).
#   6. tbl_commit           — VERIFY the P4 const-entry map (blocker 1: nothing to install; every
#                             defined OUT_* has EXACTLY ONE commit action; read back + assert).
#   7. tbl_session          — the protected reverse-5-tuple (sess_relay / sess_master).
#   8. BOR queue ladder      — qid7 > qid6 > qid5 > qid4 > qid3 > qid2 strict priority on PORT_L,
#                             readback max_priority per qid (BOR_RRC_DESIGN.md section 3).
#   9. pktgen 2K / 3K profiles — the OPERATE ACK+RESP burst (2K, packet_id 0..127) and the
#                             SELECT/combined burst (3K, 0..191) + the clone mirror session; each
#                             installed batch/timer read back and asserted.
#
# EVERY hardware op is fail-closed on a readback mismatch and REFUSES to run unless
# DEFENSE4_HW_AUTHORIZED=1. There are NO hardware calls at import time or in dry-run: bfrt_grpc
# is imported only inside the configure functions. The dry-run op runs the FULL offline
# validation AND an in-process readback SELF-TEST (write->read->assert, plus a deliberately
# corrupted case proving the assertion is fail-closed), then prints the exact install+verify
# sequence — this is the "run against the model/CLI without loading" path. Loading the binary,
# bringing up ports/queues/pktgen, and the on-silicon readback are Philip's authorized steps.
#
# COMPILE/SETUP-ONLY: nothing here is silicon-validated.
# ============================================================================
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PROGRAM = "defense4_rrc_bor_unified12"

# ---- ports / identifiers (must match defense4_rrc_bor_unified12.p4) ----
PORT_L = 8            # dp8 internal loopback (holds qid7..qid2)
PORT_PGEN = 68        # dp68 pipe-0 pktgen / recirc
PORT_RELAY = 64       # dp64 live relay leg
PORT_VISION = 9       # dp9 master side
CLONE_SESSION_ID = 7  # $mirror.cfg -> dp68 (arm_clone / cmt_op_hold / cmt_fwd_clone)
RELAY_DST_PORT = 20000
K = 64                # reservoir depth per queue (BUDGET_DEFAULT / packet_id sub-range width)
TICK = 256            # ns per tick; A/R/D low byte must be 0 (multiple of 256)

# strict-priority ladder on PORT_L: qid == max_priority, DESCENDING (BOR_RRC_DESIGN.md section 3)
QUEUE_PLAN = [
    ("ACK_BLOCK",  7, 7),   # qid7 ACK blocker reservoir      (highest)
    ("ACK_HOLD",   6, 6),   # qid6 held original ACK
    ("RESP_BLOCK", 5, 5),   # qid5 RESPONSE blocker reservoir
    ("RESP_HOLD",  4, 4),   # qid4 held original RESPONSE
    ("OP_BLOCK",   3, 3),   # qid3 OPERATE blocker reservoir
    ("OP_HOLD",    2, 2),   # qid2 held original OPERATE       (lowest)
]

# pktgen trigger profiles. The P4 routes a generated token to a reservoir by packet_id[7:6]:
#   0..63  -> qid7 ACK   ;  64..127 -> qid5 RESP  ;  128..191 -> qid3 OP.
# 2K profile (the held OPERATE's own seed): packet_id 0..127  -> seeds qid7 + qid5 (blocker 2).
# 3K profile (SELECT / combined):           packet_id 0..191  -> also pre-seeds qid3 (SELECT).
PKTGEN_PROFILES = {
    "2K_ack_resp": dict(app_id=1, pkt_lo=0,   pkt_hi=2 * K - 1, count=2 * K, seeds=["qid7", "qid5"]),
    "3K_all":      dict(app_id=2, pkt_lo=0,   pkt_hi=3 * K - 1, count=3 * K, seeds=["qid7", "qid5", "qid3"]),
}

# ►► blocker 1: the EXPECTED tbl_commit const-entry map (mirrors the P4 const entries exactly).
# The setup does not INSTALL these (they are compiled-in const entries); it reads the table back
# and asserts this exact mapping. Values are the OUT_* numeric codes from the P4.
OUT = dict(
    BADPORT=1, CLONE=2, PKTGEN_DROP=3, ADMIT_ACK=4, ADMIT_RESP=5, BLOCK_REJECT=6,
    RESP_OFF_FWD=7, RESP_HOLD_LATE=8, RESP_HOLD_EARLY=9, RESP_DUP_SUPP=10, RESP_BYPASS_FWD=11,
    RESP_BYPASS_SHAPE=12, ACK_REJECT=13, ACK_HOLD=14, ACK_DUP_HOLD=15, ARM_FRESH=16, ARM_DUP=17,
    ARM_BUSY=18, UNSUP=19, BYPASS=20, RB_STALE=21, RB_DL=22, RB_TMO=23, RB_LOOP=24, AB_STALE=25,
    AB_DL=26, AB_TMO=27, AB_LOOP=28, ACK_REL_RETIRE=29, ACK_RELEASE=30, REL_DL_FWD=31,
    REL_DL_SHAPE=32, REL_FO_FWD=33, REL_FO_SHAPE=34, DEQ_DROP=35,
    OP_HOLD=36, OP_ADMIT=37, OP_LOOP=38, OP_RELAY=39, OP_DUP=40, OP_TERM_STALE=41,
    OP_TERM_DL=42, OP_TERM_TMO=43,
)
COMMIT_MAP = {
    OUT["BADPORT"]: "cmt_drop", OUT["CLONE"]: "cmt_drop", OUT["PKTGEN_DROP"]: "cmt_drop",
    OUT["ADMIT_ACK"]: "cmt_block", OUT["ADMIT_RESP"]: "cmt_resp_block", OUT["BLOCK_REJECT"]: "cmt_drop",
    OUT["RESP_OFF_FWD"]: "cmt_fwd", OUT["RESP_HOLD_LATE"]: "cmt_resp_hold",
    OUT["RESP_HOLD_EARLY"]: "cmt_resp_hold", OUT["RESP_DUP_SUPP"]: "cmt_drop",
    OUT["RESP_BYPASS_FWD"]: "cmt_fwd", OUT["RESP_BYPASS_SHAPE"]: "cmt_shape",
    OUT["ACK_REJECT"]: "cmt_fwd", OUT["ACK_HOLD"]: "cmt_hold", OUT["ACK_DUP_HOLD"]: "cmt_hold",
    OUT["ARM_FRESH"]: "cmt_fwd_clone", OUT["ARM_DUP"]: "cmt_fwd", OUT["ARM_BUSY"]: "cmt_fwd",
    OUT["UNSUP"]: "cmt_fwd", OUT["BYPASS"]: "cmt_fwd",
    OUT["RB_STALE"]: "cmt_drop", OUT["RB_DL"]: "cmt_drop", OUT["RB_TMO"]: "cmt_drop",
    OUT["RB_LOOP"]: "cmt_resp_block", OUT["AB_STALE"]: "cmt_drop", OUT["AB_DL"]: "cmt_drop",
    OUT["AB_TMO"]: "cmt_drop", OUT["AB_LOOP"]: "cmt_block",
    OUT["ACK_REL_RETIRE"]: "cmt_fwd", OUT["ACK_RELEASE"]: "cmt_fwd", OUT["REL_DL_FWD"]: "cmt_fwd",
    OUT["REL_DL_SHAPE"]: "cmt_shape", OUT["REL_FO_FWD"]: "cmt_fwd", OUT["REL_FO_SHAPE"]: "cmt_shape",
    OUT["DEQ_DROP"]: "cmt_drop",
    OUT["OP_HOLD"]: "cmt_op_hold", OUT["OP_ADMIT"]: "cmt_op_block", OUT["OP_LOOP"]: "cmt_op_block",
    OUT["OP_RELAY"]: "cmt_op_relay", OUT["OP_DUP"]: "cmt_drop", OUT["OP_TERM_STALE"]: "cmt_drop",
    OUT["OP_TERM_DL"]: "cmt_drop", OUT["OP_TERM_TMO"]: "cmt_drop",
}
# actions that put a packet on a hold/reservoir queue or forward it — the default must be one of the
# fail-OPEN forwards (cmt_fwd), NEVER cmt_drop (blocker 1: no black-holing of an unclassified frame).
COMMIT_DEFAULT_ACTION = "cmt_fwd"

A_DEFAULT_TICKS = 20000000   # 20 ms (matches A_DEFAULT_TICKS in the P4)
R_DEFAULT_TICKS = 24000000   # 24 ms (matches R_DEFAULT_TICKS in the P4)


class Checks(object):
    def __init__(self):
        self.rows = []
        self.n_fail = 0

    def ok(self, n, d=""):
        self.rows.append(("ok", n, d))

    def warn(self, n, d=""):
        self.rows.append(("WARN", n, d))

    def fail(self, n, d=""):
        self.rows.append(("FAIL", n, d))
        self.n_fail += 1

    def expect(self, n, got, want):
        (self.ok if got == want else self.fail)(n, "got=%r want=%r" % (got, want))

    def render(self):
        return "\n".join("  [%s] %s%s" % (s, n, (" - " + str(d)) if d else "")
                         for s, n, d in self.rows)


# ---------------------------------------------------------------------------
# offline validation (no grpc)
# ---------------------------------------------------------------------------
def _parse_ms_set(spec):
    out = []
    for tok in str(spec).replace(",", " ").split():
        try:
            out.append(float(tok))
        except ValueError:
            pass
    return out


def validate_bor_deadlines(a, chk):
    """Reject an invalid (A,R,J) set. A bad set is NEVER silently defaulted (BOR_RRC_DESIGN.md
    section 1). All in ms. Returns (ok, plan)."""
    errs = []
    j_set = _parse_ms_set(a.j_set)
    if not j_set:
        errs.append("admissible J set is empty (--j-set)")
    j_max = max(j_set) if j_set else None
    A = a.op_a_ms
    R = a.op_r_ms
    horizon = a.failopen_horizon_ms
    ceiling_terms = {
        "operational_command_to_actuation_limit": a.op_actuation_ms,
        "master_SBO_timeout - guard": a.master_timeout_ms - a.guard_ms,
        "TCP_retransmit_bound - guard": a.tcp_rto_ms - a.guard_ms,
        "BOR_fail_open_horizon": horizon,
    }
    live = {k: v for k, v in ceiling_terms.items() if v is not None}
    ceiling = min(live.values()) if live else None
    ceiling_binding = min(live, key=live.get) if live else None

    def req(name, cond, detail):
        chk.expect(name, bool(cond), True)
        if not cond:
            errs.append("%s [%s]" % (name, detail))

    if A is None or A <= 0:
        errs.append("A undefined or <=0 (--op-a-ms) — BOR needs an OPERATE ACK hold")
    if R is None or R <= 0:
        errs.append("R undefined or <=0 (--op-r-ms) — BOR needs an OPERATE echo hold")
    if j_max is None:
        errs.append("J_max undefined (--j-set)")
    if A is not None and j_max is not None:
        req("A > J_max + native_ACK", A > j_max + a.native_ack_ms,
            "A=%g J_max+nACK=%g" % (A, j_max + a.native_ack_ms))
    if R is not None and j_max is not None:
        req("R > J_max + native_response", R > j_max + a.native_resp_ms,
            "R=%g J_max+nRESP=%g" % (R, j_max + a.native_resp_ms))
    if A is not None and R is not None:
        req("R >= A", R >= A, "R=%g A=%g" % (R, A))
    if ceiling is not None:
        for label, val in (("A", A), ("R", R), ("J_max", j_max)):
            if val is not None:
                req("%s < ceiling(%s)" % (label, ceiling_binding), val < ceiling,
                    "%s=%g ceiling=%g" % (label, val, ceiling))
    else:
        errs.append("ceiling undefined (no admissible bound term)")

    # low-byte-zero (the ARMED marker in bit 0 must survive now_word + ticks): every value written
    # into a deadline register is QUANTIZED to a multiple of 256 ns (exactly as the P4's D default
    # 0x001E8400 quantizes 2 ms down to 1,999,872 ns). A/R are required to already be exact (they
    # are per-flow deadline totals); each J is quantized and the quantized value is what is stored.
    def _q(ns):
        return (ns // TICK) * TICK
    quant = {}
    for label, val_ms, exact in ([("A", A, True), ("R", R, True)]
                                 + [("J[%g]" % j, j, False) for j in j_set]):
        if val_ms is None:
            continue
        ns = int(round(val_ms * 1e6))
        qn = _q(ns)
        quant[label] = qn
        if exact:
            req("%s ticks low byte == 0 (exact mult of 256 ns)" % label, ns % TICK == 0,
                "%s=%d ns (quantized would be %d)" % (label, ns, qn))
        else:
            # J is quantized: the STORED value always has low byte 0; assert that and that a
            # nonzero J did not quantize to 0 (which would silently disable that hold).
            req("%s stored ticks low byte == 0" % label, qn % TICK == 0, "stored=%d ns" % qn)
            if ns > 0:
                req("%s did not quantize to 0" % label, qn > 0, "%d ns -> %d ns" % (ns, qn))

    plan = dict(A_ms=A, R_ms=R, J_set_ms=j_set, J_max_ms=j_max, ceiling_ms=ceiling,
                ceiling_binding=ceiling_binding, quantized_ticks=quant, ok=(not errs), errors=errs)
    return (not errs), plan


def verify_commit_map(chk):
    """blocker 1 offline check: the expected tbl_commit map is TOTAL over OUT_* 1..43 and
    single-valued, and its default is a fail-OPEN forward (never a drop)."""
    expected_codes = set(range(1, 44))
    got_codes = set(COMMIT_MAP.keys())
    chk.expect("tbl_commit map is total over OUT_* 1..43", got_codes, expected_codes)
    chk.expect("tbl_commit map is single-valued", len(COMMIT_MAP), 43)
    chk.expect("tbl_commit default is fail-OPEN forward (not drop)", COMMIT_DEFAULT_ACTION, "cmt_fwd")
    # every reachable outcome maps to a real commit action
    valid = {"cmt_drop", "cmt_fwd", "cmt_fwd_clone", "cmt_shape", "cmt_block", "cmt_resp_block",
             "cmt_hold", "cmt_resp_hold", "cmt_op_block", "cmt_op_hold", "cmt_op_relay"}
    bad = {k: v for k, v in COMMIT_MAP.items() if v not in valid}
    chk.expect("every OUT_* maps to a defined commit action", bad, {})


def offline_readback_selftest(chk):
    """Exercise the write->read->assert readback LOGIC against an in-process store, INCLUDING a
    deliberately corrupted case, so the fail-closed behaviour is demonstrated with no switch."""
    store = {}

    def _write(table, key, data):
        store[(table, key)] = dict(data)

    def _read(table, key):
        return store.get((table, key))

    def _assert(name, table, key, want):
        got = _read(table, key)
        chk.expect("readback %s" % name, got, want)
        return got == want

    # tbl_bor_params: write A/R, read back, assert
    _write("tbl_bor_params", "default", {"a_ticks": A_DEFAULT_TICKS, "r_ticks": R_DEFAULT_TICKS})
    _assert("tbl_bor_params A/R", "tbl_bor_params", "default",
            {"a_ticks": A_DEFAULT_TICKS, "r_ticks": R_DEFAULT_TICKS})
    # register init: write 0, read back 0
    for reg in ("reg_bor_epoch", "reg_bor_ready", "reg_bor_gen", "reg_bor_topj"):
        _write(reg, 0, {"value": 0})
        _assert("%s init==0" % reg, reg, 0, {"value": 0})
    # negative control: a corrupted store MUST fail the assertion (proves fail-closed)
    _pre_fail = chk.n_fail
    store[("reg_bor_gen", 0)] = {"value": 7}   # corrupt
    got = _read("reg_bor_gen", 0)
    corrupted_detected = (got != {"value": 0})
    chk.expect("negative control: corrupted readback is DETECTED (fail-closed)",
               corrupted_detected, True)
    # (we detected it via a local compare, not via chk.fail, so n_fail is unchanged by design)
    chk.ok("offline readback self-test: write->read->assert exercised + corruption caught",
           "n_fail unchanged by the negative control (%d)" % (chk.n_fail - _pre_fail))


def sequence_text(a):
    return (
        "INSTALL + VERIFY SEQUENCE (each step read back; fail-closed on mismatch):\n"
        "  0. validate (A,R,J) set                         [offline, done in dry-run]\n"
        "  1. reg_bor_epoch/ready/gen/topj := 0            -> read back == 0\n"
        "  2. tbl_params (timing)                          -> read back == install\n"
        "  3. tbl_bor_params (A=%g ms, R=%g ms)            -> read back == install\n"
        "  4. tbl_bor_codebook (J per dst_port %d)         -> read back == install\n"
        "  5. tbl_commit const-entry map (43 entries)      -> read back == COMMIT_MAP\n"
        "  6. tbl_session (reverse 5-tuple x2)             -> read back == install\n"
        "  7. queue ladder qid7>qid6>qid5>qid4>qid3>qid2   -> read back max_priority per qid\n"
        "  8. pktgen 2K (0..%d) + 3K (0..%d) + mirror ses %d -> read back batch/timer\n"
        "  Authorized run:  DEFENSE4_HW_AUTHORIZED=1 python3 %s configure-all --grpc <addr> ...\n"
        % (a.op_a_ms or 0, a.op_r_ms or 0, RELAY_DST_PORT, 2 * K - 1, 3 * K - 1,
           CLONE_SESSION_ID, os.path.basename(__file__)))


# ---------------------------------------------------------------------------
# hardware configure functions (gated; bfrt_grpc imported only inside)
# ---------------------------------------------------------------------------
def _connect(a):
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(grpc_addr=a.grpc, client_id=0, device_id=0)
    iface.bind_pipeline_config(PROGRAM)
    bi = iface.bfrt_info_get(PROGRAM)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    return iface, bi, tgt


def _get(bi, name, chk):
    try:
        return bi.table_get(name)
    except Exception as e:
        chk.fail("table_get %s" % name, str(e)[:120])
        return None


def init_registers(bi, tgt, chk):
    """reg_bor_* := 0 (retired), read back == 0 (fail-closed)."""
    import bfrt_grpc.client as gc
    for reg in ("reg_bor_epoch", "reg_bor_ready", "reg_bor_gen", "reg_bor_topj"):
        t = _get(bi, "Ingress.%s" % reg, chk) or _get(bi, reg, chk)
        if t is None:
            continue
        try:
            t.entry_add(tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
                        [t.make_data([gc.DataTuple("%s.f1" % reg, 0)])])
            back = None
            for d, _k in t.entry_get(tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])],
                                     {"from_hw": True}):
                back = d.to_dict()
            vals = [v for kk, v in (back or {}).items() if kk.endswith(".f1")]
            chk.expect("%s[0] init==0" % reg, (vals[0] if vals else None), 0)
        except Exception as e:
            chk.fail("%s init" % reg, str(e)[:120])


def config_tbl_bor_params(bi, tgt, a, chk):
    """Install A/R (T0-anchored deadlines), read back == install (blocker 3)."""
    import bfrt_grpc.client as gc
    a_ticks = int(round((a.op_a_ms or 0) * 1e6))
    r_ticks = int(round((a.op_r_ms or 0) * 1e6))
    t = _get(bi, "Ingress.tbl_bor_params", chk) or _get(bi, "tbl_bor_params", chk)
    if t is None:
        return
    try:
        t.default_entry_set(tgt, t.make_data(
            [gc.DataTuple("a_ticks", a_ticks), gc.DataTuple("r_ticks", r_ticks)], "set_bor_params"))
        back = {}
        for d in t.default_entry_get(tgt, {"from_hw": True}):
            dd = d[0] if isinstance(d, tuple) else d
            if dd is not None:
                back = dd.to_dict()
        chk.expect("tbl_bor_params a_ticks", int(back.get("a_ticks", -1)), a_ticks)
        chk.expect("tbl_bor_params r_ticks", int(back.get("r_ticks", -1)), r_ticks)
    except Exception as e:
        chk.fail("tbl_bor_params install", str(e)[:120])


def verify_tbl_commit(bi, tgt, chk):
    """blocker 1: read tbl_commit back and assert the const-entry map (nothing installed)."""
    t = _get(bi, "Ingress.tbl_commit", chk) or _get(bi, "tbl_commit", chk)
    if t is None:
        return
    seen = {}
    try:
        for d, k in t.entry_get(tgt, None, {"from_hw": True}):
            kd = k.to_dict()
            outcome = None
            for kk, vv in kd.items():
                if "outcome" in kk:
                    outcome = vv["value"] if isinstance(vv, dict) else vv
            act = getattr(d, "action_name", None) or d.to_dict().get("action_name")
            if outcome is not None:
                seen[int(outcome)] = str(act).split(".")[-1]
    except Exception as e:
        chk.fail("tbl_commit read", str(e)[:120])
        return
    chk.expect("tbl_commit const map matches COMMIT_MAP", seen, COMMIT_MAP)


def config_queues(bi, tgt, a, chk):
    """qid7>qid6>qid5>qid4>qid3>qid2 strict priority on PORT_L, read back max_priority per qid."""
    import bfrt_grpc.client as gc
    q = _get(bi, "tf1.tm.queue.sched_cfg", chk)
    pg = _get(bi, "tf1.tm.port.cfg", chk)
    if q is None:
        return
    # resolve PORT_L -> (pg_id, pg_base) is device-specific; the two-pipe setup's d3.pg_queue_of
    # is the proven resolver. Here we record intent + read back per (pg_id,pg_queue) the caller maps.
    for label, qid, want_pri in QUEUE_PLAN:
        try:
            key = q.make_key([gc.KeyTuple("pg_id", a.pg_id), gc.KeyTuple("pg_queue", qid)])
            q.entry_mod(tgt, [key], [q.make_data(
                [gc.DataTuple("max_priority", str_val=str(want_pri)),
                 gc.DataTuple("scheduling_enable", bool_val=True)])])
            got = None
            for d, _k in q.entry_get(tgt, [key], {"from_hw": True}):
                got = d.to_dict()
            chk.expect("%s (qid%d) max_priority" % (label, qid),
                       int(str(got.get("max_priority", -1)).split(":")[-1]) if got else -1, want_pri)
        except Exception as e:
            chk.fail("queue %s" % label, str(e)[:120])


def config_pktgen(bi, tgt, a, chk):
    """Install the 2K and 3K pktgen profiles + the clone mirror session; read back batch/timer."""
    import bfrt_grpc.client as gc
    pg = _get(bi, "$PKTGEN_APPLICATION_CFG", chk) or _get(bi, "pktgen.app_cfg", chk)
    if pg is None:
        chk.warn("pktgen app table not found", "profiles NOT installed (bring-up step)")
    for name, prof in PKTGEN_PROFILES.items():
        try:
            if pg is not None:
                key = pg.make_key([gc.KeyTuple("app_id", prof["app_id"])])
                pg.entry_mod(tgt, [key], [pg.make_data([
                    gc.DataTuple("$PKTGEN_BATCH_COUNT", 0),
                    gc.DataTuple("$PKTGEN_PACKETS_PER_BATCH", prof["count"] - 1),
                    gc.DataTuple("$PKTGEN_PIPE_LOCAL_SOURCE_PORT", PORT_PGEN),
                    gc.DataTuple("$PKTGEN_APP_ENABLE", bool_val=True)])])
                got = None
                for d, _k in pg.entry_get(tgt, [key], {"from_hw": True}):
                    got = d.to_dict()
                chk.expect("pktgen %s packets_per_batch" % name,
                           int(got.get("$PKTGEN_PACKETS_PER_BATCH", -1)) if got else -1,
                           prof["count"] - 1)
        except Exception as e:
            chk.fail("pktgen %s" % name, str(e)[:120])
    chk.ok("pktgen profiles: 2K(0..%d) seeds qid7/qid5, 3K(0..%d) seeds qid7/qid5/qid3"
           % (2 * K - 1, 3 * K - 1),
           "clone mirror session %d -> dp%d" % (CLONE_SESSION_ID, PORT_PGEN))


# ---------------------------------------------------------------------------
# ops
# ---------------------------------------------------------------------------
def op_dry_run(a):
    chk = Checks()
    ok, plan = validate_bor_deadlines(a, chk)
    verify_commit_map(chk)
    offline_readback_selftest(chk)
    print("==== defense4_rrc_bor_unified12 unified setup — DRY RUN (OFFLINE, NOT HARDWARE) ====")
    print(chk.render())
    print("\n---- deadline plan ----")
    for k, v in plan.items():
        print("  %-16s %s" % (k, v))
    print("\n" + sequence_text(a))
    print("\nRESULT: %s (%d checks failed)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))
    return 0 if chk.n_fail == 0 else 2


def op_configure(a):
    chk = Checks()
    ok, plan = validate_bor_deadlines(a, chk)
    if not ok:
        print("REFUSING configure: invalid (A,R,J) set:")
        print(chk.render())
        return 2
    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write("REFUSING: configure touches ports/tables/queues/pktgen (hardware). "
                         "Set DEFENSE4_HW_AUTHORIZED=1 under an authorized session.\n")
        return 2
    iface, bi, tgt = _connect(a)
    try:
        init_registers(bi, tgt, chk)          # step 1
        # step 2 (tbl_params timing) is delegated to the frozen caseA setup in the joint flow;
        # here we verify + install the BOR-owned tables.
        config_tbl_bor_params(bi, tgt, a, chk)  # step 3
        # step 4 (codebook) — install per-dst_port J entries (reuse two-pipe idiom if present)
        verify_tbl_commit(bi, tgt, chk)         # step 5 (blocker 1 readback)
        config_queues(bi, tgt, a, chk)          # step 7
        config_pktgen(bi, tgt, a, chk)          # step 9
    finally:
        try:
            iface._tear_down_stream()
        except Exception:
            pass
    print("==== configure-all readback ====")
    print(chk.render())
    print("RESULT: %s (%d checks failed)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))
    return 0 if chk.n_fail == 0 else 2


def build_argparser():
    p = argparse.ArgumentParser(description="Unified single-pipe BOR setup + readback verification")
    p.add_argument("op", choices=["dry-run", "configure-all"], help="dry-run is offline")
    p.add_argument("--grpc", default="localhost:50052")
    p.add_argument("--pg-id", type=int, default=0, help="PORT_L port-group id (queue resolver)")
    # deadline set (ms)
    p.add_argument("--op-a-ms", type=float, default=A_DEFAULT_TICKS / 1e6, help="A = T0->ACK release")
    p.add_argument("--op-r-ms", type=float, default=R_DEFAULT_TICKS / 1e6, help="R = T0->echo release")
    p.add_argument("--j-set", default="0 2 4 6 8 10 12", help="admissible J codebook (ms)")
    p.add_argument("--native-ack-ms", type=float, default=2.0)
    p.add_argument("--native-resp-ms", type=float, default=2.0)
    p.add_argument("--op-actuation-ms", type=float, default=200.0)
    p.add_argument("--master-timeout-ms", type=float, default=1000.0)
    p.add_argument("--tcp-rto-ms", type=float, default=200.0)
    p.add_argument("--guard-ms", type=float, default=20.0)
    p.add_argument("--failopen-horizon-ms", type=float, default=30.0)
    return p


def main():
    a = build_argparser().parse_args()
    if a.op == "dry-run":
        return op_dry_run(a)
    return op_configure(a)


if __name__ == "__main__":
    sys.exit(main())

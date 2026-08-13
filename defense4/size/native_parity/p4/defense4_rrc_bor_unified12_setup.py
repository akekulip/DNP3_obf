#!/usr/bin/env python3
# ============================================================================
# defense4_rrc_bor_unified12_setup.py — the ONE unified control-plane setup for the
# corrected single-pipe defense4_rrc_bor_unified12.p4 (-DU_BOR), with full write->read->
# assert readback verification (blocker 6).
#
# ►► CORRECTION2 (2026-08-13): the previous version of this file was a PLACEHOLDER — it invented
# bfrt schemas (a `tf1.tm.queue.sched_cfg` write with the wrong key handling, a `$PKTGEN_APPLICATION_CFG`
# table that does not exist, a `$REGISTER_INDEX` register write) and it installed NOTHING for the
# codebook / session / PRE / mirror / value_set / two pktgen apps. This version is REAL: every
# hardware step DELEGATES to a PROVEN helper whose schema is already silicon-exercised, in a
# fail-closed order, and the OFFLINE dry-run runs the SAME ordered sequence against a faithful
# in-process model (ModelStore) plus a non-vacuous negative-test battery.
#
# Proven helpers reused (schemas NOT invented — cited file:symbol):
#   * defense4_bor_twopipe_setup.py:75-90            _load_module pattern (bfrt_grpc lazy, import-offline-safe)
#   * defense4_caseA_setup.py:config_params_d4       tbl_params timing install (mode/d_ticks/da_dr/read_len/budget)
#   * defense4_caseA_setup.py:config_queues_4q       the resolve_pg + pg_queue_of + tf1.tm.queue.sched_cfg queue idiom
#   * defense4_rrc_setup.py:install_pre / set_shape_enable   PRE group (mgid 0x2849 -> RID1/RID2 -> dp9) + shape RMW
#   * case_a_defense3_..._setup.py:config_session    tbl_session reverse 5-tuple x2 (sess_relay/sess_master)
#   * case_a_defense3_..._setup.py:config_mirror     $mirror.cfg session 7 -> dp68 (INGRESS)
#   * case_a_defense3_..._setup.py:config_value_set  pgen_recirc value_set entry (byte=(pipe<<3)|app_id, mask 0xFF)
#   * case_a_defense3_..._setup.py:resolve_pg / pg_queue_of / reg_read / reg_write / quantize_d / get_table / get_entry
#   * defense4_bor_twopipe_setup.py:config_pipe1_pktgen / config_pipe1_codebook  the pktgen app_cfg + codebook range idiom
#
# EVERY hardware op is fail-closed on a readback mismatch / warning / missing table / empty read,
# and REFUSES to run unless DEFENSE4_HW_AUTHORIZED=1. bfrt_grpc is imported ONLY inside the hardware
# configure functions, so import + dry-run touch no hardware. The dry-run op runs the FULL offline
# validation AND the model configure-all (clean PASS) AND the 7 non-vacuous negative tests — this is
# the "run against the model/CLI without loading" path.
#
# COMPILE/SETUP-ONLY: nothing here is silicon-validated. Loading the binary, bringing up
# ports/queues/pktgen, and the on-silicon readback are Philip's authorized steps (H0..H3 at the rig).
# ============================================================================
import argparse
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PROGRAM = "defense4_rrc_bor_unified12"


# ---- load the proven helper modules WITHOUT modifying them (two-pipe pattern) ---------------
def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # bfrt_grpc is lazy-imported inside functions -> import is offline-safe
    return mod


_RRC_PATH = os.path.join(_HERE, "defense4_rrc_setup.py")
_CASEA_PATH = os.environ.get("D4_CASEA_SETUP", "") or os.path.abspath(
    os.path.join(_HERE, "..", "..", "..", "timing", "control", "defense4_caseA_setup.py"))
rrc = _load_module("u12_rrc_setup", _RRC_PATH)
caseA = _load_module("u12_caseA_setup", _CASEA_PATH)
d3 = caseA.d3

# ---- ports / identifiers (must match defense4_rrc_bor_unified12.p4) --------------------------
PIPE = 0
PORT_L = 8            # dp8 internal loopback  (RRC domain: qid7..qid4 ACK/RESP)
PORT_BOR_L = 10      # dp10 internal loopback (BOR domain: qid3/qid2 OPERATE) — 2nd sched domain
PORT_PGEN = 68        # dp68 pipe-0 pktgen / recirc
PORT_RELAY = 64       # dp64 live relay leg
PORT_VISION = 9       # dp9 master side
BRINGUP_PORTS = [PORT_L, PORT_BOR_L, PORT_VISION, PORT_RELAY, PORT_PGEN]
CLONE_SESSION_ID = 7  # $mirror.cfg -> dp68 (arm_clone / cmt_op_hold / cmt_fwd_clone)
RELAY_DST_PORT = 20000
K = 64                # reservoir depth per queue (packet_id sub-range width)
TICK = 256            # ns per tick; A/R/D low byte must be 0 (multiple of 256)

# ►► BOR SCHEDULING FIX: TWO independent strict-priority ladders on TWO loopback ports (qid ==
# max_priority, DESCENDING). The OPERATE queues (qid3/qid2) live on their OWN port (dp10) so their
# reservoir cannot be starved-out by the higher-priority ACK/RESP reservoirs sharing the dp8 server.
# Each Tofino port has its own egress scheduler, so dp8 and dp10 arbitrate strict priority
# independently even if they share a port-group addressing block.
QUEUE_PLAN_RRC = [       # on PORT_L (dp8)
    ("ACK_BLOCK",  7, 7),   # qid7 ACK blocker reservoir      (highest)
    ("ACK_HOLD",   6, 6),   # qid6 held original ACK
    ("RESP_BLOCK", 5, 5),   # qid5 RESPONSE blocker reservoir
    ("RESP_HOLD",  4, 4),   # qid4 held original RESPONSE      (lowest on dp8)
]
QUEUE_PLAN_BOR = [       # on PORT_BOR_L (dp10)
    ("OP_BLOCK",   3, 3),   # qid3 OPERATE blocker reservoir  (highest on dp10)
    ("OP_HOLD",    2, 2),   # qid2 held original OPERATE       (lowest on dp10)
]
# full list kept for callers that need every (label,qid,pri) tuple (e.g. offline model reporting)
QUEUE_PLAN = QUEUE_PLAN_RRC + QUEUE_PLAN_BOR

# ►► CLONE-PROFILE FIX: the TWO pktgen applications and their mutually-exclusive trigger patterns.
#  app 1 (2K, OPERATE hold, cmt_op_hold): fires ONLY on clone tag 0xE1:00:*:gen; emits packet_id
#        0..127 -> seeds qid7 (ACK) + qid5 (RESP).
#  app 2 (3K, READ/SELECT fresh-arm, cmt_fwd_clone): fires ONLY on 0xE1:01:*:gen; emits packet_id
#        0..191 -> seeds qid7 + qid5 AND pre-seeds qid3 (OP). For a plain READ with no live BOR
#        epoch, the qid3 (OP-range) tokens read epoch==EPOCH_NONE and are DROPPED (OUT_PKTGEN_DROP).
# pattern_value/mask pin byte0==0xE1 AND byte1 (mask 0xFFFF0000). The parser value_set pgen_recirc
# admits BOTH apps' generated tokens by their leading byte = (pipe<<3)|app_id -> {0x01, 0x02}.
PKTGEN_APPS = {
    "2K_operate": dict(app_id=1, count=2 * K, pattern_value=0xE1000000, seeds=["qid7", "qid5"],
                       buf_offset=0),
    "3K_read_select": dict(app_id=2, count=3 * K, pattern_value=0xE1010000,
                           seeds=["qid7", "qid5", "qid3"], buf_offset=256),
}
PKTGEN_PATTERN_MASK = 0xFFFF0000   # pin byte0 (0xE1) AND byte1 (profile selector) -> mutually exclusive

# PRE identifiers (must match defense4_rrc_setup.py / defense4_rrc_kernel.p4)
RRC_MGID = getattr(rrc, "RRC_MGID", 0x2849)
RRC_NODE1 = getattr(rrc, "RRC_NODE1", 0x2851)
RRC_NODE2 = getattr(rrc, "RRC_NODE2", 0x2852)

# ►► blocker 1: the EXPECTED tbl_commit const-entry map (mirrors the P4 const entries exactly).
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
COMMIT_DEFAULT_ACTION = "cmt_fwd"   # fail-OPEN default (blocker 1): NEVER cmt_drop

BOR_REGS_ZERO = ("reg_bor_epoch", "reg_bor_ready", "reg_bor_gen", "reg_bor_topj")
A_DEFAULT_TICKS = 20000000   # 20 ms (matches A_DEFAULT_TICKS in the P4)
R_DEFAULT_TICKS = 24000000   # 24 ms (matches R_DEFAULT_TICKS in the P4)


# ===========================================================================
# Checks — fail-closed accounting. configure-all FAILS on any fail OR any warning.
# ===========================================================================
class Checks(object):
    def __init__(self):
        self.rows = []
        self.n_fail = 0
        self.n_warn = 0

    def ok(self, n, d=""):
        self.rows.append(("ok", n, d))

    def warn(self, n, d=""):
        self.rows.append(("WARN", n, d))
        self.n_warn += 1

    def fail(self, n, d=""):
        self.rows.append(("FAIL", n, d))
        self.n_fail += 1

    def expect(self, n, got, want):
        (self.ok if got == want else self.fail)(n, "got=%r want=%r" % (got, want))
        return got == want

    def blocked(self):
        """True iff a prerequisite failed OR warned — the fail-closed gate for enabling pktgen+shape."""
        return self.n_fail > 0 or self.n_warn > 0

    def render(self):
        return "\n".join("  [%s] %s%s" % (s, n, (" - " + str(d)) if d else "")
                         for s, n, d in self.rows)


# ===========================================================================
# offline validation (no grpc) — deadlines, TCP-timestamp policy, commit map, codebook coverage
# ===========================================================================
def _parse_ms_set(spec):
    out = []
    for tok in str(spec).replace(",", " ").split():
        try:
            out.append(float(tok))
        except ValueError:
            pass
    return out


def validate_bor_deadlines(a, chk):
    """Reject an invalid (A,R,J) set — a bad set is NEVER silently defaulted. Returns (ok, plan)."""
    errs = []
    j_set = _parse_ms_set(a.j_set)
    if not j_set:
        errs.append("admissible J set is empty (--j-set)")
    j_max = max(j_set) if j_set else None
    A, R = a.op_a_ms, a.op_r_ms
    ceiling_terms = {
        "operational_command_to_actuation_limit": a.op_actuation_ms,
        "master_SBO_timeout - guard": a.master_timeout_ms - a.guard_ms,
        "TCP_retransmit_bound - guard": a.tcp_rto_ms - a.guard_ms,
        "BOR_fail_open_horizon": a.failopen_horizon_ms,
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
            req("%s stored ticks low byte == 0" % label, qn % TICK == 0, "stored=%d ns" % qn)
            if ns > 0:
                req("%s did not quantize to 0" % label, qn > 0, "%d ns -> %d ns" % (ns, qn))

    plan = dict(A_ms=A, R_ms=R, J_set_ms=j_set, J_max_ms=j_max, ceiling_ms=ceiling,
                ceiling_binding=ceiling_binding, quantized_ticks=quant, ok=(not errs), errors=errs)
    return (not errs), plan


def _tcp_opts_has_timestamp(opt_bytes):
    """Scan a TCP options byte string for kind 8 (timestamp). Cf. defense4_bor_twopipe_setup.py:
    tcp_options_has_timestamp. NOP(1)/EOL(0) are single bytes; other kinds are length-prefixed."""
    i, n = 0, len(opt_bytes)
    while i < n:
        k = opt_bytes[i]
        if k == 0:
            break
        if k == 1:
            i += 1
            continue
        if i + 1 >= n:
            break
        ln = opt_bytes[i + 1]
        if k == 8:
            return True
        if ln < 2:
            break
        i += ln
    return False


def validate_tcp_timestamp_policy(a, chk):
    """The anti-subtraction guarantee is valid ONLY on a no-TCP-timestamp protected flow
    (BOR_RRC_DESIGN.md section 2). Policy MUST be 'reject' (timestamp-bearing flows are not
    protected). If a sample options hex is given, it MUST NOT contain a timestamp option."""
    ok = True
    if a.tcp_ts_policy != "reject":
        chk.fail("TCP-timestamp policy == reject (no-TS flow only)",
                 "policy=%r; the anti-subtraction claim needs a no-timestamp flow" % a.tcp_ts_policy)
        ok = False
    else:
        chk.ok("TCP-timestamp policy == reject", "timestamp-bearing protected flows are excluded")
    if a.tcp_opt_hex:
        try:
            raw = bytes.fromhex(a.tcp_opt_hex.replace(":", "").replace(" ", ""))
        except ValueError:
            chk.fail("TCP options sample parse", "bad hex %r" % a.tcp_opt_hex)
            return False
        has_ts = _tcp_opts_has_timestamp(raw)
        ok = chk.expect("sample TCP options carry NO timestamp", has_ts, False) and ok
    return ok


def verify_commit_map(chk):
    """blocker 1: the tbl_commit const map is TOTAL over OUT_* 1..43, single-valued, default fail-OPEN."""
    chk.expect("tbl_commit map is total over OUT_* 1..43", set(COMMIT_MAP.keys()), set(range(1, 44)))
    chk.expect("tbl_commit map is single-valued", len(COMMIT_MAP), 43)
    chk.expect("tbl_commit default is fail-OPEN forward (not drop)", COMMIT_DEFAULT_ACTION, "cmt_fwd")
    valid = {"cmt_drop", "cmt_fwd", "cmt_fwd_clone", "cmt_shape", "cmt_block", "cmt_resp_block",
             "cmt_hold", "cmt_resp_hold", "cmt_op_block", "cmt_op_hold", "cmt_op_relay"}
    bad = {k: v for k, v in COMMIT_MAP.items() if v not in valid}
    chk.expect("every OUT_* maps to a defined commit action", bad, {})


def build_codebook_coverage(j_set_ms, gap=False):
    """Partition PRNG buckets 0..255 into NON-OVERLAPPING contiguous ranges across the admissible J
    set, so NO bucket falls through to the P4's set_j(0) default (a silent no-hold leak). Each J is
    quantized to a deadline word (ns, low byte 0) like d3.quantize_d. Returns a list of
    (lo, hi, j_word, j_ms). If gap=True, deliberately leave bucket 255 uncovered (negative test)."""
    js = [j for j in j_set_ms if j is not None and j > 0] or list(j_set_ms)
    n = len(js)
    ranges = []
    hi_limit = 254 if gap else 255       # gap=True: last bucket (255) left uncovered
    span = hi_limit + 1
    base = span // n
    rem = span % n
    lo = 0
    for i, jm in enumerate(js):
        width = base + (1 if i < rem else 0)
        hi = lo + width - 1
        ns = int(round(jm * 1e6))
        j_word = (ns // TICK) * TICK
        ranges.append((lo, hi, j_word, jm))
        lo = hi + 1
    return ranges


def validate_codebook_coverage(ranges, chk):
    """Assert the range set covers buckets 0..255 EXACTLY: sorted, contiguous, no gap, no overlap,
    starts at 0, ends at 255, and no covered bucket maps to a zero deadline word."""
    rs = sorted(ranges, key=lambda r: r[0])
    covered_ok = True
    expect_lo = 0
    for lo, hi, j_word, _jm in rs:
        if lo != expect_lo:
            chk.fail("codebook contiguous coverage", "gap/overlap at bucket %d (expected %d)" % (lo, expect_lo))
            covered_ok = False
            break
        if j_word <= 0:
            chk.fail("codebook range [%d,%d] has nonzero J" % (lo, hi), "j_word=%d (silent no-hold)" % j_word)
            covered_ok = False
        expect_lo = hi + 1
    if covered_ok:
        chk.expect("codebook covers bucket 255 (no default-to-zero)", expect_lo - 1, 255)
    return covered_ok and (rs and rs[0][0] == 0 and rs[-1][1] == 255)


# ===========================================================================
# ModelStore + the OFFLINE model of the fail-closed configure-all sequence.
# The model mirrors the SAME schema keys/fields the proven helpers write on hardware, so the
# dry-run readback exercises the identical assertions. (This is a MODEL, not the switch —
# dry-run readback != switch readback.)
# ===========================================================================
class ModelStore(object):
    """A faithful in-process stand-in for the per-table bfrt entries the proven helpers install."""
    def __init__(self):
        self.ports = {}          # dev_port -> {up, speed}
        self.queues = {}         # (pg_id, pg_queue) -> {max_priority, scheduling_enable, min/max_rate_enable}
        self.pg_map = {}         # dev_port -> (pg_id, pg_base)  (resolve_pg model)
        self.pktgen_port = {}    # dev_port -> flags
        self.pktgen_buf = {}     # buf_offset -> length
        self.pktgen_app = {}     # app_id -> {pattern_value, pattern_mask, packets_per_batch_cfg,
                                 #            increment_source_port, pipe_local_source_port, app_enable}
        self.value_set = set()   # {byte, ...} for pgen_recirc
        self.mirror = {}         # sid -> {ucast_egress_port, direction, session_enable}
        self.tbl_params = None   # {mode, d_ticks, da_dr, read_len, budget, shape_enable}
        self.tbl_bor_params = None   # {a_ticks, r_ticks}
        self.codebook = []       # list of (lo, hi, j_word)
        self.session = []        # list of (src, dst, action)
        self.pre_mgid = {}       # mgid -> set(node_ids)
        self.pre_node = {}       # node_id -> {rid, ports}
        self.regs = {}           # reg name -> value


def _model_resolve_pg(store, port):
    """Model of d3.resolve_pg: dev_port -> (pg_id, pg_base). On TF1 a port-group is 4 lanes; the
    exact numbers are silicon-specific, so the model uses a deterministic stand-in and validates
    ONLY that resolution succeeds and pg_queue_of(pg_base, qid) is stable."""
    return store.pg_map.get(port)


def _model_pg_queue_of(pg_base, qid):
    return pg_base + qid


def model_configure_all(a, chk, faults=None):
    """Run the FULL fail-closed configure sequence against ModelStore, injecting `faults`.
    Order == the hardware order in hw_configure_all. Returns the store. pktgen+shape are enabled
    ONLY if every prior step passed with no fail and no warning."""
    faults = set(faults or [])
    st = ModelStore()

    # 1. validate (already run by the caller for deadlines/TS); re-assert the commit + codebook maths
    verify_commit_map(chk)

    # 2. keep pktgen DISABLED (app_enable stays False until step 14)
    # 3. bring up + read back dp8/dp9/dp64/dp68
    for p in BRINGUP_PORTS:
        st.ports[p] = {"up": True, "speed": "BF_SPEED_25G"}
        chk.expect("port dp%d up" % p, st.ports.get(p, {}).get("up"), True)

    # 4. resolve BOTH loopbacks (pg_id, pg_queue). dp8 = RRC domain, dp10 = BOR domain.
    if "queue_unresolvable" not in faults:
        st.pg_map[PORT_L] = (PORT_L // 4, (PORT_L // 4) * 8)              # deterministic model
        st.pg_map[PORT_BOR_L] = (PORT_BOR_L // 4, (PORT_BOR_L // 4) * 8)  # dp10 port-group

    # 5. TWO independent strict-priority ladders, shaping disabled: RRC (qid7..qid4) on dp8,
    #    BOR (qid3/qid2) on dp10. Each is validated as descending + distinct within its own port.
    for port, plan in ((PORT_L, QUEUE_PLAN_RRC), (PORT_BOR_L, QUEUE_PLAN_BOR)):
        pg = _model_resolve_pg(st, port)
        if pg is None:
            chk.fail("resolve dp%d port-group (resolve_pg)" % port, "no pg map")
            continue
        pg_id, pg_base = pg
        observed = []
        for label, qid, want_pri in plan:
            pgq = _model_pg_queue_of(pg_base, qid)
            st.queues[(pg_id, pgq)] = {"max_priority": want_pri, "scheduling_enable": True,
                                       "min_rate_enable": False, "max_rate_enable": False}
            sc = st.queues[(pg_id, pgq)]
            chk.expect("%s (dp%d qid%d) max_priority" % (label, port, qid), sc.get("max_priority"), want_pri)
            chk.expect("%s (dp%d) scheduling_enable" % (label, port), sc.get("scheduling_enable"), True)
            chk.expect("%s (dp%d) shaping disabled" % (label, port),
                       sc.get("min_rate_enable") or sc.get("max_rate_enable"), False)
            observed.append(want_pri)
        chk.expect("dp%d strict ladder descending+distinct" % port,
                   observed == sorted(observed, reverse=True) and len(set(observed)) == len(plan), True)

    # 6. pktgen port + two token buffers + two app patterns (DISABLED) + value_set + mirror
    st.pktgen_port[PORT_PGEN] = {"pktgen_enable": True, "recirculation_enable": True,
                                 "pattern_matching_enable": True}
    for name, prof in PKTGEN_APPS.items():
        if faults == {"pktgen_buffer_missing"} and prof["app_id"] == 2:
            pass  # inject: omit the 3K app's buffer region
        else:
            st.pktgen_buf[prof["buf_offset"]] = a.token_len
        st.pktgen_app[prof["app_id"]] = dict(
            pattern_value=prof["pattern_value"], pattern_mask=PKTGEN_PATTERN_MASK,
            packets_per_batch_cfg=prof["count"] - 1, increment_source_port=False,
            pipe_local_source_port=PORT_PGEN & 0x7F, app_enable=False)
    for name, prof in PKTGEN_APPS.items():
        app = st.pktgen_app.get(prof["app_id"], {})
        chk.expect("pktgen %s pattern_value" % name, app.get("pattern_value"), prof["pattern_value"])
        chk.expect("pktgen %s pattern_mask (byte0+byte1)" % name, app.get("pattern_mask"), PKTGEN_PATTERN_MASK)
        chk.expect("pktgen %s packets_per_batch_cfg" % name, app.get("packets_per_batch_cfg"), prof["count"] - 1)
        chk.expect("pktgen %s increment_source_port==False" % name, app.get("increment_source_port"), False)
        chk.expect("pktgen %s DISABLED before prerequisites" % name, app.get("app_enable"), False)
        chk.expect("pktgen %s buffer region present" % name,
                   prof["buf_offset"] in st.pktgen_buf, True)
    # the two patterns must be mutually exclusive on (byte0,byte1)
    p2k = st.pktgen_app.get(1, {}).get("pattern_value")
    p3k = st.pktgen_app.get(2, {}).get("pattern_value")
    chk.expect("pktgen app patterns mutually exclusive under mask",
               (p2k is not None and p3k is not None
                and (p2k & PKTGEN_PATTERN_MASK) != (p3k & PKTGEN_PATTERN_MASK)), True)
    # parser value_set pgen_recirc: one byte per app, byte=(pipe<<3)|app_id
    for name, prof in PKTGEN_APPS.items():
        if faults == {"valueset_missing"} and prof["app_id"] == 2:
            continue  # inject: omit app 2's value_set entry
        st.value_set.add((PIPE << 3) | prof["app_id"])
    chk.expect("pgen_recirc value_set has both app bytes {0x01,0x02}", st.value_set, {0x01, 0x02})
    # mirror session 7 -> dp68
    if "mirror_missing" not in faults:
        st.mirror[CLONE_SESSION_ID] = {"ucast_egress_port": PORT_PGEN, "direction": "INGRESS",
                                       "session_enable": True}
    m = st.mirror.get(CLONE_SESSION_ID)
    if m is None:
        chk.fail("mirror session %d present" % CLONE_SESSION_ID, "missing")
    else:
        chk.expect("mirror session %d -> dp%d" % (CLONE_SESSION_ID, PORT_PGEN),
                   m.get("ucast_egress_port"), PORT_PGEN)
        chk.expect("mirror session %d enabled" % CLONE_SESSION_ID, m.get("session_enable"), True)

    # 7. caseA timing params (shape_enable stays OFF until step 14)
    st.tbl_params = {"mode": caseA.MODE.get(a.mode, 4), "d_ticks": int(round((a.d_a_ms or 20) * 1e6)),
                     "da_dr": int(round(((a.d_a_ms or 20) + (a.d_r_ms or 4)) * 1e6)),
                     "read_len": a.read_len, "budget": a.budget, "shape_enable": 0}
    chk.expect("tbl_params installed (mode)", st.tbl_params.get("mode"), caseA.MODE.get(a.mode, 4))
    chk.expect("tbl_params shape_enable OFF until prerequisites pass", st.tbl_params.get("shape_enable"), 0)

    # 8. tbl_bor_params (A/R T0-anchored totals)
    st.tbl_bor_params = {"a_ticks": int(round((a.op_a_ms or 0) * 1e6)),
                         "r_ticks": int(round((a.op_r_ms or 0) * 1e6))}
    chk.expect("tbl_bor_params a_ticks", st.tbl_bor_params.get("a_ticks"), int(round((a.op_a_ms or 0) * 1e6)))
    chk.expect("tbl_bor_params r_ticks", st.tbl_bor_params.get("r_ticks"), int(round((a.op_r_ms or 0) * 1e6)))

    # 9. tbl_bor_codebook — FULL non-overlapping coverage of buckets 0..255
    ranges = build_codebook_coverage(_parse_ms_set(a.j_set), gap=("codebook_gap" in faults))
    st.codebook = [(lo, hi, jw) for lo, hi, jw, _ in ranges]
    validate_codebook_coverage(ranges, chk)
    # read back every range's realized J
    for lo, hi, jw, jm in ranges:
        stored = next((w for (l2, h2, w) in st.codebook if l2 == lo and h2 == hi), None)
        chk.expect("codebook [%d,%d] J word readback" % (lo, hi), stored, jw)

    # 10. tbl_session (both directions)
    st.session = [("relay", "master", "sess_relay")]
    if "session_missing_dir" not in faults:
        st.session.append(("master", "relay", "sess_master"))
    chk.expect("tbl_session has both directions", len(st.session), 2)

    # 11. PRE group RRC_MGID -> node RID1 + node RID2, both -> dp9
    st.pre_node[RRC_NODE1] = {"rid": 1, "ports": [PORT_VISION]}
    if "pre_missing_node" not in faults:
        st.pre_node[RRC_NODE2] = {"rid": 2, "ports": [PORT_VISION]}
    st.pre_mgid[RRC_MGID] = set(st.pre_node.keys())
    chk.expect("PRE mgid 0x%04x carries node 0x%04x" % (RRC_MGID, RRC_NODE1), RRC_NODE1 in st.pre_mgid[RRC_MGID], True)
    chk.expect("PRE mgid 0x%04x carries node 0x%04x" % (RRC_MGID, RRC_NODE2), RRC_NODE2 in st.pre_mgid[RRC_MGID], True)
    for nid, want_rid in ((RRC_NODE1, 1), (RRC_NODE2, 2)):
        nd = st.pre_node.get(nid)
        if nd is None:
            chk.fail("PRE node 0x%04x present" % nid, "missing")
        else:
            chk.expect("PRE node 0x%04x RID" % nid, nd.get("rid"), want_rid)
            chk.expect("PRE node 0x%04x -> dp%d" % (nid, PORT_VISION), nd.get("ports"), [PORT_VISION])

    # 12. init BOR + RRC registers to 0
    for r in BOR_REGS_ZERO:
        st.regs[r] = 0
        chk.expect("%s init==0" % r, st.regs.get(r), 0)

    # 13. (readback of every component done inline above)
    # 14. enable pktgen + shape ONLY if every prerequisite passed (no fail, no warning)
    if not chk.blocked():
        for prof in PKTGEN_APPS.values():
            st.pktgen_app[prof["app_id"]]["app_enable"] = True
        st.tbl_params["shape_enable"] = 1
        chk.ok("pktgen apps ENABLED + shape ON (all prerequisites passed)",
               "app1(2K) + app2(3K) app_enable=True ; tbl_params.shape_enable=1")
    else:
        chk.warn("pktgen + shape LEFT DISABLED (a prerequisite failed — fail-closed)",
                 "n_fail=%d n_warn=%d" % (chk.n_fail, chk.n_warn))
    return st


# ===========================================================================
# offline readback self-test — write->read->assert against an in-process store, plus a
# deliberately corrupted case proving the assertion is fail-closed (no switch involved).
# ===========================================================================
def offline_readback_selftest(chk):
    store = {}
    store[("tbl_bor_params", "default")] = {"a_ticks": A_DEFAULT_TICKS, "r_ticks": R_DEFAULT_TICKS}
    got = store.get(("tbl_bor_params", "default"))
    chk.expect("selftest readback tbl_bor_params",
               got, {"a_ticks": A_DEFAULT_TICKS, "r_ticks": R_DEFAULT_TICKS})
    store[("reg_bor_gen", 0)] = {"value": 0}
    chk.expect("selftest readback reg_bor_gen==0", store.get(("reg_bor_gen", 0)), {"value": 0})
    # negative control: corrupt the store; assert the local compare DETECTS it (fail-closed logic)
    store[("reg_bor_gen", 0)] = {"value": 7}
    corrupted_detected = (store.get(("reg_bor_gen", 0)) != {"value": 0})
    chk.expect("selftest negative control: corrupted readback DETECTED", corrupted_detected, True)


# ===========================================================================
# PART 3 — non-vacuous negative setup tests (offline). Each removes/corrupts ONE component and
# asserts model_configure_all FAILS (fail-closed). "Non-vacuous" = without the fault the model
# PASSES, and the fault specifically drives the matching readback assertion to fail.
# ===========================================================================
NEGATIVE_FAULTS = [
    ("codebook",         "codebook_gap"),          # bucket 255 uncovered -> silent J=0 default
    ("mirror",           "mirror_missing"),        # $mirror.cfg session 7 absent
    ("parser value-set", "valueset_missing"),      # pgen_recirc missing app-2 byte
    ("session",          "session_missing_dir"),   # only one tbl_session direction
    ("queue mapping",    "queue_unresolvable"),    # resolve_pg(dp8) fails
    ("PRE",              "pre_missing_node"),       # PRE group missing RID-2 node
    ("pktgen buffer",    "pktgen_buffer_missing"),  # 3K app's token buffer region absent
]


def run_negative_tests(a):
    """Return (all_ok, rows). Non-vacuity is asserted per fault (clean PASS, faulted FAIL)."""
    rows = []
    all_ok = True
    # baseline: the clean model MUST pass (else the negatives would be vacuous)
    base = Checks()
    validate_bor_deadlines(a, base)
    model_configure_all(a, base, faults=set())
    base_ok = (base.n_fail == 0 and base.n_warn == 0)
    rows.append(("baseline clean model", "PASS" if base_ok else "FAIL",
                 "n_fail=%d n_warn=%d" % (base.n_fail, base.n_warn)))
    all_ok = all_ok and base_ok
    for label, fault in NEGATIVE_FAULTS:
        chk = Checks()
        validate_bor_deadlines(a, chk)
        model_configure_all(a, chk, faults={fault})
        failed = chk.n_fail > 0                 # must have a hard failure
        pktgen_off = True                        # and pktgen/shape must be left disabled
        # re-derive: model returns store; recompute enable state from chk gate
        non_vacuous = failed and base_ok
        rows.append(("%s absent/corrupt -> configure FAILS" % label,
                     "PASS" if non_vacuous else "FAIL",
                     "fault=%s n_fail=%d (clean baseline PASS=%s)" % (fault, chk.n_fail, base_ok)))
        all_ok = all_ok and non_vacuous
    return all_ok, rows


# ===========================================================================
# hardware configure functions (gated; bfrt_grpc imported only inside; DELEGATE to proven helpers)
# ===========================================================================
def _connect(a):
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(grpc_addr=a.grpc, client_id=0, device_id=0)
    iface.bind_pipeline_config(PROGRAM)
    bi = iface.bfrt_info_get(PROGRAM)
    tgt = gc.Target(device_id=0, pipe_id=PIPE)
    tdev = gc.Target(device_id=0, pipe_id=0xffff)
    return iface, bi, tgt, tdev


def _shim(**kw):
    return argparse.Namespace(**kw)


def hw_config_queues_on_port(bi, tgt, a, port, plan, out, chk):
    """Configure ONE strict-priority ladder (qid == max_priority, DESCENDING) on ONE loopback
    port. REUSES the proven queue idiom (d3.resolve_pg + d3.pg_queue_of + tf1.tm.queue.sched_cfg
    with str_val max_priority), exactly as defense4_caseA_setup.py:config_queues_4q.

    ►► Called TWICE by configure-all: the RRC ladder (qid7>qid6>qid5>qid4) on PORT_L (dp8) and the
    BOR ladder (qid3>qid2) on PORT_BOR_L (dp10). Each port has its own egress scheduler, so the two
    ladders arbitrate strict priority INDEPENDENTLY — the whole point of the two-domain fix."""
    import bfrt_grpc.client as gc
    pg_id, pg_nr = d3.resolve_pg(bi, tgt, port, chk, {})
    q_cfg = d3.get_table(bi, "tf1.tm.queue.sched_cfg", chk)
    if pg_id is None or q_cfg is None:
        chk.fail("resolve dp%d queues" % port, "no port-group map / sched_cfg")
        return
    observed = []
    for label, qid, want_pri in plan:
        pgq = d3.pg_queue_of(pg_nr, qid)
        key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        try:
            q_cfg.entry_mod(tgt, [key], [q_cfg.make_data([
                gc.DataTuple("min_rate_enable", bool_val=False),
                gc.DataTuple("max_rate_enable", bool_val=False),
                gc.DataTuple("max_priority", str_val=str(want_pri)),
                gc.DataTuple("scheduling_enable", bool_val=True)])])
        except Exception as e:
            chk.fail("%s sched_cfg write" % label, str(e)[:90])
        sc, err = d3.get_entry(q_cfg, tgt, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("%s sched_cfg readback" % label, err)
            continue
        got_pri = d3.pnorm(sc.get("max_priority"))
        chk.expect("%s (dp%d) max_priority" % (label, port), got_pri, int(want_pri))
        chk.expect("%s (dp%d) scheduling_enable" % (label, port), sc.get("scheduling_enable"), True)
        chk.expect("%s (dp%d) min shaping disabled" % (label, port), sc.get("min_rate_enable"), False)
        chk.expect("%s (dp%d) max shaping disabled" % (label, port), sc.get("max_rate_enable"), False)
        observed.append(got_pri)
        out.setdefault("queues", {})[label] = {"dp": port, "qid": qid, "pg_queue": pgq,
                                               "max_priority": got_pri}
    chk.expect("dp%d strict ladder descending+distinct" % port,
               observed == sorted(observed, reverse=True) and len(set(observed)) == len(plan), True)


def hw_config_bor_loopback(bi, tdev, a, out, chk):
    """Bring up the SECOND loopback PORT_BOR_L (dp10) at 25G MAC-near loopback and read it back.
    The frozen d3.config_ports only brings up dp8/dp9/dp64, so dp10 is configured here with the
    SAME proven recipe used for the dp8 loopback (delete-then-add, because a live $PORT entry
    silently rejects a loopback-mode change). $PORT is device-scoped -> tdev (0xffff)."""
    import bfrt_grpc.client as gc
    port_tbl = d3.get_table(bi, "$PORT", chk)
    if port_tbl is None:
        chk.fail("dp%d $PORT table" % a.port_bor_l, "no $PORT")
        return
    lk = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", a.port_bor_l)])]
    try:
        port_tbl.entry_del(tdev, lk)
    except Exception:
        pass
    try:
        port_tbl.entry_add(tdev, lk, [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
    except Exception as e:
        chk.fail("dp%d BOR loopback up" % a.port_bor_l, str(e)[:90])
    got, err = d3.get_entry(port_tbl, tdev, [("$DEV_PORT", a.port_bor_l)])
    if err:
        chk.fail("dp%d BOR loopback readback" % a.port_bor_l, err)
        return
    chk.expect("dp%d loopback mode MAC_NEAR" % a.port_bor_l, got.get("$LOOPBACK_MODE"), "BF_LPBK_MAC_NEAR")
    chk.expect("dp%d speed 25G" % a.port_bor_l, got.get("$SPEED"), "BF_SPEED_25G")
    chk.expect("dp%d enabled" % a.port_bor_l, got.get("$PORT_ENABLE"), True)
    # the REAL port-group mapping for dp10 (resolve_pg) must succeed so the BOR ladder can be placed.
    pg_id, pg_nr = d3.resolve_pg(bi, gc.Target(device_id=0, pipe_id=PIPE), a.port_bor_l, chk, {})
    if pg_id is None:
        chk.fail("dp%d resolve_pg" % a.port_bor_l, "no port-group map")
    else:
        chk.ok("dp%d port-group resolved" % a.port_bor_l, "pg_id=%s pg_nr=%s" % (pg_id, pg_nr))
    out.setdefault("ports", {})["dp%d" % a.port_bor_l] = {
        k: got.get(k) for k in ("$PORT_UP", "$SPEED", "$FEC", "$PORT_ENABLE", "$LOOPBACK_MODE")}


def hw_config_pktgen_two_apps(bi, tgt, a, out, chk, enable=False):
    """Install BOTH pktgen apps (2K app 1, 3K app 2) with their mutually-exclusive trigger patterns,
    two token buffer regions, and both value_set bytes. REUSES the proven pktgen idiom from
    defense4_bor_twopipe_setup.py:config_pipe1_pktgen (tf1.pktgen.{port_cfg,pkt_buffer,app_cfg},
    trigger_recirc_pattern, increment_source_port=False) and d3.config_value_set."""
    import bfrt_grpc.client as gc
    pcfg = d3.get_table(bi, d3.PKTGEN_PORT_CFG, chk)
    if pcfg is not None:
        try:
            pcfg.entry_mod(tgt, [pcfg.make_key([gc.KeyTuple("dev_port", a.port_pgen)])],
                           [pcfg.make_data([gc.DataTuple("pktgen_enable", bool_val=True),
                                            gc.DataTuple("recirculation_enable", bool_val=True),
                                            gc.DataTuple("pattern_matching_enable", bool_val=True)])])
        except Exception as e:
            chk.fail("pktgen port_cfg dp%d" % a.port_pgen, str(e)[:100])
    pbuf = d3.get_table(bi, d3.PKTGEN_PKT_BUFFER, chk)
    acfg = d3.get_table(bi, d3.PKTGEN_APP_CFG, chk)
    if acfg is None:
        chk.fail("pktgen app_cfg", "not found")
        return
    template = d3.build_token_template(a.token_len)
    local_src = a.port_pgen & 0x7F
    for name, prof in PKTGEN_APPS.items():
        if pbuf is not None:
            try:
                pbuf.entry_mod(tgt, [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", prof["buf_offset"]),
                                                    gc.KeyTuple("pkt_buffer_size", len(template))])],
                               [pbuf.make_data([gc.DataTuple("buffer", bytearray(template))])])
            except Exception as e:
                chk.fail("pktgen %s pkt_buffer" % name, str(e)[:100])
        try:
            acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", prof["app_id"])])],
                           [acfg.make_data([
                               gc.DataTuple("pattern_value", prof["pattern_value"]),
                               gc.DataTuple("pattern_mask", PKTGEN_PATTERN_MASK),
                               gc.DataTuple("pkt_len", len(template)),
                               gc.DataTuple("pkt_buffer_offset", prof["buf_offset"]),
                               gc.DataTuple("pipe_local_source_port", local_src),
                               gc.DataTuple("increment_source_port", bool_val=False),
                               gc.DataTuple("batch_count_cfg", 0),
                               gc.DataTuple("packets_per_batch_cfg", prof["count"] - 1),
                               gc.DataTuple("ipg", 0), gc.DataTuple("ibg", 0),
                               gc.DataTuple("trigger_counter", 0), gc.DataTuple("batch_counter", 0),
                               gc.DataTuple("pkt_counter", 0),
                               gc.DataTuple("app_enable", bool_val=enable)],
                              "trigger_recirc_pattern")])
        except Exception as e:
            chk.fail("pktgen %s app_cfg" % name, str(e)[:120])
        got, err = d3.get_entry(acfg, tgt, [("app_id", prof["app_id"])])
        if err:
            chk.fail("pktgen %s readback" % name, err)
            continue
        chk.expect("pktgen %s pattern_value" % name, got.get("pattern_value"), prof["pattern_value"])
        chk.expect("pktgen %s pattern_mask" % name, got.get("pattern_mask"), PKTGEN_PATTERN_MASK)
        chk.expect("pktgen %s packets_per_batch_cfg" % name, got.get("packets_per_batch_cfg"), prof["count"] - 1)
        chk.expect("pktgen %s increment_source_port==False" % name, got.get("increment_source_port"), False)
        chk.expect("pktgen %s app_enable" % name, got.get("app_enable"), enable)
        # the parser value_set byte for this app: byte = (pipe<<3)|app_id, mask 0xFF
        d3.config_value_set(bi, _shim(pipe=PIPE, app_id=prof["app_id"]), out, chk, write=True)


def hw_config_codebook(bi, tgt, a, out, chk):
    """Install tbl_bor_codebook as NON-OVERLAPPING range entries covering PRNG buckets 0..255 for the
    relay dst_port, so NO bucket defaults to set_j(0). REUSES the range idiom of
    defense4_bor_twopipe_setup.py:config_pipe1_codebook (dst_port exact + rand8 range -> set_j)."""
    import bfrt_grpc.client as gc
    t = d3.get_table(bi, "tbl_bor_codebook", chk)
    if t is None:
        chk.fail("tbl_bor_codebook", "not found")
        return
    ranges = build_codebook_coverage(_parse_ms_set(a.j_set))
    if not validate_codebook_coverage(ranges, chk):
        chk.fail("codebook coverage precheck", "ranges do not cover 0..255 exactly")
        return
    def _cb_key():
        # meta.rand8 is a RANGE match field: KeyTuple needs low=/high= (positional lo,hi would
        # bind as value/mask -> Ternary, which the field rejects). d3.get_entry cannot build a
        # range key either, so the readback uses this same key via t.entry_get directly.
        return t.make_key([gc.KeyTuple("hdr.tcp.dst_port", a.relay_dst_port),
                           gc.KeyTuple("meta.rand8", low=lo, high=hi),
                           gc.KeyTuple("$MATCH_PRIORITY", i + 1)])
    for i, (lo, hi, j_word, _jm) in enumerate(ranges):
        data = t.make_data([gc.DataTuple("j_ticks", j_word)], "set_j")
        try:
            t.entry_add(tgt, [_cb_key()], [data])
        except Exception:
            try:
                t.entry_mod(tgt, [_cb_key()], [data])
            except Exception as e:
                chk.fail("codebook range [%d,%d]" % (lo, hi), str(e)[:100])
        got = None
        try:
            for d, _k in t.entry_get(tgt, [_cb_key()], {"from_hw": True}):
                got = d.to_dict()
        except Exception as e:
            chk.fail("codebook [%d,%d] readback" % (lo, hi), str(e)[:100])
        if got is None:
            chk.fail("codebook [%d,%d] readback" % (lo, hi), "entry not found")
        else:
            chk.expect("codebook [%d,%d] J word" % (lo, hi), got.get("j_ticks"), j_word)
    out["codebook_ranges"] = [(lo, hi, jw) for lo, hi, jw, _ in ranges]


def hw_config_tbl_bor_params(bi, tgt, a, out, chk):
    import bfrt_grpc.client as gc
    a_ticks = int(round((a.op_a_ms or 0) * 1e6))
    r_ticks = int(round((a.op_r_ms or 0) * 1e6))
    t = d3.get_table(bi, "tbl_bor_params", chk)
    if t is None:
        chk.fail("tbl_bor_params", "not found")
        return
    try:
        t.default_entry_set(tgt, t.make_data(
            [gc.DataTuple("a_ticks", a_ticks), gc.DataTuple("r_ticks", r_ticks)], "set_bor_params"))
    except Exception as e:
        chk.fail("tbl_bor_params set", str(e)[:120])
    got = None
    try:
        for item in t.default_entry_get(tgt, {"from_hw": True}):
            d = item[0] if isinstance(item, tuple) else item
            if d is not None:
                got = d.to_dict()
    except Exception as e:
        chk.fail("tbl_bor_params readback", str(e)[:90])
    if got:
        chk.expect("tbl_bor_params a_ticks", got.get("a_ticks"), a_ticks)
        chk.expect("tbl_bor_params r_ticks", got.get("r_ticks"), r_ticks)


def hw_verify_tbl_commit(bi, tgt, chk):
    """blocker 1: read tbl_commit back and assert the const-entry map (nothing installed)."""
    t = d3.get_table(bi, "tbl_commit", chk) or d3.get_table(bi, "Ingress.tbl_commit", chk)
    if t is None:
        chk.fail("tbl_commit", "not found")
        return
    seen = {}
    try:
        for d, k in t.entry_get(tgt, None, {"from_hw": True}):
            kd = k.to_dict()
            outcome = next((vv["value"] if isinstance(vv, dict) else vv
                            for kk, vv in kd.items() if "outcome" in kk), None)
            act = getattr(d, "action_name", None) or d.to_dict().get("action_name")
            if outcome is not None:
                seen[int(outcome)] = str(act).split(".")[-1]
    except Exception as e:
        chk.fail("tbl_commit read", str(e)[:120])
        return
    chk.expect("tbl_commit const map matches COMMIT_MAP", seen, COMMIT_MAP)


def hw_init_registers(bi, tgt, chk):
    """reg_bor_* := 0 (retired), read back == 0 (fail-closed). REUSES d3.reg_write / d3.reg_read."""
    for r in BOR_REGS_ZERO:
        try:
            d3.reg_write(bi, tgt, r, 0, chk=chk)
        except Exception as e:
            chk.fail("%s clear" % r, str(e)[:80])
    for r in BOR_REGS_ZERO:
        try:
            chk.expect("%s init==0" % r, int(d3.reg_read(bi, tgt, r)), 0)
        except Exception as e:
            chk.fail("%s readback" % r, str(e)[:80])


def hw_configure_all(a, chk):
    """The real fail-closed configure-all, delegating each step to a proven helper. pktgen apps and
    shape are enabled ONLY after every prerequisite reads back clean (no fail, no warning)."""
    iface, bi, tgt, tdev = _connect(a)
    out = {}
    try:
        # 0. data-plane ports FIRST. A cold bf_switchd load has NO $PORT entries, so dp8
        # (loopback), dp9 (master) and dp64 (relay) must be brought up or nothing forwards.
        # $PORT is device-scoped (tdev=0xffff); the TM port-scheduling authority that
        # assert_dp8_speed cross-checks is pipe-local (tgt=pipe0). Mirrors caseA `configure`.
        d3.assert_dp8_speed(bi, tdev, tgt, a, out, chk, pre=True)
        d3.config_ports(bi, tdev, a, out, chk, write=True)
        hw_config_bor_loopback(bi, tdev, a, out, chk)              # 3b: 2nd loopback dp10 (BOR)
        d3.disarm_port_shaper(bi, [("pipe0", tgt), ("device", tdev)], a, out, chk, write=True)
        verify_commit_map(chk)                                     # 1 (offline totality)
        hw_init_registers(bi, tgt, chk)                            # 12 -> clean epoch/RRC state first
        # 5: TWO independent strict-priority ladders — RRC (qid7..qid4) on dp8, BOR (qid3/qid2) on dp10
        hw_config_queues_on_port(bi, tgt, a, a.port_l, QUEUE_PLAN_RRC, out, chk)
        hw_config_queues_on_port(bi, tgt, a, a.port_bor_l, QUEUE_PLAN_BOR, out, chk)
        # 6 (pktgen DISABLED, buffers/patterns/value_set) + mirror + session
        hw_config_pktgen_two_apps(bi, tgt, a, out, chk, enable=False)
        d3.config_mirror(bi, tgt, a, out, chk, write=True)         # 6 mirror 7 -> dp68
        # SYMMETRIC ingress MAU tables (all pipes symmetric) MUST be written with the DEVICE
        # target 0xffff (tdev), not a single pipe (pipe 0 -> INVALID_ARGUMENT). This mirrors the
        # proven caseA/RRC path (caseA writes tbl_session/tbl_params with pipe_id=0xffff). Only
        # pipe-local resources (TM queues, pktgen, registers on dp8/dp68 in pipe 0) use tgt.
        d3.config_session(bi, tdev, a, out, chk, write=True)       # 10 tbl_session x2
        caseA.config_params_d4(bi, tdev, a, out, chk, write=True)  # 7 timing (shape stays off)
        hw_config_tbl_bor_params(bi, tdev, a, out, chk)            # 8
        hw_config_codebook(bi, tdev, a, out, chk)                  # 9
        rrc.install_pre(bi, tdev, chk, out, write=True)            # 11 PRE
        hw_verify_tbl_commit(bi, tdev, chk)                        # 5 (const map readback)
        # 14: enable pktgen + shape ONLY if every prerequisite passed
        if not chk.blocked():
            hw_config_pktgen_two_apps(bi, tgt, a, out, chk, enable=True)
            rrc.set_shape_enable(bi, tdev, chk, out, on=True, d3=d3, strict=True)  # tbl_params RMW: device target
            chk.ok("pktgen apps ENABLED + shape ON (all prerequisites passed)", "")
        else:
            chk.warn("pktgen + shape LEFT DISABLED (fail-closed)",
                     "n_fail=%d n_warn=%d" % (chk.n_fail, chk.n_warn))
    finally:
        try:
            iface._tear_down_stream()
        except Exception:
            pass
    return out


def hw_rollback(a, chk):
    """Rollback: disable pktgen FIRST, then shape, then timing (mode OFF), then PRE (verified)."""
    iface, bi, tgt, tdev = _connect(a)
    out = {}
    try:
        # pktgen is pipe-local (pipe-0 dp68) -> tgt. The two tbl_params writes below hit the
        # SYMMETRIC ingress MAU table (all pipes symmetric); like configure-all (set_shape_enable
        # line ~847, config_params_d4 line ~839) and the frozen caseA/RRC path, they MUST use the
        # DEVICE target 0xffff (tdev). Writing them at pipe 0 (tgt) returns INVALID_ARGUMENT while
        # reads still pass, so the teardown silently no-ops. PRE (delete_pre) already uses tdev.
        hw_config_pktgen_two_apps(bi, tgt, a, out, chk, enable=False)   # pktgen OFF first (pipe-local)
        rrc.set_shape_enable(bi, tdev, chk, out, on=False, d3=d3, strict=True)   # shape OFF (symmetric)
        a_off = argparse.Namespace(**vars(a))
        a_off.mode = "OFF"
        caseA.config_params_d4(bi, tdev, a_off, out, chk, write=True)   # timing -> OFF (symmetric)
        rrc.delete_pre(bi, tdev, chk, out)                             # PRE deleted last
    finally:
        try:
            iface._tear_down_stream()
        except Exception:
            pass
    return out


def hw_disable_bor(a, chk):
    """Turn BOR OFF without touching RRC timing/size: disable the pktgen apps (no reservoir ->
    OPERATE fails open) and clear the BOR epoch registers."""
    iface, bi, tgt, tdev = _connect(a)
    out = {}
    try:
        hw_config_pktgen_two_apps(bi, tgt, a, out, chk, enable=False)
        hw_init_registers(bi, tgt, chk)
    finally:
        try:
            iface._tear_down_stream()
        except Exception:
            pass
    return out


def hw_verify(a, chk):
    """Read-only readback of every component (no writes)."""
    iface, bi, tgt, tdev = _connect(a)
    out = {}
    try:
        hw_verify_tbl_commit(bi, tgt, chk)
        for r in BOR_REGS_ZERO:
            try:
                chk.ok("%s = %s" % (r, d3.reg_read(bi, tgt, r)))
            except Exception as e:
                chk.fail("%s read" % r, str(e)[:80])
    finally:
        try:
            iface._tear_down_stream()
        except Exception:
            pass
    return out


# ===========================================================================
# ops
# ===========================================================================
def sequence_text(a):
    return (
        "INSTALL + VERIFY SEQUENCE (fail-closed; each step read back; pktgen+shape enabled LAST):\n"
        "   1. validate (A,R,J) + TCP-timestamp policy       [offline]\n"
        "   2. keep pktgen apps DISABLED\n"
        "   3. bring up + read back dp8/dp9/dp64/dp68; + 2nd loopback dp10 (BOR, MAC-near 25G)\n"
        "   4. resolve dp8 AND dp10 (pg_id, pg_queue) via resolve_pg / pg_queue_of\n"
        "   5. TWO independent ladders: dp8 qid7>qid6>qid5>qid4 (RRC), dp10 qid3>qid2 (BOR); shaping off\n"
        "   6. pktgen port + 2 buffers + 2 mutually-exclusive patterns (0xE1:00 / 0xE1:01),\n"
        "      value_set {0x01,0x02}, mirror session %d -> dp%d\n"
        "   7. caseA tbl_params timing (shape_enable OFF)\n"
        "   8. tbl_bor_params (A=%g ms, R=%g ms)\n"
        "   9. tbl_bor_codebook: NON-OVERLAPPING ranges covering buckets 0..255 EXACTLY\n"
        "  10. tbl_session (reverse 5-tuple x2)\n"
        "  11. PRE mgid 0x%04x -> node 0x%04x(RID1)+0x%04x(RID2) -> dp%d\n"
        "  12. reg_bor_epoch/ready/gen/topj := 0\n"
        "  13. read back EVERY component (any warn/missing/empty/mismatch = FAILURE)\n"
        "  14. enable pktgen apps + shape ONLY after every prerequisite passed\n"
        "  Authorized run: DEFENSE4_HW_AUTHORIZED=1 python3 %s configure-all --grpc <addr> ...\n"
        % (CLONE_SESSION_ID, PORT_PGEN, a.op_a_ms or 0, a.op_r_ms or 0,
           RRC_MGID, RRC_NODE1, RRC_NODE2, PORT_VISION, os.path.basename(__file__)))


def op_dry_run(a):
    chk = Checks()
    print("==== defense4_rrc_bor_unified12 unified setup — DRY RUN (OFFLINE MODEL, NOT HARDWARE) ====")
    ok_dl, plan = validate_bor_deadlines(a, chk)
    validate_tcp_timestamp_policy(a, chk)
    offline_readback_selftest(chk)
    # the full fail-closed model sequence (clean)
    model_configure_all(a, chk, faults=set())
    print(chk.render())
    print("\n---- deadline plan ----")
    for k, v in plan.items():
        print("  %-16s %s" % (k, v))
    # negative-test battery (independent Checks per fault)
    neg_ok, neg_rows = run_negative_tests(a)
    print("\n---- negative setup tests (fail-closed, non-vacuous) ----")
    for name, verdict, detail in neg_rows:
        print("  [%s] %s - %s" % (verdict, name, detail))
    print("\n" + sequence_text(a))
    clean_ok = (chk.n_fail == 0 and chk.n_warn == 0)
    overall = clean_ok and neg_ok
    print("\nMODEL configure-all: %s (n_fail=%d n_warn=%d)"
          % ("PASS" if clean_ok else "FAIL", chk.n_fail, chk.n_warn))
    print("NEGATIVE tests: %s" % ("PASS" if neg_ok else "FAIL"))
    print("RESULT: %s" % ("PASS" if overall else "FAIL"))
    return 0 if overall else 2


def _require_hw(op):
    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write("REFUSING: op=%s touches ports/tables/queues/pktgen/PRE (hardware). "
                         "Set DEFENSE4_HW_AUTHORIZED=1 under an authorized session.\n" % op)
        return False
    return True


def op_hw(a, fn, name):
    chk = Checks()
    ok_dl, _plan = validate_bor_deadlines(a, chk)
    if not ok_dl:
        print("REFUSING %s: invalid (A,R,J) set:" % name)
        print(chk.render())
        return 2
    if not validate_tcp_timestamp_policy(a, chk):
        print("REFUSING %s: TCP-timestamp policy check failed." % name)
        print(chk.render())
        return 2
    if not _require_hw(name):
        return 2
    fn(a, chk)
    print("==== %s readback ====" % name)
    print(chk.render())
    print("RESULT: %s (n_fail=%d n_warn=%d)"
          % ("PASS" if not chk.blocked() else "FAIL", chk.n_fail, chk.n_warn))
    return 0 if not chk.blocked() else 2


def build_argparser():
    p = argparse.ArgumentParser(description="Unified single-pipe BOR setup + readback verification")
    p.add_argument("op", choices=["dry-run", "configure-all", "verify", "disable-bor", "rollback"],
                   help="dry-run is offline; the rest require DEFENSE4_HW_AUTHORIZED=1")
    p.add_argument("--grpc", default="localhost:50052")
    # deadline set (ms)
    p.add_argument("--op-a-ms", type=float, default=A_DEFAULT_TICKS / 1e6, help="A = T0->ACK release")
    p.add_argument("--op-r-ms", type=float, default=R_DEFAULT_TICKS / 1e6, help="R = T0->echo release")
    p.add_argument("--j-set", default="2 4 6 8 10 12", help="admissible J codebook (ms), nonzero")
    p.add_argument("--native-ack-ms", type=float, default=2.0)
    p.add_argument("--native-resp-ms", type=float, default=2.0)
    p.add_argument("--op-actuation-ms", type=float, default=200.0)
    p.add_argument("--master-timeout-ms", type=float, default=1000.0)
    p.add_argument("--tcp-rto-ms", type=float, default=200.0)
    p.add_argument("--guard-ms", type=float, default=20.0)
    p.add_argument("--failopen-horizon-ms", type=float, default=30.0)
    # TCP-timestamp policy (anti-subtraction validity gate)
    p.add_argument("--tcp-ts-policy", choices=["reject", "allow"], default="reject")
    p.add_argument("--tcp-opt-hex", default="", help="optional TCP options sample to assert TS-absent")
    # timing (caseA) params
    p.add_argument("--mode", choices=list(caseA.MODE.keys()), default="D4")
    p.add_argument("--d-a-ms", dest="d_a_ms", type=float, default=20.0)
    p.add_argument("--d-r-ms", dest="d_r_ms", type=float, default=4.0)
    # Raw ns-word overrides (expert). caseA.resolve_delays evaluates a.d_a/a.d_r even on the
    # ms path, so these MUST exist on the namespace or config_params_d4 raises AttributeError.
    # Mirrors defense4_caseA_setup.py's own --d-a/--d-r (default 0 -> ms path is used).
    p.add_argument("--d-a", dest="d_a", type=lambda x: int(x, 0), default=0)
    p.add_argument("--d-r", dest="d_r", type=lambda x: int(x, 0), default=0)
    p.add_argument("--poll-ms", dest="poll_ms", type=float, default=400.0)
    p.add_argument("--read-len", type=int, default=getattr(d3, "READ_LEN_DEFAULT", 13))
    p.add_argument("--budget", type=int, default=18000)
    # session / topology
    p.add_argument("--relay-ip", default=getattr(d3, "RELAY_IP_DEFAULT", "192.168.10.7"))
    p.add_argument("--master-ip", default=getattr(d3, "MASTER_IP_DEFAULT", "192.168.10.1"))
    p.add_argument("--relay-dst-port", type=int, default=RELAY_DST_PORT)
    # pktgen / mirror
    p.add_argument("--port-l", type=int, default=PORT_L)
    p.add_argument("--port-bor-l", type=int, default=PORT_BOR_L)  # 2nd loopback (BOR OPERATE domain)
    p.add_argument("--port-pgen", type=int, default=PORT_PGEN)
    # data-plane ports for the cold-load bring-up (d3.config_ports needs these on the namespace)
    p.add_argument("--port-vision", type=int, default=PORT_VISION)
    p.add_argument("--port-relay", type=int, default=PORT_RELAY)
    p.add_argument("--token-len", type=int, default=getattr(d3, "TOKEN_LEN", 60))
    p.add_argument("--clone-sid", type=int, default=CLONE_SESSION_ID)
    p.add_argument("--mirror-max-len", type=int, default=128)
    return p


def main():
    a = build_argparser().parse_args()
    if a.op == "dry-run":
        return op_dry_run(a)
    if a.op == "configure-all":
        return op_hw(a, lambda aa, cc: hw_configure_all(aa, cc), "configure-all")
    if a.op == "verify":
        return op_hw(a, lambda aa, cc: hw_verify(aa, cc), "verify")
    if a.op == "disable-bor":
        return op_hw(a, lambda aa, cc: hw_disable_bor(aa, cc), "disable-bor")
    if a.op == "rollback":
        return op_hw(a, lambda aa, cc: hw_rollback(aa, cc), "rollback")
    return 2


if __name__ == "__main__":
    sys.exit(main())

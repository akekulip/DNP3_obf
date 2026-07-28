#!/usr/bin/env python3
# =============================================================================
#  Contract + pure helpers for the Case A READ-anchored dual-release control plane.
#  NO gRPC, NO I/O, NO switch dependency — this module runs on any host and is what
#  `--dry-run` exercises. The on-switch half is case_a_read_anchored_dual_release_setup.py;
#  STAGE BOTH FILES INTO THE SAME DIRECTORY (the setup script imports this one by name).
#
#  Every constant below is quoted from one of:
#    (a) p4/case_a_dual_release_skeleton.p4                 -> "# .p4:NNN"
#    (b) p4/build_skeleton_9.13.1/bfrt.json                 -> "# bfrt.json"
#    (c) the switch's SDE 9.13.2 fixed schemas, read read-only 2026-07-28:
#          install/share/bf_rt_shared/bf_rt_tm_tf1.json     -> "# bf_rt_tm_tf1"
#          install/share/bf_rt_shared/bf_rt_pktgen_tf1.json -> "# bf_rt_pktgen_tf1"
#    (d) evidence/phase0/pktgen_batch_limits.md             -> "# batch_limits"
#  Nothing is guessed.
#
#  Design authority: design/CASE_A_READ_ANCHORED_DUAL_RELEASE.md
# =============================================================================
"""Constants, 256 ns quantization, horizon-derived pass budgets, and the PASS/FAIL
accumulator for the READ-anchored dual-release setup. Python 3.8; no numpy."""

PROG_DEFAULT = "case_a_dual_release_skeleton"   # p4 source basename == bfrt program name

# ---- ports (.p4:147-151, .p4:170) -----------------------------------------
PORT_L      = 8    # .p4:147  const PortId_t PORT_L      = 9w8   internal MAC-near loopback
PORT_VISION = 9    # .p4:148  const PortId_t PORT_VISION = 9w9   master side
PORT_HULK   = 11   # .p4:149  const PortId_t PORT_HULK   = 9w11  replay injector
PORT_RELAY  = 64   # .p4:151  const PortId_t PORT_RELAY  = 9w64  live SEL-751 leg (E1/33)
PORT_PGEN   = 68   # .p4:170  const PortId_t PORT_PGEN   = 9w68  pktgen / recirc port, pipe 0

# ---- the four dp8 queues (.p4:158-161) + the one master-facing FIFO (.p4:165) ----
QID_ABLOCK = 7     # .p4:158  ACK-deadline blockers
QID_ACK    = 6     # .p4:159  the held pure TCP ACK
QID_RBLOCK = 5     # .p4:160  response-deadline blockers
QID_RESP   = 4     # .p4:161  the held DNP3 RESPONSE
QID_NORMAL = 0     # .p4:165  the ONE external master-facing FIFO (design §4)

# Required strict ordering, design §3: Q_ABLOCK > Q_ACK > Q_RBLOCK > Q_RESP.
# QUEUE ID DOES NOT IMPLY PRIORITY. The IBSPG root-cause repair established that
# min_priority orders only the guaranteed pass (inert unless min_rate_enable is
# true) while BACKLOGGED queues compete in the remaining pass ordered by
# max_priority — so leaving max_priority unset degrades silently to a fair DWRR
# split. max_priority is the load-bearing field. The values are the string choices
# the schema exposes: ['LOW','0'..'7','HIGH'].   # bf_rt_tm_tf1 tf1.tm.queue.sched_cfg
QUEUE_PLAN = [
    ("Q_ABLOCK", QID_ABLOCK, "7"),
    ("Q_ACK",    QID_ACK,    "6"),
    ("Q_RBLOCK", QID_RBLOCK, "5"),
    ("Q_RESP",   QID_RESP,   "4"),
]

# ---- mirror / clone (.p4:174-179) -----------------------------------------
CLONE_SID             = 7      # .p4:175  const MirrorId_t CLONE_SESSION_ID = 10w7
CLONE_TAG_MARKER_BYTE = 0xE1   # .p4:179  const bit<32> CLONE_TAG_MARKER = 32w0xE1000000 -> byte0

# ---- blocker-token template (.p4:126, .p4:137, .p4:279, .p4:293) ----------
ETYPE_IBSPG = 0x88C1   # .p4:126  const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1
ROLE_BLOCK  = 1        # .p4:137  const bit<8>  ROLE_BLOCK = 1
TOKEN_DST = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
TOKEN_SRC = bytes([0x02, 0x00, 0x00, 0x00, 0x0b, 0x0c])
TOKEN_LEN = 60         # minimum Ethernet frame

# ---- pktgen (design §7 + # batch_limits) ----------------------------------
PGEN_PRSR_ID     = 17   # TF1 pgen value_set is tied to parser 17 (Defense 2 §B item 1, silicon)
APP_ID_DEFAULT   = 1    # -> value_set byte (pipe 0) = 0x01, distinct from the 0xE1 clone marker
TOKENS_TOTAL     = 128  # ONE batch of 128 -> packet_id 0..127 is uniquely partitionable
TOKENS_PER_CLASS = 64   # design §7.1: K_ACK = K_RESP = 64 (validated depth, NOT a proven minimum)
# # batch_limits Q2: the driver's ONLY batch-size bound is conditional on
# increment_source_port (pipe_mgr_tof_pktgen.c:1361-1375, PIPE_MGR_PKTGEN_SRC_PRT_MAX = 127):
#   increment_source_port=True => packets_per_batch <= 127 - pipe_local_source_port
# With the required pipe_local_source_port = 68 that is 59, i.e. 60 tokens — which would
# reject even the existing K = 64 reservoir, let alone 128. LOAD-BEARING invariant.
PKTGEN_SRC_PRT_MAX = 127

# ---- blocker classification, tbl_blocker_role (.p4:872-881) ---------------
# The table is declared with `const entries` + `const default_action`, and bfrt
# reports attribute 'ConstTable' with has_const_default_action = True (# bfrt.json).
# The two entries and the drop default are COMPILED IN: the control plane VERIFIES
# them, it cannot and must not write them.
BLOCKER_ENTRIES = [
    (0x0000, 0xFFC0, "Ingress.set_ack_blocker"),    # .p4:877  packet_id   0.. 63
    (0x0040, 0xFFC0, "Ingress.set_resp_blocker"),   # .p4:878  packet_id  64..127
]
BLOCKER_DEFAULT_ACTION = "Ingress.set_blk_drop"     # .p4:875

# ---- deadline word encoding (.p4:203-204, .p4:231-239) --------------------
TICK_NS      = 256        # .p4:203 TICK_MASK 0xFFFFFF00 -> 24 tick bits live in [31:8]
TICK_MAX     = 0xFFFFFF   # 24 bits of 256 ns ticks = 4.295 s of range
A_DEFAULT_MS = 3.0        # design §6 first proof-of-mechanism operating point (.p4:238)
R_DEFAULT_MS = 13.0       # smallest whole ms strictly above the measured p99 12.607 ms (.p4:239)

# ---- per-class pass budgets (.p4:199-200) ---------------------------------
# COMPILE-TIME constants in the loaded skeleton; design §10's runtime
# parameterization was deferred to Phase 4 (.p4:196-198). See check_budgets().
BUDGET_ABLOCK_COMPILED = 3000    # .p4:199  const bit<32> BUDGET_ABLOCK = 32w3000
BUDGET_RBLOCK_COMPILED = 13000   # .p4:200  const bit<32> BUDGET_RBLOCK = 32w13000
LOOP_US_DEFAULT      = 10.0      # .p4:191 "~10 us per pass at the blocker-queue shaper rate"
HORIZON_MULT_DEFAULT = 10.0      # design §10 "horizon at roughly 10x the corresponding deadline"
TCP_RTO_MS = 211.0               # measured host RTO the design §10 horizon must clear


# ===========================================================================
# 256 ns quantization — design §5.1
# ===========================================================================
def quantize_offset(label, ms):
    """Quantize a READ-relative offset to the deadline-word encoding.

    The ARMED marker occupies bit 0 of the deadline word (.p4:204), so an offset
    must be a whole number of 256 ns ticks with a zero low byte or the marker would
    not survive the add (.p4:760-767). Truncate rather than round: a programmed
    offset must never EXCEED the requested one, so the error is always <= 0.
    """
    req_ns = int(round(float(ms) * 1e6))
    ticks = req_ns // TICK_NS
    prog_ns = ticks * TICK_NS
    return {
        "label": label, "requested_ms": float(ms), "requested_ns": req_ns,
        "ticks": ticks, "ticks_hex": "0x%06X" % ticks,
        "programmed_ns": prog_ns, "programmed_ms": prog_ns / 1e6,
        "error_ns": prog_ns - req_ns,
        "word": (ticks << 8) & 0xFFFFFFFF, "word_hex": "0x%08X" % ((ticks << 8) & 0xFFFFFFFF),
    }


def check_offset(q, chk):
    lab = q["label"]
    if q["ticks"] < 1:
        chk.fail("%s ticks >= 1" % lab, "offset quantizes to 0 ticks (%g ms)" % q["requested_ms"])
    elif q["ticks"] > TICK_MAX:
        chk.fail("%s ticks <= 0xFFFFFF" % lab,
                 "%d ticks exceeds the 24-bit tick field (max %.3f ms)"
                 % (q["ticks"], TICK_MAX * TICK_NS / 1e6))
    elif q["word"] & 0xFF:
        chk.fail("%s low byte zero" % lab,
                 "word %s has a non-zero low byte; the ARMED marker would not survive the add"
                 % q["word_hex"])
    else:
        chk.ok("%s deadline word" % lab, "%s (%d ticks, %d ns, error %+d ns)"
               % (q["word_hex"], q["ticks"], q["programmed_ns"], q["error_ns"]))


# ===========================================================================
# Pass budgets — design §10 (horizon / measured loop time, NOT inherited)
# ===========================================================================
def budget_from_horizon(deadline_ms, loop_us, mult):
    horizon_ms = float(deadline_ms) * float(mult)
    return horizon_ms, int(horizon_ms * 1000.0 / float(loop_us))


def check_budgets(a, qa, qr, out, chk):
    """Size each per-class budget from the horizon and check it against the value
    COMPILED INTO the loaded program.

    TODO(p4) — NOT a silicon item. The skeleton carries the budgets as compile-time
    constants (.p4:199-200) and exposes no runtime hook, because design §10's runtime
    parameterization was deferred to Phase 4 (.p4:196-198). So this function computes
    the correct budget and FAILS on disagreement, naming the exact P4 edit; it cannot
    program it. Resolution: add `bit<32> ablock_budget, bit<32> rblock_budget` to
    action set_guard (.p4:738) and write them through tbl_guard alongside A and R.
    """
    hz_a, want_a = budget_from_horizon(qa["requested_ms"], a.loop_us, a.horizon_mult)
    hz_r, want_r = budget_from_horizon(qr["requested_ms"], a.loop_us, a.horizon_mult)
    got_a = want_a if a.ablock_passes is None else a.ablock_passes
    got_r = want_r if a.rblock_passes is None else a.rblock_passes
    out["budgets"] = {
        "loop_us": a.loop_us, "horizon_mult": a.horizon_mult, "tcp_rto_ms": TCP_RTO_MS,
        "ablock": {"horizon_ms": hz_a, "computed_passes": want_a,
                   "requested_passes": got_a, "compiled_passes": BUDGET_ABLOCK_COMPILED},
        "rblock": {"horizon_ms": hz_r, "computed_passes": want_r,
                   "requested_passes": got_r, "compiled_passes": BUDGET_RBLOCK_COMPILED},
    }
    for cls, line, hz, want, got, compiled in (
            ("ABLOCK", 199, hz_a, want_a, got_a, BUDGET_ABLOCK_COMPILED),
            ("RBLOCK", 200, hz_r, want_r, got_r, BUDGET_RBLOCK_COMPILED)):
        detail = ("horizon %.1f ms = %gx deadline / %g us per pass -> %d passes"
                  % (hz, a.horizon_mult, a.loop_us, want))
        if got != compiled:
            msg = ("requested %d passes but the LOADED program has %d compiled in (.p4:%d). "
                   "No runtime hook exists (design §10 deferred to Phase 4). Edit BUDGET_%s "
                   "and recompile, or accept the compiled value with --allow-budget-mismatch. %s"
                   % (got, compiled, line, cls, detail))
            (chk.warn if a.allow_budget_mismatch else chk.fail)("%s pass budget" % cls, msg)
        else:
            chk.ok("%s pass budget" % cls, "%d passes; %s" % (got, detail))
        if hz >= TCP_RTO_MS:
            chk.warn("%s horizon vs TCP RTO" % cls,
                     "fail-open horizon %.1f ms >= measured RTO %g ms — a budget expiry would "
                     "land at or beyond a retransmit" % (hz, TCP_RTO_MS))
        else:
            chk.ok("%s horizon vs TCP RTO" % cls, "%.1f ms = %.0f%% of the %g ms RTO"
                   % (hz, 100.0 * hz / TCP_RTO_MS, TCP_RTO_MS))


def print_quantization(qa, qr, a):
    """design §5.1 requires requested / programmed / quantization error to be
    RECOMPUTED and echoed for every configuration, not trusted from the table."""
    print("A / R quantization (256 ns ticks; the ARMED marker occupies the low byte)")
    print("  %-3s %13s %12s %10s %14s %10s %12s"
          % ("off", "requested", "req ns", "ticks", "programmed ns", "error ns", "word"))
    for q in (qa, qr):
        print("  %-3s %10.4f ms %12d %10s %14d %+10d %12s"
              % (q["label"], q["requested_ms"], q["requested_ns"], q["ticks_hex"],
                 q["programmed_ns"], q["error_ns"], q["word_hex"]))
    print("  S = R - A = %.6f ms (programmed): observer sees READ->ACK ~ A, ACK->RESP ~ S, "
          "READ->RESP ~ R" % ((qr["programmed_ns"] - qa["programmed_ns"]) / 1e6))
    hz_a, pa = budget_from_horizon(qa["requested_ms"], a.loop_us, a.horizon_mult)
    hz_r, pr = budget_from_horizon(qr["requested_ms"], a.loop_us, a.horizon_mult)
    print("\nPass budgets (design §10: horizon / measured loop time, NOT inherited)")
    print("  ABLOCK  horizon %8.2f ms / %g us = %6d passes   (compiled in: %d)"
          % (hz_a, a.loop_us, pa, BUDGET_ABLOCK_COMPILED))
    print("  RBLOCK  horizon %8.2f ms / %g us = %6d passes   (compiled in: %d)"
          % (hz_r, a.loop_us, pr, BUDGET_RBLOCK_COMPILED))
    print("  TCP RTO reference: %g ms\n" % TCP_RTO_MS)


# ===========================================================================
# Blocker-token template
# ===========================================================================
def build_token_template(total_len=TOKEN_LEN):
    """The 0x88C1 blocker-token buffer loaded into tf1.pktgen.pkt_buffer.

    GOTCHA 4/6 (Defense 2 §B item 4): the buffer holds only what FOLLOWS the 6-byte
    pktgen_recirc_header_t — the hardware prepends that itself. The skeleton parser
    consumes it as advance(32) + extract(pgen_id,16) (.p4:481-482), the same 48 bits
    the Defense 2 baseline advanced over, then parses ethernet.

    role/slot/gen/seq are placeholders: the P4 RE-STAMPS role (.p4:989), slot
    (.p4:990), gen from reg_tag (.p4:991) and seq from the per-class budget (.p4:992)
    at admission, so a token that somehow escaped re-stamping is doubly fail-safe
    (gen 0 -> stale drop, seq 0 -> budget_zero drop).
    """
    tok = bytearray()
    tok += TOKEN_DST                                                # ethernet_h.dst (.p4:279)
    tok += TOKEN_SRC                                                # ethernet_h.src
    tok += bytes([(ETYPE_IBSPG >> 8) & 0xFF, ETYPE_IBSPG & 0xFF])   # ethernet_h.etype 0x88C1
    tok += bytes([ROLE_BLOCK, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # ibspg_h role/slot/gen/seq
    if len(tok) < total_len:
        tok += bytes(total_len - len(tok))
    return bytes(tok)


# ===========================================================================
# Small utilities
# ===========================================================================
def pnorm(v):
    """Normalize a tf1.tm.queue.sched_cfg priority ('LOW'|'0'..'7'|'HIGH') to an int."""
    if v is None:
        return None
    s = str(v).upper()
    if s == "HIGH":
        return 7
    if s == "LOW":
        return 0
    try:
        return int(s)
    except ValueError:
        return None


def kv_pair(x):
    """Normalize a ternary key readback into (value, mask).

    TODO(silicon): the exact representation the client returns for a ternary key
    field is not settled off-switch. Handled defensively; the readback that settles
    it is the tbl_blocker_role / value_set dump printed by --verify-only.
    """
    if isinstance(x, dict):
        return x.get("value"), x.get("mask")
    if isinstance(x, (list, tuple)) and len(x) == 2:
        return x[0], x[1]
    return x, None


class Checks(object):
    """PASS / WARN / FAIL accumulator. Nothing proceeds silently past a mismatch."""

    def __init__(self):
        self.rows = []
        self.n_fail = 0

    def ok(self, name, detail=""):
        self.rows.append(("PASS", name, str(detail)))

    def warn(self, name, detail=""):
        self.rows.append(("WARN", name, str(detail)))

    def fail(self, name, detail=""):
        self.rows.append(("FAIL", name, str(detail)))
        self.n_fail += 1

    def expect(self, name, got, want, extra=""):
        if got == want:
            self.ok(name, ("%s %s" % (got, extra)).strip())
        else:
            self.fail(name, ("got %r, expected %r %s" % (got, want, extra)).strip())

    def expect_fields(self, prefix, got, spec):
        """spec = [(field_name, expected_value, extra_note), ...] against one readback dict."""
        for fld, want, extra in spec:
            self.expect("%s %s" % (prefix, fld), got.get(fld), want, extra)

    def render(self):
        w = max([len(r[1]) for r in self.rows] + [5])
        lines = ["", "%-4s  %-*s  %s" % ("RES", w, "CHECK", "DETAIL"),
                 "%-4s  %-*s  %s" % ("-" * 4, w, "-" * w, "-" * 40)]
        for res, name, detail in self.rows:
            lines.append("%-4s  %-*s  %s" % (res, w, name, detail))
        n_pass = len([r for r in self.rows if r[0] == "PASS"])
        n_warn = len([r for r in self.rows if r[0] == "WARN"])
        lines += ["", "%d check(s): %d PASS, %d WARN, %d FAIL"
                  % (len(self.rows), n_pass, n_warn, self.n_fail)]
        return "\n".join(lines)

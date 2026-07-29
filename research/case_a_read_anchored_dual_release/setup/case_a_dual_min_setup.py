#!/usr/bin/env python3.8
# =============================================================================
#  case_a_dual_min_setup.py — control plane for the MINIMAL SYNTHETIC
#  DUAL-RELEASE GATE (p4/case_a_dual_min.p4).
#
#  AUTHORED OFF-SWITCH. This file has NOT been executed against bf_switchd,
#  case_a_dual_min has NOT been loaded, and the switch is still running the
#  proven Defense 2 program. Loading is a separate, explicitly authorized step.
#
#  Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052):
#
#    SDE=/home/decps/Downloads/bf-sde-9.13.2
#    SP=$SDE/install/lib/python3.8/site-packages
#    PYTHONPATH=$SP:$SP/tofino python3.8 case_a_dual_min_setup.py --config
#
#  ---------------------------------------------------------------------------
#  WHAT IT CONFIGURES, AND WHY EACH PIECE EXISTS
#
#  1. dp8 MAC-near loopback and FIVE queues with max_priority 7/6/5/4/3, read
#     back. max_priority is the load-bearing field: min_priority orders only
#     the GUARANTEED pass and is inert unless min_rate_enable is true, which is
#     exactly the silent misconfiguration the IBSPG root-cause repair found.
#     Per-queue max_rate_enable is asserted OFF: a queue over its own max rate
#     goes shaping-ineligible and the TM serves a lower-priority queue, which
#     is indistinguishable from a priority violation.
#
#  2. TWO packet-generator applications on dp68:
#       app 1  trigger_recirc_pattern, ONE batch of 128 blocker tokens, fired
#              by the READ's mirrored 0xE1 clone. This is the mechanism the
#              frozen Defense 2 proved on silicon.
#       app 2  trigger_timer_one_shot, ONE batch of 3 synthetic events spaced
#              by ipg nanoseconds: READ, then the two events whose roles the
#              tbl_event_role map assigns.
#     A hardware ipg is what makes the safety tests precise: gRPC write skew is
#     milliseconds, and the ACK deadline is 3 ms, so arming three timers from
#     the host could not express "the ACK arrives after d_ACK" reliably.
#
#  3. tbl_event_role — packet_id 0 is ALWAYS the READ; which of packet_id 1 and
#     2 is the ACK is written here. Swapping them IS the early-response test.
#
#  4. tbl_guard — A, R and the two fail-open pass budgets as action data, so an
#     (A, R) sweep needs no recompile. A and R are quantized to 256 ns here and
#     the requested / programmed / error triple is echoed into the manifest
#     rather than trusted from a table (design §5.1).
#
#  THERE IS NO RELEASE GATE. The four-queue oracle needed a dp8 PORT-level
#  shaper because it preloaded a finite backlog and released it with one write.
#  This gate is SELF-TIMED: the READ anchors both deadlines in hardware and the
#  blockers terminate on their own. No shaper is armed, so none can leak.
#
#  ---------------------------------------------------------------------------
#  TRIAL ISOLATION. Every transaction asserts a clean start and REFUSES to run
#  on a dirty switch, and runs the cleanup in a `finally`, so a transaction
#  that ends INVALID leaves the switch exactly as one that ends PASS does. This
#  is carried from setup/four_queue_dequeue_oracle_setup.py, where the
#  five-control pilot proved that neither mechanism alone is enough: cleanup
#  can fail, and a trial that starts anyway on a dirty switch produces a
#  plausible-looking number.
#
#  THE DRAIN TEST IS TOKEN CONSERVATION, NOT usage_cells. The oracle measured
#  usage_cells reading 0 on every dp8 queue in all five shaper settings
#  INCLUDING the one that demonstrably leaked, so a drain check built on it can
#  never fail. Here, every admitted token leaves by exactly one of three
#  counted doors, so
#      admitted == terminated_deadline + terminated_budget + terminated_stale
#  closes if and only if nothing is still circulating. watermark_cells and
#  drop_count_packets are still read, as diagnostics and as a hard drop check.
#
#  Ports touched: dp8 (loopback, owns the queues) and dp68 (packet generator).
#  dp9, dp11 and dp64 are NOT configured. Hulk is NOT contacted. sudo is NEVER
#  invoked. Python 3.8; no numpy (not installed on the switch).
# =============================================================================
"""case_a_dual_min_setup.py — control plane for the minimal synthetic
dual-release gate.

Modes (at least one required):
  --config          one-time: dp8 loopback, five queues, mirror session, parser
                    value_set, both pktgen apps, both buffer templates, the
                    event role map and the guard words. Apps left DISABLED.
  --verify-only     read everything back, print PASS/FAIL, write NOTHING.
  --queues          write + read back the five max_priority values.
  --guard           write A / R / budgets into tbl_guard's default action.
  --event-map       write the three tbl_event_role entries for --scenario.
  --assert-clean    read the clean facts; exit non-zero if any is wrong.
  --cleanup         run the mandatory cleanup path on its own.
  --txn             ONE COMPLETE TRANSACTION in this process: ASSERT CLEAN,
                    program the scenario, arm, wait for completion, read the
                    registers and counters, MANDATORY CLEANUP, write JSON.
  --occupancy       per-queue watermark / drop counters.
  --restore-dp8     put dp8's scheduling config back to its original state.
  --dry-run         no gRPC at all: print the plan and the quantization, exit.

Scenarios (--scenario), all expressed as (ipg, event role map) only:
  normal          ipg 500 us   pid1=ACK  pid2=RESP  both events well before d_ACK
  early-response  ipg 500 us   pid1=RESP pid2=ACK   RESPONSE parked before the ACK
  late-ack        ipg 7 ms     pid1=RESP pid2=ACK   RESPONSE after d_ACK, ACK after
                                                    d_RESP -> the generation-bound
                                                    gate is what holds the response
                                                    blockers past their deadline

Exit status is non-zero if any check FAILs. Prints a PASS/FAIL table and one
JSON line `CADM {...}`.
"""
import argparse
import json
import sys
import time

# ---------------------------------------------------------------------------
# Constants. Every one mirrors p4/case_a_dual_min.p4; the cited line is where
# it is defined there. PROVENANCE for the bfrt names is the SDE 9.13.1/9.13.2
# fixed schemas install/share/bf_rt_shared/bf_rt_{tm,pktgen,mirror}_tf1.json,
# and for the generator sequence pkgsrc/p4-examples/p4_16_programs/tna_pktgen.
# Nothing here is guessed.
# ---------------------------------------------------------------------------
PROG_DEFAULT = "case_a_dual_min"      # p4 source basename == bfrt program name

PORT_L    = 8      # .p4:132  const PortId_t PORT_L    = 9w8
PORT_PGEN = 68     # .p4:131  const PortId_t PORT_PGEN = 9w68

QID_ABLOCK = 7     # .p4:142
QID_ACK    = 6     # .p4:143
QID_RBLOCK = 5     # .p4:144
QID_RESP   = 4     # .p4:145
QID_FINAL  = 3     # .p4:146

# (name, qid, max_priority). The ladder is the whole point; it is written and
# read back, and the readback is recorded as CONFIGURATION evidence only — the
# behavioural evidence for four-level strict priority on this silicon is the
# closed four-queue dequeue oracle (reports/FOUR_QUEUE_ORACLE_CLOSED.md).
QUEUE_PLAN = [
    ("Q_ABLOCK", QID_ABLOCK, "7"),
    ("Q_ACK",    QID_ACK,    "6"),
    ("Q_RBLOCK", QID_RBLOCK, "5"),
    ("Q_RESP",   QID_RESP,   "4"),
    ("Q_FINAL",  QID_FINAL,  "3"),
]

ETYPE_DUAL = 0x88C5   # .p4:124  const bit<16> ETHERTYPE_DUAL = 0x88C5

ROLE_NONE   = 0       # .p4:178
ROLE_ABLOCK = 1       # .p4:179
ROLE_ACK    = 2       # .p4:180
ROLE_RBLOCK = 3       # .p4:181
ROLE_RESP   = 4       # .p4:182
ROLE_READ   = 5       # .p4:183
ROLE_NAME = {0: "NONE", 1: "ABLOCK", 2: "ACK", 3: "RBLOCK", 4: "RESP", 5: "READ"}

PH_NEW = 0            # .p4:189

ACKC_NONE = 0xFF      # .p4:207

# app ids. The pipe-0 generator header byte 0 is pad(3)|pipe_id(2)|app_id(3),
# so a pipe-0 app id N appears as the byte value N — which is what
# .p4:156-157 APP_BLOCK_BYTE / APP_EVENT_BYTE and the parser value_set match.
APP_BLOCK = 1
APP_EVENT = 2
PIPE      = 0
PGEN_PRSR_ID = 17     # the pgen value_set is tied to parser 17 on TF1

CLONE_SID          = 7           # .p4:166  const MirrorId_t CLONE_SESSION_ID = 10w7
CLONE_TAG_MARKER   = 0xE1        # .p4:163  CLONE_TAG_MARKER = 32w0xE1000000 -> byte0
PATTERN_VALUE      = 0xE1000000  # first 32 bits of the recirculated clone
PATTERN_MASK       = 0xFF000000  # pin byte 0 only; gen occupies the low byte

N_BLOCKERS       = 128           # ONE batch. packet_id 0..127 is uniquely
N_BLOCKERS_PER_CLASS = 64        # partitionable; two batches of 64 would not be
N_EVENTS         = 3             # READ + two events

# ---- the 256 ns deadline-word encoding (.p4:194-195, design §5.1) ----------
TICK_NS   = 256
A_MS_DEFAULT = 3
R_MS_DEFAULT = 13

# ---- fail-open pass budgets (.p4:235-236) ---------------------------------
BUDGET_A_DEFAULT = 20000
BUDGET_R_DEFAULT = 80000

# ---- registers, and the JSON key each is reported under -------------------
# Registers, not Counter slots, for everything the cleanup path polls: a
# Register reads live over bfrt while a Stats-ALU Counter returns a stale 0
# unless SyncCounters is run first.
STATE_REGS = [
    ("reg_tag",              "tag"),               # .p4:498
    ("reg_d_ack",            "d_ack_word"),        # .p4:521
    ("reg_d_resp",           "d_resp_word"),       # .p4:528
    ("reg_ackc_gen",         "ack_commit_gen"),    # .p4:567
]
TS_REGS = [
    ("reg_t_read",           "t_read"),            # .p4:583
    ("reg_ts_ablock_first",  "ts_ablock_first"),   # .p4:587
    ("reg_ts_ablock_last",   "ts_ablock_last"),    # .p4:591
    ("reg_ts_ack_commit",    "ts_ack_commit"),     # .p4:595
    ("reg_ts_rblock_first",  "ts_rblock_first"),   # .p4:599
    ("reg_ts_rblock_last",   "ts_rblock_last"),    # .p4:603
    ("reg_ts_resp_commit",   "ts_resp_commit"),    # .p4:607
    ("reg_final_first",      "final_first_role"),  # .p4:614
]
ALL_REGS = STATE_REGS + TS_REGS

# ---- the ONE indexed reason counter (.p4:257-280, Counter .p4:620) --------
CTR_NAME = "ctr_evt"
CTR_SLOTS = [
    (0,  "drop_bad_port"),   (1,  "drop_non_dual"),
    (2,  "arm_fresh"),       (3,  "arm_dup"),
    (4,  "admit_ablock"),    (5,  "admit_rblock"),
    (6,  "pgen_notxn"),
    (8,  "ack_held"),        (9,  "ack_notxn"),
    (10, "resp_held"),       (11, "resp_notxn"),
    (12, "fresh_bad"),
    (13, "loop_ablock"),     (14, "loop_rblock"),
    (15, "term_ablock_dl"),  (16, "term_ablock_tmo"), (17, "term_ablock_stale"),
    (18, "term_rblock_dl"),  (19, "term_rblock_tmo"), (20, "term_rblock_stale"),
    (21, "ack_commit"),      (22, "resp_commit"),
    (23, "final_drain"),     (24, "deq_bad"),
]

# ---- bfrt table names (fixed-function schemas) ----------------------------
TM_PORT_CFG       = "tf1.tm.port.cfg"              # KEY dev_port
TM_SCHED_CFG      = "tf1.tm.queue.sched_cfg"       # KEY pg_id, pg_queue
TM_QUEUE_MAP      = "tf1.tm.queue.map"             # KEY pg_id, pg_queue
TM_COUNTER_QUEUE  = "tf1.tm.counter.queue"         # KEY pg_id, pg_queue
TM_PORT_SHAPING   = "tf1.tm.port.sched_shaping"    # KEY dev_port
TM_PORT_SCHED_CFG = "tf1.tm.port.sched_cfg"        # KEY dev_port
PKTGEN_PORT_CFG   = "tf1.pktgen.port_cfg"          # KEY dev_port
PKTGEN_PKT_BUFFER = "tf1.pktgen.pkt_buffer"        # KEY offset, size
PKTGEN_APP_CFG    = "tf1.pktgen.app_cfg"           # KEY app_id (ACTION-based)
MIRROR_CFG        = "$mirror.cfg"                  # KEY $sid (ACTION-based)

CTR_FIELDS = ("usage_cells", "watermark_cells", "drop_count_packets")

# ---- dp8's ORIGINAL scheduling state, restored by --restore-dp8 -----------
DP8_ORIGINAL = {
    "max_rate_enable": False,
    "max_rate": 25010000,
    "unit": "BPS",
    "max_burst_size": 9216,
    "scheduling_speed": "BF_SPEED_25G",
}

# ---- the two 64-byte buffer templates -------------------------------------
# The hardware PREPENDS its own 6-byte generator header, which the P4 extracts
# and never emits, so what reaches a queue is exactly these bytes with role /
# phase / gen / seq stamped in. Offsets must be 16-byte aligned.
TPL_LEN     = 64
BUF_OFF_BLOCK = 0
BUF_OFF_EVENT = 64
TPL_DST = bytes([0x02, 0x00, 0x00, 0x00, 0x88, 0xC5])
TPL_SRC = bytes([0x02, 0x00, 0x00, 0x00, 0x88, 0xC6])

# ---- the three scenarios ---------------------------------------------------
# A scenario is ONLY (ipg, event role map). There is no second P4 variant and
# no second generator programme: the emission order is hardware-fixed at
# 0, 1, 2 and only the roles and the spacing move.
#
#   normal          ACK at t_READ+0.5 ms, RESPONSE at +1.0 ms. Both are parked
#                   long before d_ACK = 3 ms, which is the ordinary case.
#   early-response  the same 0.5 ms spacing with the roles SWAPPED, so the
#                   RESPONSE is already sitting in Q_RESP before the ACK even
#                   arrives, let alone before d_ACK.
#   late-ack        7 ms spacing with the roles swapped: RESPONSE at 7 ms (past
#                   d_ACK, so Q_RBLOCK is already the active gate) and ACK at
#                   14 ms — past d_RESP = 13 ms. That last part is deliberate:
#                   it is the only spacing in which the response blockers reach
#                   their deadline with NO ACK committed, so their continued
#                   circulation is caused by the generation-bound gate and by
#                   nothing else.
SCENARIOS = {
    "normal":         {"ipg_ns":  500000, "pid1": "ACK",  "pid2": "RESP"},
    "early-response": {"ipg_ns":  500000, "pid1": "RESP", "pid2": "ACK"},
    "late-ack":       {"ipg_ns": 7000000, "pid1": "RESP", "pid2": "ACK"},
}
EVENT_ACTION = {
    "READ": "Ingress.set_ev_read",
    "ACK":  "Ingress.set_ev_ack",
    "RESP": "Ingress.set_ev_resp",
}

CLEAN_FACTS = ("all registers zero", "all counter slots zero",
               "both pktgen apps disabled", "zero queue drops")


class DirtyStateError(Exception):
    """A transaction refused to start because the switch was not clean.

    Deliberately an EXCEPTION and not a return code. The four-queue pilot's
    whole failure was that one control ended without releasing, left 124
    packets backlogged, and the next control drained those together with its
    own batch. Nothing downstream of a dirty start is interpretable, so the
    transaction must not proceed at all.
    """


# ===========================================================================
# small helpers
# ===========================================================================
def _i(v):
    """None-preserving int()."""
    return None if v is None else int(v)


def pnorm(v):
    """Normalize a sched_cfg priority ('LOW'|'0'..'7'|'HIGH') to an int."""
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


def quantize_offset(ns):
    """(ticks, programmed_ns, error_ns, deadline_word) for a requested offset.

    The ARMED marker occupies the low byte of the deadline word (.p4:195), so
    an offset must be a whole number of 256 ns ticks and must be shifted into
    [31:8] with a ZERO low byte, or the marker would not survive the addition.
    design §5.1 requires requested / programmed / error to be RECOMPUTED and
    echoed per run rather than trusted from a table.
    """
    ticks = int(ns) // TICK_NS
    programmed = ticks * TICK_NS
    return ticks, programmed, programmed - int(ns), (ticks << 8) & 0xFFFFFFFF


def build_template(role, phase, gen, seq):
    """A 64-byte packet-buffer template.

    Layout mirrors headers_t in the .p4 exactly (.p4:283,311):
        [0:6]   eth.dst
        [6:12]  eth.src
        [12:14] eth.etype = 0x88C5
        [14]    dl.role
        [15]    dl.phase
        [16]    dl.gen
        [17:21] dl.seq
        [21:64] pad, never extracted, re-emitted verbatim by the deparser
    """
    b = bytearray(TPL_LEN)
    b[0:6] = TPL_DST
    b[6:12] = TPL_SRC
    b[12] = (ETYPE_DUAL >> 8) & 0xFF
    b[13] = ETYPE_DUAL & 0xFF
    b[14] = role & 0xFF
    b[15] = phase & 0xFF
    b[16] = gen & 0xFF
    b[17] = (seq >> 24) & 0xFF
    b[18] = (seq >> 16) & 0xFF
    b[19] = (seq >> 8) & 0xFF
    b[20] = seq & 0xFF
    return bytes(b)


class Checks(object):
    """PASS / WARN / FAIL accumulator. Nothing proceeds silently past a
    mismatch."""

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

    def render(self):
        if not self.rows:
            return "\n(no checks run)"
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


# ===========================================================================
# gRPC helpers — carried from setup/four_queue_dequeue_oracle_setup.py, which
# is the reader that produced the four-queue result.
# ===========================================================================
def get_entry(tbl, tgt, keyfields, from_hw=True):
    """entry_get one key -> (data dict, None) or (None, error string)."""
    import bfrt_grpc.client as gc
    try:
        key = tbl.make_key([gc.KeyTuple(k, v) for k, v in keyfields])
    except Exception as e:
        return None, "make_key: %s" % str(e)[:90]
    try:
        got = None
        for d, _k in tbl.entry_get(tgt, [key], {"from_hw": from_hw}):
            got = d.to_dict()
        return (got, None) if got is not None else (None, "entry does not exist")
    except Exception as e:
        return None, "entry_get: %s" % str(e)[:90]


def get_table(bi, name, chk=None):
    """Resolve a bfrt table, tolerant of the pipeline prefix.

    P4 objects resolve as 'pipe.Ingress.<name>' on this SDE, but the prefix has
    differed between builds, so candidates are tried in order and a name scan
    is the last resort.
    """
    for cand in ("pipe.Ingress." + name, "Ingress." + name, name):
        try:
            return bi.table_get(cand)
        except Exception:
            continue
    try:
        for tn in bi.table_dict.keys():
            if tn.endswith("." + name) or tn.endswith("Ingress." + name):
                return bi.table_get(tn)
    except Exception:
        pass
    if chk is not None:
        chk.fail("table lookup '%s'" % name, "not found in bfrt info")
    return None


def _flatten_max(vals):
    """Collapse a register readback to one int.

    A Register read returns one value per pipe (and per SALU half), so the raw
    result is a list, sometimes nested. This program only ever writes from
    pipe 0, so every other element is the initial 0 and the maximum is the
    written value.
    """
    ints = []
    stack = list(vals)
    while stack:
        v = stack.pop()
        if isinstance(v, (list, tuple)):
            stack.extend(v)
        elif isinstance(v, bool):
            ints.append(int(v))
        elif isinstance(v, int):
            ints.append(v)
    return max(ints) if ints else None


def _reg_value_from(dd):
    """Pull the single data value out of a register entry dict."""
    vals = []
    for kk, vv in dd.items():
        if kk == "$REGISTER_INDEX" or kk == "action_name" or kk.startswith("is_"):
            continue
        vals.append(vv)
    return _flatten_max(vals)


def reg_read(bi, tgt, name, idx=0, chk=None):
    """Read Register <name> at one index."""
    import bfrt_grpc.client as gc
    t = get_table(bi, name, chk)
    if t is None:
        return None
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
    try:
        for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
            return _reg_value_from(d.to_dict())
    except Exception as e:
        if chk is not None:
            chk.fail("reg_read %s[%d]" % (name, idx), str(e)[:90])
    return None


def reg_zero(bi, tgt, name, idx=0, chk=None):
    """Write 0 into Register <name> at <idx>.

    The data field name is DISCOVERED from a read rather than guessed: it
    resolves as something like 'Ingress.<name>.f1' and the exact spelling has
    varied between builds.
    """
    import bfrt_grpc.client as gc
    t = get_table(bi, name, chk)
    if t is None:
        return False
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
    field = None
    try:
        for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
            for kk in d.to_dict():
                if kk == "$REGISTER_INDEX" or kk == "action_name" or kk.startswith("is_"):
                    continue
                field = kk
                break
    except Exception as e:
        if chk is not None:
            chk.fail("reg_zero %s discover field" % name, str(e)[:80])
        return False
    if field is None:
        if chk is not None:
            chk.fail("reg_zero %s" % name, "no data field found in readback")
        return False
    try:
        t.entry_mod(tgt, [k], [t.make_data([gc.DataTuple(field, 0)])])
        return True
    except Exception as e:
        if chk is not None:
            chk.fail("reg_zero %s write" % name, str(e)[:80])
        return False


def ctr_read(bi, tgt, idx, chk=None):
    """Read the PACKETS Counter ctr_evt at <idx>.

    A Stats-ALU counter needs an explicit HW->SW sync before a control-plane
    read; from_hw alone returns a stale 0.
    """
    import bfrt_grpc.client as gc
    t = get_table(bi, CTR_NAME, chk)
    if t is None:
        return None
    try:
        t.operations_execute(tgt, "SyncCounters")
    except Exception:
        pass
    k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])
    vals = []
    try:
        for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
            dd = d.to_dict()
            if "$COUNTER_SPEC_PKTS" in dd:
                vals.append(dd["$COUNTER_SPEC_PKTS"])
    except Exception as e:
        if chk is not None:
            chk.warn("ctr_read [%d]" % idx, str(e)[:80])
        return None
    return int(_flatten_max(vals) or 0)


def ctr_zero(bi, tgt, idx):
    """Write 0 into the PACKETS Counter ctr_evt at <idx>.

    TODO(silicon): whether this SDE accepts a write to $COUNTER_SPEC_PKTS on an
    indirect P4 counter is unverified off-switch. RESOLVING CHECK: the
    "P4 counters cleared" row of the cleanup record reports how many slots
    accepted the write and WARNs naming the first that did not. It is NOT
    load-bearing: read_counters() also reports before/after DELTAS, so an
    uncleanable counter degrades the evidence rather than invalidating it.
    """
    import bfrt_grpc.client as gc
    t = get_table(bi, CTR_NAME)
    if t is None:
        return False
    try:
        k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])
        t.entry_mod(tgt, [k], [t.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])])
        return True
    except Exception:
        return False


def read_counters(bi, tgt, chk=None):
    """All ctr_evt slots as {name: value}."""
    return dict((nm, ctr_read(bi, tgt, idx, chk)) for idx, nm in CTR_SLOTS)


def read_registers(bi, tgt, chk=None):
    """All registers as {json_key: value}."""
    return dict((key, _i(reg_read(bi, tgt, nm, 0, chk))) for nm, key in ALL_REGS)


# ===========================================================================
# 1. Port group + the five queues
# ===========================================================================
_PG_CACHE = {}


def resolve_pg_quiet(bi, tgt0, dev_port):
    """(pg_id, pg_port_nr), cached, no printing and no PASS/FAIL rows."""
    if dev_port in _PG_CACHE:
        return _PG_CACHE[dev_port]
    pcfg = get_table(bi, TM_PORT_CFG)
    if pcfg is None:
        return None, None
    got, err = get_entry(pcfg, tgt0, [("dev_port", dev_port)])
    if err or got is None:
        return None, None
    val = (got.get("pg_id"), got.get("pg_port_nr"))
    _PG_CACHE[dev_port] = val
    return val


def resolve_pg(bi, tgt0, dev_port, chk, out):
    """READ the (pg_id, pg_port_nr) of a dev_port instead of guessing it."""
    pcfg = get_table(bi, TM_PORT_CFG, chk)
    if pcfg is None:
        return None, None
    got, err = get_entry(pcfg, tgt0, [("dev_port", dev_port)])
    if err:
        chk.fail("%s dp%d" % (TM_PORT_CFG, dev_port), err)
        return None, None
    pg_id, pg_nr = got.get("pg_id"), got.get("pg_port_nr")
    out.setdefault("port_cfg", {})["dp%d" % dev_port] = {
        "pg_id": pg_id, "pg_port_nr": pg_nr,
        "port_queues_count": got.get("port_queues_count")}
    chk.ok("dp%d port-group map (read, not guessed)" % dev_port,
           "pg_id=%s pg_port_nr=%s" % (pg_id, pg_nr))
    return pg_id, pg_nr


def pg_queue_of(pg_nr, qid):
    """pg_queue = pg_port_nr * 8 + qid (TF1: 8 queues per port in a group)."""
    return pg_nr * 8 + qid


def config_ports(bi, tgt, a, out, chk):
    """dp8 MAC-near loopback. dp9 / dp11 / dp64 are NOT configured."""
    import bfrt_grpc.client as gc
    port_tbl = bi.table_get("$PORT")
    try:
        lk = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", a.port_l)])]
        try:
            port_tbl.entry_del(tgt, lk)   # a live entry rejects a mode change
        except Exception:
            pass
        port_tbl.entry_add(tgt, lk, [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
        chk.ok("dp%d MAC-near loopback" % a.port_l, "BF_LPBK_MAC_NEAR 25G")
    except Exception as e:
        chk.fail("dp%d MAC-near loopback" % a.port_l, str(e)[:90])
    out["ports_configured"] = [a.port_l]
    chk.ok("no host port configured",
           "dp9 / dp11 / dp64 do not appear in this gate, by construction")


def write_queues(bi, tgt0, a, out, chk, write=True):
    """Write and read back max_priority on the five dp8 queues.

    max_priority arbitrates among BACKLOGGED queues in the remaining-bandwidth
    pass. min_priority orders only the guaranteed pass and is INERT unless
    min_rate_enable is true — setting it instead of max_priority is precisely
    the silent configuration error the IBSPG root-cause repair found, so it is
    left alone here and both rate enables are forced off.
    """
    import bfrt_grpc.client as gc
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    if pg_id is None:
        chk.fail("queues", "could not resolve dp%d pg map" % a.port_l)
        return
    q_cfg = get_table(bi, TM_SCHED_CFG, chk)
    if q_cfg is None:
        return
    q_map = get_table(bi, TM_QUEUE_MAP)

    for name, qid, prio in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id),
                              gc.KeyTuple("pg_queue", pgq)])
        if write:
            try:
                q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data([
                    gc.DataTuple("scheduling_enable", bool_val=True),
                    gc.DataTuple("max_rate_enable", bool_val=False),
                    gc.DataTuple("min_rate_enable", bool_val=False),
                    gc.DataTuple("max_priority", str_val=prio)])])
            except Exception as e:
                chk.fail("%s max_priority write" % name, str(e)[:90])
                continue
        sc, err = get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("%s sched_cfg readback" % name, err)
            continue
        dev_port = None
        if q_map is not None:
            qm, qerr = get_entry(q_map, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
            if not qerr:
                dev_port = (qm or {}).get("dev_port")
        rec = {"qid": qid, "pg_queue": pgq,
               "max_priority": sc.get("max_priority"),
               "min_priority": sc.get("min_priority"),
               "scheduling_enable": sc.get("scheduling_enable"),
               "max_rate_enable": sc.get("max_rate_enable"),
               "min_rate_enable": sc.get("min_rate_enable"),
               "dwrr_weight": sc.get("dwrr_weight"),
               "dev_port": dev_port}
        out.setdefault("queues", {})[name] = rec
        chk.expect("%s max_priority" % name, pnorm(rec["max_priority"]), pnorm(prio),
                   "(qid %d, pg_queue %d)" % (qid, pgq))
        chk.expect("%s scheduling_enable" % name, rec["scheduling_enable"], True)
        # A queue over its own max rate goes shaping-INELIGIBLE and the TM
        # serves a lower-priority eligible queue. That is not a priority
        # violation but it is indistinguishable from one, so it is asserted off.
        chk.expect("%s per-queue max_rate_enable is False" % name,
                   rec["max_rate_enable"], False)
        if dev_port is not None and int(dev_port) != a.port_l:
            chk.fail("%s maps to dp%d" % (name, a.port_l),
                     "queue.map reports dev_port=%s" % dev_port)

    got = dict((n, pnorm((out.get("queues", {}).get(n) or {}).get("max_priority")))
               for n, _q, _p in QUEUE_PLAN)
    out["priority_got"] = got
    ladder_ok = (got.get("Q_ABLOCK") is not None
                 and got.get("Q_ABLOCK") > got.get("Q_ACK")
                 > got.get("Q_RBLOCK") > got.get("Q_RESP") > got.get("Q_FINAL"))
    out["ladder_strict"] = bool(ladder_ok)
    if ladder_ok:
        chk.ok("strict ladder ABLOCK > ACK > RBLOCK > RESP > FINAL", str(got))
    else:
        chk.fail("strict ladder ABLOCK > ACK > RBLOCK > RESP > FINAL", str(got))
    print("")
    print("dp%d queue ladder  [%s]" % (a.port_l, TM_SCHED_CFG))
    print("  %-10s %4s %10s %10s %12s" % ("queue", "qid", "want", "got", "sched_en"))
    for name, qid, prio in QUEUE_PLAN:
        r = out.get("queues", {}).get(name, {})
        print("  %-10s %4d %10s %10s %12s"
              % (name, qid, prio, r.get("max_priority"), r.get("scheduling_enable")))
    print("")
    # This readback says what was WRITTEN. The behavioural evidence for the
    # ladder on this silicon is the closed four-queue dequeue oracle.
    chk.warn("readback is configuration evidence, not proof",
             "four-level strict priority was established behaviourally by the "
             "CLOSED four-queue dequeue oracle "
             "(reports/FOUR_QUEUE_ORACLE_CLOSED.md); this run does not re-prove it")


# ===========================================================================
# 2. tbl_guard — A, R and the two budgets
# ===========================================================================
def write_guard(bi, tgt, a, out, chk):
    """Quantize A and R and write them, with the budgets, as tbl_guard's
    default action parameters (.p4:691-703)."""
    import bfrt_grpc.client as gc
    ta, pa, ea, wa = quantize_offset(a.a_ms * 1000000)
    tr, pr, er, wr = quantize_offset(a.r_ms * 1000000)
    q = {"A": {"requested_ns": a.a_ms * 1000000, "ticks": ta,
               "programmed_ns": pa, "error_ns": ea, "word": "0x%08X" % wa},
         "R": {"requested_ns": a.r_ms * 1000000, "ticks": tr,
               "programmed_ns": pr, "error_ns": er, "word": "0x%08X" % wr},
         "S_ns": pr - pa,
         "budget_a": a.budget_a, "budget_r": a.budget_r}
    out["guard"] = q
    print("A/R quantization (256 ns ticks, low byte reserved for the ARMED marker)")
    for k in ("A", "R"):
        d = q[k]
        print("  %s  requested %9d ns -> %6d ticks -> programmed %9d ns "
              "(error %+5d ns)  word %s"
              % (k, d["requested_ns"], d["ticks"], d["programmed_ns"],
                 d["error_ns"], d["word"]))
    print("  S  = R - A = %d ns" % q["S_ns"])
    print("")
    if pr <= pa:
        chk.fail("R > A", "programmed R=%d is not greater than A=%d" % (pr, pa))
        return
    chk.ok("R > A", "S = %d ns" % (pr - pa))

    t = get_table(bi, "tbl_guard", chk)
    if t is None:
        return
    try:
        t.default_entry_set(tgt, t.make_data([
            gc.DataTuple("a_word", wa),
            gc.DataTuple("r_word", wr),
            gc.DataTuple("budget_a", a.budget_a),
            gc.DataTuple("budget_r", a.budget_r)], "Ingress.set_guard"))
        chk.ok("tbl_guard default action written",
               "a_word=0x%08X r_word=0x%08X budget_a=%d budget_r=%d"
               % (wa, wr, a.budget_a, a.budget_r))
    except Exception as e:
        chk.fail("tbl_guard default action written", str(e)[:90])
        return
    # Read the default entry back. The bfrt default_entry_get shape has varied
    # between builds, so a failure here is a WARN, not a FAIL: the values are
    # also observable in the measured d_ACK / d_RESP words the trial reads.
    try:
        got = None
        for d in t.default_entry_get(tgt, {"from_hw": True}):
            got = d[0].to_dict() if isinstance(d, tuple) else d.to_dict()
        out["guard_readback"] = got
        if got:
            chk.ok("tbl_guard readback", str(got)[:110])
    except Exception as e:
        chk.warn("tbl_guard readback",
                 "TODO(silicon): default_entry_get shape unknown on this SDE (%s). "
                 "RESOLVING CHECK: the trial's measured d_ack_word / d_resp_word "
                 "carry A and R directly, so a wrong write is visible there."
                 % str(e)[:60])


# ===========================================================================
# 3. tbl_event_role — the three synthetic events
# ===========================================================================
def write_event_map(bi, tgt, a, out, chk):
    """packet_id 0 -> READ, 1 and 2 -> the scenario's roles (.p4:731-746)."""
    import bfrt_grpc.client as gc
    sc = SCENARIOS[a.scenario]
    mapping = [("0", "READ"), ("1", sc["pid1"]), ("2", sc["pid2"])]
    t = get_table(bi, "tbl_event_role", chk)
    if t is None:
        return
    keys, datas = [], []
    for pid, role in mapping:
        keys.append(t.make_key([gc.KeyTuple("hdr.pgen.packet_id", int(pid))]))
        datas.append(t.make_data([], EVENT_ACTION[role]))
    path = None
    try:
        t.entry_add(tgt, keys, datas)
        path = "entry_add"
    except Exception:
        try:
            t.entry_mod(tgt, keys, datas)
            path = "entry_mod"
        except Exception as e:
            chk.fail("tbl_event_role write", str(e)[:90])
            return
    out["event_map"] = {"scenario": a.scenario, "path": path,
                        "mapping": dict(mapping), "ipg_ns": sc["ipg_ns"]}
    chk.ok("tbl_event_role: 3 entries", "%s, scenario=%s, pid1=%s pid2=%s"
           % (path, a.scenario, sc["pid1"], sc["pid2"]))
    # Read all three back, because which of pid 1 / 2 is the ACK IS the
    # scenario and a silent mis-write would change the experiment.
    rb = {}
    for pid, _role in mapping:
        got, err = get_entry(t, tgt, [("hdr.pgen.packet_id", int(pid))])
        rb[pid] = (got or {}).get("action_name") if not err else err
    out["event_map_readback"] = rb
    want = dict((pid, EVENT_ACTION[role]) for pid, role in mapping)
    if all(str(rb.get(p, "")).endswith(want[p].split(".")[-1]) for p in want):
        chk.ok("tbl_event_role readback matches", str(rb))
    else:
        chk.fail("tbl_event_role readback matches", "got %s want %s" % (rb, want))


# ===========================================================================
# 4. Mirror session, parser value_set, generator
# ===========================================================================
def config_mirror(bi, tgt, a, out, chk):
    """Bind CLONE_SESSION_ID(=7) to egress dp68.

    The P4 arm_clone() sets ig_dprsr_md.mirror_type = CLONE and
    meta.clone_ses = 7 (.p4:673-677), and the ingress deparser's
    clone_mirror.emit(meta.clone_ses, {tag}) prepends the 4-byte tag. That
    mirrored copy IS the packet-generator trigger.

    GOTCHA 3/6: $mirror.cfg is ACTION-based on this SDE (actions '$normal' /
    '$coalescing'); make_data REQUIRES the action name or it fails
    INVALID_ARGUMENT.
    """
    import bfrt_grpc.client as gc
    try:
        mtbl = bi.table_get(MIRROR_CFG)
        mkey = [mtbl.make_key([gc.KeyTuple("$sid", a.clone_sid)])]
        mdata = [mtbl.make_data([
            gc.DataTuple("$direction", str_val="INGRESS"),
            gc.DataTuple("$ucast_egress_port", a.port_pgen),
            gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
            gc.DataTuple("$session_enable", bool_val=True),
            gc.DataTuple("$max_pkt_len", a.mirror_max_len)], "$normal")]
        try:
            mtbl.entry_add(tgt, mkey, mdata)
        except Exception:
            mtbl.entry_mod(tgt, mkey, mdata)
        out["mirror"] = {"sid": a.clone_sid, "egress_port": a.port_pgen,
                         "max_pkt_len": a.mirror_max_len}
        chk.ok("mirror session %d -> dp%d" % (a.clone_sid, a.port_pgen),
               "$normal, max_pkt_len=%d" % a.mirror_max_len)
    except Exception as e:
        chk.fail("mirror session %d" % a.clone_sid, str(e)[:90])


def config_value_set(bi, a, out, chk):
    """Load the parser value_set with BOTH generator app bytes.

    Generated packets lead with generator-header byte 0 = pad(3)|pipe(2)|app(3),
    so pipe 0 app 1 is 0x01 and app 2 is 0x02 — which is what the P4's
    APP_BLOCK_BYTE / APP_EVENT_BYTE (.p4:156-157) and this value_set match.

    GOTCHA 4/6: the MASK IS 0xFF (EXACT), NOT the SDE example's 0x1F. On dp68
    the parser also sees the recirculated trigger clone, whose leading byte is
    the marker 0xE1. Under a 0x1F mask, 0xE1 & 0x1F == 0x01 would ALIAS to app
    id 1 and mis-admit the clone as a generated packet. An exact match admits
    only a true generator byte (pad = 0, so 0x00..0x1F) and lets 0xE1 fall
    through to the drop path. 0xE1 can never equal a valid generator byte, so
    no generated packet is ever missed.

    The scope attribute can only be set while the value_set is EMPTY, so a
    failure on a re-run must NOT block the entries.
    """
    import bfrt_grpc.client as gc
    try:
        import bfruntime_pb2 as bfr_pb2
    except Exception:
        try:
            from bfrt_grpc import bfruntime_pb2 as bfr_pb2
        except Exception:
            bfr_pb2 = None
    try:
        vs = bi.table_get("pipe.IgParser.pgen_app")
    except Exception as e:
        chk.fail("value_set pipe.IgParser.pgen_app", str(e)[:90])
        return
    if bfr_pb2 is not None:
        try:
            vs.attribute_entry_scope_set(
                gc.Target(device_id=0, pipe_id=a.pipe),
                config_pipe_scope=True, predefined_pipe_scope=True,
                predefined_pipe_scope_val=bfr_pb2.Mode.SINGLE,
                config_gress_scope=True, predefined_gress_scope_val=bfr_pb2.Mode.ALL,
                config_prsr_scope=True, predefined_prsr_scope_val=bfr_pb2.Mode.SINGLE)
        except Exception as se:
            out["value_set_scope_note"] = "scope already set (ok on re-run): " \
                                          + str(se)[:50]
    vtgt = gc.Target(device_id=0, pipe_id=a.pipe, prsr_id=PGEN_PRSR_ID)
    added = []
    for app in (APP_BLOCK, APP_EVENT):
        byte = (a.pipe << 3) | app
        if byte == CLONE_TAG_MARKER:
            chk.fail("value_set byte 0x%02X" % byte,
                     "aliases the 0xE1 trigger marker — refusing")
            continue
        vkey = [vs.make_key([gc.KeyTuple("f1", byte, 0xFF)])]
        try:
            vs.entry_del(vtgt, vkey)     # idempotent: clear any prior entry
        except Exception:
            pass
        try:
            vs.entry_add(vtgt, vkey)
            added.append("0x%02X" % byte)
        except Exception as e:
            chk.fail("value_set entry 0x%02X" % byte, str(e)[:80])
    out["value_set"] = {"prsr_id": PGEN_PRSR_ID, "pipe": a.pipe,
                        "mask": "0xFF", "entries": added}
    if len(added) == 2:
        chk.ok("parser value_set pgen_app", "%s, EXACT 0xFF mask, prsr_id=%d"
               % (",".join(added), PGEN_PRSR_ID))
    else:
        chk.fail("parser value_set pgen_app", "only added %s" % added)


def config_pktgen_port(bi, tgts, a, out, chk):
    """Enable the generator on dp68.

    GOTCHA 2/6: dp68 needs ALL THREE flags, because app 1 uses a
    recirculation-PATTERN trigger:
        pktgen_enable            run the generator on dp68
        recirculation_enable     let the mirrored clone loop egress -> ingress
        pattern_matching_enable  compare the first 32 bits against the pattern
    Omitting any of them silently produces a generator that never fires. There
    is deliberately no $PORT entry for dp68; it is an internal port and reads
    back up=False, which is expected and not a fault.
    """
    import bfrt_grpc.client as gc
    pcfg = get_table(bi, PKTGEN_PORT_CFG, chk)
    if pcfg is None:
        return
    wrote = False
    for _tn, tgt in tgts:
        try:
            pcfg.entry_mod(tgt,
                           [pcfg.make_key([gc.KeyTuple("dev_port", a.port_pgen)])],
                           [pcfg.make_data([
                               gc.DataTuple("pktgen_enable", bool_val=True),
                               gc.DataTuple("recirculation_enable", bool_val=True),
                               gc.DataTuple("pattern_matching_enable", bool_val=True)])])
            wrote = True
            break
        except Exception as e:
            out["pktgen_port_err"] = str(e)[:90]
    got, err = None, None
    for _tn, tgt in tgts:
        got, err = get_entry(pcfg, tgt, [("dev_port", a.port_pgen)])
        if not err:
            break
    out["pktgen_port_cfg"] = got if not err else {"err": err}
    if wrote and not err and got.get("pktgen_enable"):
        chk.ok("pktgen enabled on dp%d" % a.port_pgen, str(got))
    elif wrote and err:
        # The four-queue silicon config gate recorded entry_get UNIMPLEMENTED on
        # tf1.pktgen.port_cfg: a readback limit, not a misconfiguration.
        chk.warn("pktgen enabled on dp%d (write ok, readback unavailable)"
                 % a.port_pgen,
                 "%s — known entry_get limitation on this table. RESOLVING "
                 "CHECK: the app's pkt_counter after a transaction." % err)
    else:
        chk.fail("pktgen enabled on dp%d" % a.port_pgen,
                 "write_ok=%s readback=%s" % (wrote, got if not err else err))


def write_buffers(bi, tgts, a, out, chk, gen):
    """Load both 64-byte templates into the generator packet buffer.

    GOTCHA 6/6: pkt_len counts BUFFER bytes and EXCLUDES the 6-byte generator
    header the hardware prepends. If that were wrong the ethertype would not
    land at byte 12 of the post-header frame, the parser's 0x88C5 test would
    fail, and every generated packet would land on drop_non_dual instead of the
    admit slots. RESOLVING CHECK: drop_non_dual == 0 and
    admit_ablock + admit_rblock == 128 confirms the layout.

    The BLOCKER template carries role 0 / phase 0 / gen 0 / seq 0 — all four
    are stamped by the MAU at admission. The EVENT template carries role 0 /
    phase 0 / THIS TRANSACTION'S GENERATION / seq 0: the generation is the one
    per-transaction field, and writing it into the template is what makes the
    generation advance externally controllable and externally visible.
    """
    import bfrt_grpc.client as gc
    pbuf = get_table(bi, PKTGEN_PKT_BUFFER, chk)
    if pbuf is None:
        return
    tpls = [("blocker", a.buf_off_block, build_template(ROLE_NONE, PH_NEW, 0, 0)),
            ("event",   a.buf_off_event, build_template(ROLE_NONE, PH_NEW, gen, 0))]
    rec = {}
    for name, off, tpl in tpls:
        wrote = False
        for _tn, tgt in tgts:
            try:
                pbuf.entry_mod(
                    tgt,
                    [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", off),
                                    gc.KeyTuple("pkt_buffer_size", len(tpl))])],
                    [pbuf.make_data([gc.DataTuple("buffer", bytearray(tpl))])])
                wrote = True
                break
            except Exception as e:
                rec[name + "_err"] = str(e)[:90]
        rec[name] = {"offset": off, "size": len(tpl), "hex": tpl.hex()}
        if wrote:
            chk.ok("%s template written" % name,
                   "%d B at offset %d" % (len(tpl), off))
        else:
            chk.fail("%s template written" % name, rec.get(name + "_err", "unknown"))
    rec["event_gen"] = gen
    out["pkt_buffer"] = rec


def config_apps(bi, tgts, a, out, chk, ipg_ns):
    """Configure BOTH generator applications. Both are left DISABLED.

    GOTCHA 1/6: pipe_local_source_port is REQUIRED on this silicon despite the
    SDE's "implicit on Tofino-1" note. It sets the ingress_port the generated
    packets carry; without it they arrive on the wrong port, miss the parser's
    from_pgen path and are dropped. The localizing symptom is pkt_counter = N
    with the P4's admit counters at 0 and drop_bad_port at N.

    GOTCHA 5/6: counts are ZERO-BASED. batch_count_cfg = 0 is ONE batch and
    packets_per_batch_cfg = 127 is 128 packets.

    increment_source_port MUST be False. It is the only driver bound on batch
    size: with it true, packets_per_batch must be <= 127 - 68 = 59, which would
    reject even the existing K = 64 reservoir, let alone 128.

    ONE batch is also what makes packet_id unique across the whole burst.
    packet_id restarts at 0 for every batch and the 24-bit `key` occupies the
    position a batch_id would, so two batches of 64 would both emit
    packet_id 0..63 with no way to tell them apart.
    """
    import bfrt_grpc.client as gc
    acfg = get_table(bi, PKTGEN_APP_CFG, chk)
    if acfg is None:
        return

    def _app(app_id, action, extra, npkts, off, ipg, label):
        flds = [
            gc.DataTuple("pkt_len", TPL_LEN),
            gc.DataTuple("pkt_buffer_offset", off),
            gc.DataTuple("pipe_local_source_port", a.port_pgen),
            gc.DataTuple("increment_source_port", bool_val=False),
            gc.DataTuple("batch_count_cfg", 0),
            gc.DataTuple("packets_per_batch_cfg", npkts - 1),
            gc.DataTuple("ipg", int(ipg)),
            gc.DataTuple("ibg", 0),
            gc.DataTuple("trigger_counter", 0),
            gc.DataTuple("batch_counter", 0),
            gc.DataTuple("pkt_counter", 0),
            gc.DataTuple("app_enable", bool_val=False),
        ] + extra
        used = None
        for tn, tgt in tgts:
            try:
                acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", app_id)])],
                               [acfg.make_data(flds, action)])
                used = tn
                break
            except Exception as e:
                out["app%d_err" % app_id] = str(e)[:90]
        rec = {"app_id": app_id, "trigger": action, "pkt_len": TPL_LEN,
               "pkt_buffer_offset": off, "batch_count_cfg": 0,
               "packets_per_batch_cfg": npkts - 1, "packets": npkts,
               "ipg_ns_requested": int(ipg), "increment_source_port": False,
               "pipe_local_source_port": a.port_pgen, "target": used}
        out.setdefault("apps", {})[label] = rec
        if used is None:
            chk.fail("%s app %d configured" % (label, app_id),
                     out.get("app%d_err" % app_id, "unknown"))
            return
        chk.ok("%s app %d configured (%s)" % (label, app_id, action),
               "1 batch x %d pkts, ipg=%d ns, target=%s" % (npkts, ipg, used))
        # ipg is converted ns -> core clocks by the driver, so the readback is
        # the QUANTIZED value. Report it; do not fail on a small delta.
        got, err = None, None
        for _tn, tgt in tgts:
            got, err = get_entry(acfg, tgt, [("app_id", app_id)])
            if not err:
                break
        if not err and got is not None:
            rec["readback"] = {k: got.get(k) for k in
                               ("pkt_len", "pkt_buffer_offset", "ipg", "ibg",
                                "batch_count_cfg", "packets_per_batch_cfg",
                                "increment_source_port", "pipe_local_source_port",
                                "app_enable")}
            chk.expect("%s packets_per_batch_cfg" % label,
                       _i(got.get("packets_per_batch_cfg")), npkts - 1)
            chk.expect("%s increment_source_port is False" % label,
                       got.get("increment_source_port"), False)
            chk.expect("%s pipe_local_source_port" % label,
                       _i(got.get("pipe_local_source_port")), a.port_pgen)
            gi = _i(got.get("ipg"))
            rec["ipg_ns_readback"] = gi
            if gi is not None and ipg > 0:
                drift = abs(gi - int(ipg))
                if drift > max(1000, int(ipg) // 1000):
                    chk.fail("%s ipg readback" % label,
                             "wrote %d ns, read %d ns" % (ipg, gi))
                else:
                    chk.ok("%s ipg readback" % label,
                           "wrote %d ns, read %d ns (clock quantization)" % (ipg, gi))
        else:
            chk.warn("%s app readback" % label, str(err)[:80])

    # app 1: the 128 blocker tokens, fired by the READ's mirrored 0xE1 clone.
    #
    # TODO(silicon): the frozen Defense 2 proved this exact trigger on this
    # switch, but there the READ that produced the clone arrived on a HOST
    # port. Here it arrives on dp68 itself, so the mirror copy is a dp68
    # packet mirrored back to dp68. The pattern matcher inspects frames
    # arriving on the recirculation port and should not care where the mirror
    # came from, but that has not been observed.
    # RESOLVING CHECK: out["pktgen"]["blocker"]["trigger_counter"] after a
    # transaction. It reads 1 if the trigger fired. Reading 0 while the P4's
    # arm_fresh counter reads 1 localizes the failure to exactly this — the
    # READ was processed and the clone was requested, but nothing triggered —
    # and is also the check that resolves the separate drop_ctl-versus-mirror
    # question documented in the P4 at arm_clone().
    _app(a.app_block, "trigger_recirc_pattern",
         [gc.DataTuple("pattern_value", PATTERN_VALUE),
          gc.DataTuple("pattern_mask", PATTERN_MASK)],
         N_BLOCKERS, a.buf_off_block, 0, "blocker")
    out.setdefault("apps", {}).setdefault("blocker", {})["pattern"] = {
        "value": "0x%08X" % PATTERN_VALUE, "mask": "0x%08X" % PATTERN_MASK}

    # app 2: the three synthetic events, ipg apart, fired by a one-shot timer.
    _app(a.app_event, "trigger_timer_one_shot",
         [gc.DataTuple("timer_nanosec", int(a.timer_ns))],
         N_EVENTS, a.buf_off_event, ipg_ns, "event")


def read_app(bi, tgts, app_id):
    """(trigger_counter, batch_counter, pkt_counter, app_enable) or Nones."""
    acfg = get_table(bi, PKTGEN_APP_CFG)
    if acfg is None:
        return None, None, None, None
    for _tn, tgt in tgts:
        got, err = get_entry(acfg, tgt, [("app_id", app_id)])
        if not err and got is not None:
            return (_i(got.get("trigger_counter")), _i(got.get("batch_counter")),
                    _i(got.get("pkt_counter")), got.get("app_enable"))
    return None, None, None, None


def set_app_enable(bi, tgts, app_id, enable, chk=None):
    """Flip ONLY app_enable.

    A one-shot app does NOT auto-disable after its batch, so it must be driven
    False before it can be re-armed True — arm is False -> True -> wait -> False.
    """
    import bfrt_grpc.client as gc
    acfg = get_table(bi, PKTGEN_APP_CFG, chk)
    if acfg is None:
        return False
    for _tn, tgt in tgts:
        try:
            acfg.entry_mod(tgt, [acfg.make_key([gc.KeyTuple("app_id", app_id)])],
                           [acfg.make_data([gc.DataTuple("app_enable",
                                                         bool_val=enable)])])
            return True
        except Exception:
            continue
    if chk is not None:
        chk.fail("app %d app_enable=%s" % (app_id, enable),
                 "no target accepted the write")
    return False


# ===========================================================================
# 5. Occupancy (diagnostic) and the hard drop check
# ===========================================================================
def queue_counters(bi, tgt0, a):
    """{queue: {usage_cells, watermark_cells, drop_count_packets}}, QUIET."""
    pg_id, pg_nr = resolve_pg_quiet(bi, tgt0, a.port_l)
    if pg_id is None:
        return {}
    ctr = get_table(bi, TM_COUNTER_QUEUE)
    if ctr is None:
        return {}
    occ = {}
    for name, qid, _p in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        got, err = get_entry(ctr, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            continue
        occ[name] = {"qid": qid, "pg_queue": pgq,
                     "usage_cells": _i(got.get("usage_cells")),
                     "watermark_cells": _i(got.get("watermark_cells")),
                     "drop_count_packets": _i(got.get("drop_count_packets"))}
    return occ


def read_occupancy(bi, tgt0, a, out, chk):
    """Print the per-queue counters and FAIL on any TM drop.

    usage_cells is reported but is NOT part of any verdict: the four-queue
    oracle measured it reading 0 on every dp8 queue in all five shaper settings
    including the one that demonstrably leaked, so it is an unsupported gauge
    on these queues. watermark_cells is retained as diagnostic evidence that a
    queue really was occupied, and drop_count_packets IS load-bearing — a TM
    drop means a token was lost rather than held, and the transaction is void.
    """
    occ = queue_counters(bi, tgt0, a)
    out["occupancy"] = occ
    print("dp%d queue counters [%s]" % (a.port_l, TM_COUNTER_QUEUE))
    print("  %-10s %4s %9s %12s %18s" % ("queue", "qid", "usage", "watermark",
                                         "drop_count_pkts"))
    for name, qid, _p in QUEUE_PLAN:
        r = occ.get(name) or {}
        print("  %-10s %4d %9s %12s %18s"
              % (name, qid, r.get("usage_cells"), r.get("watermark_cells"),
                 r.get("drop_count_packets")))
        d = r.get("drop_count_packets")
        if d is not None and int(d) != 0:
            chk.fail("%s drop_count_packets == 0" % name,
                     "the TM DROPPED %s packet(s) — the transaction is VOID" % d)
    print("")
    out["zero_queue_drops"] = all(
        int((r or {}).get("drop_count_packets") or 0) == 0 for r in occ.values())
    return occ


def reset_queue_counters(bi, tgt0, a, out, chk):
    """Zero the three tf1.tm.counter.queue fields on the five dp8 queues.

    Each field is written INDEPENDENTLY so one rejected field cannot prevent
    the others from being cleared. This runs only AFTER the drain: usage_cells
    is a LIVE occupancy gauge, not a latched statistic, so clearing it while
    packets are still queued would certify a switch that is still holding
    traffic.
    """
    import bfrt_grpc.client as gc
    pg_id, pg_nr = resolve_pg_quiet(bi, tgt0, a.port_l)
    if pg_id is None:
        return
    ctr = get_table(bi, TM_COUNTER_QUEUE)
    if ctr is None:
        return
    for name, qid, _p in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        key = ctr.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        for fld in CTR_FIELDS:
            try:
                ctr.entry_mod(tgt0, [key], [ctr.make_data([gc.DataTuple(fld, 0)])])
            except Exception as e:
                chk.warn("reset %s %s" % (name, fld), "TODO(silicon): %s" % str(e)[:60])
    out["queue_counters_reset"] = True


# ===========================================================================
# 6. TOKEN CONSERVATION, the clean state, and the mandatory cleanup
# ===========================================================================
def conservation(ctrs):
    """The per-class token account.

    Every admitted token leaves by exactly one of three counted doors, so
    admitted == deadline + budget + stale holds if and only if nothing is
    still circulating. This is the drain test, in place of the unsupported
    usage_cells gauge.
    """
    def g(k):
        v = ctrs.get(k)
        return 0 if v is None else int(v)
    a_out = g("term_ablock_dl") + g("term_ablock_tmo") + g("term_ablock_stale")
    r_out = g("term_rblock_dl") + g("term_rblock_tmo") + g("term_rblock_stale")
    return {
        "ablock_admitted": g("admit_ablock"), "ablock_terminated": a_out,
        "ablock_closed": g("admit_ablock") == a_out,
        "rblock_admitted": g("admit_rblock"), "rblock_terminated": r_out,
        "rblock_closed": g("admit_rblock") == r_out,
        "ack_commits": g("ack_commit"), "resp_commits": g("resp_commit"),
        "final_drains": g("final_drain"),
    }


def transaction_complete(ctrs):
    """True when one whole transaction has finished on chip.

    Deliberately expressed as an ACCOUNT rather than a timer: 64 ACK blockers
    and 64 response blockers admitted and all of them terminated, one ACK and
    one RESPONSE committed, and both of those drained out of the shared final
    FIFO.
    """
    c = conservation(ctrs)
    return bool(c["ablock_admitted"] == N_BLOCKERS_PER_CLASS
                and c["rblock_admitted"] == N_BLOCKERS_PER_CLASS
                and c["ablock_closed"] and c["rblock_closed"]
                and c["ack_commits"] == 1 and c["resp_commits"] == 1
                and c["final_drains"] == 2)


def read_clean_state(bi, tgt, tgt0, tgts, a):
    """Everything the clean-state definition depends on, as one dict.

    `clean` is True only when ALL FOUR facts hold. A fact that could not be
    READ is not clean: an unreadable counter is exactly the case where assuming
    cleanliness would repeat the four-queue pilot.
    """
    regs = read_registers(bi, tgt)
    ctrs = read_counters(bi, tgt)
    occ = queue_counters(bi, tgt0, a)
    _t1, _b1, _p1, en_b = read_app(bi, tgts, a.app_block)
    _t2, _b2, _p2, en_e = read_app(bi, tgts, a.app_event)

    regs_zero = all(v == 0 for v in regs.values()) and None not in regs.values()
    ctrs_zero = all(v == 0 for v in ctrs.values()) and None not in ctrs.values()
    apps_off = (en_b is False and en_e is False)
    drops_zero = all(int((r or {}).get("drop_count_packets") or 0) == 0
                     for r in occ.values())

    st = {"registers": regs, "counters": ctrs, "occupancy": occ,
          "app_enable": {"blocker": en_b, "event": en_e},
          "registers_zero": regs_zero, "counters_zero": ctrs_zero,
          "apps_disabled": apps_off, "zero_queue_drops": drops_zero}
    st["clean"] = bool(regs_zero and ctrs_zero and apps_off and drops_zero)
    st["violated_facts"] = [f for f, ok in (
        ("all registers zero", regs_zero),
        ("all counter slots zero", ctrs_zero),
        ("both pktgen apps disabled", apps_off),
        ("zero queue drops", drops_zero)) if not ok]
    return st


def assert_clean_start(bi, tgt, tgt0, tgts, a, out, chk):
    """REFUSE to start unless the switch is already clean. Not best-effort.

    Raises DirtyStateError, which run_txn() lets propagate to its `finally`, so
    the cleanup path still runs and the switch is left better than it was
    found.
    """
    st = read_clean_state(bi, tgt, tgt0, tgts, a)
    out["clean_start"] = st
    if st["clean"]:
        chk.ok("CLEAN START asserted", "all four facts: %s" % ", ".join(CLEAN_FACTS))
        return st
    nz_r = dict((k, v) for k, v in st["registers"].items() if v)
    nz_c = dict((k, v) for k, v in st["counters"].items() if v)
    detail = ("these clean facts do NOT hold: %s | nonzero registers=%s | "
              "nonzero counters=%s | app_enable=%s"
              % (", ".join(st["violated_facts"]) or "unknown", nz_r, nz_c,
                 st["app_enable"]))
    chk.fail("CLEAN START asserted", detail)
    raise DirtyStateError(detail)


def cleanup_txn(bi, tgt, tgt0, tgts, a, out, chk, label="cleanup"):
    """THE MANDATORY CLEANUP. Runs on every exit path, success or failure.

    Order matters and is fixed:
      1. disable BOTH generator apps    nothing new can be generated
      2. wait for token conservation    every admitted token has left, or the
                                        fail-open budget has retired it. This
                                        is the ONLY drain test used, because
                                        usage_cells is an unsupported gauge on
                                        these queues.
      3. counters STABLE                two consecutive equal reads of the two
                                        loop counters, so a straggler cannot
                                        land after the reset in step 4
      4. reset registers + counters     AFTER the drain, never before
      5. verify the four clean facts    and record which ones failed

    Step 4 must not move ahead of step 2. Resetting first would zero the very
    account that step 2 uses to decide whether anything is still circulating,
    and would certify a switch that is still holding traffic — the exact false
    negative this mechanism exists to prevent.

    The fail-open budgets bound this: a transaction that goes wrong self-clears
    within one budget (~34 ms for the ACK class, ~138 ms for the response
    class at the dp8 line-rate loop period), with no control-plane action.
    """
    rec = {"label": label, "steps": []}

    def step(name, detail=""):
        rec["steps"].append({"step": name, "detail": str(detail)})

    # 1. disable both apps
    ok_b = set_app_enable(bi, tgts, a.app_block, False, chk)
    ok_e = set_app_enable(bi, tgts, a.app_event, False, chk)
    step("1 disable pktgen apps", "blocker=%s event=%s" % (ok_b, ok_e))

    # 2. wait for token conservation to close
    deadline = time.time() + a.cleanup_timeout
    ctrs, cons = {}, {}
    closed = False
    while time.time() < deadline:
        ctrs = read_counters(bi, tgt)
        cons = conservation(ctrs)
        closed = bool(cons["ablock_closed"] and cons["rblock_closed"])
        if closed:
            break
        time.sleep(0.1)
    rec["conservation_after_drain"] = cons
    step("2 token conservation", "closed=%s %s" % (closed, cons))
    if not closed:
        chk.fail("cleanup: every token accounted for",
                 "admitted/terminated ABLOCK %s/%s RBLOCK %s/%s after %.1f s"
                 % (cons.get("ablock_admitted"), cons.get("ablock_terminated"),
                    cons.get("rblock_admitted"), cons.get("rblock_terminated"),
                    a.cleanup_timeout))

    # 3. the two loop counters must be STABLE across two consecutive reads
    stable, s1, s2 = False, None, None
    deadline = time.time() + a.cleanup_timeout
    while time.time() < deadline:
        c1 = read_counters(bi, tgt)
        s1 = (c1.get("loop_ablock"), c1.get("loop_rblock"))
        time.sleep(a.stable_gap)
        c2 = read_counters(bi, tgt)
        s2 = (c2.get("loop_ablock"), c2.get("loop_rblock"))
        if s1 == s2 and None not in s1:
            stable = True
            break
    rec["loop_counters_stable"] = {"first": s1, "second": s2, "stable": stable}
    step("3 loop counters stable", "%s == %s -> %s" % (s1, s2, stable))
    if not stable:
        chk.fail("cleanup: loop counters stable",
                 "tokens are still circulating (%s then %s)" % (s1, s2))

    # 4. reset the registers, the P4 counters and the TM queue counters
    for nm, _key in ALL_REGS:
        reg_zero(bi, tgt, nm, 0, chk)
    n_ctr = sum(1 for idx, _nm in CTR_SLOTS if ctr_zero(bi, tgt, idx))
    rec["p4_counter_slots_cleared"] = n_ctr
    if n_ctr != len(CTR_SLOTS):
        chk.warn("cleanup: P4 counters cleared",
                 "TODO(silicon): %d of %d slots accepted a write to "
                 "$COUNTER_SPEC_PKTS. The clean-start assertion depends on them, "
                 "so a persistent shortfall must be fixed before a campaign; a "
                 "single transaction still reports before/after deltas."
                 % (n_ctr, len(CTR_SLOTS)))
    reset_queue_counters(bi, tgt0, a, out, chk)
    step("4 reset registers + counters",
         "%d registers, %d/%d counter slots, TM queue counters"
         % (len(ALL_REGS), n_ctr, len(CTR_SLOTS)))

    # 5. verify
    st = read_clean_state(bi, tgt, tgt0, tgts, a)
    rec["verified"] = st
    rec["clean"] = st["clean"]
    step("5 verify clean", "clean=%s violated=%s" % (st["clean"], st["violated_facts"]))
    if st["clean"]:
        chk.ok("CLEANUP verified clean", "all four facts: %s" % ", ".join(CLEAN_FACTS))
    else:
        chk.fail("CLEANUP verified clean",
                 "these clean facts do NOT hold: %s" % ", ".join(st["violated_facts"]))
    out[label] = rec
    return rec


# ===========================================================================
# 7. ONE transaction
# ===========================================================================
def _txn_body(bi, tgt, tgt0, tgts, a, out, chk):
    """The measured part. Called only from run_txn(), which owns the
    clean-start assertion and the mandatory cleanup."""
    sc = SCENARIOS[a.scenario]

    # 1. per-transaction programming
    write_guard(bi, tgt, a, out, chk)
    write_event_map(bi, tgt, a, out, chk)
    write_buffers(bi, tgts, a, out, chk, a.gen)
    config_apps(bi, tgts, a, out, chk, sc["ipg_ns"])

    # 2. ARM. The blocker app must be armed FIRST: it is recirculation-pattern
    #    triggered and therefore inert until the READ's clone arrives, whereas
    #    enabling the event app starts a countdown that cannot be recalled.
    set_app_enable(bi, tgts, a.app_block, False, chk)
    set_app_enable(bi, tgts, a.app_event, False, chk)
    if not set_app_enable(bi, tgts, a.app_block, True, chk):
        out["verdict"] = "INVALID"
        return
    t_arm = time.time()
    if not set_app_enable(bi, tgts, a.app_event, True, chk):
        out["verdict"] = "INVALID"
        return
    out["armed_unix"] = t_arm

    # 3. wait for the transaction to complete, on the ACCOUNT and not a timer
    deadline = time.time() + a.txn_timeout
    ctrs, done = {}, False
    while time.time() < deadline:
        ctrs = read_counters(bi, tgt)
        if transaction_complete(ctrs):
            done = True
            break
        time.sleep(0.05)
    out["elapsed_s"] = round(time.time() - t_arm, 4)
    out["completed"] = done

    # 4. disarm before reading, so nothing moves under the read
    set_app_enable(bi, tgts, a.app_event, False, chk)
    set_app_enable(bi, tgts, a.app_block, False, chk)
    time.sleep(a.settle)

    # 5. read everything
    out["counters"] = read_counters(bi, tgt, chk)
    out["registers"] = read_registers(bi, tgt, chk)
    out["conservation"] = conservation(out["counters"])
    tb, bb, pb, eb = read_app(bi, tgts, a.app_block)
    te, be, pe, ee = read_app(bi, tgts, a.app_event)
    out["pktgen"] = {"blocker": {"trigger_counter": tb, "batch_counter": bb,
                                 "pkt_counter": pb, "app_enable": eb},
                     "event":   {"trigger_counter": te, "batch_counter": be,
                                 "pkt_counter": pe, "app_enable": ee}}
    read_occupancy(bi, tgt0, a, out, chk)

    # 6. the checks this script can make locally. The ORDERING and DEADLINE
    #    verdict is the analyzer's job — it needs the wrap-correct arithmetic
    #    and the per-scenario expectation — but the structural facts are
    #    checked here so a broken run stops even if it is never analyzed.
    c = out["counters"]
    chk.expect("blocker app fired exactly once", tb, 1)
    chk.expect("blocker app generated %d" % N_BLOCKERS, pb, N_BLOCKERS)
    chk.expect("event app generated %d" % N_EVENTS, pe, N_EVENTS)
    chk.expect("one fresh READ armed the transaction", c.get("arm_fresh"), 1)
    chk.expect("exactly %d ACK blockers admitted" % N_BLOCKERS_PER_CLASS,
               c.get("admit_ablock"), N_BLOCKERS_PER_CLASS)
    chk.expect("exactly %d response blockers admitted" % N_BLOCKERS_PER_CLASS,
               c.get("admit_rblock"), N_BLOCKERS_PER_CLASS)
    chk.expect("one ACK admitted", c.get("ack_held"), 1)
    chk.expect("one RESPONSE admitted", c.get("resp_held"), 1)
    chk.expect("one ACK committed", c.get("ack_commit"), 1)
    chk.expect("one RESPONSE committed", c.get("resp_commit"), 1)
    chk.expect("both committed frames left the shared FIFO",
               c.get("final_drain"), 2)
    chk.expect("ACK left the shared FIFO first",
               ROLE_NAME.get(out["registers"].get("final_first_role")), "ACK")
    chk.expect("zero tokens leaked to a bad port", c.get("drop_bad_port"), 0)
    chk.expect("zero generated packets misparsed", c.get("drop_non_dual"), 0)
    chk.expect("zero stale ACK blockers", c.get("term_ablock_stale"), 0)
    chk.expect("zero stale response blockers", c.get("term_rblock_stale"), 0)
    chk.expect("zero fail-open ACK-blocker expiries", c.get("term_ablock_tmo"), 0)
    chk.expect("zero fail-open response-blocker expiries", c.get("term_rblock_tmo"), 0)
    cons = out["conservation"]
    if cons["ablock_closed"] and cons["rblock_closed"]:
        chk.ok("token conservation closes", str(cons))
    else:
        chk.fail("token conservation closes", str(cons))
    if not done:
        chk.fail("transaction completed within %.1f s" % a.txn_timeout,
                 "counters at timeout: %s" % out["conservation"])
    out["verdict"] = "COMPLETE" if (done and chk.n_fail == 0) else "INCOMPLETE"


def run_txn(bi, tgt, tgt0, tgts, a, out, chk):
    """ASSERT CLEAN -> program -> arm -> wait -> read -> MANDATORY CLEANUP."""
    out["scenario"] = a.scenario
    out["txn_index"] = a.txn_index
    out["generation"] = a.gen
    out["utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out.setdefault("verdict", "INVALID")
    try:
        assert_clean_start(bi, tgt, tgt0, tgts, a, out, chk)
        _txn_body(bi, tgt, tgt0, tgts, a, out, chk)
    except DirtyStateError as e:
        out["verdict"] = "INVALID"
        out["refused_dirty_start"] = str(e)
        chk.fail("transaction REFUSED to start", str(e)[:160])
    finally:
        if a.no_cleanup:
            chk.warn("cleanup SKIPPED", "--no-cleanup was passed (debug only). "
                                        "The next transaction will refuse to start.")
        else:
            rc = cleanup_txn(bi, tgt, tgt0, tgts, a, out, chk)
            if not rc.get("clean"):
                out["verdict"] = "INVALID"


# ===========================================================================
# 8. dp8 restore
# ===========================================================================
def restore_dp8(bi, tgts, a, out, chk):
    """Put dp8's scheduling configuration back to its ORIGINAL state.

    This gate never arms a port shaper, so there should be nothing to undo —
    but the assertion is cheap and it is what lets the runner verify "dp8
    shaping restored" as one of its five facts regardless of which experiment
    ran last.
    """
    import bfrt_grpc.client as gc
    shp = get_table(bi, TM_PORT_SHAPING, chk)
    cfg = get_table(bi, TM_PORT_SCHED_CFG, chk)
    if shp is None or cfg is None:
        return
    o = DP8_ORIGINAL

    def _mod(tbl, tuples, what):
        last = "no target tried"
        for _tn, tgt in tgts:
            try:
                key = tbl.make_key([gc.KeyTuple("dev_port", a.port_l)])
                tbl.entry_mod(tgt, [key], [tbl.make_data(tuples)])
                return True
            except Exception as e:
                last = str(e)[:90]
        chk.fail(what, last)
        return False

    _mod(shp, [gc.DataTuple("unit", str_val=o["unit"]),
               gc.DataTuple("provisioning", str_val="UPPER"),
               gc.DataTuple("max_rate", int(o["max_rate"])),
               gc.DataTuple("max_burst_size", int(o["max_burst_size"]))],
         "restore dp8 shaping")
    _mod(cfg, [gc.DataTuple("max_rate_enable", bool_val=o["max_rate_enable"]),
               gc.DataTuple("scheduling_speed", str_val=o["scheduling_speed"])],
         "restore dp8 sched_cfg")

    rec = {}
    for tname, tbl, key in (("sched_shaping", shp, "shaping"),
                            ("sched_cfg", cfg, "cfg")):
        for _tn, tgt in tgts:
            got, err = get_entry(tbl, tgt, [("dev_port", a.port_l)])
            if not err:
                rec[tname] = got
                break
    out["dp8_after_restore"] = rec
    sh = rec.get("sched_shaping") or {}
    sc = rec.get("sched_cfg") or {}
    chk.expect("dp8 max_rate_enable restored", sc.get("max_rate_enable"),
               o["max_rate_enable"])
    chk.expect("dp8 max_rate restored",
               None if sh.get("max_rate") is None else int(sh["max_rate"]),
               o["max_rate"])
    chk.expect("dp8 unit restored", sh.get("unit"), o["unit"])
    chk.expect("dp8 max_burst_size restored",
               None if sh.get("max_burst_size") is None else int(sh["max_burst_size"]),
               o["max_burst_size"])
    chk.expect("dp8 scheduling_speed restored", sc.get("scheduling_speed"),
               o["scheduling_speed"])
    out["dp8_restored"] = True


# ===========================================================================
# CLI
# ===========================================================================
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="control plane for the minimal synthetic dual-release gate")
    p.add_argument("--grpc", default="localhost:50052")
    p.add_argument("--client-id", type=int, default=0)
    p.add_argument("--prog", default=PROG_DEFAULT)

    p.add_argument("--config", action="store_true")
    p.add_argument("--verify-only", action="store_true")
    p.add_argument("--queues", action="store_true")
    p.add_argument("--guard", action="store_true")
    p.add_argument("--event-map", action="store_true")
    p.add_argument("--assert-clean", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    p.add_argument("--txn", action="store_true",
                   help="run ONE complete transaction in this process")
    p.add_argument("--occupancy", action="store_true")
    p.add_argument("--restore-dp8", action="store_true")
    p.add_argument("--dry-run", action="store_true")

    p.add_argument("--scenario", default="normal", choices=sorted(SCENARIOS))
    # int(s, 0) so both 0xC3 and 195 are accepted; plain type=int rejects hex.
    p.add_argument("--gen", type=lambda s: int(s, 0), default=0xC1,
                   help="transaction generation byte, 0xC0..0xCF")
    p.add_argument("--txn-index", type=int, default=1)
    p.add_argument("--a-ms", type=float, default=A_MS_DEFAULT)
    p.add_argument("--r-ms", type=float, default=R_MS_DEFAULT)
    p.add_argument("--budget-a", type=int, default=BUDGET_A_DEFAULT)
    p.add_argument("--budget-r", type=int, default=BUDGET_R_DEFAULT)
    p.add_argument("--out", default=None, help="write the result JSON here")

    p.add_argument("--port-l", type=int, default=PORT_L)
    p.add_argument("--port-pgen", type=int, default=PORT_PGEN)
    p.add_argument("--pipe", type=int, default=PIPE)
    p.add_argument("--app-block", type=int, default=APP_BLOCK)
    p.add_argument("--app-event", type=int, default=APP_EVENT)
    p.add_argument("--buf-off-block", type=int, default=BUF_OFF_BLOCK)
    p.add_argument("--buf-off-event", type=int, default=BUF_OFF_EVENT)
    p.add_argument("--clone-sid", type=int, default=CLONE_SID)
    p.add_argument("--mirror-max-len", type=int, default=128)
    p.add_argument("--timer-ns", type=int, default=1000000,
                   help="event app one-shot countdown after app_enable")

    p.add_argument("--txn-timeout", type=float, default=10.0)
    p.add_argument("--settle", type=float, default=0.2)
    p.add_argument("--cleanup-timeout", type=float, default=15.0)
    p.add_argument("--stable-gap", type=float, default=0.25)
    p.add_argument("--no-cleanup", action="store_true",
                   help="DEBUG ONLY: skip the mandatory cleanup. The next "
                        "transaction will refuse to start, which is intended.")
    return p.parse_args(argv)


def print_plan(a):
    sc = SCENARIOS[a.scenario]
    ta, pa, ea, wa = quantize_offset(a.a_ms * 1000000)
    tr, pr, er, wr = quantize_offset(a.r_ms * 1000000)
    print("")
    print("minimal synthetic dual-release gate — control plane")
    print("  program        : %s" % a.prog)
    print("  queues (dp%d)   : %s" % (a.port_l, ", ".join(
        "%s=qid%d@%s" % (n, q, p) for n, q, p in QUEUE_PLAN)))
    print("  deadlines      : A = %g ms -> 0x%08X (%+d ns)   "
          "R = %g ms -> 0x%08X (%+d ns)   S = %d ns"
          % (a.a_ms, wa, ea, a.r_ms, wr, er, pr - pa))
    print("  budgets        : ACK class %d passes, RESP class %d passes"
          % (a.budget_a, a.budget_r))
    print("  blockers       : app %d, recirc pattern 0x%08X/0x%08X, "
          "1 batch x %d (%d + %d)"
          % (a.app_block, PATTERN_VALUE, PATTERN_MASK, N_BLOCKERS,
             N_BLOCKERS_PER_CLASS, N_BLOCKERS_PER_CLASS))
    print("  events         : app %d, one-shot timer %d ns, 1 batch x %d, "
          "ipg %d ns" % (a.app_event, a.timer_ns, N_EVENTS, sc["ipg_ns"]))
    print("  scenario       : %s  (pid0=READ, pid1=%s, pid2=%s)"
          % (a.scenario, sc["pid1"], sc["pid2"]))
    print("  generation     : 0x%02X" % a.gen)
    print("  release gate   : NONE. This gate is self-timed; no port shaper is "
          "armed, so none can leak.")
    print("  isolation      : assert-clean-start (REFUSES a dirty switch), "
          "cleanup in a finally")
    print("  clean facts    : %s" % ", ".join(CLEAN_FACTS))
    print("  NOT touched    : dp9, dp11, dp64, Hulk, sudo, any capture")
    print("")


def main(argv=None):
    a = parse_args(argv)
    chk = Checks()
    out = {"prog": a.prog, "authored_off_switch": True, "silicon_validated": False,
           "scenario": a.scenario, "generation": a.gen, "txn_index": a.txn_index}

    if not (0xC0 <= a.gen <= 0xCF):
        print("FATAL: --gen must be in 0xC0..0xCF (the generation domain the P4's "
              "tbl_txn_active ternary 0xC0 &&& 0xF0 recognises, and which can "
              "never collide with the SALU no-write sentinel 0x00, TAG_INACTIVE "
              "0xFF or ACKC_NONE 0xFF)", file=sys.stderr)
        return 2

    print_plan(a)
    if a.dry_run:
        out["guard_preview"] = {
            "A": quantize_offset(a.a_ms * 1000000),
            "R": quantize_offset(a.r_ms * 1000000)}
        out["event_map_preview"] = {
            "0": "READ", "1": SCENARIOS[a.scenario]["pid1"],
            "2": SCENARIOS[a.scenario]["pid2"]}
        out["templates"] = {
            "blocker": build_template(ROLE_NONE, PH_NEW, 0, 0).hex(),
            "event": build_template(ROLE_NONE, PH_NEW, a.gen, 0).hex()}
        print(chk.render())
        print("CADM " + json.dumps(out, default=str))
        if a.out:
            with open(a.out, "w") as fh:
                json.dump(out, fh, indent=2, default=str)
        return 0

    modes = [a.config, a.verify_only, a.queues, a.guard, a.event_map,
             a.assert_clean, a.cleanup, a.txn, a.occupancy, a.restore_dp8]
    if not any(modes):
        print("nothing to do: pass --config, --verify-only, --queues, --guard, "
              "--event-map, --assert-clean, --cleanup, --txn, --occupancy, "
              "--restore-dp8 or --dry-run", file=sys.stderr)
        return 2

    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(a.grpc, client_id=a.client_id, device_id=0,
                               notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    # dev_port-keyed fixed-function tables: pipe-0 first (so only pipe 0's
    # generator is armed), device scope as fallback. Which one this SDE accepts
    # is not decidable off-switch, so both are tried and the winner is recorded.
    tgts = [("pipe0", tgt0), ("device", tgt)]

    if a.config:
        config_ports(bi, tgt, a, out, chk)
        write_queues(bi, tgt0, a, out, chk, write=True)
        config_mirror(bi, tgt, a, out, chk)
        config_value_set(bi, a, out, chk)
        config_pktgen_port(bi, tgts, a, out, chk)
        write_buffers(bi, tgts, a, out, chk, a.gen)
        config_apps(bi, tgts, a, out, chk, SCENARIOS[a.scenario]["ipg_ns"])
        write_guard(bi, tgt, a, out, chk)
        write_event_map(bi, tgt, a, out, chk)
    if a.verify_only:
        write_queues(bi, tgt0, a, out, chk, write=False)
        read_occupancy(bi, tgt0, a, out, chk)
        out["counters"] = read_counters(bi, tgt, chk)
        out["registers"] = read_registers(bi, tgt, chk)
    if a.queues:
        write_queues(bi, tgt0, a, out, chk, write=True)
    if a.guard:
        write_guard(bi, tgt, a, out, chk)
    if a.event_map:
        write_event_map(bi, tgt, a, out, chk)
    if a.assert_clean:
        # Read-only. "is it clean?" and "make it clean" stay separate questions.
        st = read_clean_state(bi, tgt, tgt0, tgts, a)
        out["clean_state"] = st
        if st["clean"]:
            chk.ok("switch is CLEAN", "all four facts: %s" % ", ".join(CLEAN_FACTS))
        else:
            chk.fail("switch is CLEAN",
                     "these clean facts do NOT hold: %s" % ", ".join(st["violated_facts"]))
    if a.cleanup:
        cleanup_txn(bi, tgt, tgt0, tgts, a, out, chk)
    if a.occupancy:
        read_occupancy(bi, tgt0, a, out, chk)
    if a.txn:
        run_txn(bi, tgt, tgt0, tgts, a, out, chk)
    if a.restore_dp8:
        restore_dp8(bi, tgts, a, out, chk)

    print(chk.render())
    out["n_fail"] = chk.n_fail
    out["checks"] = [{"result": r, "check": n, "detail": d} for r, n, d in chk.rows]
    print("CADM " + json.dumps(out, default=str))
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(out, fh, indent=2, default=str)
        print("wrote %s" % a.out)
    return 1 if chk.n_fail else 0


if __name__ == "__main__":
    sys.exit(main())

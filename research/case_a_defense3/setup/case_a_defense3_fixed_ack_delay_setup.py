#!/usr/bin/env python3
"""
case_a_defense3_fixed_ack_delay_setup.py — control plane for DEFENSE 3,
PREDETERMINED ACK-DELAY RELEASE (d_ACK = t_ACK + D) on Tofino-1.

Drives research/case_a_defense3/p4/case_a_defense3_fixed_ack_delay.p4.

AUTHORED OFF-SWITCH. Nothing here has been executed against the switch by this
work; the switch still runs Defense 2 (`dnp3_timing_normalizer_pktgen`, verified
read-only). Every `TODO(silicon)` below names the exact readback that resolves it.

WHAT THIS SCRIPT IS RESPONSIBLE FOR, and why each item is here rather than assumed
(each is a control that a named risk in CONSENSUS §7 requires):

  R1  dp8 $SPEED IS A CORRECTNESS PARAMETER, not a diagnostic. The K=64 reservoir
      margin is 10.5x at 10G, 4.2x at 25G and 1.05x at 100G, and the fail-open
      horizon H = B x K / rate_dp8 rescales with it. A prior run on this testbed was
      silently invalidated by dp8 sitting at 10G. -> assert_dp8_speed() ABORTS the
      run (SpeedError, exit 4) rather than warning.
  R6  A PER-QUEUE SHAPER OR THE dp8 PORT SHAPER LEFT ARMED by prior oracle work
      makes Q_BLOCK shaping-INELIGIBLE, so the TM serves Q_HOLD instead. That is a
      false early release which is INDISTINGUISHABLE from an empty reservoir gap in
      every other instrument. The Defense 2 setup writes neither field.
      -> both are forced off AND read back.
  §8.4 D IS CLAMPED AT 40 ms and quantized to 256 ns ticks with a zero low byte
      (the ARMED marker rides in bit 0 of the same word). A silently truncated or
      mis-scaled D produces a plausible-looking headline number that is simply
      wrong. -> quantize_d() reports the exact realized value and refuses > 40 ms.
  §1.3 A TRIAL REFUSES TO START DIRTY (DirtyStateError, exit 3) and CLEANS UP FROM A
      `finally`. Measured: a trial that ended without release left 124 packets
      behind and corrupted the following trial; the first trial after a fresh load
      leaked 4, 5 and 6 packets across three runs.

ENVIRONMENT: python3.8 on the switch, SDE site-packages on PYTHONPATH, STDLIB ONLY
(numpy is not installed there):

    SDE=/home/decps/Downloads/bf-sde-9.13.2
    SP="$SDE/install/lib/python3.8/site-packages"
    PYTHONPATH=$SP:$SP/tofino python3.8 case_a_defense3_fixed_ack_delay_setup.py --config

Machine-readable stdout tag: `D3SETUP {json}`.
Exit codes: 0 ok / 1 checks failed / 2 nothing to do / 3 dirty start / 4 dp8 speed.
"""

import argparse
import json
import sys
import time

# bfruntime_pb2 carries the Mode enum used for value_set pipe/parser scope.
try:
    from bfrt_grpc import bfruntime_pb2 as bfr_pb2  # noqa: N813
except Exception:  # pragma: no cover
    try:
        import bfruntime_pb2 as bfr_pb2  # type: ignore
    except Exception:
        bfr_pb2 = None


# ===========================================================================
# Contract constants — every value is copied from the P4 it drives.
# Cited as: <value>  # <what it mirrors in the .p4>
# ===========================================================================
PROG_DEFAULT = "case_a_defense3_fixed_ack_delay"

PORT_L      = 8    # const PortId_t PORT_L      = 9w8   (loopback / hold ring)
PORT_VISION = 9    # const PortId_t PORT_VISION = 9w9   (master side)
PORT_RELAY  = 64   # const PortId_t PORT_RELAY  = 9w64  (live SEL-751 relay leg)
PORT_PGEN   = 68   # const PortId_t PORT_PGEN   = 9w68  (pktgen / recirc, pipe 0)

QID_BLOCK   = 7    # const bit<5> QID_BLOCK = 5w7  (HIGH: the reservoir)
QID_HOLD    = 1    # const bit<5> QID_HOLD  = 5w1  (LOW : the held ACK + RESPONSE)

CLONE_SID        = 7       # const MirrorId_t CLONE_SESSION_ID = 10w7
CLONE_TAG_MARKER = 0xE1    # CLONE_TAG_MARKER = 32w0xE1000000 -> byte0 = 0xE1
TAG_INACTIVE     = 0x00    # const bit<8> TAG_INACTIVE = 8w0x00 (also reg_tag's init).
# const bit<8> TAG_NO_WRITE = 8w0x01. MIRRORED HERE BECAUSE IT MUST NEVER EQUAL
# TAG_INACTIVE: tag_rmw / ack_rel_rmw write conditionally on
# `meta.tag_val != TAG_NO_WRITE`, and both transaction-retire paths write
# TAG_INACTIVE through tag_rmw. Equal constants => the retire is a silent no-op and
# the generation is never retired. Asserted at trial-plan time (CHECK 1).
TAG_NO_WRITE     = 0x01
# 0x00 NOT 0xFF: with 0xFF the SALU predicate `v == TAG_INACTIVE` compiled to
# `equ lo, lo, -255` -- 255 does not fit the stateful ALU's signed immediate, so the
# compare-and-arm write never committed while its RETURN value still worked. Read out
# of the .bfa; see the P4 header note at TAG_INACTIVE.

# blocker-token template (0x88C1 frame), carried verbatim from the silicon-proven
# Defense 2 setup. The pktgen HW PREPENDS the 6-byte pktgen_recirc_header_t; this
# buffer holds only what follows it, i.e. exactly what the P4 parses after
# advance(PGEN_HDR_BITS=48) -> parse_eth (etype 0x88C1 -> parse_token) -> hdr.ib.
ETYPE_IBSPG = 0x88C1       # const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1
ROLE_BLOCK  = 1            # const bit<8> ROLE_BLOCK = 1
TOKEN_DST   = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
TOKEN_SRC   = bytes([0x02, 0x00, 0x00, 0x00, 0x0b, 0x0c])
TOKEN_LEN   = 60           # min Ethernet frame

# Tofino-1 pktgen facts (SDE tna_pktgen/test.py; both confirmed on silicon for D2):
#   - generator/recirc port is dev_port 68 in pipe 0
#   - the pgen value_set is tied to parser 17 on TF1
PGEN_PRSR_ID   = 17
APP_ID_DEFAULT = 1         # -> value_set byte (pipe 0) = 0x01, distinct from 0xE1

# ---- fixed-function TM / pktgen table names (bf_rt_tm_tf1.json) ----
TM_PORT_CFG       = "tf1.tm.port.cfg"            # KEY dev_port
TM_QUEUE_SCHED    = "tf1.tm.queue.sched_cfg"     # KEY pg_id, pg_queue
TM_QUEUE_SHAPING  = "tf1.tm.queue.sched_shaping" # KEY pg_id, pg_queue
TM_QUEUE_COUNTER  = "tf1.tm.counter.queue"       # KEY pg_id, pg_queue
TM_PORT_SHAPING   = "tf1.tm.port.sched_shaping"  # KEY dev_port
TM_PORT_SCHED_CFG = "tf1.tm.port.sched_cfg"      # KEY dev_port
PKTGEN_PORT_CFG   = "tf1.pktgen.port_cfg"        # KEY dev_port
PKTGEN_PKT_BUFFER = "tf1.pktgen.pkt_buffer"      # KEY pkt_buffer_offset, pkt_buffer_size
PKTGEN_APP_CFG    = "tf1.pktgen.app_cfg"         # KEY app_id (ACTION-based)

REQUIRED_DP8_SPEED = "BF_SPEED_25G"

# ---- D quantization ----
TICK_NS      = 256          # the deadline word carries 24 bits of 256 ns ticks
D_MAX_MS     = 40.0         # CONSENSUS §8.4 hard clamp (poll-period overlap at ~40 ms)
D_DEFAULT_MS = 2.0

# ---- fail-open budget ----
BUDGET_DEFAULT = 18000      # CONSENSUS §6.1
K_TOKENS       = 64         # the validated reservoir depth. NOT claimed minimal.
RATE_DP8_PPS   = 37.4e6     # MEASURED dp8 loop rate at 25G, 64 B frames

# ---- master READ TCP payload length (for EXP_ACK) ----
READ_LEN_DEFAULT = 18       # Class-0 integrity poll: 10 link + 1 tp + 2 app + 3 obj + 2 CRC

# ---- protected session (campaign parameters, NOT literals in the P4) ----
RELAY_IP_DEFAULT  = "192.168.10.7"
MASTER_IP_DEFAULT = "192.168.10.1"
DNP3_PORT         = 20000

# registers the trial must find clean / must reset
# ---- CHECK 2 measured constants (2026-07-29, 100 clean trials on silicon) -----
# The production blocker trigger chain, so the schedule checks can be written against
# a MEASUREMENT instead of an estimate. Evidence:
# evidence/defense3/CHECK2_PRODUCTION_BLOCKER_START_LATENCY.md
C2_CLONE_CHAIN_NS    = 688      # READ -> clone back on dp68 (t_pktgen_trigger)
C2_FIRST_BLOCKER_NS  = 699      # READ -> first blocker admitted   (max observed 701)
C2_FULL_RESERVOIR_NS = 1217     # READ -> all 64 admitted, MAX over 100 trials
C2_BURST_SPAN_NS     = 518      # first -> last of the 64          (max observed)

REGS_ZERO = ("reg_deadline", "reg_ack_rel", "reg_exp_relay_seq", "reg_exp_ack",
             "reg_session_port", "reg_ts_first_block", "reg_ts_ack_arm",
             "reg_ts_block_term", "reg_ts_ack_release")
# reg_tag is reset to TAG_INACTIVE == 0x00, which is also the register's init and is
# what tag_arm compares against. It is kept OUT of REGS_ZERO and written by name so the
# reset is a statement about the MARKER rather than about the number zero: if
# TAG_INACTIVE ever moves again, this line follows it and the blanket zeroing does not
# silently take over. (Before the F02 repair the marker was 0xFF and zeroing reg_tag
# would have left the first READ unable to arm; that is no longer the failure mode, but
# the separation is still the right one.)
REG_TAG = "reg_tag"


class SpeedError(Exception):
    """dp8 is not at the speed the K=64 margin and the fail-open horizon assume.

    This is an EXCEPTION and not a warning on purpose: at 10G the horizon is 99 ms
    instead of 30.9 ms and the reservoir margin changes by 2.5x, so every timing
    number from such a run is void. A prior campaign was invalidated exactly here.
    """


class DirtyStateError(Exception):
    """The trial refused to start because the switch was not in a clean state.

    An INVALID trial never established its preconditions, so it is not a verdict
    about ordering or timing and must never be reported as one.
    """


# ===========================================================================
# Offline helpers — no gRPC, so --dry-run exercises all of this
# ===========================================================================
def build_token_template(total_len=TOKEN_LEN):
    """The 0x88C1 blocker-token buffer (no pktgen header — the HW adds that).

    gen/seq are placeholders: the P4 RE-STAMPS gen (from reg_tag) and seq (from the
    runtime budget) on admission, so a token that somehow escaped re-stamping is
    doubly fail-safe (gen 0 -> stale drop, seq 0 -> budget_zero drop).
    """
    tok = bytearray()
    tok += TOKEN_DST
    tok += TOKEN_SRC
    tok += bytes([(ETYPE_IBSPG >> 8) & 0xFF, ETYPE_IBSPG & 0xFF])
    tok += bytes([ROLE_BLOCK])                 # ibspg.role (re-stamped)
    tok += bytes([0x00])                       # ibspg.slot
    tok += bytes([0x00])                       # ibspg.gen  (re-stamped)
    tok += bytes([0x00, 0x00, 0x00, 0x00])     # ibspg.seq  (re-stamped)
    if len(tok) < total_len:
        tok += bytes(total_len - len(tok))
    return bytes(tok)


def quantize_d(d_ms):
    """Quantize D to the deadline word's 256 ns tick grid and CLAMP it at 40 ms.

    The deadline word is  ticks[31:8] | ARMED_MARK(bit 0),  and the P4 computes
    dl_cand = now_word + d_word. The addend's LOW BYTE MUST THEREFORE BE ZERO, or
    the carry corrupts the armed marker and the whole expiry test. This function is
    the only place that invariant is enforced, so it returns the realized value and
    the error rather than the request.
    """
    if d_ms < 0:
        raise ValueError("D must be non-negative (got %r ms)" % (d_ms,))
    if d_ms > D_MAX_MS:
        raise ValueError(
            "D = %.6f ms exceeds the %.1f ms clamp (CONSENSUS 8.4: poll-period "
            "overlap on the 400 ms schedule). Refusing." % (d_ms, D_MAX_MS))
    req_ns = d_ms * 1e6
    ticks = int(req_ns // TICK_NS)              # round DOWN: never overshoot D
    if ticks > 0xFFFFFF:
        raise ValueError("D = %.6f ms overflows the 24-bit tick field" % (d_ms,))
    word = (ticks << 8) & 0xFFFFFFFF
    realized_ns = ticks * TICK_NS
    assert (word & 0xFF) == 0, "quantized D word must have a zero low byte"
    return {
        "requested_ms": d_ms,
        "ticks": ticks,
        "word": word,
        "word_hex": "0x%08X" % word,
        "realized_ns": realized_ns,
        "realized_ms": realized_ns / 1e6,
        "quantization_error_ns": req_ns - realized_ns,
        "low_byte_zero": (word & 0xFF) == 0,
    }


def failopen_horizon(budget, k=K_TOKENS, rate_pps=RATE_DP8_PPS):
    """H = B x K / rate_dp8  — THE MODEL, not a per-pass constant.

    The inherited comment used ~10 us/pass and was ~5.8x wrong. The value survived
    the error; the model did not, and the model is what someone uses the next time
    D, K or dp8's speed changes. H scales with PORT SPEED, which is why
    assert_dp8_speed() is a hard gate.
    """
    tau_s = float(k) / float(rate_pps)
    h_s = budget * tau_s
    return {"budget": budget, "k": k, "rate_pps": rate_pps,
            "tau_us": tau_s * 1e6, "horizon_ms": h_s * 1e3}


def pnorm(v):
    """Normalize a sched_cfg priority ('LOW' | '0'..'7' | 'HIGH') to an int."""
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


def ip2int(s):
    parts = [int(x) for x in s.split(".")]
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        raise ValueError("bad IPv4 address %r" % (s,))
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


class Checks(object):
    """PASS/FAIL ledger. n_fail drives the exit status; nothing is claimed from a
    command's exit code, only from a readback."""

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

    def expect(self, name, got, want):
        if got == want:
            self.ok(name, "= %r" % (got,))
        else:
            self.fail(name, "got %r, want %r" % (got, want))
        return got == want

    def render(self):
        if not self.rows:
            return "(no checks run)"
        w = max(len(r[1]) for r in self.rows)
        return "\n".join("[%-4s] %-*s  %s" % (r, w, n, d) for r, n, d in self.rows)


# ===========================================================================
# gRPC helpers
# ===========================================================================
def get_table(bi, name, chk=None):
    """Resolve a table by short or qualified name."""
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


def _flatten_max(vals):
    """Collapse a register readback to one int.

    A Register read returns one value per pipe (and per SALU half), so the raw
    result is a list, sometimes nested. The written value is the maximum.
    """
    out = []
    stack = list(vals)
    while stack:
        v = stack.pop()
        if isinstance(v, (list, tuple)):
            stack.extend(v)
        elif isinstance(v, int):
            out.append(v)
    return max(out) if out else None


def _reg_field_and_value(dd):
    """Return (field_name, flattened value) from a register readback dict.

    The data field name is DISCOVERED from the read rather than guessed: it
    resolves as something like 'Ingress.<name>.f1' and the exact spelling has
    varied between builds.
    """
    field, vals = None, []
    for kk, vv in dd.items():
        if kk == "$REGISTER_INDEX" or kk == "action_name" or kk.startswith("is_"):
            continue
        if field is None:
            field = kk
        vals.append(vv)
    return field, _flatten_max(vals)


def reg_read(bi, tgt, name, idx=0, chk=None):
    import bfrt_grpc.client as gc
    t = get_table(bi, name, chk)
    if t is None:
        return None
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
    try:
        for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
            return _reg_field_and_value(d.to_dict())[1]
    except Exception as e:
        if chk is not None:
            chk.fail("reg_read %s" % name, str(e)[:90])
    return None


def reg_write(bi, tgt, name, value, idx=0, chk=None):
    import bfrt_grpc.client as gc
    t = get_table(bi, name, chk)
    if t is None:
        return False
    k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])
    field = None
    try:
        for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
            field = _reg_field_and_value(d.to_dict())[0]
    except Exception:
        pass
    for fn in [f for f in (field, "Ingress.%s.f1" % name, "%s.f1" % name, "f1") if f]:
        try:
            t.entry_mod(tgt, [k], [t.make_data([gc.DataTuple(fn, value)])])
            return True
        except Exception:
            continue
    if chk is not None:
        chk.fail("reg_write %s" % name, "no accepted data field name")
    return False


def ctr_read(bi, tgt, name, idx, chk=None):
    """Read a PACKETS Counter slot.

    A Stats-ALU counter needs an explicit HW->SW sync before a control-plane read;
    from_hw alone returns a stale 0. (A Register, by contrast, reads live — which is
    why the per-trial accounting values live in Registers.)
    """
    import bfrt_grpc.client as gc
    t = get_table(bi, name, chk)
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
            chk.fail("ctr_read %s[%d]" % (name, idx), str(e)[:90])
        return None
    return int(_flatten_max(vals) or 0)


def ctr_zero(bi, tgt, name, idx):
    import bfrt_grpc.client as gc
    t = get_table(bi, name)
    if t is None:
        return False
    k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", idx)])
    try:
        t.entry_mod(tgt, [k], [t.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])])
        return True
    except Exception:
        return False


def resolve_pg(bi, tgt0, dev_port, chk, out):
    """READ the (pg_id, pg_port_nr) of a dev_port instead of guessing it.

    The hardcoded --pg-l 2 / --pg-l-nr 0 defaults are a prior, not a fact; the
    derived values are asserted against them.
    """
    pcfg = get_table(bi, TM_PORT_CFG, chk)
    if pcfg is None:
        return None, None
    got, err = get_entry(pcfg, tgt0, [("dev_port", dev_port)])
    if err:
        chk.fail("%s dp%d" % (TM_PORT_CFG, dev_port), err)
        return None, None
    pg_id, pg_nr = got.get("pg_id"), got.get("pg_port_nr")
    out.setdefault("pg", {})["dp%d" % dev_port] = {"pg_id": pg_id, "pg_port_nr": pg_nr}
    return pg_id, pg_nr


def pg_queue_of(pg_nr, qid):
    """pg_queue = pg_port_nr * 8 + qid (TF1: 8 queues per port in a port group)."""
    return pg_nr * 8 + qid


# ===========================================================================
# R1 — the dp8 speed gate. THIS ABORTS.
# ===========================================================================
def assert_dp8_speed(bi, tgt, tgt0, a, out, chk, pre=False):
    """Read dp8's speed from BOTH authorities and abort unless both say 25G.

    $PORT.$SPEED is the MAC's view; tf1.tm.port.sched_cfg.scheduling_speed is the
    TM's. They are configured independently and have disagreed before, so both are
    required — a TM that believes dp8 is 10G shapes it as 10G regardless of the MAC.
    """
    rec = {}
    port_tbl = get_table(bi, "$PORT", chk)
    if port_tbl is not None:
        got, err = get_entry(port_tbl, tgt, [("$DEV_PORT", a.port_l)])
        if err:
            (chk.ok if pre else chk.fail)("dp8 $PORT read", err)
        else:
            rec["mac"] = {k: got.get(k) for k in
                          ("$PORT_UP", "$SPEED", "$FEC", "$PORT_ENABLE", "$LOOPBACK_MODE")}
    psc = get_table(bi, TM_PORT_SCHED_CFG, chk)
    if psc is not None:
        got, err = get_entry(psc, tgt0, [("dev_port", a.port_l)])
        if err:
            (chk.ok if pre else chk.fail)("dp8 %s read" % TM_PORT_SCHED_CFG, err)
        else:
            rec["tm"] = {"scheduling_speed": got.get("scheduling_speed"),
                         "max_rate_enable": got.get("max_rate_enable")}
    out["dp8_speed"] = rec

    mac_speed = rec.get("mac", {}).get("$SPEED")
    tm_speed = rec.get("tm", {}).get("scheduling_speed")
    bad = []
    if mac_speed != REQUIRED_DP8_SPEED:
        bad.append("$PORT.$SPEED=%r" % (mac_speed,))
    if tm_speed != REQUIRED_DP8_SPEED:
        bad.append("tm.scheduling_speed=%r" % (tm_speed,))
    # A COLD LOAD has no $PORT entries at all: the port is ABSENT, not misconfigured.
    # The pre-check must distinguish those two. Absent -> config_ports() will create it
    # and the post-check (the real gate) will verify it. Present-but-wrong -> abort now,
    # because that is a switch someone else left in a bad state.
    absent = (mac_speed is None)
    if bad and pre and absent:
        chk.ok("dp8 $SPEED pre-check (port not yet configured)",
               "$PORT has no dp8 entry on a cold load; config_ports() will create it "
               "at %s and the POST-check is the hard gate." % REQUIRED_DP8_SPEED)
        return rec
    if bad:
        detail = ("dp8 must be %s; read %s. The K=64 reservoir margin and the "
                  "fail-open horizon H = B x K / rate_dp8 are BOTH speed-conditional, "
                  "so every timing number from this configuration would be void."
                  % (REQUIRED_DP8_SPEED, " and ".join(bad)))
        chk.fail("dp8 $SPEED == %s" % REQUIRED_DP8_SPEED, detail)
        raise SpeedError(detail)
    chk.ok("dp8 $SPEED == %s (MAC and TM agree)" % REQUIRED_DP8_SPEED,
           "PORT_UP=%r LOOPBACK=%r" % (rec.get("mac", {}).get("$PORT_UP"),
                                       rec.get("mac", {}).get("$LOOPBACK_MODE")))
    return rec


# ===========================================================================
# Ports
# ===========================================================================
def config_ports(bi, tgt, a, out, chk, write=True):
    import bfrt_grpc.client as gc
    port_tbl = get_table(bi, "$PORT", chk)
    if port_tbl is None:
        return

    def port_up(dp, speed, fec, an, lpbk="BF_LPBK_NONE"):
        key = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", dp)])]
        data = [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val=speed),
            gc.DataTuple("$FEC", str_val=fec),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val=an),
            gc.DataTuple("$LOOPBACK_MODE", str_val=lpbk),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
        try:
            port_tbl.entry_add(tgt, key, data)
        except Exception:
            try:
                port_tbl.entry_mod(tgt, key, data)
            except Exception as e:
                chk.fail("port dp%d up" % dp, str(e)[:80])

    if write:
        port_up(a.port_vision, "BF_SPEED_25G", "BF_FEC_TYP_RS", "PM_AN_DEFAULT")
        port_up(a.port_relay, "BF_SPEED_1G", "BF_FEC_TYP_NONE", "PM_AN_FORCE_DISABLE")
        # dp8 MAC-near loopback: DELETE then re-add. A live entry rejects a
        # loopback-mode change, and the failure is silent.
        lk = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", a.port_l)])]
        try:
            port_tbl.entry_del(tgt, lk)
        except Exception:
            pass
        try:
            port_tbl.entry_add(tgt, lk, [port_tbl.make_data([
                gc.DataTuple("$SPEED", str_val=REQUIRED_DP8_SPEED),
                gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
                gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
                gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
        except Exception as e:
            chk.fail("dp8 loopback up", str(e)[:80])

    rec = {}
    for dp in (a.port_l, a.port_vision, a.port_relay):
        got, err = get_entry(port_tbl, tgt, [("$DEV_PORT", dp)])
        rec["dp%d" % dp] = err or {k: got.get(k) for k in
                                   ("$PORT_UP", "$SPEED", "$FEC", "$PORT_ENABLE",
                                    "$LOOPBACK_MODE")}
    out["ports"] = rec
    # TODO(silicon): dp64 must read $PORT_UP True at BF_SPEED_1G with the relay
    # cabled. RESOLVING CHECK: out["ports"]["dp64"]["$PORT_UP"] is True.


# ===========================================================================
# Queues: priorities + BOTH shaper families off, all read back (R6)
# ===========================================================================
def config_queues(bi, tgt0, tgts, a, out, chk, write=True):
    import bfrt_grpc.client as gc
    q_cfg = get_table(bi, TM_QUEUE_SCHED, chk)
    q_shp = get_table(bi, TM_QUEUE_SHAPING, chk)
    if q_cfg is None:
        return

    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    if pg_id is None:
        chk.fail("dp8 port group resolved", "tf1.tm.port.cfg read failed")
        return
    chk.expect("dp8 pg_id derived == --pg-l", pg_id, a.pg_l)
    chk.expect("dp8 pg_port_nr derived == --pg-l-nr", pg_nr, a.pg_l_nr)

    want = {QID_BLOCK: "7", QID_HOLD: "0"}   # Q_BLOCK HIGH strictly above Q_HOLD
    rec = {}
    for qid, pri in want.items():
        pgq = pg_queue_of(pg_nr, qid)
        key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        if write:
            try:
                # max_priority is the field that arbitrates the remaining-bandwidth
                # pass and is therefore the ONLY one that orders these queues.
                # min_priority is INERT unless min_rate_enable is true; writing it
                # alone is the exact IBSPG silent failure (a fair DWRR split that
                # looks like a priority violation). Write both for parity, gate on max.
                #
                # max_rate_enable / min_rate_enable are forced FALSE here: a queue
                # over its own max rate becomes shaping-INELIGIBLE and the TM serves
                # the lower-priority eligible queue instead — a false early release
                # indistinguishable from an empty reservoir gap.
                q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data([
                    gc.DataTuple("scheduling_enable", bool_val=True),
                    gc.DataTuple("min_priority", str_val=pri),
                    gc.DataTuple("max_priority", str_val=pri),
                    gc.DataTuple("max_rate_enable", bool_val=False),
                    gc.DataTuple("min_rate_enable", bool_val=False)])])
            except Exception as e:
                chk.fail("queue qid%d sched_cfg write" % qid, str(e)[:90])
        got, err = get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("queue qid%d readback" % qid, err)
            continue
        rec["qid%d" % qid] = {
            "pg_queue": pgq,
            "max_priority": got.get("max_priority"),
            "min_priority": got.get("min_priority"),
            "scheduling_enable": got.get("scheduling_enable"),
            "max_rate_enable": got.get("max_rate_enable"),
            "min_rate_enable": got.get("min_rate_enable"),
            "dwrr_weight": got.get("dwrr_weight"),
        }
        chk.expect("qid%d max_priority" % qid, pnorm(got.get("max_priority")), int(pri))
        chk.expect("qid%d scheduling_enable" % qid, got.get("scheduling_enable"), True)
        chk.expect("qid%d max_rate_enable OFF" % qid, got.get("max_rate_enable"), False)
        chk.expect("qid%d min_rate_enable OFF" % qid, got.get("min_rate_enable"), False)

    out["queues"] = rec
    pb = pnorm(rec.get("qid%d" % QID_BLOCK, {}).get("max_priority"))
    ph = pnorm(rec.get("qid%d" % QID_HOLD, {}).get("max_priority"))
    if pb is not None and ph is not None and pb > ph:
        chk.ok("STRICT PRIORITY Q_BLOCK > Q_HOLD (max_priority)", "%s > %s" % (pb, ph))
    else:
        chk.fail("STRICT PRIORITY Q_BLOCK > Q_HOLD (max_priority)",
                 "Q_BLOCK=%r Q_HOLD=%r" % (pb, ph))
    # A readback of max_priority is NOT proof that strict priority is behaving.
    # TODO(silicon): run the causal-reversal control in THIS two-queue configuration
    # (K=64 was validated for Defense 2's queue set, not this one).
    # RESOLVING CHECK: reverse ONLY max_priority (Q_BLOCK=0, Q_HOLD=7), re-run one
    # transaction, and confirm the ACK is released immediately (hold ~= 0) instead of
    # at t_ACK + D. If the order does NOT reverse, the priority is not what is
    # producing the hold and every timing number is unattributed.

    # record the per-queue shaper parameters too, so a silent clamp is visible
    if q_shp is not None:
        shp = {}
        for qid in want:
            pgq = pg_queue_of(pg_nr, qid)
            got, err = get_entry(q_shp, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
            shp["qid%d" % qid] = err or {k: got.get(k) for k in
                                         ("unit", "provisioning", "max_rate",
                                          "max_burst_size", "min_rate", "min_burst_size")}
        out["queue_shaping"] = shp


def disarm_port_shaper(bi, tgts, a, out, chk, write=True):
    """Disarm the dp8 PORT shaper and read it back (R6).

    The four-queue oracle work uses this shaper as a single-write GLOBAL release
    gate. A Defense 3 run that inherits it armed gates the entire ring: Q_BLOCK
    cannot drain, so the hold never ends and the trial reads as a stuck ACK with no
    error anywhere. The Defense 2 setup never touches this table, so "it was fine
    last time" is not evidence.
    """
    import bfrt_grpc.client as gc
    cfg = get_table(bi, TM_PORT_SCHED_CFG, chk)
    if cfg is None:
        return
    if write:
        last = "no target accepted"
        done = False
        for tname, tg in tgts:
            try:
                key = cfg.make_key([gc.KeyTuple("dev_port", a.port_l)])
                cfg.entry_mod(tg, [key], [cfg.make_data([
                    gc.DataTuple("max_rate_enable", bool_val=False)])])
                out["port_shaper_target"] = tname
                done = True
                break
            except Exception as e:
                last = str(e)[:90]
        if not done:
            chk.fail("dp8 PORT shaper disarm", last)
    rec = None
    for _tname, tg in tgts:
        got, err = get_entry(cfg, tg, [("dev_port", a.port_l)])
        if not err:
            rec = {"max_rate_enable": got.get("max_rate_enable"),
                   "scheduling_speed": got.get("scheduling_speed")}
            break
    out["port_shaper"] = rec if rec is not None else "unreadable"
    if rec is None:
        chk.fail("dp8 PORT shaper readback", "unreadable on every target")
    else:
        chk.expect("dp8 PORT shaper max_rate_enable OFF", rec["max_rate_enable"], False)

    shp = get_table(bi, TM_PORT_SHAPING, a and chk)
    if shp is not None:
        for _tname, tg in tgts:
            got, err = get_entry(shp, tg, [("dev_port", a.port_l)])
            if not err:
                # NOTE: tf1.tm.port.sched_shaping is MAX-ONLY on TF1 — it has no
                # min_rate / min_burst_size, unlike the per-queue shaper.
                out["port_shaping_params"] = {k: got.get(k) for k in
                                              ("unit", "provisioning", "max_rate",
                                               "max_burst_size")}
                break


# ===========================================================================
# P4 runtime parameters: D, read_len, budget
# ===========================================================================
def config_params(bi, tgt, a, out, chk, write=True):
    import bfrt_grpc.client as gc
    qd = quantize_d(a.d_ms)
    hz = failopen_horizon(a.budget)
    out["D"] = qd
    out["failopen"] = hz
    out["read_len"] = a.read_len

    # The quantization report. This is printed, not just stored: D rides in the same
    # 32-bit word as the armed marker, so a mis-scaled D yields a plausible-looking
    # headline number that is simply wrong.
    print("D3 D quantization : requested %.6f ms -> %d ticks x %d ns = %.6f ms "
          "(word %s, low byte %s, error %+.1f ns)"
          % (qd["requested_ms"], qd["ticks"], TICK_NS, qd["realized_ms"],
             qd["word_hex"], "ZERO (ok)" if qd["low_byte_zero"] else "NONZERO (BUG)",
             -qd["quantization_error_ns"]))
    print("D3 fail-open      : H = B x K / rate_dp8 = %d x %d / %.3g pps "
          "= %.3f ms  (tau = %.3f us/pass)"
          % (hz["budget"], hz["k"], hz["rate_pps"], hz["horizon_ms"], hz["tau_us"]))
    print("D3 headroom       : H / (a_worst + D) with a_worst = 22 ms -> %.2fx ; "
          "RTO(200 ms) / H -> %.2fx"
          % (hz["horizon_ms"] / (22.0 + qd["realized_ms"]), 200.0 / hz["horizon_ms"]))
    if hz["horizon_ms"] <= (22.0 + qd["realized_ms"]):
        chk.fail("fail-open horizon exceeds the worst-case hold",
                 "H=%.3f ms <= a_worst+D=%.3f ms: the budget would fire DURING a "
                 "legitimate hold and the trial would measure B, not D."
                 % (hz["horizon_ms"], 22.0 + qd["realized_ms"]))
    elif hz["horizon_ms"] >= 200.0:
        chk.fail("fail-open horizon below the master RTO floor",
                 "H=%.3f ms >= 200 ms: a late fail-open would collide with the "
                 "master's retransmission instead of pre-empting it." % hz["horizon_ms"])
    else:
        chk.ok("fail-open horizon inside (a_worst+D, RTO)",
               "%.3f ms" % hz["horizon_ms"])

    t = get_table(bi, "tbl_params", chk)
    if t is None:
        return
    if write:
        wrote = False
        last = ""
        for act in ("Ingress.set_params", "set_params"):
            try:
                t.default_entry_set(tgt, t.make_data([
                    gc.DataTuple("d_ticks", qd["word"]),
                    gc.DataTuple("read_len", a.read_len),
                    gc.DataTuple("budget", a.budget)], act))
                wrote = True
                break
            except Exception as e:
                last = str(e)[:90]
        if not wrote:
            chk.fail("tbl_params default_entry_set", last)
    got = None
    try:
        for item in t.default_entry_get(tgt, {"from_hw": True}):
            d = item[0] if isinstance(item, tuple) else item
            if d is not None:
                got = d.to_dict()
    except Exception as e:
        chk.fail("tbl_params default_entry_get", str(e)[:90])
    out["tbl_params_readback"] = got
    if got:
        chk.expect("tbl_params d_ticks", got.get("d_ticks"), qd["word"])
        chk.expect("tbl_params read_len", got.get("read_len"), a.read_len)
        chk.expect("tbl_params budget", got.get("budget"), a.budget)
    # TODO(silicon): read_len is a CALIBRATION value, not a constant of nature.
    # RESOLVING CHECK: after the first calibration poll, ctr_fresh[CF_ACK_HOLD] must
    # equal the number of transactions and ctr_fresh[CF_ACK_REJECT] must be 0. If
    # CF_ACK_REJECT == n_txn and CF_ACK_HOLD == 0, read_len is wrong: take the READ's
    # TCP payload length from the capture and re-run --config.


def config_session(bi, tgt, a, out, chk, write=True):
    """Install the protected 5-tuple. The addresses are campaign parameters and are
    deliberately NOT literals in the P4."""
    import bfrt_grpc.client as gc
    t = get_table(bi, "tbl_session", chk)
    if t is None:
        return
    relay, master = ip2int(a.relay_ip), ip2int(a.master_ip)
    M32, M16 = 0xFFFFFFFF, 0xFFFF
    rows = [
        # relay -> master: src 20000, master ephemeral port is a don't-care (it is
        # what reg_session_port learns).
        (relay, master, (DNP3_PORT, M16), (0, 0), "sess_relay", 1),
        # master -> relay: dst 20000, ephemeral source is the don't-care.
        (master, relay, (0, 0), (DNP3_PORT, M16), "sess_master", 2),
    ]
    if write:
        for src, dst, sp, dp, act, prio in rows:
            key = t.make_key([
                gc.KeyTuple("hdr.ipv4.src_addr", src, M32),
                gc.KeyTuple("hdr.ipv4.dst_addr", dst, M32),
                gc.KeyTuple("hdr.tcp.src_port", sp[0], sp[1]),
                gc.KeyTuple("hdr.tcp.dst_port", dp[0], dp[1]),
                gc.KeyTuple("$MATCH_PRIORITY", prio)])
            data = None
            for an in ("Ingress." + act, act):
                try:
                    data = t.make_data([], an)
                    break
                except Exception:
                    continue
            if data is None:
                chk.fail("tbl_session action %s" % act, "make_data rejected both names")
                continue
            try:
                t.entry_add(tgt, [key], [data])
            except Exception:
                try:
                    t.entry_mod(tgt, [key], [data])
                except Exception as e:
                    chk.fail("tbl_session %s install" % act, str(e)[:90])
    n = 0
    try:
        for _d, _k in t.entry_get(tgt, None, {"from_hw": True}):
            n += 1
    except Exception as e:
        chk.warn("tbl_session dump", str(e)[:90])
        n = None
    out["session"] = {"relay_ip": a.relay_ip, "master_ip": a.master_ip,
                      "dnp3_port": DNP3_PORT, "entries_read": n}
    if n is not None:
        chk.expect("tbl_session entries", n, 2)


# ===========================================================================
# Mirror session, parser value_set, pktgen (K=64)
# ===========================================================================
def config_mirror(bi, tgt, a, out, chk, write=True):
    import bfrt_grpc.client as gc
    mtbl = get_table(bi, "$mirror.cfg", chk)
    if mtbl is None:
        return
    mkey = [mtbl.make_key([gc.KeyTuple("$sid", a.clone_sid)])]
    if write:
        # $mirror.cfg is ACTION-based on this SDE ('$normal' / '$coalescing');
        # make_data REQUIRES the action name or it fails INVALID_ARGUMENT.
        mdata = [mtbl.make_data([
            gc.DataTuple("$direction", str_val="INGRESS"),
            gc.DataTuple("$ucast_egress_port", a.port_pgen),
            gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
            gc.DataTuple("$session_enable", bool_val=True),
            gc.DataTuple("$max_pkt_len", a.mirror_max_len)], "$normal")]
        try:
            mtbl.entry_add(tgt, mkey, mdata)
        except Exception:
            try:
                mtbl.entry_mod(tgt, mkey, mdata)
            except Exception as e:
                chk.fail("$mirror.cfg sid %d" % a.clone_sid, str(e)[:90])
    got, err = get_entry(mtbl, tgt, [("$sid", a.clone_sid)])
    out["mirror"] = err or {k: got.get(k) for k in
                            ("$direction", "$ucast_egress_port",
                             "$ucast_egress_port_valid", "$session_enable",
                             "$max_pkt_len")}
    if not err:
        chk.expect("mirror $ucast_egress_port", got.get("$ucast_egress_port"), a.port_pgen)
        chk.expect("mirror $session_enable", got.get("$session_enable"), True)


def config_value_set(bi, a, out, chk, write=True):
    import bfrt_grpc.client as gc
    vs_byte = (a.pipe << 3) | a.app_id
    vs_mask = 0xFF   # MUST be exact 0xFF. Under the SDE example's 0x1F the 0xE1
                     # clone marker aliases to app_id 1 and the recirculated clone is
                     # mis-admitted as a blocker token.
    out["value_set"] = {"byte": vs_byte, "mask": vs_mask, "prsr_id": PGEN_PRSR_ID,
                        "pipe": a.pipe}
    try:
        vs = bi.table_get("pipe.IgParser.pgen_recirc")
    except Exception as e:
        chk.fail("value_set pgen_recirc lookup", str(e)[:90])
        return
    if write:
        if bfr_pb2 is not None:
            try:
                # scope can only be set while the table is EMPTY; failing here on a
                # re-run is expected and harmless.
                vs.attribute_entry_scope_set(
                    gc.Target(device_id=0, pipe_id=0xffff),
                    config_pipe_scope=True, predefined_pipe_scope=True,
                    predefined_pipe_scope_val=bfr_pb2.Mode.SINGLE,
                    config_gress_scope=True, predefined_gress_scope_val=bfr_pb2.Mode.ALL,
                    config_prsr_scope=True, predefined_prsr_scope_val=bfr_pb2.Mode.SINGLE)
            except Exception as se:
                out["value_set_scope_note"] = "scope already set (ok on re-run): " + str(se)[:40]
        vtgt = gc.Target(device_id=0, pipe_id=a.pipe, prsr_id=PGEN_PRSR_ID)
        vkey = [vs.make_key([gc.KeyTuple("f1", vs_byte, vs_mask)])]
        try:
            vs.entry_del(vtgt, vkey)     # idempotent: clear any prior entry first
        except Exception:
            pass
        try:
            vs.entry_add(vtgt, vkey)
        except Exception as e:
            chk.fail("value_set pgen_recirc add", str(e)[:90])
    chk.ok("value_set pgen_recirc programmed", "byte=0x%02X mask=0x%02X" % (vs_byte, vs_mask))


def config_pktgen(bi, tgt, a, out, chk, write=True, app_enable=False):
    import bfrt_grpc.client as gc
    template = build_token_template(a.token_len)

    pcfg = get_table(bi, PKTGEN_PORT_CFG, chk)
    if pcfg is not None and write:
        # dp68 needs ALL THREE flags for a recirc-PATTERN trigger:
        #   pktgen_enable           run the generator on dp68
        #   recirculation_enable    let the mirrored clone loop egress->ingress on
        #                           dp68. WITHOUT THIS the clone never comes back to
        #                           trigger and the reservoir is silently never built.
        #   pattern_matching_enable arm the recirc-pattern matcher
        try:
            pcfg.entry_mod(tgt, [pcfg.make_key([gc.KeyTuple("dev_port", a.port_pgen)])],
                           [pcfg.make_data([
                               gc.DataTuple("pktgen_enable", bool_val=True),
                               gc.DataTuple("recirculation_enable", bool_val=True),
                               gc.DataTuple("pattern_matching_enable", bool_val=True)])])
        except Exception as e:
            chk.fail("pktgen port_cfg dp%d" % a.port_pgen, str(e)[:90])

    pbuf = get_table(bi, PKTGEN_PKT_BUFFER, chk)
    if pbuf is not None and write:
        try:
            pbuf.entry_mod(
                tgt,
                [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", a.buf_offset),
                                gc.KeyTuple("pkt_buffer_size", len(template))])],
                [pbuf.make_data([gc.DataTuple("buffer", bytearray(template))])])
        except Exception as e:
            chk.fail("pktgen pkt_buffer", str(e)[:90])

    acfg = get_table(bi, PKTGEN_APP_CFG, chk)
    if acfg is None:
        return
    pattern_value = CLONE_TAG_MARKER << 24     # 0xE1000000
    pattern_mask = 0xFF000000                  # pin byte 0 only
    if write:
        try:
            acfg.entry_mod(
                tgt,
                [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
                [acfg.make_data([
                    gc.DataTuple("pattern_value", pattern_value),
                    gc.DataTuple("pattern_mask", pattern_mask),
                    gc.DataTuple("pkt_len", len(template)),
                    gc.DataTuple("pkt_buffer_offset", a.buf_offset),
                    # pipe_local_source_port sets the ingress_port the generated
                    # tokens CARRY. It is REQUIRED on this switch — the SDE's
                    # "implicit on TF1" note does NOT hold here, and without it the
                    # tokens are never admitted.
                    gc.DataTuple("pipe_local_source_port", a.port_pgen),
                    # LOAD-BEARING: if this reads back True the driver caps
                    # packets_per_batch at 127 - 68 = 59, silently rejecting K=64.
                    gc.DataTuple("increment_source_port", bool_val=False),
                    gc.DataTuple("batch_count_cfg", 0),               # 1 batch (zero-based)
                    gc.DataTuple("packets_per_batch_cfg", a.k - 1),   # K=64 -> 63
                    gc.DataTuple("ipg", 0),
                    gc.DataTuple("ibg", 0),
                    gc.DataTuple("trigger_counter", 0),
                    gc.DataTuple("batch_counter", 0),
                    gc.DataTuple("pkt_counter", 0),
                    gc.DataTuple("app_enable", bool_val=app_enable),
                ], "trigger_recirc_pattern")])
        except Exception as e:
            chk.fail("pktgen app_cfg", str(e)[:90])

    got, err = get_entry(acfg, tgt, [("app_id", a.app_id)])
    out["pktgen"] = err or {k: got.get(k) for k in
                            ("pattern_value", "pattern_mask", "pkt_len",
                             "pkt_buffer_offset", "pipe_local_source_port",
                             "increment_source_port", "batch_count_cfg",
                             "packets_per_batch_cfg", "app_enable",
                             "trigger_counter", "batch_counter", "pkt_counter")}
    if not err:
        isp = got.get("increment_source_port")
        if isp is not True and isp is not False:
            chk.fail("pktgen increment_source_port is boolean", "read %r" % (isp,))
        else:
            chk.expect("pktgen increment_source_port == False", isp, False)
        chk.expect("pktgen pipe_local_source_port", got.get("pipe_local_source_port"),
                   a.port_pgen)
        chk.expect("pktgen packets_per_batch_cfg (K-1)", got.get("packets_per_batch_cfg"),
                   a.k - 1)
        chk.expect("pktgen batch_count_cfg (1 batch)", got.get("batch_count_cfg"), 0)
        chk.expect("pktgen app_enable at config time", got.get("app_enable"), app_enable)


def set_app_enable(bi, tgt, a, enable, chk=None):
    """Toggle the generator. The app does NOT auto-disable after a one-shot batch,
    so it must be driven False before being re-armed True."""
    import bfrt_grpc.client as gc
    acfg = get_table(bi, PKTGEN_APP_CFG, chk)
    if acfg is None:
        return False
    # F01-c: scope to ONE pipe. The caller's tgt is pipe_id=0xffff (device-wide)
    # and this chip has TWO pipes, so a device-wide enable arms the generator in
    # both. Harmless for a recirc-pattern app (only pipe 0 sees the dp68 clone)
    # but NOT for a timer app, which fires in every pipe it is armed in.
    ptgt = gc.Target(device_id=0, pipe_id=a.pipe)
    try:
        acfg.entry_mod(ptgt, [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
                       [acfg.make_data([gc.DataTuple("app_enable", bool_val=enable)])])
        return True
    except Exception as e:
        if chk is not None:
            chk.fail("pktgen app_enable=%s" % enable, str(e)[:90])
        return False


# ===========================================================================
# Clean start (§1.3) and cleanup (§1.5)
# ===========================================================================
def read_queue_counters(bi, tgt0, a, out, chk):
    """drop_count_packets / watermark_cells for both queues.

    usage_cells IS RECORDED BUT NEVER REASONED FROM: it reads 0 on dp8 queues even
    when packets are demonstrably queued (measured across five shaper settings,
    including one that leaked), and it is writable, so "zero it and read back zero"
    certifies nothing. watermark_cells is latched and one-way: watermark > 0 proves a
    queue WAS occupied; it can never prove a queue is now empty.
    """
    qc = get_table(bi, TM_QUEUE_COUNTER, chk)
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    rec = {}
    if qc is None or pg_id is None:
        return rec
    for qid in (QID_BLOCK, QID_HOLD):
        pgq = pg_queue_of(pg_nr, qid)
        got, err = get_entry(qc, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        rec["qid%d" % qid] = err or {
            "drop_count_packets": got.get("drop_count_packets"),
            "watermark_cells": got.get("watermark_cells"),
            "usage_cells_DIAGNOSTIC_ONLY": got.get("usage_cells"),
        }
    return rec


def read_clean_state(bi, tgt, tgt0, a, out, chk):
    st = {}
    st["reg_tag"] = reg_read(bi, tgt, REG_TAG)
    st["reg_deadline"] = reg_read(bi, tgt, "reg_deadline")
    st["reg_ack_rel"] = reg_read(bi, tgt, "reg_ack_rel")
    acfg = get_table(bi, PKTGEN_APP_CFG)
    if acfg is not None:
        import bfrt_grpc.client as gc  # noqa: F401
        got, err = get_entry(acfg, tgt, [("app_id", a.app_id)])
        st["pktgen"] = err or {"app_enable": got.get("app_enable"),
                               "pkt_counter": got.get("pkt_counter"),
                               "batch_counter": got.get("batch_counter"),
                               "trigger_counter": got.get("trigger_counter")}
    st["queue_counters"] = read_queue_counters(bi, tgt0, a, out, chk)

    reasons = []
    # An UNREADABLE fact is NOT a clean fact.
    if st["reg_tag"] is None:
        reasons.append("reg_tag unreadable")
    elif st["reg_tag"] != TAG_INACTIVE:
        reasons.append("reg_tag = 0x%02X (a generation is still live; want 0x%02X)"
                       % (st["reg_tag"], TAG_INACTIVE))
    if st["reg_deadline"] is None:
        reasons.append("reg_deadline unreadable")
    elif (st["reg_deadline"] & 0x1) != 0:
        reasons.append("deadline word 0x%08X still ARMED (bit 0 set)" % st["reg_deadline"])
    pg = st.get("pktgen")
    if isinstance(pg, dict):
        if pg.get("app_enable") is not False:
            reasons.append("pktgen app_enable = %r (want False)" % pg.get("app_enable"))
    else:
        reasons.append("pktgen app_cfg unreadable: %s" % pg)
    for qname, q in (st.get("queue_counters") or {}).items():
        if not isinstance(q, dict):
            reasons.append("%s counters unreadable: %s" % (qname, q))
        elif q.get("drop_count_packets"):
            reasons.append("%s drop_count_packets = %r (want 0)"
                           % (qname, q.get("drop_count_packets")))
    st["clean"] = not reasons
    st["reasons"] = reasons
    return st


def assert_clean_start(bi, tgt, tgt0, a, out, chk):
    st = read_clean_state(bi, tgt, tgt0, a, out, chk)
    out["clean_start"] = st
    if a.first_after_load:
        st["clean"] = False
        st["reasons"].append(
            "first trial after a program load — measured to leak 4, 5 and 6 packets "
            "across three runs; it is discarded or repeated, never a data point")
    if st["clean"]:
        chk.ok("CLEAN START asserted", "reg_tag=0x%02X deadline=0x%08X"
               % (st["reg_tag"], st["reg_deadline"]))
        return st
    detail = "; ".join(st["reasons"])
    chk.fail("CLEAN START asserted", detail)
    raise DirtyStateError(detail)


def cleanup_trial(bi, tgt, tgt0, tgts, a, out, chk):
    """Cleanup, in the ONE order that is sound. This runs from a `finally`.

    ORDER IS LOAD-BEARING:
      1 disable pktgen     — stop making tokens before anything else
      2 restore line rate  — a shaper left armed prevents the drain
      3 drain              — let the ring empty
      4 verify             — read the drop counters
      5 reset counters     — ONLY NOW. Resetting before draining certifies a switch
                             that is still holding traffic.
    Measured consequence of skipping this: a trial that ended INVALID without release
    left its backlog behind and 124 leftover packets were consumed by the FOLLOWING
    trial, corrupting it.
    """
    rec = {"order": ["disable_pktgen", "line_rate", "drain", "verify", "reset"]}
    rec["disable_pktgen"] = set_app_enable(bi, tgt, a, False, chk)
    disarm_port_shaper(bi, tgts, a, rec, chk, write=True)
    time.sleep(a.drain_s)
    rec["queue_counters_after_drain"] = read_queue_counters(bi, tgt0, a, rec, chk)
    if not a.no_reset:
        rec["reg_tag_reset"] = reg_write(bi, tgt, REG_TAG, TAG_INACTIVE, chk=chk)
        for r in REGS_ZERO:
            reg_write(bi, tgt, r, 0)
        for i in range(32):
            ctr_zero(bi, tgt, "ctr_fresh", i)
        for i in range(16):
            ctr_zero(bi, tgt, "ctr_deq", i)
        # verify the two that matter
        rec["reg_tag_after"] = reg_read(bi, tgt, REG_TAG)
        rec["reg_deadline_after"] = reg_read(bi, tgt, "reg_deadline")
        chk.expect("cleanup: reg_tag == TAG_INACTIVE", rec["reg_tag_after"], TAG_INACTIVE)
        chk.expect("cleanup: reg_deadline == 0", rec["reg_deadline_after"], 0)
    out["cleanup"] = rec
    return rec


def snapshot(bi, tgt, tgt0, tgts, a, out, chk):
    """Pre-run snapshot. Restore reads from THIS, not from constants."""
    snap = {"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    port_tbl = get_table(bi, "$PORT", chk)
    if port_tbl is not None:
        snap["ports"] = {}
        for dp in (a.port_l, a.port_vision, a.port_relay):
            got, err = get_entry(port_tbl, tgt, [("$DEV_PORT", dp)])
            snap["ports"]["dp%d" % dp] = err or {
                k: got.get(k) for k in ("$SPEED", "$FEC", "$AUTO_NEGOTIATION",
                                        "$LOOPBACK_MODE", "$PORT_ENABLE", "$PORT_UP")}
    psc = get_table(bi, TM_PORT_SCHED_CFG, chk)
    if psc is not None:
        for _tn, tg in tgts:
            got, err = get_entry(psc, tg, [("dev_port", a.port_l)])
            if not err:
                snap["dp8_port_sched_cfg"] = {k: got.get(k) for k in
                                              ("max_rate_enable", "scheduling_speed")}
                break
    q_cfg = get_table(bi, TM_QUEUE_SCHED, chk)
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, snap)
    if q_cfg is not None and pg_id is not None:
        snap["queues"] = {}
        for qid in (QID_BLOCK, QID_HOLD):
            got, err = get_entry(q_cfg, tgt0, [("pg_id", pg_id),
                                               ("pg_queue", pg_queue_of(pg_nr, qid))])
            snap["queues"]["qid%d" % qid] = err or {
                k: got.get(k) for k in ("max_priority", "min_priority",
                                        "scheduling_enable", "max_rate_enable",
                                        "min_rate_enable", "dwrr_weight")}
    acfg = get_table(bi, PKTGEN_APP_CFG, chk)
    if acfg is not None:
        got, err = get_entry(acfg, tgt, [("app_id", a.app_id)])
        snap["pktgen"] = err or {k: got.get(k) for k in
                                 ("app_enable", "batch_count_cfg",
                                  "packets_per_batch_cfg", "pattern_value",
                                  "pattern_mask", "pipe_local_source_port",
                                  "increment_source_port")}
    snap["queue_counters_base"] = read_queue_counters(bi, tgt0, a, snap, chk)
    out["snapshot"] = snap
    if a.snapshot_out:
        with open(a.snapshot_out, "w") as fh:
            json.dump(snap, fh, indent=2, default=str)
    return snap


# ===========================================================================
# Body / main
# ===========================================================================
def _trial_body(bi, tgt, tgt0, tgts, a, out, chk, write):
    assert_dp8_speed(bi, tgt, tgt0, a, out, chk, pre=True)   # R1 pre-check: tolerates an ABSENT port on a cold load
    config_ports(bi, tgt, a, out, chk, write)
    assert_dp8_speed(bi, tgt, tgt0, a, out, chk)     # re-assert AFTER the port write
    config_queues(bi, tgt0, tgts, a, out, chk, write)
    disarm_port_shaper(bi, tgts, a, out, chk, write) # R6
    config_params(bi, tgt, a, out, chk, write)
    config_session(bi, tgt, a, out, chk, write)
    config_mirror(bi, tgt, a, out, chk, write)
    config_value_set(bi, a, out, chk, write)
    config_pktgen(bi, tgt, a, out, chk, write, app_enable=False)
    if write:
        reg_write(bi, tgt, REG_TAG, TAG_INACTIVE, chk=chk)
        for r in REGS_ZERO:
            reg_write(bi, tgt, r, 0)
        chk.expect("reg_tag initialised to TAG_INACTIVE",
                   reg_read(bi, tgt, REG_TAG), TAG_INACTIVE)


def offline_checks(a, out, chk):
    """Everything that can be established without touching the switch."""
    try:
        qd = quantize_d(a.d_ms)
        out["D"] = qd
        chk.expect("D quantized word low byte is zero", qd["word"] & 0xFF, 0)
        chk.ok("D within the %.0f ms clamp" % D_MAX_MS,
               "%.6f ms -> %.6f ms realized" % (qd["requested_ms"], qd["realized_ms"]))
    except ValueError as e:
        chk.fail("D clamp / quantization", str(e))
    hz = failopen_horizon(a.budget)
    out["failopen"] = hz
    chk.ok("fail-open model H = B x K / rate_dp8",
           "B=%d K=%d -> tau=%.3f us, H=%.3f ms" % (hz["budget"], hz["k"],
                                                    hz["tau_us"], hz["horizon_ms"]))
    tmpl = build_token_template(a.token_len)
    out["token_template"] = {"len": len(tmpl), "first_bytes": tmpl[:23].hex()}
    chk.expect("blocker template length", len(tmpl), a.token_len)
    chk.expect("blocker template etype 0x88C1", tmpl[12:14].hex(), "88c1")
    chk.expect("K", a.k, 64)
    try:
        ip2int(a.relay_ip), ip2int(a.master_ip)
        chk.ok("session addresses parse", "%s <-> %s" % (a.relay_ip, a.master_ip))
    except ValueError as e:
        chk.fail("session addresses parse", str(e))


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--prog", default=PROG_DEFAULT)
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--client-id", type=int, default=63)
    ap.add_argument("--config", action="store_true", help="write the configuration")
    ap.add_argument("--verify-only", action="store_true", help="read back only")
    ap.add_argument("--arm-blockers", action="store_true",
                    help="LIVE PATH ONLY: enable pktgen app 1 (the K=64 reservoir) and "
                         "leave it enabled, so a real READ's clone fires the burst. "
                         "Implies --no-cleanup, because cleanup_trial disables it again "
                         "-- which is exactly why the first physical Stage 3 ran with an "
                         "EMPTY Q_BLOCK: --config alone configures the app but the "
                         "mandatory cleanup disarms it on the way out.")
    ap.add_argument("--dry-run", action="store_true",
                    help="offline checks only; no gRPC import, no switch contact")
    ap.add_argument("--restore-only", action="store_true",
                    help="run cleanup/restore and exit")
    ap.add_argument("--d-ms", type=float, default=D_DEFAULT_MS,
                    help="the predetermined ACK delay D, in ms (clamped at %.0f)" % D_MAX_MS)
    ap.add_argument("--budget", type=int, default=BUDGET_DEFAULT,
                    help="fail-open pass budget B; H = B x K / rate_dp8")
    ap.add_argument("--read-len", type=int, default=READ_LEN_DEFAULT,
                    help="master READ TCP payload length, for EXP_ACK")
    ap.add_argument("--relay-ip", default=RELAY_IP_DEFAULT)
    ap.add_argument("--master-ip", default=MASTER_IP_DEFAULT)
    ap.add_argument("--k", type=int, default=K_TOKENS)
    ap.add_argument("--app-id", type=int, default=APP_ID_DEFAULT)
    ap.add_argument("--pipe", type=int, default=0)
    ap.add_argument("--buf-offset", type=int, default=0)
    ap.add_argument("--token-len", type=int, default=TOKEN_LEN)
    ap.add_argument("--clone-sid", type=int, default=CLONE_SID)
    ap.add_argument("--mirror-max-len", type=int, default=128)
    ap.add_argument("--port-l", type=int, default=PORT_L)
    ap.add_argument("--port-vision", type=int, default=PORT_VISION)
    ap.add_argument("--port-relay", type=int, default=PORT_RELAY)
    ap.add_argument("--port-pgen", type=int, default=PORT_PGEN)
    ap.add_argument("--pg-l", type=int, default=2, help="EXPECTED dp8 pg_id (asserted)")
    ap.add_argument("--pg-l-nr", type=int, default=0, help="EXPECTED dp8 pg_port_nr")
    ap.add_argument("--drain-s", type=float, default=0.5)
    ap.add_argument("--no-cleanup", action="store_true",
                    help="debug only; the NEXT trial will refuse to start")
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--first-after-load", action="store_true",
                    help="mark this as the first trial after a program load (always dirty)")
    ap.add_argument("--snapshot-out", default=None)
    ap.add_argument("--out", default=None)
    return ap.parse_args(argv)


def main(argv=None):
    a = parse_args(argv)
    chk = Checks()
    out = {"prog": a.prog, "authored_off_switch": True, "silicon_validated": False}
    offline_checks(a, out, chk)

    rc = 0
    if a.dry_run:
        print(chk.render())
        out["n_fail"] = chk.n_fail
        print("D3SETUP " + json.dumps(out, default=str))
        return 1 if chk.n_fail else 0

    if not (a.config or a.verify_only or a.restore_only):
        print("nothing to do: pass --config, --verify-only, --restore-only or --dry-run",
              file=sys.stderr)
        return 2

    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(a.grpc, client_id=a.client_id, device_id=0,
                               notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)     # P4 objects, $PORT, $mirror, pktgen
    tgt0 = gc.Target(device_id=0, pipe_id=0)         # tf1.tm.*
    # dev_port-keyed fixed-function tables: pipe 0 first, device scope as fallback.
    # Which one this SDE accepts is not decidable off-switch, so both are tried and
    # the winner is recorded.
    tgts = [("pipe0", tgt0), ("device", tgt)]

    write = bool(a.config) and not a.verify_only
    out["write"] = write

    try:
        snapshot(bi, tgt, tgt0, tgts, a, out, chk)
        if a.restore_only:
            out["mode"] = "restore-only"
        else:
            assert_clean_start(bi, tgt, tgt0, a, out, chk)
            _trial_body(bi, tgt, tgt0, tgts, a, out, chk, write)
            if a.arm_blockers and write:
                # ►► THE MISSING LIVE ARMING STEP. _trial_body calls config_pktgen with
                # app_enable=False (the Gate-1 contract: configure, arm nothing), and the
                # SYNTHETIC driver enables app 1 itself before arming its event apps --
                # that ordering is the F01-a fix. The LIVE path had no equivalent, so the
                # reservoir never fired for a real READ and the ACK dequeued from an
                # empty Q_BLOCK in 1 068 ns instead of being held for D.
                #
                # Unlike the synthetic per-transaction arm, this one is left ON: in the
                # live path the trigger is the real master's READ, which can arrive at
                # any time, so "armed" is a standing condition rather than a
                # per-transaction action.
                ok = set_app_enable(bi, tgt, a, True, chk)
                out["blockers_armed"] = ok
                got = read_app(bi, tgt, a) if "read_app" in globals() else None
                if ok:
                    chk.ok("LIVE: pktgen app %d (K=%d reservoir) ENABLED and left on"
                           % (a.app_id, a.k),
                           "a real READ's 0xE1 clone will now fire the burst")
                else:
                    chk.fail("LIVE: enable pktgen app %d" % a.app_id,
                             "the reservoir will not fire and the ACK will dequeue from "
                             "an empty Q_BLOCK")
    except SpeedError as e:
        out["verdict"] = "ABORTED_SPEED"
        out["aborted"] = str(e)
        rc = 4
    except DirtyStateError as e:
        out["verdict"] = "INVALID"
        out["refused_dirty_start"] = str(e)
        chk.fail("trial REFUSED to start", str(e)[:160])
        rc = 3
    finally:
        # MANDATORY. Not conditional on success, not conditional on the verdict.
        if a.no_cleanup or a.arm_blockers:
            chk.warn("cleanup SKIPPED",
                     "--no-cleanup" if a.no_cleanup else
                     "--arm-blockers implies it: cleanup_trial disables app 1, which "
                     "would undo the arm this run exists to perform")
        else:
            try:
                cleanup_trial(bi, tgt, tgt0, tgts, a, out, chk)
            except Exception as e:                      # noqa: BLE001
                chk.fail("cleanup raised", str(e)[:120])

    print(chk.render())
    out["n_fail"] = chk.n_fail
    out["checks"] = [{"result": r, "check": n, "detail": d} for r, n, d in chk.rows]
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(out, fh, indent=2, default=str)
    print("D3SETUP " + json.dumps(out, default=str))
    if rc:
        return rc
    return 1 if chk.n_fail else 0


if __name__ == "__main__":
    sys.exit(main())

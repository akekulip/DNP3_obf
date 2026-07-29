#!/usr/bin/env python3
# =============================================================================
#  AUTHORED OFF-SWITCH — NEVER RUN AGAINST bf_switchd WITHOUT PHILIP'S GO-AHEAD.
#  This file has not been executed against the switch. four_queue_oracle.p4 has
#  NOT been loaded. bf_switchd is running the proven dnp3_timing_normalizer_pktgen
#  (conf /home/decps/defense2_pktgen_compile/pktgen_abs.conf) and was not touched
#  while this was written.
#
#  Configures:  p4/four_queue_oracle.p4
#  Report:      reports/FOUR_QUEUE_ORACLE_REPORT.md
#  Patterns reused from setup/case_a_read_anchored_dual_release_setup.py:
#    - resolve_pg(): READ the (pg_id, pg_port_nr) of a dev_port, never guess it
#    - write_queue_priority(): read-modify-write so rate flags / dwrr_weight
#      survive, with a minimal-write fallback
#    - the seven-field queue readback and the PASS/FAIL Checks table
#    - one machine-readable JSON line on stdout
#  Deliberately NOT reused: the pktgen / mirror / value_set / tbl_guard sections.
#  The oracle has no pktgen, no mirror, no deadline and no recirculation.
#
#  SCHEMA PROVENANCE. Every table and field name below was read out of this
#  SDE's own schema, not from memory:
#      $SDE/install/share/bf_rt_shared/bf_rt_tm_tf1.json
#    tf1.tm.port.cfg        KEY dev_port          DATA pg_id, pg_port_nr,
#                                                      port_queues_count
#    tf1.tm.queue.map       KEY pg_id, pg_queue   DATA dev_port, queue_nr,
#                                                      ingress_qid_count,
#                                                      ingress_qid_max
#    tf1.tm.queue.sched_cfg KEY pg_id, pg_queue   DATA min_rate_enable,
#                                                      min_priority, max_rate_enable,
#                                                      max_priority, dwrr_weight,
#                                                      scheduling_enable
#    tf1.tm.counter.queue   KEY pg_id, pg_queue   DATA drop_count_packets,
#                                                      usage_cells, watermark_cells
#    tf1.tm.queue.buffer    KEY pg_id, pg_queue   DATA guaranteed_cells,
#                                                      hysteresis_cells, tail_drop_enable
#    tf1.tm.queue.sched_shaping                         (per-QUEUE shaper: cleared,
#                           KEY pg_id, pg_queue        never used as the gate)
#                                                 DATA unit, provisioning,
#                                                      min_rate, min_burst_size,
#                                                      max_rate, max_burst_size
#    tf1.tm.port.sched_shaping                          *** THE GATE ***
#                           KEY dev_port          DATA unit ['PPS','BPS'],
#                                                      provisioning ['UPPER',
#                                                        'LOWER','MIN_ERROR'],
#                                                      max_rate, max_burst_size
#    tf1.tm.port.sched_cfg  KEY dev_port          DATA max_rate_enable (ARMS the
#                                                        port gate),
#                                                      scheduling_speed
#    $PORT                  KEY $DEV_PORT         DATA $SPEED, $FEC,
#                                                      $AUTO_NEGOTIATION,
#                                                      $LOOPBACK_MODE, $PORT_ENABLE
#  min_priority / max_priority are STRING enums with choices
#      ['LOW','0','1','2','3','4','5','6','7','HIGH'].
#  NOTE tf1.tm.port.sched_shaping has NO min_rate/min_burst_size — unlike the
#  per-queue shaper it is max-only. Verified in the same schema file.
#
#  THE RELEASE-SKEW CONFOUND — why the primary mechanism changed (2026-07-28).
#  There is NO port-level SCHEDULING ENABLE on Tofino-1 in this SDE:
#  tf1.tm.port.sched_cfg carries only {max_rate_enable, scheduling_speed}. So if
#  scheduling_enable is used as the release actuator, releasing four queues is
#  inescapably FOUR separate writes. Draining 64 x 64-byte frames at 25G takes
#  roughly 1.7 us, which is the same order as the driver's per-entry write
#  latency. Enabling four queues sequentially therefore lets ENABLE ORDER — not
#  priority — decide the drain order, and the oracle would prove nothing.
#  'lo-first' is separately unusable as a primary: it can let a finite
#  low-priority backlog drain to completion before the other queues are enabled
#  at all, producing an uninterpretable failure rather than a conservative one.
#
#  ==> PRIMARY MECHANISM IS NOW A SINGLE GLOBAL RELEASE EVENT (--gate-close /
#      --gate-open). All four queues stay scheduling_enable=True for the whole
#      trial. The hold is a PORT-LEVEL max-rate shaper on the port that OWNS the
#      four queues; the release is ONE write that reopens that port. Because the
#      gate is above the queue scheduler, all four queues become servable at the
#      same instant and the observed order is arbitration, not write order.
#
#  *** WHICH PORT CARRIES THE GATE — A CORRECTION TO THE TASK BRIEF ***
#  The brief says "dp11 PORT-level max-rate shaper". The four queues under test
#  are NOT on dp11. Per p4/four_queue_oracle.p4, a freshly injected frame is
#  enqueued to PORT_L = dp8 (qids 7/6/5/4); dp11 carries only QID_FWD = qid 0,
#  the single return FIFO that released frames come back on. Gating dp11 would
#  hold traffic that the dp8 scheduler has ALREADY ordered, so it cannot gate the
#  measurement. The gate must sit on the port whose scheduler is under test:
#      GATE PORT = dp8 = PORT_L.
#  --gate-port makes this explicit and overridable; the default is PORT_L and the
#  script REFUSES to gate dp11 unless --i-know-the-gate-port-is-wrong is passed,
#  because a dp11 gate would silently produce a meaningless pass.
#
#  RELEASE = ONE WRITE. Two ways to reopen the port, both single-field:
#      disarm (default) tf1.tm.port.sched_cfg max_rate_enable = False. Takes the
#               token bucket OUT of the path entirely, so the release boundary
#               does not depend on accumulated burst credit or on the bucket's
#               deficit state.
#      rate     tf1.tm.port.sched_shaping max_rate = line rate. Leaves the bucket
#               armed and merely re-parameterizes it, so the first packet still
#               waits for credit. Kept as the alternative so the microbenchmark
#               can MEASURE both boundaries instead of the choice being asserted.
#
#  BURST CREDIT IS THE MAIN THREAT to a clean boundary: a max-rate token bucket
#  refills while idle, so at injection time up to max_burst_size of credit is
#  already banked and that many frames escape immediately. max_burst_size must be
#  at its minimum, and "zero frames escaped before release" is a GATE, not a
#  nice-to-have. run/shaper_preload_microbench.sh establishes the lowest usable
#  (max_rate, max_burst_size) empirically before any trial is run.
#
#  THE THREE ENABLE ORDERS REMAIN (--release-order batch|lo-first|hi-first) but
#  ONLY as supplemental stress evidence. They are explicitly NOT the acceptance
#  gate. See --release, which now prints that demotion on every invocation.
# =============================================================================
"""four_queue_oracle_setup.py — control plane for the behavioural four-queue
dequeue oracle.

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052):

    SP=/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages
    PYTHONPATH=$SP:$SP/tofino python3.8 four_queue_oracle_setup.py --config

Modes (exactly one of):
  --config        configure dp11, the dp8 MAC-near loopback and the four queues
                  (max_priority 7/6/5/4), then read back all seven fields.
  --verify-only   read back everything, print PASS/FAIL, write NOTHING.
  --preload       scheduling_enable = False on all four dp8 queues (HOLD).
  --release       scheduling_enable = True  on all four dp8 queues (RELEASE).
  --occupancy     print usage_cells / watermark_cells / drop_count_packets per queue.
  --reset-counters  zero those three counters on all four queues.
  --dry-run       no gRPC at all: print the intended plan and exit.

Exit status is non-zero if any check FAILs. Prints a PASS/FAIL table and one
JSON line `FQORACLE {...}`. Python 3.8; no numpy (not installed on the switch).
"""
import argparse
import json
import sys
import time

# ---------------------------------------------------------------------------
# Constants. Every one of these is mirrored in p4/four_queue_oracle.p4 and the
# cited line is where it is defined there.
# ---------------------------------------------------------------------------
PROG_DEFAULT = "four_queue_oracle"

PORT_L = 8         # .p4 const PortId_t PORT_L    = 9w8   (MAC-near loopback)
PORT_HULK = 11     # .p4 const PortId_t PORT_HULK = 9w11  (inject + capture)

QID_ABLOCK = 7     # .p4 const bit<5> QID_ABLOCK = 5w7
QID_ACK = 6        # .p4 const bit<5> QID_ACK    = 5w6
QID_RBLOCK = 5     # .p4 const bit<5> QID_RBLOCK = 5w5
QID_RESP = 4       # .p4 const bit<5> QID_RESP   = 5w4
QID_FWD = 0        # .p4 const bit<5> QID_FWD    = 5w0   (return FIFO on dp11)

# (label, qid, wanted max_priority) in STRICT DESCENDING priority order.
QUEUE_PLAN = [
    ("Q_ABLOCK", QID_ABLOCK, "7"),
    ("Q_ACK", QID_ACK, "6"),
    ("Q_RBLOCK", QID_RBLOCK, "5"),
    ("Q_RESP", QID_RESP, "4"),
]

# Release orders. See the release-skew confound note in the file header.
RELEASE_ORDERS = {
    "batch": [q[0] for q in QUEUE_PLAN],          # one RPC, order is nominal
    "hi-first": [q[0] for q in QUEUE_PLAN],       # ABLOCK, ACK, RBLOCK, RESP
    "lo-first": [q[0] for q in reversed(QUEUE_PLAN)],  # RESP, RBLOCK, ACK, ABLOCK
}

TM_SCHED_CFG = "tf1.tm.queue.sched_cfg"    # bf_rt_tm_tf1.json
TM_QUEUE_MAP = "tf1.tm.queue.map"          # bf_rt_tm_tf1.json
TM_PORT_CFG = "tf1.tm.port.cfg"            # bf_rt_tm_tf1.json
TM_COUNTER_QUEUE = "tf1.tm.counter.queue"  # bf_rt_tm_tf1.json
TM_QUEUE_BUFFER = "tf1.tm.queue.buffer"    # bf_rt_tm_tf1.json
TM_QUEUE_SHAPING = "tf1.tm.queue.sched_shaping"  # bf_rt_tm_tf1.json
# --- the global release gate. KEY dev_port on BOTH tables. -------------------
TM_PORT_SHAPING = "tf1.tm.port.sched_shaping"    # unit, provisioning,
#                                                  max_rate, max_burst_size
TM_PORT_SCHED_CFG = "tf1.tm.port.sched_cfg"      # max_rate_enable,
#                                                  scheduling_speed

# tf1.tm.counter.queue data fields (all uint64, all rw in the schema).
CTR_FIELDS = ("usage_cells", "watermark_cells", "drop_count_packets")


def pnorm(v):
    """Normalize a sched_cfg priority ('LOW'|'0'..'7'|'HIGH') to an int.

    Carried verbatim from case_a_dual_release_contract.py:245.
    """
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


class Checks(object):
    """PASS / WARN / FAIL accumulator. Nothing proceeds silently past a mismatch.

    Carried verbatim from case_a_dual_release_contract.py:274.
    """

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
# gRPC read helpers
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


def resolve_pg(bi, tgt0, dev_port, chk, out):
    """READ the (pg_id, pg_port_nr) of a dev_port instead of guessing it.

    tf1.tm.port.cfg KEY dev_port DATA pg_id, pg_port_nr, port_queues_count.
    """
    try:
        pcfg = bi.table_get(TM_PORT_CFG)
    except Exception as e:
        chk.fail("%s dp%d" % (TM_PORT_CFG, dev_port), str(e)[:90])
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
    """pg_queue = pg_port_nr * 8 + qid (TF1: 8 queues per port in a port group)."""
    return pg_nr * 8 + qid


# ===========================================================================
# 1. Ports: dp11 (host) and the dp8 MAC-near loopback
# ===========================================================================
def config_ports(bi, tgt, a, out, chk):
    """dp11 is the ONLY host port this oracle touches. dp9 (Vision) and dp64
    (the SEL-751 relay leg) are deliberately absent — see the .p4 header."""
    import bfrt_grpc.client as gc
    port_tbl = bi.table_get("$PORT")

    key = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", a.port_hulk)])]
    data = [port_tbl.make_data([
        gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
        gc.DataTuple("$FEC", str_val="BF_FEC_TYP_RS"),
        gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
        gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_NONE"),
        gc.DataTuple("$PORT_ENABLE", bool_val=True)])]
    try:
        try:
            port_tbl.entry_add(tgt, key, data)
        except Exception:
            port_tbl.entry_mod(tgt, key, data)      # idempotent re-run
        chk.ok("port dp%d up (Hulk)" % a.port_hulk, "BF_SPEED_25G RS PM_AN_DEFAULT")
    except Exception as e:
        chk.fail("port dp%d up (Hulk)" % a.port_hulk, str(e)[:90])

    # dp8 MAC-near loopback: delete + re-add — a live entry rejects a mode change.
    try:
        lk = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", a.port_l)])]
        try:
            port_tbl.entry_del(tgt, lk)
        except Exception:
            pass
        port_tbl.entry_add(tgt, lk, [port_tbl.make_data([
            gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
            gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
        chk.ok("dp%d MAC-near loopback" % a.port_l, "BF_LPBK_MAC_NEAR")
    except Exception as e:
        chk.fail("dp%d MAC-near loopback" % a.port_l, str(e)[:90])
    out["ports_configured"] = [a.port_hulk, a.port_l]


# ===========================================================================
# 2. The four dp8 queues + the seven-field readback
# ===========================================================================
def write_queue_priority(q_cfg, tgt0, pg_id, pg_queue, want_pri, set_min, chk, label):
    """Set max_priority (+ scheduling_enable True) on one queue.

    max_priority arbitrates among BACKLOGGED queues in the remaining-bandwidth
    pass; min_priority orders only the guaranteed pass and is INERT unless
    min_rate_enable is true. Writing max_priority is what the IBSPG root-cause
    repair established as load-bearing — leaving it unset degrades SILENTLY to a
    fair DWRR split, which is precisely the failure this oracle exists to catch.

    Read-modify-write first, so the rate flags and dwrr_weight already on the
    queue survive; minimal write as a fallback.

    TODO(silicon): whether this SDE's entry_mod accepts the full field set is
    unconfirmed off-switch. The returned path name records which one ran.
    """
    import bfrt_grpc.client as gc
    key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pg_queue)])
    cur, _e = get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pg_queue)],
                        from_hw=False)
    tuples = []
    if cur is not None:
        try:
            tuples = [
                gc.DataTuple("min_rate_enable", bool_val=bool(cur.get("min_rate_enable"))),
                gc.DataTuple("max_rate_enable", bool_val=bool(cur.get("max_rate_enable"))),
                gc.DataTuple("dwrr_weight", int(cur.get("dwrr_weight") or 0)),
                gc.DataTuple("min_priority",
                             str_val=(want_pri if set_min else str(cur.get("min_priority")))),
                gc.DataTuple("max_priority", str_val=want_pri),
                gc.DataTuple("scheduling_enable", bool_val=True)]
        except Exception:
            tuples = []
    try:
        if not tuples:
            raise RuntimeError("no readback to modify")
        q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data(tuples)])
        return "rmw"
    except Exception:
        flds = [gc.DataTuple("scheduling_enable", bool_val=True),
                gc.DataTuple("max_priority", str_val=want_pri)]
        if set_min:
            flds.append(gc.DataTuple("min_priority", str_val=want_pri))
        try:
            q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data(flds)])
            return "minimal"
        except Exception as e:
            chk.fail("%s max_priority write" % label, str(e)[:90])
            return None


def print_queue_table(queues):
    """Per queue: queue ID, max_priority, min_priority, scheduling enable state,
    port, pipe, queue mapping — all seven, from the readback. Nothing here is
    echoed from what was written."""
    print("dp8 queue readback (seven fields, from %s + %s)" % (TM_SCHED_CFG, TM_QUEUE_MAP))
    hdr = ("queue", "qid", "max_pri", "min_pri", "sched_en", "port", "pipe", "queue mapping")
    print("  %-9s %4s %8s %8s %9s %5s %5s  %s" % hdr)
    for label, _qid, _w in QUEUE_PLAN:
        r = queues.get(label)
        if r is None:
            print("  %-9s %s" % (label, "<no readback>"))
            continue
        m = r["queue_mapping"]
        print("  %-9s %4s %8s %8s %9s %5s %5s  pg_id=%s pg_port_nr=%s pg_queue=%s "
              "queue_nr=%s ingress_qid_count=%s"
              % (label, r["queue_id"], r["max_priority"], r["min_priority"],
                 r["scheduling_enable"], r["port"], r["pipe"], m["pg_id"],
                 m["pg_port_nr"], m["pg_queue"], m["queue_nr"], m["ingress_qid_count"]))
    print("")


def config_queues(bi, tgt0, a, out, chk, write=True):
    """Configure and read back all four dp8 queues."""
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    if pg_id is None:
        pg_id, pg_nr = a.pg_l, a.pg_l_nr
        chk.warn("dp%d pg map fallback" % a.port_l,
                 "using --pg-l=%d --pg-l-nr=%d (readback failed)" % (pg_id, pg_nr))
    try:
        q_cfg = bi.table_get(TM_SCHED_CFG)
    except Exception as e:
        chk.fail(TM_SCHED_CFG, str(e)[:90])
        return
    try:
        q_map = bi.table_get(TM_QUEUE_MAP)
    except Exception:
        q_map = None
        chk.warn(TM_QUEUE_MAP, "unavailable; queue-mapping readback degraded")

    order = []
    for label, qid, want_pri in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        if write:
            path = write_queue_priority(q_cfg, tgt0, pg_id, pgq, want_pri,
                                        a.also_set_min_priority, chk, label)
            if path:
                out.setdefault("queue_write_path", {})[label] = path
        sc, err = get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("%s sched_cfg readback" % label, err)
            continue
        qm, qm_err = (({}, "unavailable") if q_map is None
                      else get_entry(q_map, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)]))
        qm = qm or {}
        dev_port = qm.get("dev_port")
        rec = {
            "queue_id": qid,                                    # field 1
            "max_priority": sc.get("max_priority"),             # field 2
            "min_priority": sc.get("min_priority"),             # field 3
            "scheduling_enable": sc.get("scheduling_enable"),    # field 4
            "port": dev_port,                                   # field 5
            # TF1 dev_port encoding: pipe = dev_port >> 7 (dp8/dp11 -> pipe 0).
            "pipe": None if dev_port is None else (int(dev_port) >> 7),   # field 6
            "queue_mapping": {"pg_id": pg_id, "pg_port_nr": pg_nr, "pg_queue": pgq,
                              "queue_nr": qm.get("queue_nr"),
                              "ingress_qid_count": qm.get("ingress_qid_count"),
                              "ingress_qid_max": qm.get("ingress_qid_max"),
                              "err": qm_err},                   # field 7
            # context: these decide whether min_priority matters at all
            "min_rate_enable": sc.get("min_rate_enable"),
            "max_rate_enable": sc.get("max_rate_enable"),
            "dwrr_weight": sc.get("dwrr_weight"),
        }
        out.setdefault("queues", {})[label] = rec
        order.append((label, pnorm(rec["max_priority"])))
        chk.expect("%s max_priority" % label, pnorm(rec["max_priority"]), int(want_pri),
                   "(qid %d, pg_queue %d)" % (qid, pgq))
        if dev_port is not None and int(dev_port) != a.port_l:
            chk.fail("%s maps to dp%d" % (label, a.port_l),
                     "queue.map reports dev_port=%s" % dev_port)

    print_queue_table(out.get("queues", {}))

    vals = [v for _l, v in order]
    strict = (len(vals) == 4 and all(v is not None for v in vals)
              and vals[0] > vals[1] > vals[2] > vals[3])
    out["max_priority_strictly_decreasing"] = strict
    if strict:
        chk.ok("max_priority strictly decreasing ABLOCK>ACK>RBLOCK>RESP",
               " > ".join("%s(%d)" % (l, v) for l, v in order))
    else:
        chk.fail("max_priority strictly decreasing ABLOCK>ACK>RBLOCK>RESP",
                 "readback = %s (must be strictly decreasing)" % order)
    # The point of the whole exercise: this readback is CONFIGURATION EVIDENCE
    # ONLY. It is explicitly NOT proof that the scheduler behaves this way.
    chk.warn("readback is not the proof",
             "max_priority readback shows what was WRITTEN. The behavioural "
             "verdict comes from the dequeue order at Hulk, via "
             "analysis/analyze_four_queue_oracle.py")

    # Informational: the single return FIFO on dp11 that every released packet
    # shares (.p4 to_hulk(): PORT_HULK / QID_FWD). Left at its default config.
    h_pg, h_nr = resolve_pg(bi, tgt0, a.port_hulk, chk, out)
    if h_pg is not None:
        sc, err = get_entry(q_cfg, tgt0,
                            [("pg_id", h_pg), ("pg_queue", pg_queue_of(h_nr, QID_FWD))])
        out["return_fifo"] = {"dev_port": a.port_hulk, "qid": QID_FWD, "pg_id": h_pg,
                              "pg_queue": pg_queue_of(h_nr, QID_FWD),
                              "sched_cfg": sc, "err": err}
        chk.ok("return FIFO dp%d qid%d (info only)" % (a.port_hulk, QID_FWD),
               sc if sc else err)


# ===========================================================================
# 3. Preload / release — scheduling_enable
# ===========================================================================
def set_scheduling(bi, tgt0, a, enable, out, chk, order_name="batch"):
    """Set scheduling_enable on all four dp8 queues.

    enable=False -> PRELOAD (packets accumulate in the queues, un-dequeued)
    enable=True  -> RELEASE (the TM starts serving them; THIS is the measurement)

    Read the release-skew note in the file header before changing the ordering
    semantics here. In 'batch' mode all four updates go in ONE gRPC Write RPC.
    """
    import bfrt_grpc.client as gc
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    if pg_id is None:
        chk.fail("scheduling_enable=%s" % enable, "could not resolve dp%d pg map" % a.port_l)
        return
    try:
        q_cfg = bi.table_get(TM_SCHED_CFG)
    except Exception as e:
        chk.fail(TM_SCHED_CFG, str(e)[:90])
        return

    labels = RELEASE_ORDERS.get(order_name, RELEASE_ORDERS["batch"])
    plan = {l: (q, p) for l, q, p in QUEUE_PLAN}
    keys, datas, applied = [], [], []
    for label in labels:
        qid, _want = plan[label]
        pgq = pg_queue_of(pg_nr, qid)
        keys.append(q_cfg.make_key([gc.KeyTuple("pg_id", pg_id),
                                    gc.KeyTuple("pg_queue", pgq)]))
        datas.append(q_cfg.make_data([
            gc.DataTuple("scheduling_enable", bool_val=bool(enable))]))
        applied.append({"queue": label, "qid": qid, "pg_queue": pgq})

    out["scheduling_write"] = {"enable": bool(enable), "order": order_name,
                               "sequence": [x["queue"] for x in applied]}
    try:
        if order_name == "batch":
            # ONE Write RPC carrying all four updates: the smallest skew this
            # SDE makes available. TODO(silicon): the residual skew is not
            # measurable off-switch; the lo-first / hi-first controls bound it.
            q_cfg.entry_mod(tgt0, keys, datas)
        else:
            for k, d in zip(keys, datas):
                q_cfg.entry_mod(tgt0, [k], [d])
        chk.ok("scheduling_enable=%s on 4 dp8 queues" % bool(enable),
               "order=%s (%s)" % (order_name, " -> ".join(x["queue"] for x in applied)))
    except Exception as e:
        chk.fail("scheduling_enable=%s on 4 dp8 queues" % bool(enable), str(e)[:90])
        return

    # Read back so the hold/release state is evidence, not an assumption.
    for label, qid, _w in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        sc, err = get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("%s scheduling_enable readback" % label, err)
        else:
            chk.expect("%s scheduling_enable" % label,
                       sc.get("scheduling_enable"), bool(enable))
            out.setdefault("scheduling_state", {})[label] = sc.get("scheduling_enable")


# ===========================================================================
# 4. Occupancy — the "demonstrably nonempty" requirement
# ===========================================================================
def read_occupancy(bi, tgt0, a, out, chk, require_nonempty=False):
    """Print usage_cells / watermark_cells / drop_count_packets per dp8 queue.

    tf1.tm.counter.queue KEY pg_id, pg_queue DATA drop_count_packets,
    usage_cells, watermark_cells (all uint64).

    require_nonempty=True enforces the challenge requirement that ALL FOUR
    queues read > 0 after preload. A trial where any queue reads 0 is INVALID —
    the packets never actually got parked — and must be recorded separately, NOT
    scored as an ordering failure.
    """
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    if pg_id is None:
        chk.fail("occupancy", "could not resolve dp%d pg map" % a.port_l)
        return
    try:
        ctr = bi.table_get(TM_COUNTER_QUEUE)
    except Exception as e:
        chk.fail(TM_COUNTER_QUEUE, str(e)[:90])
        return
    try:
        qbuf = bi.table_get(TM_QUEUE_BUFFER)
    except Exception:
        qbuf = None

    print("dp8 queue occupancy (%s)" % TM_COUNTER_QUEUE)
    print("  %-9s %4s %9s %12s %16s %14s" % ("queue", "qid", "usage", "watermark",
                                             "drop_count_pkts", "tail_drop_en"))
    occ = {}
    for label, qid, _w in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        got, err = get_entry(ctr, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("%s counter readback" % label, err)
            continue
        tde = None
        if qbuf is not None:
            b, berr = get_entry(qbuf, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
            if not berr:
                tde = (b or {}).get("tail_drop_enable")
        rec = {"qid": qid, "pg_queue": pgq,
               "usage_cells": got.get("usage_cells"),
               "watermark_cells": got.get("watermark_cells"),
               "drop_count_packets": got.get("drop_count_packets"),
               "tail_drop_enable": tde}
        occ[label] = rec
        print("  %-9s %4d %9s %12s %16s %14s"
              % (label, qid, rec["usage_cells"], rec["watermark_cells"],
                 rec["drop_count_packets"], tde))

        drops = rec["drop_count_packets"]
        if drops is not None and int(drops) != 0:
            chk.fail("%s drop_count_packets == 0" % label,
                     "TM DROPPED %s packet(s) on this queue — the trial is void" % drops)

        if require_nonempty:
            use = rec["usage_cells"]
            wm = rec["watermark_cells"]
            if use is None or wm is None:
                chk.fail("%s demonstrably nonempty" % label, "counter readback returned None")
            elif int(use) > 0 and int(wm) > 0:
                chk.ok("%s demonstrably nonempty" % label,
                       "usage_cells=%s watermark_cells=%s" % (use, wm))
            else:
                # INVALID, not FAIL-of-ordering. The runner records it separately.
                chk.fail("%s demonstrably nonempty" % label,
                         "usage_cells=%s watermark_cells=%s — nothing was parked on this "
                         "queue, so the trial is INVALID (not an ordering failure)"
                         % (use, wm))
    print("")
    out["occupancy"] = occ
    out["all_queues_nonempty"] = all(
        (r.get("usage_cells") or 0) > 0 and (r.get("watermark_cells") or 0) > 0
        for r in occ.values()) if len(occ) == 4 else False


def config_shaper(bi, tgt0, a, out, chk):
    """Stretch (or clear) the dp8 drain with a per-queue PPS max-rate shaper.

    tf1.tm.queue.sched_shaping KEY pg_id, pg_queue DATA unit ['PPS','BPS'],
    provisioning ['UPPER','LOWER','MIN_ERROR'], min_rate, min_burst_size,
    max_rate, max_burst_size.

    WHY THIS EXISTS. Draining 64 x 64-byte frames at 25G takes about 1.7 us. A
    host cannot land a packet inside a 1.7 us window, so the three "late
    injection" trial modes (late_ack_preempt, empty_ack_queue, empty_resp_queue)
    are physically impossible unshaped. At --drain-shaper-pps 1000 the same 64
    frames take about 64 ms, which is a comfortable target.

    *** THIS CHANGES WHAT IS BEING MEASURED — READ BEFORE USING ***
    A queue that is over its max rate becomes shaping-INELIGIBLE, and the TM
    then serves a lower-priority eligible queue. That is not a strict-priority
    violation; it is the shaper doing its job. So a shaped trial measures
    "priority among shaping-eligible queues", NOT the unqualified strict-priority
    claim. The IBSPG root-cause repair records exactly this trap ("leave the
    blocker queue's max shaper disabled so it never becomes shaping-ineligible").

    THEREFORE: the PRIMARY evidence for the strict-priority verdict must come
    from UNSHAPED preload/release trials. Shaped trials are supporting evidence
    about preemption dynamics only, and must be reported as a separate class.

    TODO(silicon): a PPS shaper clumps badly at low rates and only smooths above
    roughly 600 pps (measured previously on this switch). Do not go below 1000.
    """
    import bfrt_grpc.client as gc
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    if pg_id is None:
        chk.fail("shaper", "could not resolve dp%d pg map" % a.port_l)
        return
    try:
        shp = bi.table_get("tf1.tm.queue.sched_shaping")
    except Exception as e:
        chk.fail("tf1.tm.queue.sched_shaping", str(e)[:90])
        return

    enable = a.drain_shaper_pps is not None and a.drain_shaper_pps > 0
    if enable and a.drain_shaper_pps < 600:
        chk.warn("shaper rate >= 600 pps",
                 "%d pps requested; a PPS shaper clumps below ~600 pps and the drain "
                 "will be bursty rather than paced" % a.drain_shaper_pps)
    out["shaper"] = {"enabled": enable, "pps": a.drain_shaper_pps,
                     "note": "shaped trials measure priority among shaping-ELIGIBLE "
                             "queues, not unqualified strict priority"}
    for label, qid, _w in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        key = shp.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        try:
            if enable:
                shp.entry_mod(tgt0, [key], [shp.make_data([
                    gc.DataTuple("unit", str_val="PPS"),
                    gc.DataTuple("provisioning", str_val="UPPER"),
                    gc.DataTuple("max_rate", int(a.drain_shaper_pps)),
                    gc.DataTuple("max_burst_size", int(a.drain_shaper_burst))])])
                chk.ok("%s max-rate shaper" % label,
                       "%d PPS burst %d (drain stretched for late-injection modes)"
                       % (a.drain_shaper_pps, a.drain_shaper_burst))
            else:
                # Clear: a very large max_rate is the "effectively unshaped" state.
                shp.entry_mod(tgt0, [key], [shp.make_data([
                    gc.DataTuple("unit", str_val="PPS"),
                    gc.DataTuple("provisioning", str_val="UPPER"),
                    gc.DataTuple("max_rate", int(a.shaper_off_pps)),
                    gc.DataTuple("max_burst_size", int(a.drain_shaper_burst))])])
                chk.ok("%s shaper cleared" % label,
                       "max_rate=%d PPS (effectively unshaped)" % a.shaper_off_pps)
        except Exception as e:
            chk.fail("%s shaper write" % label, str(e)[:90])
        got, err = get_entry(shp, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if not err:
            out.setdefault("shaper_readback", {})[label] = got
    # max_rate_enable in sched_cfg is what actually arms the shaper.
    chk.warn("shaper arming",
             "TODO(silicon): tf1.tm.queue.sched_cfg max_rate_enable must be True for "
             "the shaping rate to take effect; verify it in the --config readback")


# ===========================================================================
# 4b. THE GLOBAL RELEASE GATE — a PORT-level max-rate shaper on the port that
#     owns the four queues (dp8 / PORT_L), plus its arming flag.
#
#     tf1.tm.port.sched_shaping KEY dev_port DATA unit ['PPS','BPS'],
#         provisioning ['UPPER','LOWER','MIN_ERROR'], max_rate, max_burst_size
#     tf1.tm.port.sched_cfg     KEY dev_port DATA max_rate_enable,
#         scheduling_speed ['BF_SPEED_NONE','BF_SPEED_1G',...,'BF_SPEED_100G']
#
#     CLOSE = 2 writes (shape, then arm). That is fine: only the RELEASE has to
#     be atomic. OPEN = exactly ONE write.
# ===========================================================================
def _port_tbl(bi, name, chk):
    try:
        return bi.table_get(name)
    except Exception as e:
        chk.fail(name, str(e)[:90])
        return None


def _port_entry(tbl, tgts, dev_port):
    """entry_get for a dev_port-keyed table, trying each target in turn.

    TM tables are pipe-scoped in this SDE but dev_port already implies the pipe,
    so which Target works is not something that can be settled off-switch.
    Trying pipe-0 then device-scope makes the script robust either way and the
    winning target is recorded in the JSON.
    """
    last = "no target tried"
    for tname, tgt in tgts:
        got, err = get_entry(tbl, tgt, [("dev_port", dev_port)])
        if not err:
            return got, None, tname
        last = err
    return None, last, None


def read_port_gate(bi, tgts, a, out, chk, label="gate"):
    """Read back both gate tables for the gate port. Never writes."""
    shp = _port_tbl(bi, TM_PORT_SHAPING, chk)
    cfg = _port_tbl(bi, TM_PORT_SCHED_CFG, chk)
    rec = {"dev_port": a.gate_port}
    if shp is not None:
        got, err, tname = _port_entry(shp, tgts, a.gate_port)
        rec["sched_shaping"] = got if not err else {"err": err}
        rec["shaping_target"] = tname
    if cfg is not None:
        got, err, tname = _port_entry(cfg, tgts, a.gate_port)
        rec["sched_cfg"] = got if not err else {"err": err}
        rec["cfg_target"] = tname
    out.setdefault("port_gate", {})[label] = rec

    sh = rec.get("sched_shaping") or {}
    sc = rec.get("sched_cfg") or {}
    armed = sc.get("max_rate_enable")
    print("port gate readback  dp%d  (%s + %s)"
          % (a.gate_port, TM_PORT_SHAPING, TM_PORT_SCHED_CFG))
    print("  max_rate_enable=%s  unit=%s  provisioning=%s  max_rate=%s  "
          "max_burst_size=%s  scheduling_speed=%s"
          % (armed, sh.get("unit"), sh.get("provisioning"), sh.get("max_rate"),
             sh.get("max_burst_size"), sc.get("scheduling_speed")))
    print("")
    rec["armed"] = armed
    return rec


def guard_gate_port(a, chk):
    """Refuse to gate a port that does not own the four queues.

    The four queues under test live on PORT_L (dp8). dp11 carries only the
    single return FIFO, downstream of the arbitration being measured, so a dp11
    gate would hold ALREADY-ORDERED traffic and yield a meaningless pass. This
    is a silent-success failure mode, so it is refused rather than warned about.
    """
    if a.gate_port == a.port_l:
        return True
    if a.i_know_the_gate_port_is_wrong:
        chk.warn("gate port override",
                 "gating dp%d, which is NOT the port that owns the four queues "
                 "(dp%d). Override accepted; results are NOT a strict-priority "
                 "verdict." % (a.gate_port, a.port_l))
        return True
    chk.fail("gate port owns the four queues",
             "--gate-port dp%d does not own the four queues (they are on dp%d = "
             "PORT_L per the .p4). A gate downstream of the scheduler under test "
             "holds already-ordered traffic and would pass meaninglessly. Pass "
             "--i-know-the-gate-port-is-wrong to override."
             % (a.gate_port, a.port_l))
    return False


def set_port_gate(bi, tgts, a, closed, out, chk):
    """CLOSE (hold everything) or OPEN (the single global release event).

    closed=True  -> write the shaping parameters, THEN arm with
                    max_rate_enable=True. Two writes; the hold does not need to
                    be atomic.
    closed=False -> exactly ONE write. Default --gate-open-mode disarm writes
                    tf1.tm.port.sched_cfg max_rate_enable=False, which removes
                    the token bucket from the path so the boundary does not
                    depend on banked burst credit. --gate-open-mode rate instead
                    writes tf1.tm.port.sched_shaping max_rate=<line rate>,
                    leaving the bucket armed.
    """
    import bfrt_grpc.client as gc
    if not guard_gate_port(a, chk):
        return

    shp = _port_tbl(bi, TM_PORT_SHAPING, chk)
    cfg = _port_tbl(bi, TM_PORT_SCHED_CFG, chk)
    if shp is None or cfg is None:
        return

    def _mod(tbl, tuples, what):
        """entry_mod against the first target that accepts it."""
        last = "no target tried"
        for tname, tgt in tgts:
            try:
                key = tbl.make_key([gc.KeyTuple("dev_port", a.gate_port)])
                tbl.entry_mod(tgt, [key], [tbl.make_data(tuples)])
                return tname, None
            except Exception as e:
                last = str(e)[:90]
        chk.fail(what, last)
        return None, last

    if closed:
        t0 = time.time()
        tn1, e1 = _mod(shp, [
            gc.DataTuple("unit", str_val=a.gate_unit),
            gc.DataTuple("provisioning", str_val=a.gate_provisioning),
            gc.DataTuple("max_rate", int(a.gate_rate)),
            gc.DataTuple("max_burst_size", int(a.gate_burst))],
            "gate close: shaping params")
        tn2, e2 = _mod(cfg, [gc.DataTuple("max_rate_enable", bool_val=True)],
                       "gate close: arm max_rate_enable")
        dt = time.time() - t0
        out["gate_close"] = {"dev_port": a.gate_port, "unit": a.gate_unit,
                             "provisioning": a.gate_provisioning,
                             "max_rate": a.gate_rate, "max_burst_size": a.gate_burst,
                             "seconds": round(dt, 6),
                             "shaping_target": tn1, "cfg_target": tn2,
                             "n_writes": 2}
        if not e1 and not e2:
            chk.ok("gate CLOSED on dp%d" % a.gate_port,
                   "%s max_rate=%d burst=%d, max_rate_enable=True (%.3f ms, 2 writes)"
                   % (a.gate_unit, a.gate_rate, a.gate_burst, dt * 1e3))
    else:
        # ---- THE SINGLE GLOBAL RELEASE EVENT: exactly one write. ----
        t0 = time.time()
        if a.gate_open_mode == "disarm":
            tn, err = _mod(cfg, [gc.DataTuple("max_rate_enable", bool_val=False)],
                           "gate open: disarm max_rate_enable")
            detail = "tf1.tm.port.sched_cfg max_rate_enable=False"
        else:
            tn, err = _mod(shp, [
                gc.DataTuple("unit", str_val=a.gate_unit),
                gc.DataTuple("provisioning", str_val=a.gate_provisioning),
                gc.DataTuple("max_rate", int(a.gate_line_rate)),
                gc.DataTuple("max_burst_size", int(a.gate_burst))],
                "gate open: raise max_rate")
            detail = "tf1.tm.port.sched_shaping max_rate=%d" % a.gate_line_rate
        dt = time.time() - t0
        out["gate_open"] = {"dev_port": a.gate_port, "mode": a.gate_open_mode,
                            "detail": detail, "seconds": round(dt, 6),
                            "target": tn, "n_writes": 1,
                            "release_write_unix": time.time()}
        if not err:
            chk.ok("gate OPENED on dp%d — ONE write" % a.gate_port,
                   "%s (%.3f ms)" % (detail, dt * 1e3))

    read_port_gate(bi, tgts, a, out, chk,
                   label="after_close" if closed else "after_open")

    # Assert the readback agrees with the intent, so the hold/release state is
    # evidence rather than an assumption.
    rb = out.get("port_gate", {}).get("after_close" if closed else "after_open", {})
    armed = (rb.get("sched_cfg") or {}).get("max_rate_enable")
    if closed:
        chk.expect("gate armed after close", armed, True)
        sh = rb.get("sched_shaping") or {}
        if sh.get("max_rate") is not None and int(sh["max_rate"]) != int(a.gate_rate):
            chk.fail("gate max_rate readback",
                     "wrote %d, read %s — the SDE quantized or rejected the rate; "
                     "the microbenchmark must re-measure at the ACTUAL rate"
                     % (a.gate_rate, sh.get("max_rate")))
        if sh.get("max_burst_size") is not None and int(sh["max_burst_size"]) != int(a.gate_burst):
            chk.fail("gate max_burst_size readback",
                     "wrote %d, read %s — banked burst credit is the main threat to "
                     "a clean boundary, so a silently clamped burst is a STOP"
                     % (a.gate_burst, sh.get("max_burst_size")))
    elif a.gate_open_mode == "disarm":
        chk.expect("gate disarmed after open", armed, False)


def clear_queue_shapers(bi, tgt0, a, out, chk):
    """Disarm every PER-QUEUE shaper on the four queues under test.

    A queue that is over its own max rate becomes shaping-INELIGIBLE and the TM
    then serves a lower-priority eligible queue. That is not a priority
    violation, but it is indistinguishable from one at the capture. The gate is
    a PORT-level shaper precisely so that no queue is ever individually
    ineligible; this makes that explicit instead of relying on defaults.
    """
    import bfrt_grpc.client as gc
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    if pg_id is None:
        chk.fail("clear queue shapers", "could not resolve dp%d pg map" % a.port_l)
        return
    try:
        q_cfg = bi.table_get(TM_SCHED_CFG)
    except Exception as e:
        chk.fail(TM_SCHED_CFG, str(e)[:90])
        return
    for label, qid, _w in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        try:
            q_cfg.entry_mod(tgt0, [key], [q_cfg.make_data([
                gc.DataTuple("max_rate_enable", bool_val=False),
                gc.DataTuple("min_rate_enable", bool_val=False)])])
        except Exception as e:
            chk.fail("%s clear per-queue shaper" % label, str(e)[:90])
            continue
        sc, err = get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pgq)])
        if err:
            chk.fail("%s shaper-off readback" % label, err)
        else:
            chk.expect("%s max_rate_enable is False (never shaping-ineligible)" % label,
                       sc.get("max_rate_enable"), False)
            # min_rate_enable False also keeps min_priority inert, which is the
            # documented state: max_priority is the field that arbitrates.
            out.setdefault("queue_shaper_off", {})[label] = {
                "max_rate_enable": sc.get("max_rate_enable"),
                "min_rate_enable": sc.get("min_rate_enable")}


def preload_gate_check(bi, tgt0, tgts, a, out, chk):
    """The PRELOAD GATE. All four conditions, evaluated together.

    Passes only if:
      1. all four queues are simultaneously backlogged (usage_cells > 0 AND
         watermark_cells > 0),
      2. zero queue drops,
      3. the port gate is armed (still closed),
      4. (checked by the runner/analyzer, not here) no target-role frame reached
         the host before the release write.
    Condition 4 needs the capture, which this script does not own; it is
    asserted here as a REQUIREMENT line so the JSON records that the verdict is
    incomplete without it.
    """
    read_occupancy(bi, tgt0, a, out, chk, require_nonempty=True)
    rb = read_port_gate(bi, tgts, a, out, chk, label="at_preload_check")
    chk.expect("gate still closed at preload check", rb.get("armed"), True)
    out["preload_gate"] = {
        "all_queues_nonempty": out.get("all_queues_nonempty"),
        "gate_armed": rb.get("armed"),
        "zero_drops": all(int((r or {}).get("drop_count_packets") or 0) == 0
                          for r in (out.get("occupancy") or {}).values()),
        "pre_release_escape_check": "NOT EVALUATED HERE — requires the host capture; "
                                    "analysis/analyze_four_queue_oracle.py decides it",
    }


def reset_counters(bi, tgt0, a, out, chk):
    """Zero usage/watermark/drop counters on the four dp8 queues.

    All three tf1.tm.counter.queue fields are read-write in the schema, so a
    write of 0 is the documented clear.

    TODO(silicon): whether this SDE accepts a write to usage_cells (a live
    occupancy gauge, as opposed to watermark_cells and drop_count_packets which
    are latched) is unconfirmed off-switch. Each field is therefore written
    INDEPENDENTLY, so one rejected field cannot prevent the others from being
    cleared, and each result is reported on its own line.
    """
    import bfrt_grpc.client as gc
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out)
    if pg_id is None:
        chk.fail("reset-counters", "could not resolve dp%d pg map" % a.port_l)
        return
    try:
        ctr = bi.table_get(TM_COUNTER_QUEUE)
    except Exception as e:
        chk.fail(TM_COUNTER_QUEUE, str(e)[:90])
        return
    for label, qid, _w in QUEUE_PLAN:
        pgq = pg_queue_of(pg_nr, qid)
        key = ctr.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        for fld in CTR_FIELDS:
            try:
                ctr.entry_mod(tgt0, [key], [ctr.make_data([gc.DataTuple(fld, 0)])])
                chk.ok("reset %s %s" % (label, fld), "0")
            except Exception as e:
                chk.warn("reset %s %s" % (label, fld),
                         "TODO(silicon): %s" % str(e)[:70])
    out["counters_reset"] = True


# ===========================================================================
# main
# ===========================================================================
def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Control plane for four_queue_oracle.p4 (behavioural "
                    "four-queue dequeue oracle).")
    ap.add_argument("--prog", default=PROG_DEFAULT)
    ap.add_argument("--config", action="store_true",
                    help="configure ports + the four queues, then read back")
    ap.add_argument("--verify-only", action="store_true",
                    help="read back everything and print PASS/FAIL; write NOTHING")
    # ---- THE PRIMARY MECHANISM: one global release event -------------------
    g = ap.add_argument_group(
        "global release gate (PRIMARY)",
        "A PORT-level max-rate shaper on the port that owns the four queues. "
        "All four queues stay scheduling-enabled throughout; the release is ONE "
        "write. This is the acceptance mechanism.")
    g.add_argument("--gate-close", action="store_true",
                   help="close the gate: write the port shaper and arm it (2 writes)")
    g.add_argument("--gate-open", action="store_true",
                   help="THE RELEASE. Exactly one write. See --gate-open-mode.")
    g.add_argument("--gate-status", action="store_true",
                   help="read back both gate tables; write nothing")
    g.add_argument("--preload-gate-check", action="store_true",
                   help="all four queues backlogged + zero drops + gate still armed")
    g.add_argument("--gate-port", type=int, default=None,
                   help="port carrying the gate. DEFAULT = --port-l (dp8), the port "
                        "that owns the four queues. dp11 is NOT valid: it is "
                        "downstream of the scheduler under test.")
    g.add_argument("--gate-unit", choices=("PPS", "BPS"), default="PPS",
                   help="tf1.tm.port.sched_shaping unit (schema choices PPS|BPS)")
    g.add_argument("--gate-provisioning", choices=("UPPER", "LOWER", "MIN_ERROR"),
                   default="UPPER", help="tf1.tm.port.sched_shaping provisioning")
    g.add_argument("--gate-rate", type=int, default=1,
                   help="max_rate while the gate is CLOSED. Lowest practical value; "
                        "the microbenchmark establishes it empirically (default 1)")
    g.add_argument("--gate-burst", type=int, default=0,
                   help="max_burst_size while closed. MINIMUM — banked burst credit "
                        "is the main threat to a clean boundary (default 0)")
    g.add_argument("--gate-open-mode", choices=("disarm", "rate"), default="disarm",
                   help="disarm (default) = ONE write of max_rate_enable=False, "
                        "removing the token bucket from the path. rate = ONE write "
                        "raising max_rate to --gate-line-rate, bucket stays armed.")
    g.add_argument("--gate-line-rate", type=int, default=40000000,
                   help="max_rate written by --gate-open-mode rate (default 4e7)")
    g.add_argument("--i-know-the-gate-port-is-wrong", action="store_true",
                   help="permit a --gate-port that does not own the four queues. "
                        "Produces a MEANINGLESS pass; refused without this flag.")

    # ---- SUPPLEMENTAL ONLY: the per-queue scheduling_enable actuator --------
    s = ap.add_argument_group(
        "per-queue scheduling_enable (SUPPLEMENTAL STRESS EVIDENCE ONLY)",
        "Four separate writes, so enable order can beat priority (~1.7 us drain "
        "vs driver write latency). RETAINED as stress evidence; explicitly NOT "
        "the acceptance gate. Use the global gate above for the verdict.")
    s.add_argument("--preload", action="store_true",
                   help="scheduling_enable = False on all four dp8 queues (HOLD)")
    s.add_argument("--release", action="store_true",
                   help="scheduling_enable = True on all four dp8 queues (RELEASE). "
                        "NOT the acceptance mechanism.")
    s.add_argument("--release-order", choices=sorted(RELEASE_ORDERS.keys()),
                   default="batch",
                   help="batch = one gRPC Write RPC (default); hi-first = confound "
                        "check. lo-first can let a finite low-priority backlog drain "
                        "before the others are enabled, which is uninterpretable "
                        "rather than conservative — see the file header.")
    ap.add_argument("--occupancy", action="store_true",
                    help="print usage_cells / watermark_cells / drop_count_packets")
    ap.add_argument("--require-nonempty", action="store_true",
                    help="with --occupancy: FAIL unless all four queues read > 0")
    ap.add_argument("--reset-counters", action="store_true",
                    help="zero the three queue counters on all four dp8 queues")
    ap.add_argument("--shaper", action="store_true",
                    help="write the dp8 queue max-rate shaper (see --drain-shaper-pps). "
                         "ONLY for the late-injection modes; shaped trials are a "
                         "SEPARATE evidence class from the primary unshaped ones.")
    ap.add_argument("--drain-shaper-pps", type=int, default=None,
                    help="stretch the drain to this many packets/s (>=1000 recommended). "
                         "Omit or 0 with --shaper to clear the shaper.")
    ap.add_argument("--drain-shaper-burst", type=int, default=1,
                    help="max_burst_size for the drain shaper (default 1)")
    ap.add_argument("--shaper-off-pps", type=int, default=1000000,
                    help="max_rate written when clearing the shaper (default 1e6 PPS)")
    ap.add_argument("--dry-run", action="store_true",
                    help="no gRPC: print the intended plan and exit")
    ap.add_argument("--port-l", type=int, default=PORT_L)
    ap.add_argument("--port-hulk", type=int, default=PORT_HULK)
    ap.add_argument("--pg-l", type=int, default=2,
                    help="FALLBACK dp8 pg_id, used only if tf1.tm.port.cfg cannot be read")
    ap.add_argument("--pg-l-nr", type=int, default=0,
                    help="FALLBACK dp8 pg_port_nr; pg_queue = nr*8 + qid")
    ap.add_argument("--also-set-min-priority", action="store_true",
                    help="mirror max_priority into the (inert) min_priority field too")
    ap.add_argument("--skip-ports", action="store_true",
                    help="with --config: do not touch $PORT (queues only)")
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--client-id", type=int, default=63)
    a = ap.parse_args(argv)
    if a.gate_port is None:
        # The gate belongs on the port that OWNS the four queues, i.e. PORT_L.
        a.gate_port = a.port_l
    return a


def print_plan(a):
    print("four-queue dequeue oracle — intended configuration")
    print("  program            : %s" % a.prog)
    print("  host port          : dp%d (Hulk; inject AND capture)" % a.port_hulk)
    print("  loopback port      : dp%d (BF_LPBK_MAC_NEAR)" % a.port_l)
    print("  NOT touched        : dp9 (Vision), dp64 (SEL-751 relay leg) — absent "
          "from the P4 entirely")
    print("  queues under test  :")
    for label, qid, want in QUEUE_PLAN:
        print("      %-9s qid %d  max_priority %s" % (label, qid, want))
    print("  PRIMARY release    : ONE global release event — PORT gate on dp%d"
          % a.gate_port)
    print("      hold           : %s  unit=%s provisioning=%s max_rate=%d "
          "max_burst_size=%d" % (TM_PORT_SHAPING, a.gate_unit, a.gate_provisioning,
                                 a.gate_rate, a.gate_burst))
    print("      arm            : %s max_rate_enable=True" % TM_PORT_SCHED_CFG)
    print("      RELEASE        : ONE write, mode=%s (%s)"
          % (a.gate_open_mode,
             "%s max_rate_enable=False" % TM_PORT_SCHED_CFG if a.gate_open_mode == "disarm"
             else "%s max_rate=%d" % (TM_PORT_SHAPING, a.gate_line_rate)))
    print("      queues          : all four stay scheduling_enable=True throughout")
    if a.gate_port != a.port_l:
        print("      *** WARNING: gate port dp%d does not own the four queues (dp%d)"
              % (a.gate_port, a.port_l))
    print("  SUPPLEMENTAL only  : %s scheduling_enable, 4 separate writes "
          "(order=%s)." % (TM_SCHED_CFG, a.release_order))
    print("                       There is NO port-level SCHEDULING enable on TF1 —")
    print("                       %s has only max_rate_enable and scheduling_speed."
          % TM_PORT_SCHED_CFG)
    print("  occupancy counters : %s -> %s" % (TM_COUNTER_QUEUE, ", ".join(CTR_FIELDS)))
    print("")


def main(argv=None):
    a = parse_args(argv)
    chk = Checks()
    out = {"prog": a.prog, "authored_off_switch": True, "silicon_validated": False}

    print_plan(a)
    if a.dry_run:
        print(chk.render())
        print("FQORACLE " + json.dumps(out, default=str))
        return 0

    modes = [a.config, a.verify_only, a.preload, a.release, a.occupancy,
             a.reset_counters, a.shaper, a.gate_close, a.gate_open, a.gate_status,
             a.preload_gate_check]
    if not any(modes):
        print("nothing to do: pass --gate-close, --gate-open, --gate-status, "
              "--preload-gate-check, --config, --verify-only, --preload, --release, "
              "--occupancy, --reset-counters, --shaper or --dry-run", file=sys.stderr)
        return 2

    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(a.grpc, client_id=a.client_id, device_id=0,
                               notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    # dev_port-keyed TM tables: pipe-0 first, device scope as fallback. Which one
    # this SDE accepts is not decidable off-switch, so both are tried and the
    # winner is recorded (see _port_entry / _mod).
    tgts = [("pipe0", tgt0), ("device", tgt)]

    if a.config or a.verify_only:
        write = bool(a.config) and not a.verify_only
        out["write"] = write
        if write and not a.skip_ports:
            config_ports(bi, tgt, a, out, chk)
        config_queues(bi, tgt0, a, out, chk, write=write)
        if write:
            # No per-queue shaper may be armed: the gate is PORT-level precisely
            # so that no individual queue is ever shaping-ineligible.
            clear_queue_shapers(bi, tgt0, a, out, chk)
        read_port_gate(bi, tgts, a, out, chk, label="at_config")
    if a.shaper:
        config_shaper(bi, tgt0, a, out, chk)
    if a.reset_counters:
        reset_counters(bi, tgt0, a, out, chk)

    # ---- gate ordering within one invocation: close -> check -> open --------
    if a.gate_close:
        set_port_gate(bi, tgts, a, True, out, chk)
    if a.preload:
        set_scheduling(bi, tgt0, a, False, out, chk, order_name="batch")
    if a.occupancy:
        read_occupancy(bi, tgt0, a, out, chk, require_nonempty=a.require_nonempty)
    if a.preload_gate_check:
        preload_gate_check(bi, tgt0, tgts, a, out, chk)
    if a.gate_status:
        read_port_gate(bi, tgts, a, out, chk, label="status")
    if a.release:
        chk.warn("scheduling_enable release is SUPPLEMENTAL",
                 "four separate writes; enable order can beat priority. This is "
                 "stress evidence, NOT the acceptance gate — that is --gate-open.")
        set_scheduling(bi, tgt0, a, True, out, chk, order_name=a.release_order)
    if a.gate_open:
        set_port_gate(bi, tgts, a, False, out, chk)

    print(chk.render())
    out["n_fail"] = chk.n_fail
    out["checks"] = [{"result": r, "check": n, "detail": d} for r, n, d in chk.rows]
    print("FQORACLE " + json.dumps(out, default=str))
    return 1 if chk.n_fail else 0


if __name__ == "__main__":
    sys.exit(main())

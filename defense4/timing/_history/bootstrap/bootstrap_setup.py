#!/usr/bin/env python3
# ============================================================================
# bootstrap_setup.py — Defense 4 §3: the EXACT one-time control-plane setup for
# bootstrap_probe_v5.p4 (single-pass shadow staging). Reproducible RECORD of the
# one-time configuration the R11 contract depends on: two pktgen timer apps,
# templates, packet count, period, parser value-set entries, the FIXED four-queue
# strict-priority ladder (7 > 6 > 5 > 4), and the enable sequence.
#
# ►► NOT EXECUTED IN §3. This program is a committed record. It programs
#    Traffic-Manager queue priorities and the packet generator (hardware/switch
#    state), which is GATED on Philip's explicit authorization. main() refuses to
#    run unless DEFENSE4_HW_AUTHORIZED=1 is set AND a bfrt gRPC client is provided.
#    In §3 it is imported/inspected only.
#
# STATIC LADDER IS CORRECT (v5, preserving v4's mechanism). Earlier probes worried
# that a strict 7>6>5>4 ladder starves the RESP reservoir (qid5) under a
# continuously non-empty ACK reservoir (qid7). The staged admission resolves that by
# ADMISSION ORDERING, NOT by changing the ladder: a READ resets population 0/0;
# RESPONSE seeds are accepted first (ACK seeds dropped) while Q_ACK_BLOCK is EMPTY,
# so Q_RESP_BLOCK dequeues freely and RESP tokens confirm to 0/K; only then do ACK
# seeds enter Q_ACK_BLOCK, reaching K/K. Shaping is DISABLED. This setup writes the
# fixed strict ladder and READS IT BACK to assert 7>6>5>4 + shaping off.
#
# One-time-only: EVERY call is issued ONCE. The periodic timer, once enabled,
# free-runs; the data plane does all admission/stamping/staging/readiness/
# confirmation/stale-termination. There is NO per-transaction control-plane action.
#
# UNVERIFIED (silicon, R2/R11): whether staged establishment reaches and holds K/K
# within the CLRT. PERIOD_NS below is a silicon-tuned parameter.
# ============================================================================
import os
import sys

# ---- parameters (must match bootstrap_probe_v5.p4) ----
K_TOKENS      = 64            # packets_per_batch = K; packet_id 0..63
PIPE_ID       = 0
PGEN_PORT     = 68           # dp68, pipe-local packet-generator port
LOOPBACK_PORT = 8            # dp8, where the four queues live
PERIOD_NS     = 1000         # periodic top-up period; SILICON-TUNED (R2/R11)

# reservoir apps: app_id -> (role byte in the template, leading value-set byte)
APP_ACK  = 0                 # -> TOK_ACK reservoir  (Q_ACK_BLOCK  = qid7)
APP_RESP = 1                 # -> TOK_RESP reservoir (Q_RESP_BLOCK = qid5)

# token identity constants (must match the P4)
ETH_TOKEN   = 0x88C1
MARKER      = 0xE1
SD_LOOP     = 0x5A
TOK_ACK     = 0xA1
TOK_RESP    = 0xA2

# four queues on the loopback: a FIXED strict-priority ladder 7 > 6 > 5 > 4,
# shaping DISABLED. v4's staged admission (RESP reservoir established while
# Q_ACK_BLOCK is empty, only then ACK seeding) makes the strict ladder correct
# WITHOUT co-equal priorities or shaping — starvation is resolved by admission
# ordering in the data plane, not by the TM. Whether the staged establishment
# reaches and holds K/K within the CLRT on silicon remains UNVERIFIED (R2/R11).
# (label, qid, want_priority-as-str) — max_priority is a str_val in tf1.tm.queue.sched_cfg
# ('LOW'|'0'..'7'|'HIGH'). Ordering is DERIVED from the readback and asserted 7>6>5>4.
QUEUE_PLAN = [
    ("Q_ACK_BLOCK",  7, "7"),   # ACK reservoir  (highest)
    ("Q_ACK_HOLD",   6, "6"),   # held ACK
    ("Q_RESP_BLOCK", 5, "5"),   # RESPONSE reservoir
    ("Q_RESP_HOLD",  4, "4"),   # held RESPONSE (lowest)
]


def _pnorm(v):
    """Normalize a tf1.tm.queue.sched_cfg priority ('LOW'|'0'..'7'|'HIGH') to an int
    (ported from case_a_dual_release_contract.pnorm, a20aec7)."""
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


def _get_entry(tbl, tgt, keyfields, from_hw=True):
    """entry_get one key -> (data dict, None) or (None, error). Consumes entry_get as an
    ITERABLE of (data, key) pairs and uses gc.KeyTuple keys (proven pattern, a20aec7)."""
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


def _resolve_pg(bfrt, dev_port):
    """READ (pg_id, pg_port_nr) of a dev_port from tf1.tm.port.cfg — never guessed
    (proven pattern, a20aec7). Returns (pg_id, pg_port_nr) or raises."""
    pcfg = bfrt.table_get("tf1.tm.port.cfg")
    got, err = _get_entry(pcfg, bfrt.target, [("dev_port", dev_port)])
    if err:
        raise RuntimeError("tf1.tm.port.cfg dp%d: %s" % (dev_port, err))
    return got.get("pg_id"), got.get("pg_port_nr")


def build_template(role_byte: int) -> bytes:
    """The seed packet placed in the pktgen packet buffer for one reservoir app.

    HW prepends the 6-byte pktgen_timer_header_t; this buffer is
    ethernet(etype=0x88C1) + token_h + padding to a 64-byte minimum. The data
    plane RE-STAMPS every token field on admission (admit_stamp), so generation
    and token_id here are placeholders; marker/sdomain/role are set correctly so
    the template is self-describing even before the data-plane stamp.
    """
    eth = (b"\x00\x00\x00\x00\x00\x00"      # dst  (rewritten irrelevant; token never egresses to a host)
           b"\x00\x00\x00\x00\x00\x00"      # src
           + ETH_TOKEN.to_bytes(2, "big"))  # etype 0x88C1
    token = (bytes([MARKER, SD_LOOP, role_byte])   # marker(1), sdomain(1), role(1)
             + (0).to_bytes(4, "big")              # generation(4) placeholder (DP stamps reg_gen)
             + (0).to_bytes(2, "big"))             # token_id(2) placeholder   (DP stamps packet_id)
    frame = eth + token
    if len(frame) < 64:
        frame = frame + b"\x00" * (64 - len(frame))
    return frame


def make_vs_key(pipe_id: int, app_id: int) -> int:
    """Tofino-1 pktgen_timer_header_t leading byte = 000 ++ pipe_id(2) ++ app_id(3)."""
    return (pipe_id << 3) | app_id


# ---------------------------------------------------------------------------
# The one-time sequence. Each helper issues its calls ONCE.
# ---------------------------------------------------------------------------
def configure_value_set(bfrt):
    """Parser value_set pgen_timer <- {leading byte of app 0, app 1}."""
    vs = bfrt.table_get("IgParser.pgen_timer")
    for app_id in (APP_ACK, APP_RESP):
        vs.entry_add(bfrt.target,
                     [vs.make_key([("f1", make_vs_key(PIPE_ID, app_id))])])


def configure_queue_scheduling(bfrt):
    """Configure the four loopback queues as a FIXED strict-priority ladder 7>6>5>4 with
    shaping DISABLED, via tf1.tm.queue.sched_cfg (the rate-enable flags live in sched_cfg,
    NOT a separate shaping table). Keyed on the RESOLVED (pg_id, pg_queue). Read-modify-
    write so any existing dwrr_weight survives; falls back to a minimal write. One-time.
    Proven pattern ported from case_a_read_anchored_dual_release setup (a20aec7)."""
    import bfrt_grpc.client as gc
    pg_id, pg_nr = _resolve_pg(bfrt, LOOPBACK_PORT)
    q_cfg = bfrt.table_get("tf1.tm.queue.sched_cfg")
    for _label, qid, want_pri in QUEUE_PLAN:
        pgq = pg_nr * 8 + qid                              # flattened pg_queue
        key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pgq)])
        cur, _e = _get_entry(q_cfg, bfrt.target,
                             [("pg_id", pg_id), ("pg_queue", pgq)], from_hw=False)
        data = [
            gc.DataTuple("min_rate_enable", bool_val=False),   # shaping DISABLED
            gc.DataTuple("max_rate_enable", bool_val=False),   # shaping DISABLED
            gc.DataTuple("max_priority", str_val=want_pri),     # strict priority
            gc.DataTuple("scheduling_enable", bool_val=True),
        ]
        if cur is not None and cur.get("dwrr_weight") is not None:
            data.append(gc.DataTuple("dwrr_weight", int(cur.get("dwrr_weight"))))
        try:
            q_cfg.entry_mod(bfrt.target, [key], [q_cfg.make_data(data)])
        except Exception:                                   # minimal fallback
            q_cfg.entry_mod(bfrt.target, [key], [q_cfg.make_data([
                gc.DataTuple("min_rate_enable", bool_val=False),
                gc.DataTuple("max_rate_enable", bool_val=False),
                gc.DataTuple("max_priority", str_val=want_pri),
                gc.DataTuple("scheduling_enable", bool_val=True)])])


def verify_queue_scheduling(bfrt):
    """READ BACK the four loopback queues from hardware and ASSERT, from the returned
    values only (nothing echoed from what was written): (1) the observed max_priority
    ordering is EXACTLY strictly decreasing 7>6>5>4; (2) each queue's max_priority matches
    its intended level; (3) shaping is DISABLED (min_rate_enable == max_rate_enable ==
    False) on all four; (4) scheduling is enabled. Raises AssertionError on any mismatch.
    Runs only under hardware authorization (called from apply_one_time_setup)."""
    pg_id, pg_nr = _resolve_pg(bfrt, LOOPBACK_PORT)
    q_cfg = bfrt.table_get("tf1.tm.queue.sched_cfg")
    observed = []                                        # (label, pnorm(max_priority))
    for label, qid, want_pri in QUEUE_PLAN:
        pgq = pg_nr * 8 + qid
        sc, err = _get_entry(q_cfg, bfrt.target, [("pg_id", pg_id), ("pg_queue", pgq)])
        assert err is None, f"{label} (pg_queue {pgq}) sched_cfg readback: {err}"
        got_pri = _pnorm(sc.get("max_priority"))
        assert got_pri == int(want_pri), \
            f"{label}: max_priority readback {sc.get('max_priority')} (norm {got_pri}) != {want_pri}"
        assert sc.get("scheduling_enable") is True, f"{label}: scheduling not enabled"
        assert sc.get("min_rate_enable") is False, f"{label}: min-rate shaping ENABLED (must be off)"
        assert sc.get("max_rate_enable") is False, f"{label}: max-rate shaping ENABLED (must be off)"
        observed.append((label, got_pri))
    vals = [v for _l, v in observed]
    assert len(vals) == 4 and all(v is not None for v in vals) \
        and vals[0] > vals[1] > vals[2] > vals[3], \
        f"observed max_priority ordering not strictly 7>6>5>4: {observed}"


def configure_pktgen_apps(bfrt):
    """Two one-time periodic timer apps: app 0 -> ACK reservoir, app 1 -> RESP."""
    port_cfg = bfrt.table_get("tf1.pktgen.port_cfg")
    port_cfg.entry_mod(bfrt.target,
                       [port_cfg.make_key([("dev_port", PGEN_PORT)])],
                       [port_cfg.make_data([("pktgen_enable", True)])])

    pkt_buffer = bfrt.table_get("tf1.pktgen.pkt_buffer")
    app_cfg    = bfrt.table_get("tf1.pktgen.app_cfg")

    for app_id, role_byte in ((APP_ACK, TOK_ACK), (APP_RESP, TOK_RESP)):
        template = build_template(role_byte)
        offset   = app_id * 128                      # distinct 16B-aligned buffer slots
        pkt_buffer.entry_add(
            bfrt.target,
            [pkt_buffer.make_key([("pkt_buffer_offset", offset),
                                  ("pkt_buffer_size", len(template))])],
            [pkt_buffer.make_data([("buffer", template)])])

        # trigger_timer_periodic: ONE batch of K packets every PERIOD_NS, forever.
        # batch_count_cfg      = 0     -> one batch per fire
        # packets_per_batch_cfg= K-1   -> packet_id 0..K-1
        # increment_source_port= False -> LOAD-BEARING (lab memory): with it True the
        #   generated batch caps at ~59 < K=64; must be False so all 64 packet_ids fire.
        app_cfg.entry_mod(
            bfrt.target,
            [app_cfg.make_key([("app_id", app_id)])],
            [app_cfg.make_data([
                ("timer_nanosec",        PERIOD_NS),
                ("pkt_buffer_offset",    offset),
                ("pkt_buffer_size",      len(template)),
                ("batch_count_cfg",      0),
                ("packets_per_batch_cfg", K_TOKENS - 1),
                ("ipg",                  0),
                ("ibg",                  0),
                ("batch_counter",        0),
                ("increment_source_port", False),    # LOAD-BEARING for K=64 (see comment)
                ("assigned_chnl_id",     PGEN_PORT),
                ("app_enable",           True),      # arm: the periodic timer starts now
            ], "trigger_timer_periodic")])


def apply_one_time_setup(bfrt):
    """The exact one-time sequence, each step issued ONCE. Order:
    value-set (parser) -> queue scheduling (TM ladder) -> READ-BACK + ASSERT the
    ladder/shaping -> pktgen apps (seed+arm)."""
    configure_value_set(bfrt)
    configure_queue_scheduling(bfrt)
    verify_queue_scheduling(bfrt)          # asserts 7>6>5>4 + shaping disabled
    configure_pktgen_apps(bfrt)


def _make_bfrt_client():
    """Construct the bfrt gRPC client for bootstrap_probe_v5. Imported lazily so
    §3 inspection never pulls in the runtime. Only reached under authorization."""
    import bfrt_grpc.client as gc          # provided by the BF-SDE runtime
    iface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0)
    iface.bind_pipeline_config("bootstrap_probe_v5")
    bfrt_info = iface.bfrt_info_get("bootstrap_probe_v5")

    class _Bfrt:
        target = gc.Target(device_id=0, pipe_id=0xffff)
        def table_get(self, name):
            return bfrt_info.table_get(name)
    return _Bfrt()


def main():
    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write(
            "REFUSING TO RUN: this programs the packet generator + the TM strict-priority "
            "ladder (hardware state), gated on explicit authorization. This file is the "
            "committed one-time-setup RECORD for bootstrap_probe_v5.p4; in §3 it is inspected, "
            "not executed. Set DEFENSE4_HW_AUTHORIZED=1 only under an authorized hardware "
            "session (switch loaded with bootstrap_probe_v5, bf_switchd + bfrt gRPC up).\n")
        return 2
    apply_one_time_setup(_make_bfrt_client())
    sys.stderr.write("bootstrap_probe_v5 one-time setup applied (2 timer apps, 7>6>5>4 ladder).\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

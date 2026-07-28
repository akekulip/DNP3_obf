#!/usr/bin/env python3
# =============================================================================
#  AUTHORED OFF-SWITCH — NEVER RUN AGAINST bf_switchd. This file has not been
#  executed against the switch, case_a_dual_release_skeleton has NOT been loaded,
#  and bf_switchd (PID 447452, running the proven dnp3_timing_normalizer_pktgen)
#  was not touched while this was written. The load is gated on Philip.
#
#  Configures:  p4/case_a_dual_release_skeleton.p4
#  Design:      design/CASE_A_READ_ANCHORED_DUAL_RELEASE.md
#                 §3 four queues + the seven-field queue readback
#                 §4 one master-facing FIFO for the released ACK and RESPONSE
#                 §5.1 256 ns quantization of A and R
#                 §6 operating points (A=3 ms, R=13 ms first)
#                 §7 one recirc-triggered app, ONE batch of 128 tokens
#                 §10 per-class pass budgets sized from the horizon
#  Template:    ../../defense2_pktgen/setup/dnp3_timing_normalizer_pktgen_setup.py
#               — all six silicon-resolved gotchas carried forward, each marked
#                 "GOTCHA n/6" where it applies.
#  Contract:    case_a_dual_release_contract.py (constants + provenance citations).
#               STAGE BOTH FILES INTO THE SAME DIRECTORY ON THE SWITCH.
# =============================================================================
"""case_a_read_anchored_dual_release_setup.py — control plane for the READ-anchored
dual-release skeleton.

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052):

    SP=/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages
    PYTHONPATH=$SP:$SP/tofino python3.8 case_a_read_anchored_dual_release_setup.py \
        --config --a-ms 3 --r-ms 13 --mode protected

Modes
  --dry-run       no gRPC at all: print the A/R quantization and the pass budgets, exit.
  --config        write + read back the whole configuration (idempotent, re-runnable).
  --verify-only   read back everything, print the PASS/FAIL table, write NOTHING.
  --mode native|protected
                  native    -> pktgen app_enable=False (no blockers generated)
                  protected -> pktgen app_enable=True  (READ-triggered 128-token burst)

Exit status is non-zero if any check FAILs. Prints a PASS/FAIL table and one JSON
line `CASEADUAL {...}`. Python 3.8; no numpy (not installed on the switch).
"""
import argparse
import json
import sys

from case_a_dual_release_contract import (
    PROG_DEFAULT, PORT_L, PORT_VISION, PORT_RELAY, PORT_PGEN,
    QID_NORMAL, QUEUE_PLAN, CLONE_SID, CLONE_TAG_MARKER_BYTE, TOKEN_LEN,
    PGEN_PRSR_ID, APP_ID_DEFAULT, TOKENS_TOTAL, TOKENS_PER_CLASS, PKTGEN_SRC_PRT_MAX,
    BLOCKER_ENTRIES, BLOCKER_DEFAULT_ACTION, A_DEFAULT_MS, R_DEFAULT_MS,
    LOOP_US_DEFAULT, HORIZON_MULT_DEFAULT,
    Checks, build_token_template, check_budgets, check_offset, kv_pair, pnorm,
    print_quantization, quantize_offset,
)


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


def get_all_entries(tbl, tgt, from_hw=True):
    """entry_get with an empty key list -> [(key dict, data dict)]
    (client.py:2194 'An empty key_list indicates get all entries').
    A ParserValueSet carries a key and no data, so the data object may be None."""
    rows = []
    for d, k in tbl.entry_get(tgt, None, {"from_hw": from_hw}):
        rows.append((k.to_dict() if k is not None else {},
                     d.to_dict() if d is not None else {}))
    return rows


def get_default(tbl, tgt):
    """default_entry_get -> data dict. client.py:2181 documents the generator as
    yielding (Data, None) tuples."""
    got = None
    for item in tbl.default_entry_get(tgt, {"from_hw": True}):
        d = item[0] if isinstance(item, tuple) else item
        if d is not None:
            got = d.to_dict()
    return got


# ===========================================================================
# 1. Host ports + the dp8 internal loopback
# ===========================================================================
def config_ports(bi, tgt, a, out, chk):
    import bfrt_grpc.client as gc
    port_tbl = bi.table_get("$PORT")

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
                port_tbl.entry_mod(tgt, key, data)      # idempotent re-run
            except Exception as e:
                chk.fail("port dp%d up" % dp, str(e)[:90])
                return
        chk.ok("port dp%d up" % dp, "%s %s %s" % (speed, fec, an))

    port_up(a.port_vision, "BF_SPEED_25G", "BF_FEC_TYP_RS", "PM_AN_DEFAULT")
    # dp64: the physical SEL-751 hangs off E1/33 behind an unmanaged switch and links
    # at 1G / FEC none / AN force-disable (hardware-measured; .p4:150-151).
    port_up(a.port_relay, "BF_SPEED_1G", "BF_FEC_TYP_NONE", "PM_AN_FORCE_DISABLE")

    # dp8 MAC-near loopback: delete + re-add — a live entry rejects the mode change.
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
    out["ports_configured"] = [a.port_vision, a.port_relay, a.port_l]


# ===========================================================================
# 2. The four dp8 queues (design §3) + the seven-field readback
# ===========================================================================
def resolve_pg(bi, tgt0, dev_port, chk, out, expect_pg=None, expect_nr=None):
    """READ the (pg_id, pg_port_nr) of a dev_port instead of guessing it.
    # bf_rt_tm_tf1: tf1.tm.port.cfg KEY dev_port DATA pg_id, pg_port_nr, ..."""
    try:
        pcfg = bi.table_get("tf1.tm.port.cfg")
    except Exception as e:
        chk.fail("tf1.tm.port.cfg dp%d" % dev_port, str(e)[:90])
        return None, None
    got, err = get_entry(pcfg, tgt0, [("dev_port", dev_port)])
    if err:
        chk.fail("tf1.tm.port.cfg dp%d" % dev_port, err)
        return None, None
    pg_id, pg_nr = got.get("pg_id"), got.get("pg_port_nr")
    out.setdefault("port_cfg", {})["dp%d" % dev_port] = {
        "pg_id": pg_id, "pg_port_nr": pg_nr,
        "port_queues_count": got.get("port_queues_count")}
    chk.ok("dp%d port-group map (read, not guessed)" % dev_port,
           "pg_id=%s pg_port_nr=%s" % (pg_id, pg_nr))
    if expect_pg is not None and pg_id != expect_pg:
        chk.fail("dp%d pg_id matches --pg-l" % dev_port,
                 "readback pg_id=%s but --pg-l=%s" % (pg_id, expect_pg))
    if expect_nr is not None and pg_nr != expect_nr:
        chk.fail("dp%d pg_port_nr matches --pg-l-nr" % dev_port,
                 "readback pg_port_nr=%s but --pg-l-nr=%s" % (pg_nr, expect_nr))
    return pg_id, pg_nr


def write_queue_priority(q_cfg, tgt0, pg_id, pg_queue, want_pri, set_min, chk, label):
    """Set scheduling_enable + max_priority on one queue.

    max_priority arbitrates among BACKLOGGED queues in the remaining-bandwidth pass;
    min_priority orders only the guaranteed pass and is inert unless min_rate_enable
    is true. Writing max_priority is what the IBSPG root-cause repair established as
    load-bearing, and leaving it unset degrades silently to a fair DWRR split.

    Preferred path is read-modify-write so the rate flags and dwrr_weight already on
    the queue survive. TODO(silicon): whether this SDE's tf1.tm.queue.sched_cfg
    entry_mod accepts a full field set is unconfirmed off-switch; on failure this
    falls back to the exact minimal write the Defense 2 template used on silicon.
    The returned path name is recorded so the readback shows which ran.
    """
    import bfrt_grpc.client as gc
    key = q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pg_queue)])
    cur, _e = get_entry(q_cfg, tgt0, [("pg_id", pg_id), ("pg_queue", pg_queue)], from_hw=False)
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
    """design §3: 'After configuration, read back and record for each queue: queue ID,
    max_priority, min_priority, scheduling enable state, port, pipe, queue mapping.'
    All seven, from the readback — nothing here is echoed from what was written."""
    print("dp8 queue readback (design §3 — all seven fields, from tf1.tm.queue.sched_cfg "
          "+ tf1.tm.queue.map)")
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
                 r["scheduling_enable"], r["port"], r["pipe"], m["pg_id"], m["pg_port_nr"],
                 m["pg_queue"], m["queue_nr"], m["ingress_qid_count"]))
    print("")


def config_queues(bi, tgt0, a, out, chk, write=True):
    """Configure and read back all four dp8 queues. design §3 requires, per queue:
    queue ID, max_priority, min_priority, scheduling enable state, port, pipe and
    queue mapping — all seven are recorded and printed below."""
    pg_id, pg_nr = resolve_pg(bi, tgt0, a.port_l, chk, out, a.pg_l, a.pg_l_nr)
    if pg_id is None:
        pg_id, pg_nr = a.pg_l, a.pg_l_nr
        chk.warn("dp%d pg map fallback" % a.port_l,
                 "using --pg-l=%d --pg-l-nr=%d (readback failed)" % (pg_id, pg_nr))
    try:
        q_cfg = bi.table_get("tf1.tm.queue.sched_cfg")     # bf_rt_tm_tf1
    except Exception as e:
        chk.fail("tf1.tm.queue.sched_cfg", str(e)[:90])
        return
    try:
        q_map = bi.table_get("tf1.tm.queue.map")           # bf_rt_tm_tf1
    except Exception:
        q_map = None
        chk.warn("tf1.tm.queue.map", "unavailable; queue-mapping readback degraded")

    order = []
    for label, qid, want_pri in QUEUE_PLAN:
        pgq = pg_nr * 8 + qid
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
        # TF1 dev_port encoding: pipe = dev_port >> 7 (dp8/dp9/dp64/dp68 -> pipe 0).
        rec = {
            "queue_id": qid,                                   # §3 field 1
            "max_priority": sc.get("max_priority"),             # §3 field 2
            "min_priority": sc.get("min_priority"),             # §3 field 3
            "scheduling_enable": sc.get("scheduling_enable"),   # §3 field 4
            "port": dev_port,                                   # §3 field 5
            "pipe": None if dev_port is None else (int(dev_port) >> 7),   # §3 field 6
            "queue_mapping": {"pg_id": pg_id, "pg_port_nr": pg_nr, "pg_queue": pgq,
                              "queue_nr": qm.get("queue_nr"),
                              "ingress_qid_count": qm.get("ingress_qid_count"),
                              "ingress_qid_max": qm.get("ingress_qid_max"),
                              "err": qm_err},                   # §3 field 7
            # context (not one of the seven): these decide whether min_priority matters
            "min_rate_enable": sc.get("min_rate_enable"),
            "max_rate_enable": sc.get("max_rate_enable"),
            "dwrr_weight": sc.get("dwrr_weight"),
        }
        out.setdefault("queues", {})[label] = rec
        order.append((label, pnorm(rec["max_priority"])))
        chk.expect("%s max_priority" % label, pnorm(rec["max_priority"]), int(want_pri),
                   "(qid %d, pg_queue %d)" % (qid, pgq))
        chk.expect("%s scheduling_enable" % label, rec["scheduling_enable"], True)
        if dev_port is not None and int(dev_port) != a.port_l:
            chk.fail("%s maps to dp%d" % (label, a.port_l),
                     "queue.map reports dev_port=%s" % dev_port)

    print_queue_table(out.get("queues", {}))

    vals = [v for _l, v in order]
    strict = (len(vals) == 4 and all(v is not None for v in vals)
              and vals[0] > vals[1] > vals[2] > vals[3])
    out["strict_priority_verified"] = strict
    if strict:
        chk.ok("strict ordering ABLOCK>ACK>RBLOCK>RESP",
               " > ".join("%s(%d)" % (l, v) for l, v in order))
    else:
        chk.fail("strict ordering ABLOCK>ACK>RBLOCK>RESP",
                 "max_priority readback = %s (must be strictly decreasing)" % order)

    # design §4: the released ACK and the released RESPONSE must share ONE external
    # master-facing FIFO; the P4 sends both to PORT_VISION / QID_NORMAL (.p4:719-723).
    # Informational readback only — that queue is left at its default configuration.
    v_pg, v_nr = resolve_pg(bi, tgt0, a.port_vision, chk, out)
    if v_pg is not None:
        sc, err = get_entry(q_cfg, tgt0, [("pg_id", v_pg), ("pg_queue", v_nr * 8 + QID_NORMAL)])
        out["master_fifo"] = {"dev_port": a.port_vision, "qid": QID_NORMAL, "pg_id": v_pg,
                              "pg_queue": v_nr * 8 + QID_NORMAL, "sched_cfg": sc, "err": err}
        chk.ok("master FIFO dp%d qid%d (design §4, info only)" % (a.port_vision, QID_NORMAL),
               sc if sc else err)


# ===========================================================================
# 3. tbl_guard — the two READ-anchored offsets A and R (design §5.1, §6)
# ===========================================================================
def config_guard(bi, tgt, qa, qr, out, chk, write=True):
    """tbl_guard is keyless with one default action set_guard(a_word, r_word)
    (.p4:738-746). # bfrt.json: pipe.Ingress.tbl_guard ACT Ingress.set_guard
    (a_word:32, r_word:32); has_const_default_action = False, so it is writable and
    an (A, R) sweep needs no recompile.

    GOTCHA 6/6 (Defense 2 §B item 6): the default-entry API on this SDE is
    default_entry_set(tgt, make_data([DataTuple(...)], '<Control>.<action>')).
    """
    import bfrt_grpc.client as gc
    try:
        gt = bi.table_get("pipe.Ingress.tbl_guard")
    except Exception as e:
        chk.fail("pipe.Ingress.tbl_guard", str(e)[:90])
        return
    if write:
        try:
            gt.default_entry_set(tgt, gt.make_data(
                [gc.DataTuple("a_word", qa["word"]),
                 gc.DataTuple("r_word", qr["word"])], "Ingress.set_guard"))
        except Exception as e:
            chk.fail("tbl_guard default_entry_set", str(e)[:90])
            return
    try:
        got = get_default(gt, tgt)
    except Exception as e:
        chk.fail("tbl_guard default_entry_get", str(e)[:90])
        return
    if got is None:
        chk.fail("tbl_guard default_entry_get", "no default entry returned")
        return
    out["tbl_guard"] = got
    chk.expect_fields("tbl_guard", got, [
        ("action_name", "Ingress.set_guard", ""),
        ("a_word", qa["word"], "= %s (A = %g ms, error %+d ns)"
         % (qa["word_hex"], qa["requested_ms"], qa["error_ns"])),
        ("r_word", qr["word"], "= %s (R = %g ms, error %+d ns)"
         % (qr["word_hex"], qr["requested_ms"], qr["error_ns"])),
    ])


# ===========================================================================
# 4. Blocker classification — tbl_blocker_role is a CONST table: verify only
# ===========================================================================
def verify_blocker_role(bi, tgt, out, chk):
    """design §7 / .p4:872-881.

    The two entries and the drop default are compiled in (`const entries` +
    `const default_action`); bfrt reports the table with attribute 'ConstTable' and
    has_const_default_action True (# bfrt.json), and context.json shows
    static_entries = 2. The control plane therefore VERIFIES them and never writes
    them — an entry_add here would be rejected by the server.

    TODO(silicon): whether this SDE returns const entries from a wildcard entry_get
    is unconfirmed off-switch. The readback that settles it is exactly the dump
    below: it must return 2 entries, 0x0000/0xFFC0 -> Ingress.set_ack_blocker and
    0x0040/0xFFC0 -> Ingress.set_resp_blocker. If it returns 0, cross-check with
    bfrt_python `pipe.Ingress.tbl_blocker_role.dump()` before concluding they are
    absent — a const table that reads empty over gRPC is a client limitation, not a
    missing entry, and the compiled binary is authoritative.
    """
    try:
        t = bi.table_get("pipe.Ingress.tbl_blocker_role")
    except Exception as e:
        chk.fail("pipe.Ingress.tbl_blocker_role", str(e)[:90])
        return
    try:
        rows = get_all_entries(t, tgt)
    except Exception as e:
        chk.fail("tbl_blocker_role entry_get(all)", "TODO(silicon): " + str(e)[:80])
        rows = []
    seen = []
    for kd, dd in rows:
        v, m = kv_pair(kd.get("hdr.pgen_id.packet_id"))     # bfrt.json KEY name
        seen.append({"value": v, "mask": m, "action_name": dd.get("action_name")})
    out["tbl_blocker_role_entries"] = seen

    for want_v, want_m, want_act in BLOCKER_ENTRIES:
        hit = [s for s in seen
               if s["value"] == want_v and (s["mask"] is None or s["mask"] == want_m)]
        name = "blocker entry 0x%04X &&& 0x%04X" % (want_v, want_m)
        if hit and hit[0]["action_name"] == want_act:
            chk.ok(name, want_act)
        elif hit:
            chk.fail(name, "action is %r, expected %r" % (hit[0]["action_name"], want_act))
        else:
            chk.fail(name, "not found; %d entries in readback: %s" % (len(seen), seen))
    try:
        dflt = get_default(t, tgt)
        out["tbl_blocker_role_default"] = dflt
        chk.expect("blocker default action", (dflt or {}).get("action_name"),
                   BLOCKER_DEFAULT_ACTION, "(unclassifiable packet_id is dropped)")
    except Exception as e:
        chk.fail("tbl_blocker_role default_entry_get", "TODO(silicon): " + str(e)[:80])


# ===========================================================================
# 5. Pktgen — one recirculation-triggered application, ONE batch of 128 tokens
# ===========================================================================
def config_mirror(bi, tgt, a, out, chk, write):
    """arm_clone() sets mirror_type + clone_ses (.p4:728-732) and the ingress
    deparser emits the 4-byte recirc tag on that session (.p4:1150-1152).

    GOTCHA 3/6 (Defense 2 §B item 2): $mirror.cfg is ACTION-based — make_data
    WITHOUT the '$normal' action name returns INVALID_ARGUMENT.
    """
    import bfrt_grpc.client as gc
    try:
        mtbl = bi.table_get("$mirror.cfg")
        mkey = [mtbl.make_key([gc.KeyTuple("$sid", a.clone_sid)])]
        mdata = [mtbl.make_data([
            gc.DataTuple("$direction", str_val="INGRESS"),
            gc.DataTuple("$ucast_egress_port", a.port_pgen),
            gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
            gc.DataTuple("$session_enable", bool_val=True),
            gc.DataTuple("$max_pkt_len", a.mirror_max_len)], "$normal")]
        if write:
            try:
                mtbl.entry_add(tgt, mkey, mdata)
            except Exception:
                mtbl.entry_mod(tgt, mkey, mdata)          # idempotent re-run
        got, err = get_entry(mtbl, tgt, [("$sid", a.clone_sid)])
        if err:
            chk.fail("mirror sid %d readback" % a.clone_sid, err)
            return
        out["mirror_cfg"] = got
        chk.expect_fields("mirror sid %d" % a.clone_sid, got, [
            ("$ucast_egress_port", a.port_pgen, "(dp68)"),
            ("$direction", "INGRESS", ""),
            ("$session_enable", True, ""),
        ])
    except Exception as e:
        chk.fail("$mirror.cfg", str(e)[:90])


def config_value_set(bi, tgt, a, out, chk, write):
    """Generated packets lead with pktgen_recirc_header_t byte0 = pad(3)|pipe(2)|app(3);
    the parser admits them by matching that byte (.p4:402, .p4:466-471). This IS the
    pipe / app_id admission check of design §7.

    GOTCHA 1/6 (Defense 2 §B item 1): the mask must be EXACT 0xFF, NOT the SDE
    example's 0x1F. On dp68 the parser also sees the recirculated clone whose leading
    byte is the 0xE1 marker (.p4:179); under 0x1F, 0xE1 & 0x1F == 0x01 ALIASES to
    app_id 1 and the clone would be mis-admitted as a blocker token. A valid pgen byte
    is ((pipe<<3)|app) <= 0x1F and can never be 0xE1, so nothing is missed.
    """
    import bfrt_grpc.client as gc
    try:
        from bfrt_grpc import bfruntime_pb2 as bfr_pb2   # noqa: N813
    except Exception:
        try:
            import bfruntime_pb2 as bfr_pb2             # type: ignore
        except Exception:
            bfr_pb2 = None

    vs_byte, vs_mask = (a.pipe << 3) | a.app_id, 0xFF
    out["pgen_recirc_vs"] = {"byte": vs_byte, "mask": vs_mask, "pipe": a.pipe,
                             "app_id": a.app_id, "prsr_id": PGEN_PRSR_ID}
    try:
        vs = bi.table_get("pipe.IgParser.pgen_recirc")     # bfrt.json ParserValueSet
        vtgt = gc.Target(device_id=0, pipe_id=a.pipe, prsr_id=PGEN_PRSR_ID)
        if write:
            # The scope attribute can only be set while the table is EMPTY, so it is
            # wrapped separately: a failure on a re-run must not block the entry.
            if bfr_pb2 is not None:
                try:
                    vs.attribute_entry_scope_set(
                        tgt,
                        config_pipe_scope=True, predefined_pipe_scope=True,
                        predefined_pipe_scope_val=bfr_pb2.Mode.SINGLE,
                        config_gress_scope=True, predefined_gress_scope_val=bfr_pb2.Mode.ALL,
                        config_prsr_scope=True, predefined_prsr_scope_val=bfr_pb2.Mode.SINGLE)
                    out["pgen_recirc_scope_set"] = True
                except Exception as se:
                    out["pgen_recirc_scope_note"] = "already set (ok on re-run): " + str(se)[:50]
            else:
                out["pgen_recirc_scope_note"] = "bfruntime_pb2 unavailable; scope left as-is"
            vkey = [vs.make_key([gc.KeyTuple("f1", vs_byte, vs_mask)])]   # bfrt.json KEY f1
            try:
                vs.entry_del(vtgt, vkey)       # idempotent: clear any prior entry first
            except Exception:
                pass
            vs.entry_add(vtgt, vkey)
        seen = []
        for kd, _dd in get_all_entries(vs, vtgt):
            v, m = kv_pair(kd.get("f1"))
            seen.append({"value": v, "mask": m})
        out["pgen_recirc_vs_entries"] = seen
        name = "pgen value_set f1 = 0x%02X &&& 0x%02X" % (vs_byte, vs_mask)
        if [s for s in seen if s["value"] == vs_byte and
                (s["mask"] is None or s["mask"] == vs_mask)]:
            chk.ok(name, "prsr_id=%d pipe=%d" % (PGEN_PRSR_ID, a.pipe))
        else:
            chk.fail(name, "readback = %s" % seen)
        bad = [s for s in seen if s["mask"] is not None and s["mask"] != 0xFF]
        if bad:
            chk.fail("pgen value_set mask is EXACT 0xFF",
                     "found mask(s) %s — under 0x1F the 0xE1 clone marker aliases to app_id 1"
                     % [hex(s["mask"]) for s in bad])
        else:
            chk.ok("pgen value_set mask is EXACT 0xFF", "no 0x1F aliasing of the 0xE1 clone")
    except Exception as e:
        chk.fail("pipe.IgParser.pgen_recirc", "TODO(silicon): " + str(e)[:80])


def config_pktgen_port_and_buffer(bi, tgt, a, template, out, chk, write):
    """GOTCHA 2/6 (Defense 2 §B item 5a): dp68 needs ALL THREE flags. Without
    recirculation_enable the mirrored clone never loops back and nothing triggers.
    No $PORT entry is needed for dp68 — up=False is expected for an internal
    recirculation port.

    GOTCHA 4/6 (Defense 2 §B item 4): pkt_buffer EXCLUDES the 6-byte pktgen header,
    which the hardware prepends and the parser consumes at .p4:481-482.
    """
    import bfrt_grpc.client as gc
    try:
        pcfg = bi.table_get("tf1.pktgen.port_cfg")        # bf_rt_pktgen_tf1
        pkey = [pcfg.make_key([gc.KeyTuple("dev_port", a.port_pgen)])]
        if write:
            pcfg.entry_mod(tgt, pkey, [pcfg.make_data([
                gc.DataTuple("pktgen_enable", bool_val=True),
                gc.DataTuple("recirculation_enable", bool_val=True),
                gc.DataTuple("pattern_matching_enable", bool_val=True)])])
        got, err = get_entry(pcfg, tgt, [("dev_port", a.port_pgen)])
        if err:
            chk.fail("pktgen port_cfg dp%d readback" % a.port_pgen, err)
        else:
            out["pktgen_port_cfg"] = got
            chk.expect_fields("port_cfg dp%d" % a.port_pgen, got, [
                ("pktgen_enable", True, ""),
                ("recirculation_enable", True, "(without it the clone never loops back)"),
                ("pattern_matching_enable", True, ""),
            ])
    except Exception as e:
        chk.fail("tf1.pktgen.port_cfg", str(e)[:90])

    out["pkt_buffer"] = {"offset": a.buf_offset, "size": len(template),
                         "first_bytes": template[:21].hex()}   # eth(14) + ibspg(7)
    try:
        pbuf = bi.table_get("tf1.pktgen.pkt_buffer")      # bf_rt_pktgen_tf1
        bkey = [("pkt_buffer_offset", a.buf_offset), ("pkt_buffer_size", len(template))]
        if write:
            pbuf.entry_mod(
                tgt, [pbuf.make_key([gc.KeyTuple(k, v) for k, v in bkey])],
                [pbuf.make_data([gc.DataTuple("buffer", bytearray(template))])])
        got, err = get_entry(pbuf, tgt, bkey)
        if err:
            chk.fail("pkt_buffer readback", err)
        else:
            rb = got.get("buffer")
            rb = bytes(rb) if rb is not None else None
            if rb == template:
                chk.ok("pkt_buffer template (%d B)" % len(template),
                       "etype 0x88C1, role=ROLE_BLOCK; gen/slot/seq re-stamped in the P4")
            else:
                chk.fail("pkt_buffer template (%d B)" % len(template),
                         "readback differs: %s" % (rb.hex()[:48] if rb else rb))
    except Exception as e:
        chk.fail("tf1.pktgen.pkt_buffer", str(e)[:90])


def config_app(bi, tgt, a, template, out, chk, write):
    """design §7: batch_count_cfg = 0 (ONE batch, so packet_id is unique across the
    whole burst — two batches would each emit 0..63 and be unseparable) and
    packets_per_batch_cfg = 127 (ZERO-BASED -> 128 tokens; # batch_limits Q1 shows the
    hardware field pgr_app_event_number.packet_num is 16 bits, so 128 is legal).

    The trigger pattern pins recirc-tag byte0 == 0xE1 (.p4:179) and leaves the
    generation-carrying low 3 bytes don't-care. Generated tokens cannot self-retrigger:
    their own header byte0 is (pipe<<3)|app != 0xE1 and they egress to dp8, not dp68.
    """
    import bfrt_grpc.client as gc
    app_enable = (a.mode == "protected")
    pattern_value = (CLONE_TAG_MARKER_BYTE << 24) & 0xFFFFFFFF   # 0xE1000000
    pattern_mask = 0xFF000000
    ppb_cfg = a.tokens - 1                                       # zero-based
    out["mode"] = a.mode
    out["app_cfg_intended"] = {
        "app_id": a.app_id, "batch_count_cfg": 0, "packets_per_batch_cfg": ppb_cfg,
        "tokens_total": a.tokens, "pipe_local_source_port": a.port_pgen,
        "increment_source_port": False, "pkt_len": len(template),
        "pattern_value": "0x%08X" % pattern_value, "pattern_mask": "0x%08X" % pattern_mask,
        "app_enable": app_enable}
    try:
        acfg = bi.table_get("tf1.pktgen.app_cfg")         # bf_rt_pktgen_tf1
        if write:
            acfg.entry_mod(
                tgt, [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
                [acfg.make_data([
                    gc.DataTuple("pattern_value", pattern_value),
                    gc.DataTuple("pattern_mask", pattern_mask),
                    gc.DataTuple("pkt_len", len(template)),
                    gc.DataTuple("pkt_buffer_offset", a.buf_offset),
                    # GOTCHA 5/6 (Defense 2 §B item 5b): pipe_local_source_port is
                    # REQUIRED on this switch — the SDE's "implicit on TF1" note is
                    # FALSE here. Without it the generated tokens carry the wrong
                    # ingress_port, miss the parser's from_pgen path (.p4:447, .p4:466)
                    # and are dropped as port_ok == 0 (.p4:914-917): pkt_counter = N
                    # but admit = 0.
                    gc.DataTuple("pipe_local_source_port", a.port_pgen),
                    # LOAD-BEARING (# batch_limits Q2): if this were True the driver
                    # caps packets_per_batch at 127 - 68 = 59 (60 tokens), rejecting
                    # even the existing K = 64 reservoir. Asserted on readback below.
                    gc.DataTuple("increment_source_port", bool_val=False),
                    gc.DataTuple("batch_count_cfg", 0),
                    gc.DataTuple("packets_per_batch_cfg", ppb_cfg),
                    gc.DataTuple("ipg", 0), gc.DataTuple("ibg", 0),
                    gc.DataTuple("trigger_counter", 0), gc.DataTuple("batch_counter", 0),
                    gc.DataTuple("pkt_counter", 0),
                    gc.DataTuple("app_enable", bool_val=app_enable)],
                    "trigger_recirc_pattern")])
        got, err = get_entry(acfg, tgt, [("app_id", a.app_id)])
        if err:
            chk.fail("app_cfg readback", err)
            return
        out["app_cfg"] = got
        chk.expect_fields("app_cfg", got, [
            ("action_name", "trigger_recirc_pattern", ""),
            ("batch_count_cfg", 0, "(ONE batch -> packet_id unique across the burst)"),
            ("packets_per_batch_cfg", ppb_cfg, "(zero-based -> %d tokens)" % a.tokens),
            ("pipe_local_source_port", a.port_pgen, "(REQUIRED; NOT implicit on TF1)"),
            ("pattern_value", pattern_value, "= 0x%08X (clone marker byte0)" % pattern_value),
            ("pattern_mask", pattern_mask, "= 0x%08X" % pattern_mask),
            ("pkt_len", len(template), ""),
            ("app_enable", app_enable, "(--mode %s)" % a.mode),
        ])
        # ---- the hard assertion: increment_source_port MUST read back False ----
        isp = got.get("increment_source_port")
        cap = PKTGEN_SRC_PRT_MAX - a.port_pgen
        if isp is False:
            chk.ok("app_cfg increment_source_port is False",
                   "load-bearing; the bound %d-%d=%d (%d tokens) would otherwise apply"
                   % (PKTGEN_SRC_PRT_MAX, a.port_pgen, cap, cap + 1))
        elif isp is True:
            chk.fail("app_cfg increment_source_port is False",
                     "READ BACK True. The driver then caps packets_per_batch at %d-%d=%d "
                     "(i.e. %d tokens), rejecting the 128-token batch AND the existing K=64 "
                     "reservoir. Refusing to proceed."
                     % (PKTGEN_SRC_PRT_MAX, a.port_pgen, cap, cap + 1))
        else:
            chk.fail("app_cfg increment_source_port is False",
                     "readback returned %r (not a bool) — the invariant cannot be confirmed" % isp)
    except Exception as e:
        chk.fail("tf1.pktgen.app_cfg", str(e)[:90])


# ===========================================================================
# main
# ===========================================================================
def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Control plane for case_a_dual_release_skeleton.p4 "
                    "(READ-anchored dual release, design §3-§10).")
    ap.add_argument("--prog", default=PROG_DEFAULT)
    ap.add_argument("--config", action="store_true",
                    help="write + read back the whole configuration (idempotent)")
    ap.add_argument("--verify-only", action="store_true",
                    help="read back everything and print PASS/FAIL; write NOTHING")
    ap.add_argument("--dry-run", action="store_true",
                    help="no gRPC: print the A/R quantization and the pass budgets, then exit")
    ap.add_argument("--mode", choices=["native", "protected"], default="native",
                    help="native = pktgen app disabled; protected = READ-triggered burst enabled")
    # deadlines (design §5.1, §6)
    ap.add_argument("--a-ms", type=float, default=A_DEFAULT_MS,
                    help="ACK deadline offset A in ms (default %g)" % A_DEFAULT_MS)
    ap.add_argument("--r-ms", type=float, default=R_DEFAULT_MS,
                    help="RESPONSE deadline offset R in ms (default %g)" % R_DEFAULT_MS)
    # pass budgets (design §10)
    ap.add_argument("--ablock-passes", type=int, default=None,
                    help="ACK-blocker pass budget; default = horizon / loop time")
    ap.add_argument("--rblock-passes", type=int, default=None,
                    help="RESPONSE-blocker pass budget; default = horizon / loop time")
    ap.add_argument("--loop-us", type=float, default=LOOP_US_DEFAULT,
                    help="measured dp8 loop time per pass, us (default %g)" % LOOP_US_DEFAULT)
    ap.add_argument("--horizon-mult", type=float, default=HORIZON_MULT_DEFAULT,
                    help="fail-open horizon as a multiple of the deadline (default %g)"
                         % HORIZON_MULT_DEFAULT)
    ap.add_argument("--allow-budget-mismatch", action="store_true",
                    help="downgrade a budget/compiled-constant mismatch from FAIL to WARN")
    # ports
    ap.add_argument("--port-l", type=int, default=PORT_L)
    ap.add_argument("--port-vision", type=int, default=PORT_VISION)
    ap.add_argument("--port-relay", type=int, default=PORT_RELAY)
    ap.add_argument("--port-pgen", type=int, default=PORT_PGEN)
    ap.add_argument("--pg-l", type=int, default=2,
                    help="EXPECTED dp8 pg_id; verified against tf1.tm.port.cfg")
    ap.add_argument("--pg-l-nr", type=int, default=0,
                    help="EXPECTED dp8 pg_port_nr; pg_queue = nr*8 + qid")
    ap.add_argument("--also-set-min-priority", action="store_true",
                    help="mirror max_priority into the (inert) min_priority field as well")
    ap.add_argument("--skip-ports", action="store_true",
                    help="do not touch $PORT (queues / guard / pktgen only)")
    # pktgen
    ap.add_argument("--pipe", type=int, default=0)
    ap.add_argument("--app-id", type=int, default=APP_ID_DEFAULT)
    ap.add_argument("--tokens", type=int, default=TOKENS_TOTAL,
                    help="tokens per trigger, ONE batch (must be %d)" % TOKENS_TOTAL)
    ap.add_argument("--force-tokens", action="store_true",
                    help="allow --tokens != %d (splits the two classes unevenly)" % TOKENS_TOTAL)
    ap.add_argument("--buf-offset", type=int, default=0, help="pkt_buffer_offset (16 B aligned)")
    ap.add_argument("--token-len", type=int, default=TOKEN_LEN)
    ap.add_argument("--clone-sid", type=int, default=CLONE_SID)
    ap.add_argument("--mirror-max-len", type=int, default=128)
    return ap.parse_args(argv)


def offline_checks(a, qa, qr, out, chk):
    """Everything decidable without the switch. Runs in every mode."""
    check_offset(qa, chk)
    check_offset(qr, chk)
    if qr["programmed_ns"] <= qa["programmed_ns"]:
        chk.fail("R > A", "R = %d ns is not greater than A = %d ns; design §1 requires R > A > 0"
                 % (qr["programmed_ns"], qa["programmed_ns"]))
    else:
        chk.ok("R > A", "S = R - A = %.6f ms"
               % ((qr["programmed_ns"] - qa["programmed_ns"]) / 1e6))
    check_budgets(a, qa, qr, out, chk)
    if a.tokens == TOKENS_TOTAL:
        chk.ok("token batch", "%d tokens in ONE batch -> packet_id 0..%d, %d ACK + %d RESP"
               % (a.tokens, a.tokens - 1, TOKENS_PER_CLASS, TOKENS_PER_CLASS))
    elif a.force_tokens:
        chk.warn("--tokens == %d" % TOKENS_TOTAL,
                 "forced to %d: the class split will be uneven" % a.tokens)
    else:
        chk.fail("--tokens == %d" % TOKENS_TOTAL,
                 "got %d. tbl_blocker_role splits on 0xFFC0 (.p4:877-878), so only %d gives "
                 "%d ACK + %d RESP blockers. Use --force-tokens to override."
                 % (a.tokens, TOKENS_TOTAL, TOKENS_PER_CLASS, TOKENS_PER_CLASS))


def main(argv=None):
    a = parse_args(argv)
    chk = Checks()
    out = {"prog": a.prog, "authored_off_switch": True, "silicon_validated": False}

    qa, qr = quantize_offset("A", a.a_ms), quantize_offset("R", a.r_ms)
    out["A"], out["R"] = qa, qr
    print_quantization(qa, qr, a)
    offline_checks(a, qa, qr, out, chk)

    if not a.dry_run:
        if not (a.config or a.verify_only):
            print("nothing to do: pass --config, --verify-only or --dry-run", file=sys.stderr)
            return 2
        write = bool(a.config) and not a.verify_only
        out["write"] = write

        import bfrt_grpc.client as gc
        iface = gc.ClientInterface("localhost:50052", client_id=63, device_id=0,
                                   notifications=None)
        iface.bind_pipeline_config(a.prog)
        bi = iface.bfrt_info_get(a.prog)
        tgt = gc.Target(device_id=0, pipe_id=0xffff)
        tgt0 = gc.Target(device_id=0, pipe_id=0)
        template = build_token_template(a.token_len)

        if write and not a.skip_ports:
            config_ports(bi, tgt, a, out, chk)
        config_queues(bi, tgt0, a, out, chk, write=write)
        config_guard(bi, tgt, qa, qr, out, chk, write=write)
        verify_blocker_role(bi, tgt, out, chk)
        config_mirror(bi, tgt, a, out, chk, write)
        config_value_set(bi, tgt, a, out, chk, write)
        config_pktgen_port_and_buffer(bi, tgt, a, template, out, chk, write)
        config_app(bi, tgt, a, template, out, chk, write)

    print(chk.render())
    out["n_fail"] = chk.n_fail
    out["checks"] = [{"result": r, "check": n, "detail": d} for r, n, d in chk.rows]
    print("CASEADUAL " + json.dumps(out, default=str))
    return 1 if chk.n_fail else 0


if __name__ == "__main__":
    sys.exit(main())

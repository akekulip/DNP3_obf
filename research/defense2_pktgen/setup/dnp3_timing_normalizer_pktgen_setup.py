#!/usr/bin/env python3
# =============================================================================
#  AUTHORED AT COMPILE TIME — PENDING SILICON VALIDATION; not yet run against
#  the switch. This script has NEVER been executed against bf_switchd. It is the
#  pre-staged control plane for the request-triggered internal-pktgen variant of
#  Defense 2 (dnp3_timing_normalizer_pktgen). Every pktgen/mirror binding below
#  is cross-checked against the P4 it drives —
#    research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4
#  and against the SDE 9.13.2 bfrt names verified in
#    research/defense2_pktgen/evidence/REQUEST_TRIGGERED_PKTGEN_IMPLEMENTATION_REPORT.md (§A)
#  plus the SDE examples pkgsrc/p4-examples/p4_16_programs/{tna_pktgen,tna_mirror}.
#  Anything that can only be confirmed by running on hardware is marked
#  TODO(silicon). Do NOT run this as part of the compile gate.
# =============================================================================
"""dnp3_timing_normalizer_pktgen_setup.py — static control plane for the
request-triggered pktgen Defense-2 program.

Runs ON THE SWITCH against the loaded program (bfruntime localhost:50052).
Structure/idiom inherited from ibspg_paired_setup.py (client open, --config /
--reset, strict-priority queue config, per-trial register/counter reset).

Modes:
  --config             one-time static setup, idempotent:
                         - host ports up: dp9 (Vision master, 25G), dp64 (relay, 1G)
                         - dp8 MAC-near loopback (the Q_BLOCK/Q_RESP hold ring)
                         - strict priority Q_BLOCK(qid7)=HIGH / Q_RESP(qid1)=LOW
                         - G guard interval into tbl_guard (optional --g-ticks)
                         - PKTGEN: mirror session, pgen_recirc value_set, dp68
                           port_cfg, blocker-token pkt_buffer, app_cfg
  --mode native|protected
                         native   -> pktgen app_enable=False (host-seeded A/B path)
                         protected-> pktgen app_enable=True  (request-triggered burst)
  --reset              per-trial: zero named state/timestamp registers, clear counters.
  (may combine: --config --mode protected --reset)

Prints one JSON line:  PKTGENSETUP {...}
"""
import argparse
import json
import bfrt_grpc.client as gc

# bfruntime_pb2 carries the Mode enum used for value_set pipe/parser scope.
# TODO(silicon): confirm the import path on the switch's SDE 9.13.2 (either
# `from bfrt_grpc import bfruntime_pb2` or a bare `import bfruntime_pb2`); both
# have been seen across SDE builds. Guarded so the module still imports if absent.
try:
    from bfrt_grpc import bfruntime_pb2 as bfr_pb2  # noqa: N813
except Exception:  # pragma: no cover
    try:
        import bfruntime_pb2 as bfr_pb2  # type: ignore
    except Exception:
        bfr_pb2 = None


# ---------------------------------------------------------------------------
# Contract constants — every value below is copied from the P4 it drives.
# Cited as: <value>  # .p4 line NNN  <what it mirrors>
# ---------------------------------------------------------------------------
PROG_DEFAULT   = "dnp3_timing_normalizer_pktgen"

PORT_L         = 8    # .p4:165  const PortId_t PORT_L      = 9w8   (loopback / hold ring)
PORT_VISION    = 9    # .p4:166  const PortId_t PORT_VISION = 9w9   (master side)
PORT_RELAY     = 64   # .p4:172  const PortId_t PORT_RELAY  = 9w64  (live SEL-751 relay leg)
PORT_PGEN      = 68   # .p4:182  const PortId_t PORT_PGEN   = 9w68  (pktgen / recirc port, pipe 0)

QID_BLOCK      = 7    # .p4:175  const bit<5> QID_BLOCK = 5w7  (HIGH, blocker reservoir)
QID_RESP       = 1    # .p4:176  const bit<5> QID_RESP  = 5w1  (LOW, response held queue)

CLONE_SID      = 7        # .p4:192  const MirrorId_t CLONE_SESSION_ID = 10w7
CLONE_TAG_MARKER = 0xE1   # .p4:201  const bit<32> CLONE_TAG_MARKER = 32w0xE1000000 -> byte0 = 0xE1
G_DEFAULT_TICKS = 0x017D7800  # .p4:227  const bit<32> G_DEFAULT_TICKS (25 ms in 256 ns ticks)

# blocker-token template (0x88C1 frame). The pktgen HW PREPENDS the 6-byte
# pktgen_recirc_header_t; this buffer holds only what follows it, i.e. exactly
# what the P4's dp68 admission path parses AFTER `advance(PGEN_HDR_BITS=48)`
# (.p4:447) -> parse_eth (.p4:452, etype 0x88C1 -> parse_token) -> hdr.ib.
ETYPE_IBSPG    = 0x88C1   # .p4:144  const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1
ROLE_BLOCK     = 1        # .p4:155  const bit<8> ROLE_BLOCK = 1
# ibspg_h layout (.p4:247): role:8 slot:8 gen:8 seq:32  (7 bytes)
# Token MACs come from the design (design/REQUEST_TRIGGERED_PKTGEN_DESIGN.md §3);
# the P4 only keys on etype 0x88C1, not on the MACs.
TOKEN_DST      = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])  # design §3
TOKEN_SRC      = bytes([0x02, 0x00, 0x00, 0x00, 0x0b, 0x0c])  # design §3
TOKEN_LEN      = 60       # min Ethernet frame; stripped token is a clean 60 B 0x88C1 frame

# Tofino-1 pktgen facts (SDE tna_pktgen/test.py, verified this session):
#   - generator/recirc port is dev_port 68 in pipe 0 (PORT_PGEN)
#   - the pgen value_set is tied to parser 17 on TF1
#   - TF1 app_id is 3 bits (0..7); value_set byte = (pipe<<3)|app_id, mask 0x1F
PGEN_PRSR_ID   = 17
APP_ID_DEFAULT = 1        # -> pgen_recirc value_set byte (pipe0) = 0x01, distinct from 0xE1 marker


def build_token_template(total_len=TOKEN_LEN):
    """The 0x88C1 blocker-token buffer (no pktgen header — HW adds that).
    gen/seq are placeholders: the P4 RE-STAMPS gen (.p4:945, from reg_tag) and
    seq=INITIAL_BUDGET (.p4:946) on admission, so a non-re-stamped token is
    doubly fail-safe (gen 0 -> stale drop, seq 0 -> budget_zero drop)."""
    tok = bytearray()
    tok += TOKEN_DST                                   # ethernet.dst  (.p4:246)
    tok += TOKEN_SRC                                   # ethernet.src
    tok += bytes([(ETYPE_IBSPG >> 8) & 0xFF, ETYPE_IBSPG & 0xFF])  # ethernet.etype 0x88C1
    tok += bytes([ROLE_BLOCK])                         # ibspg.role  = ROLE_BLOCK (re-stamped)
    tok += bytes([0x00])                               # ibspg.slot  = 0
    tok += bytes([0x00])                               # ibspg.gen   = 0 placeholder (re-stamped)
    tok += bytes([0x00, 0x00, 0x00, 0x00])             # ibspg.seq   = 0 placeholder (re-stamped)
    if len(tok) < total_len:
        tok += bytes(total_len - len(tok))             # zero pad to a full 60 B frame
    return tok


def pnorm(v):
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


# ===========================================================================
# Defense-2 hold config (inherited scaffolding — ports, loopback, queues, G)
# ===========================================================================
def config_hold(bi, tgt, tgt0, a, out):
    port_tbl = bi.table_get("$PORT")

    # dp9 Vision master leg (25G)
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
                out["port_%d_err" % dp] = str(e)[:80]

    port_up(a.port_vision, "BF_SPEED_25G", "BF_FEC_TYP_RS", "PM_AN_DEFAULT")
    # dp64 relay leg: the SEL-751 hangs off E1/33 through an unmanaged switch and
    # links at 1G / FEC none / AN force-disable (.p4:155-159, hardware-measured).
    port_up(a.port_relay, "BF_SPEED_1G", "BF_FEC_TYP_NONE", "PM_AN_FORCE_DISABLE")
    out["ports_up"] = [a.port_vision, a.port_relay]

    # dp8 MAC-near loopback (delete + re-add; a live entry rejects the mode change)
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
        out["mac_loopback_L"] = a.port_l
    except Exception as e:
        out["mac_loopback_err"] = str(e)[:80]

    # strict priority on the dp8 hold ring: max_priority is the arbitration field
    # among backlogged queues. Q_BLOCK(qid7)=HIGH must beat Q_RESP(qid1)=LOW.
    q_cfg = bi.table_get("tf1.tm.queue.sched_cfg")

    def set_pri(qid, want):
        pgq = a.pg_l_nr * 8 + qid
        qkey = q_cfg.make_key([gc.KeyTuple("pg_id", a.pg_l), gc.KeyTuple("pg_queue", pgq)])
        got = err = None
        try:
            q_cfg.entry_mod(tgt0, [qkey], [q_cfg.make_data([
                gc.DataTuple("scheduling_enable", bool_val=True),
                gc.DataTuple("min_priority", str_val=want),
                gc.DataTuple("max_priority", str_val=want)])])
            for d, _ in q_cfg.entry_get(tgt0, [qkey], {"from_hw": False}):
                got = d.to_dict().get("max_priority")
        except Exception as e:
            err = str(e)[:80]
        return got, err

    gb, eb = set_pri(a.qb, "HIGH")
    gh, eh = set_pri(a.qh, "LOW")
    out["Q_BLOCK_pri"] = {"want": "HIGH", "got_max_priority": gb, "err": eb}
    out["Q_RESP_pri"] = {"want": "LOW", "got_max_priority": gh, "err": eh}
    out["strict_priority_verified"] = bool(
        eb is None and eh is None and pnorm(gb) == 7 and pnorm(gh) == 0 and pnorm(gb) > pnorm(gh))

    # G guard interval -> tbl_guard default action set_guard(g_ticks) (.p4:746-750).
    # The P4 comment (.p4:225-227) states the control plane rewrites this default
    # action parameter for a G sweep with no recompile.
    if a.g_ticks is not None:
        try:
            gt = bi.table_get("pipe.Ingress.tbl_guard")
            # TODO(silicon): confirm the default-entry API on this SDE — one of
            #   gt.default_entry_set(tgt, gt.make_data([gc.DataTuple('g_ticks', a.g_ticks)],
            #                        'Ingress.set_guard'))
            # vs an explicit make_data(action_name=...). Field name 'g_ticks' mirrors
            # action set_guard(bit<32> g_ticks) (.p4:746).
            gt.default_entry_set(tgt, gt.make_data(
                [gc.DataTuple("g_ticks", a.g_ticks)], "Ingress.set_guard"))
            out["g_ticks"] = a.g_ticks
        except Exception as e:
            out["g_ticks_err"] = "TODO(silicon): " + str(e)[:70]


# ===========================================================================
# PKTGEN control plane — the six bindings the P4 contract requires
# ===========================================================================
def config_pktgen(bi, tgt, tgt0, a, out):
    app_enable = (a.mode == "protected")
    out["mode"] = a.mode
    out["app_enable"] = app_enable

    # --- (1) mirror session: bind CLONE_SESSION_ID(=7) to egress dp68 ---------
    # The P4 arm_clone() sets ig_dprsr_md.mirror_type=CLONE + meta.clone_ses=7
    # (.p4:738-739) and the ingress deparser clone_mirror.emit(meta.clone_ses,{tag})
    # prepends the 4-byte tag (.p4:1088-1090). $mirror.cfg (SDE tna_mirror/test.py)
    # routes session 7 (I2E ingress) to dp68.
    try:
        mtbl = bi.table_get("$mirror.cfg")
        mkey = [mtbl.make_key([gc.KeyTuple("$sid", a.clone_sid)])]
        # $mirror.cfg is ACTION-based on this SDE (actions '$normal' / '$coalescing');
        # make_data REQUIRES the action name or it fails INVALID_ARGUMENT. We use
        # '$normal' (a plain unicast I2E mirror to dp68).
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
        out["mirror_sid"] = {"sid": a.clone_sid, "egress_port": a.port_pgen}
    except Exception as e:
        out["mirror_err"] = str(e)[:80]

    # --- (2) pgen_recirc parser value_set: recognise generated tokens ---------
    # Generated packets lead with pktgen_recirc_header_t byte0 = pad(3)=0|pipe(2)|app(3).
    # The P4 parser matches this byte via value_set pgen_recirc (.p4:363) in
    # from_pgen (.p4:431-434). TF1: byte = (pipe<<3)|app_id.
    #
    # MASK = 0xFF (EXACT), NOT the SDE's 0x1F. Cross-check against this P4: on dp68
    # the parser also sees the recirculated clone, whose leading byte is the marker
    # 0xE1 (.p4:201). Under the SDE mask 0x1F, 0xE1 & 0x1F == 0x01 would ALIAS to
    # app_id 1 and mis-admit the clone as a token. An exact 0xFF match admits ONLY
    # the true pgen byte (pad=0, so byte in 0x00..0x1F) and lets 0xE1 fall through
    # to the drop path (.p4:433-434). 0xE1 can never equal a valid pgen byte
    # ((pipe<<3)|app <= 0x1F), so no token is ever missed.
    vs_byte = (a.pipe << 3) | a.app_id
    vs_mask = 0xFF
    out["pgen_recirc_vs"] = {"byte": vs_byte, "mask": vs_mask, "app_id": a.app_id, "pipe": a.pipe}
    try:
        vs = bi.table_get("pipe.IgParser.pgen_recirc")
        # Value_set name resolves as 'pipe.IgParser.pgen_recirc' (parser 'IgParser' +
        # value_set 'pgen_recirc', .p4:354,363). The scope attribute can only be set
        # while the table is EMPTY, so it is a one-time op wrapped separately; a failure
        # on a re-run (entry already present) must NOT block the entry (idempotency).
        if bfr_pb2 is not None:
            try:
                vs.attribute_entry_scope_set(
                    tgt,
                    config_pipe_scope=True, predefined_pipe_scope=True,
                    predefined_pipe_scope_val=bfr_pb2.Mode.SINGLE,
                    config_gress_scope=True, predefined_gress_scope_val=bfr_pb2.Mode.ALL,
                    config_prsr_scope=True, predefined_prsr_scope_val=bfr_pb2.Mode.SINGLE)
            except Exception as se:
                out["pgen_recirc_scope_note"] = "scope already set (ok on re-run): " + str(se)[:40]
        vtgt = gc.Target(device_id=0, pipe_id=a.pipe, prsr_id=PGEN_PRSR_ID)
        vkey = [vs.make_key([gc.KeyTuple("f1", vs_byte, vs_mask)])]
        try:
            vs.entry_del(vtgt, vkey)      # idempotent: clear any prior entry first
        except Exception:
            pass
        vs.entry_add(vtgt, vkey)
        out["pgen_recirc_vs_added"] = True
    except Exception as e:
        out["pgen_recirc_vs_err"] = "TODO(silicon): " + str(e)[:70]

    # --- (3) tf1.pktgen.port_cfg: enable pktgen + pattern matching on dp68 ----
    # (report §A: PktgenPortCfg fields pktgen_enable / pattern_matching_enable;
    #  SDE recirc app sets BOTH on the recirc port, key = dev_port.)
    try:
        pcfg = bi.table_get("tf1.pktgen.port_cfg")
        pkey = [pcfg.make_key([gc.KeyTuple("dev_port", a.port_pgen)])]
        # dp68 needs ALL THREE flags for a recirc-PATTERN trigger (confirmed on this
        # switch vs the local working gc_pktgen_test.py + ackA_setup.py):
        #   pktgen_enable        - run the generator on dp68
        #   recirculation_enable - let the mirrored clone loop egress->ingress on dp68
        #                          (WITHOUT this the clone never comes back to trigger)
        #   pattern_matching_enable - arm the recirc-pattern matcher
        # No $PORT entry is needed for dp68 (internal recirc port; up=False is expected).
        pcfg.entry_mod(tgt, pkey, [pcfg.make_data([
            gc.DataTuple("pktgen_enable", bool_val=True),
            gc.DataTuple("recirculation_enable", bool_val=True),
            gc.DataTuple("pattern_matching_enable", bool_val=True)])])
        out["port_cfg_pgen"] = {"dev_port": a.port_pgen, "pktgen_enable": True,
                                "recirculation_enable": True, "pattern_matching_enable": True}
    except Exception as e:
        out["port_cfg_err"] = str(e)[:80]

    # --- (4) tf1.pktgen.pkt_buffer: load the 0x88C1 blocker-token template -----
    # (report §A + SDE: table tf1.pktgen.pkt_buffer, key pkt_buffer_offset +
    #  pkt_buffer_size, data 'buffer'. Buffer EXCLUDES the 6 B pktgen header,
    #  which the P4 skips via advance(48) at .p4:447.)
    template = build_token_template(a.token_len)
    out["pkt_buffer"] = {
        "offset": a.buf_offset, "size": len(template),
        "first_bytes": template[:23].hex(),  # eth(14)+ibspg(7)+2 pad, for review
    }
    try:
        pbuf = bi.table_get("tf1.pktgen.pkt_buffer")
        pbuf.entry_mod(
            tgt,
            [pbuf.make_key([gc.KeyTuple("pkt_buffer_offset", a.buf_offset),
                            gc.KeyTuple("pkt_buffer_size", len(template))])],
            [pbuf.make_data([gc.DataTuple("buffer", bytearray(template))])])
    except Exception as e:
        out["pkt_buffer_err"] = str(e)[:80]

    # --- (5) tf1.pktgen.app_cfg: recirc trigger, K=64 tokens, one batch --------
    # (report §A: action 'trigger_recirc_pattern' with pattern_value/pattern_mask;
    #  zero-based counts -> 64 pkts = packets_per_batch_cfg 63, 1 batch = batch_count_cfg 0.)
    # pattern pins recirc-tag byte0 == 0xE1 (CLONE_TAG_MARKER, .p4:201) and masks the
    # gen-carrying low 3 bytes as don't-care. Mask semantics: bit-set = significant
    # (SDE uses all-ones for a full match), so 0xFF000000 pins ONLY byte0.
    #   - excludes generated tokens (their header byte0 = (pipe<<3)|app = 0x01 != 0xE1,
    #     and they egress to dp8 not dp68 -> never reach the matcher)  -> no self-retrigger
    #   - excludes ordinary traffic (never recirculated on dp68)
    pattern_value = CLONE_TAG_MARKER << 24          # 0xE1000000
    pattern_mask = 0xFF000000                        # pin byte0 only
    out["app_cfg"] = {
        "app_id": a.app_id, "packets_per_batch_cfg": a.k - 1, "batch_count_cfg": 0,
        "pattern_value": "0x%08X" % pattern_value, "pattern_mask": "0x%08X" % pattern_mask,
        "pkt_len": len(template), "app_enable": app_enable,
    }
    try:
        acfg = bi.table_get("tf1.pktgen.app_cfg")
        data_flds = [
            gc.DataTuple("pattern_value", pattern_value),
            gc.DataTuple("pattern_mask", pattern_mask),
            gc.DataTuple("pkt_len", len(template)),
            gc.DataTuple("pkt_buffer_offset", a.buf_offset),
            # pipe_local_source_port sets the ingress_port the generated tokens CARRY.
            # It is REQUIRED on this switch (confirmed vs the working gc_pktgen_test.py):
            # without it the tokens arrive on the wrong port, miss the parser from_pgen
            # path, and get dropped as port_ok==0. Set to dp68 so they land on the
            # P4's PORT_PGEN / from_pgen path (.p4:182,411,431) and the value_set admits
            # them. (The SDE's "implicit on TF1" note does NOT hold here.)
            gc.DataTuple("pipe_local_source_port", a.port_pgen),
            gc.DataTuple("increment_source_port", bool_val=False),
            gc.DataTuple("batch_count_cfg", 0),        # 1 batch  (zero-based, report §A)
            gc.DataTuple("packets_per_batch_cfg", a.k - 1),  # 64 pkts -> 63
            gc.DataTuple("ipg", 0),
            gc.DataTuple("ibg", 0),
            gc.DataTuple("trigger_counter", 0),
            gc.DataTuple("batch_counter", 0),
            gc.DataTuple("pkt_counter", 0),
            gc.DataTuple("app_enable", bool_val=app_enable),
        ]
        acfg.entry_mod(
            tgt,
            [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
            [acfg.make_data(data_flds, "trigger_recirc_pattern")])
    except Exception as e:
        out["app_cfg_err"] = str(e)[:80]


# ===========================================================================
# Lightweight native<->protected A/B toggle (flip app_enable only)
# ===========================================================================
def toggle_app_enable(bi, tgt, a, out):
    """Flip ONLY tf1.pktgen.app_cfg.app_enable on the already-configured app, so a
    trial can switch native<->protected without re-initialising ports/queues.
    Mirrors the SDE enable/disable idiom (app_cfg entry_mod with app_enable only)."""
    app_enable = (a.mode == "protected")
    try:
        acfg = bi.table_get("tf1.pktgen.app_cfg")
        acfg.entry_mod(
            tgt,
            [acfg.make_key([gc.KeyTuple("app_id", a.app_id)])],
            [acfg.make_data([gc.DataTuple("app_enable", bool_val=app_enable)])])
        out["app_enable_toggled"] = {"mode": a.mode, "app_enable": app_enable, "app_id": a.app_id}
    except Exception as e:
        out["app_enable_toggle_err"] = str(e)[:80]


# ===========================================================================
# Per-trial reset (inherited)
# ===========================================================================
def do_reset(bi, tgt, a, out):
    rz = {}
    for nm in [x for x in a.regs.split(",") if x]:
        try:
            t = bi.table_get(a.reg_prefix + nm)
            k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
            data = None
            for fn in ("Ingress.%s.f1" % nm, "%s.f1" % nm, "f1"):
                try:
                    data = t.make_data([gc.DataTuple(fn, 0)])
                    break
                except Exception:
                    continue
            t.entry_mod(tgt, [k], [data])
            rz[nm] = 0
        except Exception as e:
            rz[nm] = "ERR:" + str(e)[:60]
    out["regs_reset"] = rz
    cz = {}
    for nm in [x for x in a.counters.split(",") if x]:
        try:
            t = bi.table_get(a.ctr_prefix + nm)
            k = t.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])
            t.entry_mod(tgt, [k], [t.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0)])])
            cz[nm] = 0
        except Exception as e:
            cz[nm] = "ERR:" + str(e)[:60]
    out["counters_reset"] = cz


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prog", default=PROG_DEFAULT)
    ap.add_argument("--config", action="store_true")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--toggle", action="store_true",
                    help="flip ONLY pktgen app_enable to match --mode (no port/queue re-init)")
    ap.add_argument("--mode", choices=["native", "protected"], default="native",
                    help="native = pktgen app disabled; protected = app enabled (request-triggered burst)")
    # ports
    ap.add_argument("--port-l", type=int, default=PORT_L)
    ap.add_argument("--port-vision", type=int, default=PORT_VISION)
    ap.add_argument("--port-relay", type=int, default=PORT_RELAY)
    ap.add_argument("--port-pgen", type=int, default=PORT_PGEN)
    # dp8 hold-ring queues (port group inherited from the ibspg loopback config)
    ap.add_argument("--pg-l", type=int, default=2)
    ap.add_argument("--pg-l-nr", type=int, default=0)
    ap.add_argument("--qb", type=int, default=QID_BLOCK)
    ap.add_argument("--qh", type=int, default=QID_RESP)
    # G guard interval (256 ns ticks); None => leave the P4 default in place
    ap.add_argument("--g-ticks", type=lambda s: int(s, 0), default=None)
    # pktgen
    ap.add_argument("--pipe", type=int, default=0)
    ap.add_argument("--app-id", type=int, default=APP_ID_DEFAULT)
    ap.add_argument("--k", type=int, default=64, help="blocker tokens per trigger (K)")
    ap.add_argument("--buf-offset", type=int, default=0, help="pkt_buffer_offset (16 B aligned)")
    ap.add_argument("--token-len", type=int, default=TOKEN_LEN)
    ap.add_argument("--clone-sid", type=int, default=CLONE_SID)
    ap.add_argument("--mirror-max-len", type=int, default=128,
                    help="$max_pkt_len for the clone; only the leading 4 B tag is functionally required")
    # reset
    ap.add_argument("--regs", default="reg_tag,reg_deadline,reg_t_ack,reg_native_clrt,reg_protection,"
                                       "reg_ts_first_block,reg_ts_ack_arm,reg_ts_block_term,reg_ts_first_resp_release")
    ap.add_argument("--counters", default="ctr_arm,ctr_arm_clone,ctr_pktgen_admit,ctr_pktgen_drop,"
                                          "ctr_block_enq,ctr_block_loop,ctr_resp_enq,ctr_resp_release")
    ap.add_argument("--reg-prefix", default="pipe.Ingress.")
    ap.add_argument("--ctr-prefix", default="pipe.Ingress.")
    a = ap.parse_args()

    iface = gc.ClientInterface("localhost:50052", client_id=63, device_id=0, notifications=None)
    iface.bind_pipeline_config(a.prog)
    bi = iface.bfrt_info_get(a.prog)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)
    tgt0 = gc.Target(device_id=0, pipe_id=0)
    out = {"prog": a.prog, "authored_at_compile_time": True, "silicon_validated": False}

    if a.config:
        config_hold(bi, tgt, tgt0, a, out)
        config_pktgen(bi, tgt, tgt0, a, out)

    if a.toggle and not a.config:
        toggle_app_enable(bi, tgt, a, out)

    if a.reset:
        do_reset(bi, tgt, a, out)

    print("PKTGENSETUP " + json.dumps(out))


if __name__ == "__main__":
    main()

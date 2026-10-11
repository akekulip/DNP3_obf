#!/usr/bin/env python3
"""Compose ONE Tofino-1 pipeline that carries both hardware-run mechanisms:

  ingress = the seven-stage timing candidate (stage_reduction/src/defense4_timing.p4, built with U_BOR),
            unchanged: its queue ladder, blocker reservoirs, BOR OPERATE hold and every release decision;
  egress  = role E of the response-only target (core/response_only/make_e.py, from the unmodified
            protocol/case4_response_path.p4): the 58-byte response padder fused with the sequence/ACK
            mapper, plus two edits made here (below).

Why this fits on paper: the timing candidate places in 7 ingress / 0 egress stages (stage_reduction
README, SDE 9.13.1 and 9.13.2); the response path places in 1 ingress / 12 egress (fused_12), and its one
ingress stage is a port-forwarding stub that the timing ingress replaces. Measured with the open-source
bf-p4c 9.13.4: 10 ingress / 12 egress before edits S3/S4 (simplify/evidence/opensource_9134_01), 10 / 11 with
them (opensource_9134_02), critical path 10, 158 PHV containers, the fifth egress checksum unit accepted.
The switch's SDE 9.13.2 build is still to be run.

Why the padder runs exactly once per frame: the timing ingress sends every hold and reservoir frame to
its loopback ports with ig_tm_md.bypass_egress = 1 (PORT_L dp8, PORT_BOR_L dp10), and every final
departure (D3_TO_FWD, cmt_op_relay) with bypass_egress = 0. Mirror clones to dp68 do run egress, so the
egress parser is dispatched on eg.egress_port and parses the mapper headers only for

  * MASTER_PORT (9):  final departure to the master -> forward mapper, padding, SYN-ACK arming;
  * RELAY_PORT (64):  final departure to the outstation -> reverse ACK/window mapper and SYN option scrub.

Every other egress port leaves the parser at `accept`: no lookup, no mapper state, bytes unchanged
(TRANSPORT_MAPPER_SPEC.md: the mapper advances once per egress pass, so a second pass would shift twice).
conn also keys on eg.egress_port (make_e edit 2), so forward rows exist only at 9, reverse only at 64.

Edit S1 (here): the reverse-pass port is RELAY_PORT instead of N_ACK_RETURN. There is no N in this
target; the master's ACKs leave for the outstation directly from the timing ingress.

Edit S2 (here): SYN option scrub. The mapper arms only on an MSS-only SYN-ACK (shape_t, SH_SYNACK_OK).
On every handshake in the relay captures (tools/syn_option_audit.py: 198 of 198) the master offers
MSS, SACK-permitted, Timestamps and Window Scale, and the SEL-751 answers with all four, so the mapper
never arms on the real rig and responses would leave at native size. The relay only echoes options it
is offered, so on the master's SYN (offset 10, SYN without ACK, first option MSS, a configured reverse
connection) the 16 option bytes after MSS are rewritten to NOP (kind 1). Removing optional SYN options
is legal TCP; the relay then answers MSS-only and the mapper arms. The TCP checksum is rebuilt in the
egress deparser from the parser residual, the same incremental method E already uses, in its own
single-term case (m.scrub), summing only headers that are valid on that SYN. That adds a fifth egress
deparser checksum unit, which the 9.13.4 build accepted.

  python3 make_single_pipe.py <out.p4> [--master-port=9] [--relay-port=64]
"""
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent.parent
TIMING = CASE4.parent
RESPONSE_ONLY = CASE4 / 'integration' / 'core' / 'response_only'
sys.path.insert(0, str(RESPONSE_ONLY))
sys.path.insert(0, str(CASE4 / 'integration' / 'read'))
import compose_t_response as ct  # noqa: E402  (strip_main, role)
import make_e  # noqa: E402

TIMING_SRC = TIMING / 'stage_reduction' / 'src' / 'defense4_timing.p4'
MASTER_PORT, RELAY_PORT = 9, 64

# ---------------------------------------------------------------- edit S1: reverse pass on the relay port
GATE_OLD = "transition select(eg.egress_port) { 9w%d: eth; 9w%d: eth; default: accept; }" % (
    make_e.MASTER_PORT, make_e.N_ACK_RETURN)
GATE_COMMENT_OLD = "/* response-only target: mapper headers only on final master departure and N's normalization pass */"
GATE_COMMENT_NEW = "/* single-pipe target: mapper headers only on final departure to the master or to the outstation */"

# ---------------------------------------------------------------- edit S2: SYN option scrub
SOPT_HEADER_ANCHOR = "header mss_h { bit<8> kind; bit<8> len; bit<16> mss; }\n"
SOPT_HEADER = (SOPT_HEADER_ANCHOR +
               "/* single-pipe edit S2: the master's 20 SYN option bytes, MSS first, the rest as four words */\n"
               "header sopt_h { bit<16> mss_kl; bit<16> mss; bit<32> w0; bit<32> w1; bit<32> w2; bit<32> w3; }\n")
HDRS_OLD = "struct headers_t { eth_h eth; ip_h ip; tcp_h tcp; mss_h mss; dl_h dl;"
HDRS_NEW = "struct headers_t { eth_h eth; ip_h ip; tcp_h tcp; mss_h mss; sopt_h sopt; dl_h dl;"
META_OLD = "    bit<8>  ip_odd; bit<8> tcp_odd; bit<8> has_mss;\n"
META_NEW = "    bit<8>  ip_odd; bit<8> tcp_odd; bit<8> has_mss;\n    bit<1>  scrub;   // single-pipe edit S2\n"
INIT_OLD = "m.ip_odd = 0; m.tcp_odd = 0; m.has_mss = 0;"
INIT_NEW = "m.ip_odd = 0; m.tcp_odd = 0; m.has_mss = 0; m.scrub = 0;"
TCP_SEL_OLD = "transition select(hdr.tcp.offset) { 4w5: dl_len; 4w6: mss; default: tcp_odd; }"
TCP_SEL_NEW = ("transition select(hdr.tcp.offset, hdr.tcp.flags) { (4w5, _): dl_len; (4w6, _): mss;\n"
               "            (4w10, 8w0x02 &&& 8w0x12): syn_opts; default: tcp_odd; }   // S2: SYN without ACK, 20 option bytes")
MSS_STATE_OLD = "    state mss { pkt.extract(hdr.mss); m.has_mss = 1; transition accept; }\n"
MSS_STATE_NEW = (MSS_STATE_OLD +
                 "    /* S2: extracted after the residual deposit, so the parser subtracts these 20 bytes too */\n"
                 "    state syn_opts { pkt.extract(hdr.sopt); transition accept; }\n")
SCRUB_TABLE_ANCHOR = "    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) widen_len;\n"
SCRUB_TABLE = (
    "    /* S2: keep MSS, rewrite every other SYN option byte to NOP, on a configured reverse connection only */\n"
    "    action scrub_syn() { hdr.sopt.w0 = 32w0x01010101; hdr.sopt.w1 = 32w0x01010101;\n"
    "                         hdr.sopt.w2 = 32w0x01010101; hdr.sopt.w3 = 32w0x01010101; m.scrub = 1; }\n"
    "    table syn_scrub_t {\n"
    "        key = { m.dir : exact; m.shape : exact; hdr.sopt.isValid() : exact; hdr.sopt.mss_kl : exact; }\n"
    "        actions = { scrub_syn; NoAction; } size = 1; const default_action = NoAction();\n"
    "        const entries = { (2, SH_SYN, true, 16w0x0204) : scrub_syn(); }\n"
    "    }\n" + SCRUB_TABLE_ANCHOR)
SCRUB_APPLY_ANCHOR = "        count_t.apply();\n"
SCRUB_APPLY = "        syn_scrub_t.apply();   // S2: SH_SYN never takes the forward, padding or reverse-ACK branch\n" + SCRUB_APPLY_ANCHOR
CSUM_DECL_OLD = "Checksum() ip_new; Checksum() tcp_plain; Checksum() tcp_read; Checksum() tcp_ctl;"
CSUM_DECL_NEW = CSUM_DECL_OLD + " Checksum() tcp_syn;"
DEPARSE_ANCHOR = "        if (hdr.rtp.isValid()) {\n"
DEPARSE_SCRUB = (
    "        /* S2: single-term case, exclusive with m.changed and both padding cases (a SYN is never padded or\n"
    "           reverse-translated). Only fields valid on that SYN are summed: seq, window, the new options. */\n"
    "        if (m.scrub == 1w1) {\n"
    "            hdr.tcp.checksum = tcp_syn.update({hdr.tcp.seq, hdr.tcp.window,\n"
    "                hdr.sopt.mss_kl, hdr.sopt.mss, hdr.sopt.w0, hdr.sopt.w1, hdr.sopt.w2, hdr.sopt.w3,\n"
    "                m.residual});\n"
    "        }\n" + DEPARSE_ANCHOR)
EMIT_OLD = "pkt.emit(hdr.tcp); pkt.emit(hdr.mss); pkt.emit(hdr.dl);"
EMIT_NEW = "pkt.emit(hdr.tcp); pkt.emit(hdr.mss); pkt.emit(hdr.sopt); pkt.emit(hdr.dl);"

S2_EDITS = ((SOPT_HEADER_ANCHOR, SOPT_HEADER), (HDRS_OLD, HDRS_NEW), (META_OLD, META_NEW), (INIT_OLD, INIT_NEW),
            (TCP_SEL_OLD, TCP_SEL_NEW), (MSS_STATE_OLD, MSS_STATE_NEW), (SCRUB_TABLE_ANCHOR, SCRUB_TABLE),
            (SCRUB_APPLY_ANCHOR, SCRUB_APPLY), (CSUM_DECL_OLD, CSUM_DECL_NEW), (DEPARSE_ANCHOR, DEPARSE_SCRUB),
            (EMIT_OLD, EMIT_NEW))

# ---------------------------------------------------------------- edit S3: reverse window fold (one egress stage)
# The reverse chain was img_wend_t (r) -> rev_prep_t (y, z, pm, t) -> classify_rev (s_end = y + t) -> window_t
# (test s_end, narrow it). Of s_end = (r + window) + (q - p), only r comes from the img_wend register, which
# sits after the forward classifier; q - p + window is ready once img_start / img_end have run. S3 computes
# u = q - p + window in early dir-2 tables, rev_prep writes u = r + u (the old s_end, mod 2^32), and
# classify_rev keys on u so the window test and narrowing happen in its own actions: window_t is gone.
# The new fields win32 and u leave m.t and m.s_end, which the forward path also uses, untouched.
S3_META_OLD = "    bit<8>  result; bit<1> changed; bit<1> pad; bit<8> wide;\n"
S3_META_NEW = S3_META_OLD + "    bit<32> win32; bit<32> u;   // single-pipe edit S3: widened window; q - p + window, then r + that\n"
S3_PREP_OLD = ("    action rev_prep() { m.y = m.r + widen_win.get({hdr.tcp.window}); m.z = m.r + IMAGE_LEN;"
               " m.pm = m.q + m.r; m.t = m.q - m.p; }\n")
S3_PREP_NEW = (
    "    /* S3: everything in the window edge except r, computed before img_wend_t on reverse packets */\n"
    "    /* m.changed set here, not in classify_rev: every reverse outcome rewrites the segment except rev_drop,\n"
    "       which drops it, so its checksum is moot. The deparser condition then no longer waits for classify_rev. */\n"
    "    /* One table: u = q - p, the widened window, and m.changed; img_wend_t's reverse action adds the window. */\n"
    "    action rev_qp() { m.u = m.q - m.p; m.win32 = widen_win.get({hdr.tcp.window}); m.changed = 1; }\n"
    "    table rev_qp_t {\n"
    "        key = { m.dir : exact; } actions = { rev_qp; NoAction; } size = 1;\n"
    "        const default_action = NoAction(); const entries = { 2 : rev_qp(); }\n"
    "    }\n"
    "    action rev_prep() { m.y = m.r + m.win32; m.z = m.r + IMAGE_LEN; m.pm = m.q + m.r; m.u = m.r + m.u; }\n")
S3_WEND_OLD = "    action do_wend_rev() { m.r = wend_rev.execute(m.idx); }\n"
S3_WEND_NEW = "    action do_wend_rev() { m.r = wend_rev.execute(m.idx); m.u = m.u + m.win32; }   // S3: u = q - p + window\n"
S3_CLASSIFY_OLD = (
    "    action rev_withhold_open() { hdr.tcp.ack = m.p; m.s_end = m.y + m.t; m.wide = 1;\n"
    "                                 m.result = OUT_REV_WITHHOLD; m.changed = 1; }\n"
    "    action rev_drop() { m.result = OUT_REV_DROP_STALE; md.drop_ctl = 3w1; }\n"
    "    table classify_rev {\n"
    "        key = { m.r : ternary; m.z : ternary; m.y : ternary; }\n"
    "        actions = { rev_translate; rev_withhold_zero; rev_withhold_open; rev_drop; } size = 4;\n"
    "        const default_action = rev_drop();\n"
    "        const entries = {\n"
    "            (32w0 &&& 32w0x80000000, _, _)                                    : rev_translate();\n"
    "            (_, 32w0 &&& 32w0x80000000, 32w0x80000000 &&& 32w0x80000000)     : rev_withhold_zero();\n"
    "            (_, 32w0 &&& 32w0x80000000, 32w0 &&& 32w0x80000000)              : rev_withhold_open();\n"
    "        }\n"
    "    }\n"
    "    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;\n"
    "    action window_exact() { hdr.tcp.window = narrow_win.get({m.s_end[15:0]}); }\n"
    "    action window_clamp() { hdr.tcp.window = 0xffff; }\n"
    "    table window_t {\n"
    "        key = { m.s_end : ternary; }\n"
    "        actions = { window_exact; window_clamp; } size = 2; const default_action = window_clamp();\n"
    "        const entries = { 32w0 &&& 32w0xFFFF0000 : window_exact(); 32w0 &&& 32w0 : window_clamp(); }\n"
    "    }\n")
S3_CLASSIFY_NEW = (
    "    /* S3: window_t folded in. u holds the old s_end; its upper half picks exact or clamped, as window_t did. */\n"
    "    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;\n"
    "    action rev_withhold_open() { hdr.tcp.ack = m.p; hdr.tcp.window = narrow_win.get({m.u[15:0]}); m.wide = 1;\n"
    "                                 m.result = OUT_REV_WITHHOLD; }\n"
    "    action rev_withhold_clamp() { hdr.tcp.ack = m.p; hdr.tcp.window = 0xffff; m.wide = 1;\n"
    "                                  m.result = OUT_REV_WITHHOLD; }\n"
    "    action rev_drop() { m.result = OUT_REV_DROP_STALE; md.drop_ctl = 3w1; }\n"
    "    table classify_rev {\n"
    "        key = { m.r : ternary; m.z : ternary; m.y : ternary; m.u : ternary; }\n"
    "        actions = { rev_translate; rev_withhold_zero; rev_withhold_open; rev_withhold_clamp; rev_drop; } size = 4;\n"
    "        const default_action = rev_drop();\n"
    "        const entries = {\n"
    "            (32w0 &&& 32w0x80000000, _, _, _)                                            : rev_translate();\n"
    "            (_, 32w0 &&& 32w0x80000000, 32w0x80000000 &&& 32w0x80000000, _)             : rev_withhold_zero();\n"
    "            (_, 32w0 &&& 32w0x80000000, 32w0 &&& 32w0x80000000, 32w0 &&& 32w0xFFFF0000) : rev_withhold_open();\n"
    "            (_, 32w0 &&& 32w0x80000000, 32w0 &&& 32w0x80000000, _)                       : rev_withhold_clamp();\n"
    "        }\n"
    "    }\n")
S3_APPLY_EARLY_OLD = "        img_start_t.apply();\n"
S3_APPLY_EARLY_NEW = (S3_APPLY_EARLY_OLD +
    "        if (m.dir == 2 && m.shape == SH_ACK && m.mode == 1) { rev_qp_t.apply(); }   // S3\n")
# The outcome counter is read after classify_rev, so count_t would still need a stage of its own. S3 instead
# has classify_rev count its own outcome code and puts count_t (and the SYN scrub, which never sees a
# reverse ACK) in the else branch of the reverse condition: the two counter users are mutually exclusive
# by control flow and share one stage. The counter, its size and every outcome index are unchanged.
# Equivalence: pad == 1 only on dir 1, so `if (pad) .. else if (rev) ..` equals `if (rev) .. else { if (pad) .. }`.
S3_APPLY_WINDOW_OLD = (
    "        if (m.pad == 1) {\n"
    "            if (m.read_shape == 1) { read_pad_t.apply(); } else { ctl_pad_t.apply(); }\n"
    "        } else if (m.dir == 2 && m.shape == SH_ACK && m.mode == 1) {   // exclusive with padding\n"
    "            rev_prep_t.apply(); classify_rev.apply();\n"
    "            if (m.wide == 1) { window_t.apply(); }\n"
    "        }\n"
    "        syn_scrub_t.apply();   // S2: SH_SYN never takes the forward, padding or reverse-ACK branch\n"
    "        count_t.apply();\n")
S3_APPLY_WINDOW_NEW = (
    "        if (m.dir == 2 && m.shape == SH_ACK && m.mode == 1) {   // S3: reverse first; pad == 1 never holds here\n"
    "            rev_prep_t.apply(); classify_rev.apply();   // window_t folded in; classify_rev counts its own outcome\n"
    "        } else {\n"
    "            if (m.pad == 1) {\n"
    "                if (m.read_shape == 1) { read_pad_t.apply(); } else { ctl_pad_t.apply(); }\n"
    "            }\n"
    "            syn_scrub_t.apply();   // S2: SH_SYN never takes the forward, padding or reverse-ACK branch\n"
    "            count_t.apply();\n"
    "        }\n")
S3_COUNTER_DECL = "    Counter<bit<32>, bit<8>>(32, CounterType_t.PACKETS) outcome;\n"
S3_COUNTER_OLD = S3_COUNTER_DECL + "    action count() { outcome.count(m.result); }\n"
S3_COUNTER_NEW = "    action count() { outcome.count(m.result); }   // S3: outcome is declared before classify_rev\n"
S3_REV_COUNT = (
    ("    action rev_translate() { hdr.tcp.ack = m.pm; m.result = OUT_REV_TRANSLATE; m.changed = 1; }\n",
     S3_COUNTER_DECL +
     "    action rev_translate() { hdr.tcp.ack = m.pm; m.result = OUT_REV_TRANSLATE;"
     " outcome.count(OUT_REV_TRANSLATE); }\n"),
    ("    action rev_withhold_zero() { hdr.tcp.ack = m.p; hdr.tcp.window = 0; m.result = OUT_REV_WITHHOLD; m.changed = 1; }\n",
     "    action rev_withhold_zero() { hdr.tcp.ack = m.p; hdr.tcp.window = 0; m.result = OUT_REV_WITHHOLD;"
     " outcome.count(OUT_REV_WITHHOLD); }\n"),
    ("                                 m.result = OUT_REV_WITHHOLD; }\n"
     "    action rev_withhold_clamp() { hdr.tcp.ack = m.p; hdr.tcp.window = 0xffff; m.wide = 1;\n"
     "                                  m.result = OUT_REV_WITHHOLD; }\n"
     "    action rev_drop() { m.result = OUT_REV_DROP_STALE; md.drop_ctl = 3w1; }\n",
     "                                 m.result = OUT_REV_WITHHOLD; outcome.count(OUT_REV_WITHHOLD); }\n"
     "    action rev_withhold_clamp() { hdr.tcp.ack = m.p; hdr.tcp.window = 0xffff; m.wide = 1;\n"
     "                                  m.result = OUT_REV_WITHHOLD; outcome.count(OUT_REV_WITHHOLD); }\n"
     "    action rev_drop() { m.result = OUT_REV_DROP_STALE; md.drop_ctl = 3w1; outcome.count(OUT_REV_DROP_STALE); }\n"),
)
S3_EDITS = ((S3_META_OLD, S3_META_NEW), (S3_PREP_OLD, S3_PREP_NEW), (S3_CLASSIFY_OLD, S3_CLASSIFY_NEW),
            (S3_APPLY_EARLY_OLD, S3_APPLY_EARLY_NEW), (S3_APPLY_WINDOW_OLD, S3_APPLY_WINDOW_NEW),
            (S3_COUNTER_OLD, S3_COUNTER_NEW), (S3_WEND_OLD, S3_WEND_NEW)) + S3_REV_COUNT


# ---------------------------------------------------------------- edit S4: fewer CRC tables (logical table IDs)
# Ingress and egress share each stage's 16 logical table IDs, and stages 0-3 are full; the timing ingress, 7
# stages alone, was pushed to 10. E spent 8 IDs in stages 1-2 on one-hash CRC tables. S4 keeps every hash and
# every action unchanged and only groups the actions into fewer tables, by the header validity each already had:
# crc_dl_t: link header (+ CONTROL padded tail1); crc_read_a_t: rb0+rb1; crc_read_b_t: rt + READ padded tail;
# crc_ctl_a_t: cb0+ct. 8 tables -> 4.
S4_DROP = ("    table in_dl_t{actions={in_dl;}size=1;const default_action=in_dl();}\n",
           "    table in_rb0_t{actions={in_rb0;}size=1;const default_action=in_rb0();}\n",
           "    table in_rb1_t{actions={in_rb1;}size=1;const default_action=in_rb1();}\n",
           "    table in_rt_t{actions={in_rt;}size=1;const default_action=in_rt();}\n",
           "    table in_cb0_t{actions={in_cb0;}size=1;const default_action=in_cb0();}\n",
           "    table in_ct_t{actions={in_ct;}size=1;const default_action=in_ct();}\n",
           "    table crc_read_tail_t{actions={crc_read_tail;}size=1;const default_action=crc_read_tail();}\n")
# bf-p4c allows 32 bits of hash output per table (two 16-bit CRCs), and a hash action must run on the hit
# pathway; crc_dl_t is keyed on the CONTROL header so both of its cases are hits.
S4_TABLES_OLD = "    table crc_ctl_tail1_t{actions={crc_ctl_tail1;}size=1;const default_action=crc_ctl_tail1();}\n"
S4_TABLES_NEW = (
    "    /* S4: the same CRC actions, grouped two per table (bf-p4c: at most 32 hash-output bits per table) */\n"
    "    action crc_dl_ctl(){in_dl();crc_ctl_tail1();}\n"
    "    table crc_dl_t{key={hdr.cb0.isValid():exact;}actions={crc_dl_ctl;in_dl;NoAction;}size=2;const default_action=NoAction();\n"
    "     const entries={true:crc_dl_ctl();false:in_dl();}}\n"
    "    action crc_read_a(){in_rb0();in_rb1();}\n"
    "    table crc_read_a_t{actions={crc_read_a;}size=1;const default_action=crc_read_a();}\n"
    "    action crc_read_b(){in_rt();crc_read_tail();}\n"
    "    table crc_read_b_t{actions={crc_read_b;}size=1;const default_action=crc_read_b();}\n"
    "    action crc_ctl_a(){in_cb0();in_ct();}\n"
    "    table crc_ctl_a_t{actions={crc_ctl_a;}size=1;const default_action=crc_ctl_a();}\n")
S4_APPLY = (
    ("        if (hdr.dl.isValid()) { in_dl_t.apply(); }\n",
     "        if (hdr.dl.isValid()) { crc_dl_t.apply(); }   // S4\n"),
    ("        if (hdr.rb0.isValid()) { read_profile.apply(); in_rb0_t.apply(); in_rb1_t.apply(); in_rt_t.apply(); crc_read_tail_t.apply(); }\n",
     "        if (hdr.rb0.isValid()) { read_profile.apply(); crc_read_a_t.apply(); crc_read_b_t.apply(); }   // S4\n"),
    ("        if (hdr.cb0.isValid()) { ctl_profile.apply(); in_cb0_t.apply(); in_ct_t.apply(); crc_ctl_tail1_t.apply(); }\n",
     "        if (hdr.cb0.isValid()) { ctl_profile.apply(); crc_ctl_a_t.apply(); }   // S4\n"))
S4_EDITS = tuple((t, "") for t in S4_DROP) + ((S4_TABLES_OLD, S4_TABLES_NEW),) + S4_APPLY


def replace_once(text, old, new):
    assert text.count(old) == 1, ('edit target not found exactly once', old[:70])
    return text.replace(old, new)


def egress_text(master_port=MASTER_PORT, relay_port=RELAY_PORT):
    text = make_e.generate()
    gate_new = "transition select(eg.egress_port) { 9w%d: eth; 9w%d: eth; default: accept; }" % (master_port, relay_port)
    text = replace_once(text, GATE_OLD, gate_new)
    text = replace_once(text, GATE_COMMENT_OLD, GATE_COMMENT_NEW)
    for old, new in S2_EDITS + S3_EDITS + S4_EDITS:
        text = replace_once(text, old, new)
    return text


# ---------------------------------------------------------------- edit S5: define the early hold_ok read
# tbl_select_deadlines, tbl_state_decode and tbl_resp_deadline key on meta.hold_ok at level 3, but tbl_hold_ok
# writes it only later in the same pass (after the BOR register chain); the parser never initialized it, so
# those three tables read undefined metadata (the stage_reduction README's retained defect). On hardware the
# OPERATE lane used the read lane's own offsets (2026-09-18 tail sweep; CLAIMS_AND_LIMITATIONS.md), which is
# what hold_ok == 0 selects. S5 zeroes hold_ok in the parser start state, so that measured behaviour is now the
# defined one. Selecting the OPERATE A/R deadlines instead would change claimed behaviour and is not done here.
S5_OLD = "        meta.is_pktgen       = 8w0;\n"
S5_NEW = S5_OLD + "        meta.hold_ok         = 8w0;   /* single-pipe edit S5: read at level 3 before tbl_hold_ok */\n"


def ingress_text():
    text = replace_once(TIMING_SRC.read_text(), S5_OLD, S5_NEW)
    # the build passes -DU_BOR (stage_reduction/build.py); make the composed file self-contained
    return '#define U_BOR 1\n' + text


COMMENTS = re.compile(r'/\*.*?\*/|//[^\n]*', re.S)


def role(text, ns):
    """compose_t_response.role, but declarations are collected from the text with comments removed:
    that role() also picks up words such as `is` and `so` after `control`/`struct` in comments and then
    prefixes them everywhere. Replacement still runs over the whole text, so comments stay consistent."""
    code = COMMENTS.sub(' ', text)
    names = set(re.findall(r'\b(?:header|struct|parser|control|typedef\s+[\w<>]+)\s+(\w+)', code))
    names.update(re.findall(r'\bconst\s+[\w<>]+\s+(\w+)\s*=', code))
    names -= {'apply'}
    pattern = r'\b(' + '|'.join(sorted(names, key=len, reverse=True)) + r')\b'
    return re.sub(pattern, lambda m: ns + '_' + m[0], text), sorted(names)


def generate(master_port=MASTER_PORT, relay_port=RELAY_PORT):
    d_out, d_names = role(ct.strip_main(ingress_text()), 'd')
    r_out, r_names = role(ct.strip_main(egress_text(master_port, relay_port)), 'r')
    source = ('/* GENERATED by case4_architecture/simplify/single_pipe/make_single_pipe.py -- do not edit.\n'
              '   One pipeline: seven-stage timing ingress (d_) + B\' padder/mapper egress (r_). Candidate; build status in simplify/README.md. */\n'
              '#include <core.p4>\n#include <tna.p4>\n' + d_out + '\n' + r_out +
              '\nPipeline(d_IgParser(), d_Ingress(), d_IgDeparser(), r_EgParser(), r_Egress(), r_EgDeparser()) pipe;\n'
              'Switch(pipe) main;\n')
    files = [TIMING_SRC, make_e.SOURCE, RESPONSE_ONLY / 'make_e.py', Path(__file__).resolve()]
    meta = dict(inputs={str(p.relative_to(TIMING)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
                master_port=master_port, relay_port=relay_port,
                source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                renamed=dict(d=len(d_names), r=len(r_names)),
                collisions_before_prefixing=sorted(set(d_names) & set(r_names)),
                compiled_with='open-source bf-p4c 9.13.4: simplify/evidence/opensource_9134_02')
    return source, meta


def main(argv):
    opts = dict(a[2:].split('=', 1) for a in argv if a.startswith('--'))
    args = [a for a in argv if not a.startswith('--')]
    if len(args) != 1:
        print(__doc__.splitlines()[-1].strip(), file=sys.stderr)
        return 2
    out = Path(args[0])
    src, meta = generate(int(opts.get('master-port', MASTER_PORT)), int(opts.get('relay-port', RELAY_PORT)))
    out.write_text(src)
    out.with_suffix('.inputs.json').write_text(json.dumps(meta, indent=2) + '\n')
    print('wrote', out, meta['renamed'], 'collisions before prefixing:', meta['collisions_before_prefixing'])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

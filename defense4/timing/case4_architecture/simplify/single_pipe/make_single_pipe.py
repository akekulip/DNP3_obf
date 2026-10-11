#!/usr/bin/env python3
"""Compose ONE Tofino-1 pipeline that carries both hardware-run mechanisms:

  ingress = the seven-stage timing candidate (stage_reduction/src/defense4_timing.p4, built with U_BOR),
            unchanged: its queue ladder, blocker reservoirs, BOR OPERATE hold and every release decision;
  egress  = role E of the response-only target (core/response_only/make_e.py, from the unmodified
            protocol/case4_response_path.p4): the 58-byte response padder fused with the sequence/ACK
            mapper, plus two edits made here (below).

Why this fits on paper: the timing candidate places in 7 ingress / 0 egress stages (stage_reduction
README, SDE 9.13.1 and 9.13.2); the response path places in 1 ingress / 12 egress (fused_12), and its one
ingress stage is a port-forwarding stub that the timing ingress replaces. Nothing here has been compiled:
this container has no bf-p4c. The fit, PHV and deparser-checksum budgets are open until a build says so.

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
deparser checksum unit; whether Tofino-1 accepts it is the first thing the build must show.

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


def replace_once(text, old, new):
    assert text.count(old) == 1, ('edit target not found exactly once', old[:70])
    return text.replace(old, new)


def egress_text(master_port=MASTER_PORT, relay_port=RELAY_PORT):
    text = make_e.generate()
    gate_new = "transition select(eg.egress_port) { 9w%d: eth; 9w%d: eth; default: accept; }" % (master_port, relay_port)
    text = replace_once(text, GATE_OLD, gate_new)
    text = replace_once(text, GATE_COMMENT_OLD, GATE_COMMENT_NEW)
    for old, new in S2_EDITS:
        text = replace_once(text, old, new)
    return text


def ingress_text():
    text = TIMING_SRC.read_text()
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
              '   One pipeline: seven-stage timing ingress (d_) + B\' padder/mapper egress (r_). UNCOMPILED candidate. */\n'
              '#include <core.p4>\n#include <tna.p4>\n' + d_out + '\n' + r_out +
              '\nPipeline(d_IgParser(), d_Ingress(), d_IgDeparser(), r_EgParser(), r_Egress(), r_EgDeparser()) pipe;\n'
              'Switch(pipe) main;\n')
    files = [TIMING_SRC, make_e.SOURCE, RESPONSE_ONLY / 'make_e.py', Path(__file__).resolve()]
    meta = dict(inputs={str(p.relative_to(TIMING)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
                master_port=master_port, relay_port=relay_port,
                source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                renamed=dict(d=len(d_names), r=len(r_names)),
                collisions_before_prefixing=sorted(set(d_names) & set(r_names)),
                compiled=False)
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

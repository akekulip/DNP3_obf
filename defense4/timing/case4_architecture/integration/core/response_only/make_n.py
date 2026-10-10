#!/usr/bin/env python3
"""Derive the response-only N (n_response_only.p4) from the binding generator's response_only profile
(connection/binding/generate.py generate(profile='response_only'): native coordinates, 37-byte native
responses, no frozen-decoy banks).

Approved 2026-10-09: retire M, the E cache and the final emitter for the response-only B' profile
(read/TIMING_QUEUE_MIGRATION_STATUS.md, "M's role"). native_binding.p4 is left untouched (its tests pin it
against a frozen oracle); this script applies the numbered edit groups below, each edit asserted to match once:

 1. route() no longer sets bypass_egress = 1. N's final departures to the front ports (9, 64) must cross
    pipe 0's egress, where the B' response path's transport mapper has to see every segment of a mapped
    connection. N's own recirculation (next_stage -> RETURN_PORT 68) keeps its explicit bypass_egress = 1,
    so the mapper still sees each packet only on its final pass.
 2. The one-byte pure-ACK segment is no longer classified as packet kind 12 ("replay_byte"). It only meant
    "replay the padded request image" in the retired request-padding design; with native requests it is an
    ordinary segment and is forwarded natively.
 3. STEP3_M_PORT, emit_replay and its read_terminal_t row are removed: N has no path into pipe 1.
 4. N_ACK_RETURN (execution document, "Preferred initial ACK placement"). One authoritative mapper state
    stays in pipe 0 egress; N never sees master-side padded coordinates. The ports table decides it, with two
    ternary keys (hdr.ip.isValid(), hdr.ip.proto). The master port's row (9, ip valid, proto 6) calls
    normalize_ack for EVERY master-side IPv4 TCP packet -- not only the ones N's parser recognises -- so the
    reverse mapper sees every master segment of a mapped connection (an unparsed length, IP options or a
    fragment included; E's egress parser handles those itself, fail-closed through odd_ip_t). The packet
    goes to N_ACK_RETURN with egress enabled and leaves m.port_valid at its parser value 0, so N's state
    tables do not run on that pass. Pipe 0 egress reverse-maps it once and it re-enters N on N_ACK_RETURN,
    whose row is an ordinary route(port). Rows carry explicit $MATCH_PRIORITY (core/response_only/cp.py).
    Keeping the test inside ports (not a separate if/table) matters: ingress and egress share a stage's
    table IDs, crossbar and hash units, and N's stage 1 is full (evidence/route_ab_01/response_only_03, _04).
 6. Provenance of direction (review finding C3). connection gains ig.ingress_port as its last key, so
    forward_flow is installed only for packets arriving on N_ACK_RETURN (every master packet does, after
    the lap) and reverse_flow only for the outstation port, plus one RETURN_PORT row per direction for N's
    own later passes (size 2 -> 4; rows in cp.py). A packet injected on the master link carrying
    the outstation's 4-tuple therefore gets no direction and is never admitted as an outstation response.
    E's conn table is bound to egress_port the same way (make_e.py).
 7. No recirculation loop, enforced in the P4 (review W2 and its two residual paths). One gateway at the
    head of the chain, before connection can rewrite tm.ucast_egress_port, drops:
      - any packet that arrived on N_ACK_RETURN or RETURN_PORT and whose ports row sends it to N_ACK_RETURN
        (a normalize_ack row on 70, or a mistaken route(70) row on 68 or 70: with egress enabled it would
        be reverse-mapped and re-enter on 70 forever; recirculation does not decrement TTL);
      - an envelope on RETURN_PORT that parsed with m.stage == 0 (epoch/generation 0, reachable only if N's
        32-bit allocate counter saturates), which would otherwise skip the chain and route back to 68.
    Edit 8 drops any packet whose connection row names N_ACK_RETURN as its output (forward_flow /
    reverse_flow set the egress port from that value, close_forward copies it back), as the first arm of
    the existing chain after guard.apply(): every bound packet passes that gateway on every pass. cp.py also asserts that no ports or connection row it
    produces sends anything to N_ACK_RETURN except the master's normalize_ack row. No table is added.
    N_ACK_RETURN = 70 (pipe 0, local 70): local 68-71 recirculate into the same pipe's ingress on the model
    (evidence/model_28/PORTS_PROPOSAL.md); 68 is N's RETURN_PORT; nothing in the repository uses pipe-0
    69-71. Confirmed on the physical switch by the coordinator, 2026-10-10: local 68, 69, 70 and 71 are each a
    separate, independently enabled, dedicated internal recirculation port (not lanes of one interface).

  python3 make_n.py [out.p4]     (default: n_response_only.p4 next to this script)
"""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BINDING = HERE.parent.parent / 'connection' / 'binding'
SOURCE = BINDING / 'generate.py'
sys.path.insert(0, str(BINDING))
import generate as binding_generate  # noqa: E402

EDITS = [
    ('action route(PortId_t port){m.port_valid=8w1;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}',
     '/* response-only: no bypass_egress here; final departures to 9/64 cross pipe 0 egress (B\' mapper) */\n'
     'action route(PortId_t port){m.port_valid=8w1;tm.ucast_egress_port=port;}'),
    ("(4w5,4w0,16w0,8w16):replay_byte;default:accept;}}", "default:accept;}}"),
    (" state replay_byte{pkt.extract(hdr.rb);tc.subtract(hdr.rb);m.packet_kind=8w12;transition finish;}\n", ""),
    ("const PortId_t STEP3_M_PORT=9w196;\n", ""),
    ("action emit_replay(){tm.ucast_egress_port=STEP3_M_PORT;m.emit_loop=8w0;count_term_bump.execute(4w0);}\n", ""),
    ("actions={emit_tev;emit_replay;terminal_strip;terminal_abort;}", "actions={emit_tev;terminal_strip;terminal_abort;}"),
    ("(8w12,32w0,32w0):emit_replay();", ""),
    # 4. N_ACK_RETURN normalization loop, decided in the ports table
    ("const PortId_t RETURN_PORT=9w68;\n",
     "const PortId_t RETURN_PORT=9w68;\nconst PortId_t N_ACK_RETURN=9w70;   /* pipe 0 local 70: dedicated recirculation port, confirmed on the switch 2026-10-10 */\n"),
    ("table ports{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}",
     "/* every master-side IPv4 TCP packet -> one reverse-map lap through pipe 0 egress; m.port_valid stays 0 */\n"
     "action normalize_ack(){tm.ucast_egress_port=N_ACK_RETURN;tm.bypass_egress=1w0;}\n"
     "table ports{key={ig.ingress_port:exact;hdr.ip.isValid():ternary;hdr.ip.proto:ternary;}"
     "actions={route;normalize_ack;deny;}size=8;default_action=deny();}"),
    # 5. One CRC table for the link header and the first data block, applied once
    *[(old, '') for old in (
        "action input_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}\n",
        "table input_head_t{actions={input_head;}size=1;const default_action=input_head();}\n",
        "Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_body;\n",
        "action input_body(){m.bcrc=hash_body.get({hdr.first.w0[31:24],hdr.first.w0[23:16],hdr.first.w0[15:8],"
        "hdr.first.w0[7:0],hdr.first.w1[31:24],hdr.first.w1[23:16],hdr.first.w1[15:0],hdr.first.w2[31:16],"
        "hdr.first.w2[15:8],hdr.first.w2[7:0],hdr.first.w3});}\n",
        "table input_body_t{actions={input_body;}size=1;const default_action=input_body();}\n",
        "table response_crc0_t{actions={response_crc0;}size=1;const default_action=response_crc0();}\n",
        "Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_head;\n",
        "action rd_head_crc(){m.hcrc=hash_rd_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}\n",
        "table rd_head_t{actions={rd_head_crc;}size=1;const default_action=rd_head_crc();}\n",
        "Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_first;\n",
        "action rd_first_crc(){m.bcrc=hash_rd_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}\n",
        "table rd_first_crc_t{actions={rd_first_crc;}size=1;const default_action=rd_first_crc();}\n")],
    ("action response_crc0(){m.bcrc=hash_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}\n",
     "/* response-only: one table computes the link-header CRC (every DNP3 kind) and the first-block CRC (every\n"
     "   kind that carries hdr.first). It replaces input_head_t, rd_head_t, input_body_t, response_crc0_t and\n"
     "   rd_first_crc_t, which computed the same two CRCs over the same bits (input_body's byte slices\n"
     "   concatenate to {w0,w1,w2,w3}). Fewer hash tables and crossbar bytes in N's stage 1, which pipe 0's\n"
     "   egress response path also needs (evidence/route_ab_01/response_only_04). */\n"
     "action crc_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}\n"
     "action crc_head_first(){crc_head();m.bcrc=hash_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}\n"
     "table crc_t{key={m.packet_kind:exact;}actions={crc_head;crc_head_first;NoAction;}size=8;"
     "const default_action=NoAction();const entries={8w5:crc_head_first();8w6:crc_head_first();"
     "8w7:crc_head_first();8w9:crc_head();8w11:crc_head_first();}}\n"),
    ("   connection.apply();\n", "   connection.apply();crc_t.apply();\n"),
    ("    input_head_t.apply();if(m.response==8w1){response_crc0_t.apply();response_crct_t.apply();}"
     "else{input_body_t.apply();input_tail_t.apply();}",
     "    if(m.response==8w1){response_crct_t.apply();}else{input_tail_t.apply();}"),
    ("    read_connection.apply();rd_head_t.apply();", "    read_connection.apply();"),
    ("read_response_profile.apply();rd_first_crc_t.apply();rd_second_crc_t.apply();",
     "read_response_profile.apply();rd_second_crc_t.apply();"),
    # 6. direction only from the right port
    ("table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}"
     "actions={forward_flow;reverse_flow;NoAction;}size=2;",
     "table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;ig.ingress_port:exact;}"
     "actions={forward_flow;reverse_flow;NoAction;}size=4;"),
    # 7. no recirculation loop: one guard at the head of the chain, before connection rewrites the port
    ("  ports.apply();network.apply();\n  if(m.port_valid==8w1&&",
     "  ports.apply();network.apply();\n"
     "  if((ig.ingress_port==RETURN_PORT&&m.stage==8w0)||"
     "((ig.ingress_port==N_ACK_RETURN||ig.ingress_port==RETURN_PORT)&&tm.ucast_egress_port==N_ACK_RETURN)){deny();}\n"
     "  else if(m.port_valid==8w1&&"),
    # 8. connection-target guard (follow-up review): connection's forward_flow / reverse_flow set the egress
    #    port from action data AFTER the head guard ran (close_forward copies the same m.output_port back on
    #    the final pass). Those are the only runtime-valued writers besides ports.route, which the head guard
    #    covers. Implemented as a guard-table entry (guard_refuses_n_ack_return below), not a gateway.
]


GUARD_KEYS_OLD = "m.bad1:ternary;m.badt:ternary;}\nactions={go_new;go_keep;go_ret_work;go_ret_nowork;go_ret_abort;NoAction;}size=48;"
GUARD_KEYS_NEW = ("m.bad1:ternary;m.badt:ternary;m.output_port:ternary;}\n"
                  "actions={go_new;go_keep;go_ret_work;go_ret_nowork;go_ret_abort;refuse_n_ack_return;NoAction;}size=48;")


def guard_refuses_n_ack_return(text):
    """Edit 8 as a table entry, not a gateway: guard gains the key m.output_port and, as its FIRST const entry,
    (_,...,_, N_ACK_RETURN) -> refuse_n_ack_return (drop, no work). Every gateway placement tried cost a 13th
    ingress stage (response_only_11 tail guard, _12 separate if, _13/_14 first arm of the m.go chain):
    N's stage 1 input crossbar is saturated and any added gateway reshuffles PHV enough to push crc_t out."""
    i = text.index("table guard{")
    j = text.index("}}", text.index("const entries={", i)) + 2
    seg = text[i:j]
    assert seg.count(GUARD_KEYS_OLD) == 1
    seg = seg.replace(GUARD_KEYS_OLD, GUARD_KEYS_NEW)
    n = seg.count("):")
    seg = seg.replace("):", ",_):")
    assert seg.count(",_):") == n == 34, n
    first = "const entries={("
    seg = seg.replace(first, first + "_,_,_,_,_,_,_,_,_,_,_,N_ACK_RETURN):refuse_n_ack_return();(", 1)
    action = "action refuse_n_ack_return(){md.drop_ctl=3w1;}\n"
    return text[:i] + action + seg + text[j:]


def generate():
    text = binding_generate.generate(profile='response_only')
    for old, new in EDITS:
        n = text.count(old)
        assert n == 1, (n, old[:80])
        text = text.replace(old, new)
    text = guard_refuses_n_ack_return(text)
    assert 'STEP3_M_PORT' not in text and 'emit_replay' not in text and 'bypass_egress=1w1' in text
    header = ('/* GENERATED by core/response_only/make_n.py from connection/binding/generate.py response_only (sha256 %s).\n'
              '   Response-only N for the B\' profile: no M, no request padding. Do not edit. */\n'
              % hashlib.sha256(SOURCE.read_bytes()).hexdigest())
    return header + text


if __name__ == '__main__':
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'n_response_only.p4'
    out.write_text(generate())
    print('wrote', out)

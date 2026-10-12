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
    hdr.ip.src is a fourth, ternary key so that both endpoints may share ONE switch port (the reflected
    hardware setup: master and outstation both on dev_port 9, forwarded 9 -> 9). With equal dev ports the
    master and outstation rows differ only by source address (cp.n_ports_rows); with distinct ports it is
    wildcarded and the rows are as before. On a shared port, "which side sent this" is the source address,
    not the port: the port-provenance property of edit 6 is only as strong as that address there.
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
    N_ACK_RETURN = 70 (pipe 0, local 70) is the MODEL's port: local 68-71 recirculate into the same pipe's
    ingress on the model (evidence/model_28/PORTS_PROPOSAL.md); 68 is N's RETURN_PORT. On the switch 70 does
    NOT recirculate (measured 2026-10-11, evidence/recirc_ports_01/STATUS.md: only 68 does; the 2026-10-10
    note that 69-71 were confirmed came from $PORT entries, not traffic). The port is a build parameter:
    compose.py --n-ack-return=N rewrites this one declaration (48, a front-panel port in MAC loopback, on the
    switch) and E's dispatch, and cp.py's rows take the same value (port_map.py). Every use below is by name.

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
     "table ports{key={ig.ingress_port:exact;hdr.ip.isValid():ternary;hdr.ip.proto:ternary;hdr.ip.src:ternary;}"
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
    # 9. Defect E: a native command (SELECT/OPERATE, IP length 75) reaches native_tcp. The clean request has
    #    TCP flags 0x10 (ACK) or 0x18 (PSH+ACK); any other flag combination on a command-sized frame -- a late
    #    OPERATE retransmission with FIN+PSH+ACK (0x19) was the case on silicon -- fell to `default:accept`,
    #    was parsed no further, and was forwarded natively around the mechanism (no T handoff, no SBO advance),
    #    so a protected command bypassed and produced a failed OPERATE response (combined_silicon_02). This is
    #    the response-only build's deliberate, simplest handling: EXPLICITLY REJECT a command-bearing FIN/RST
    #    (any non-{0x10,0x18}) form -- drop it before the lap, so no rejected command reaches the outstation, a
    #    callback, or T. native_tcp only sees IP-length-75 (command) frames, so unrelated non-command traffic
    #    (different IP length) never reaches here and its native passthrough is unaffected. FIN's extra
    #    sequence-space byte and the closing state do not matter because the form is dropped, not reparsed.
    ("(4w5,4w0,16w0,8w24):native_dl;default:accept;",
     "(4w5,4w0,16w0,8w24):native_dl;"
     "(4w5,4w0,16w0,8w0x01&&&8w0x01):native_command_reject;"   # any FIN-bearing command form
     "(4w5,4w0,16w0,8w0x04&&&8w0x04):native_command_reject;"   # any RST-bearing command form
     "default:accept;"),
    (" state native_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native_block;}",
     " state native_command_reject{m.packet_kind=8w13;transition finish;}\n"
     " state native_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native_block;}"),
    # the drop runs right after ports/network (before the lap and before any admission), on edit 7's output
    ("  ports.apply();network.apply();\n  if((ig.ingress_port==RETURN_PORT&&m.stage==8w0)||",
     "  ports.apply();network.apply();\n"
     "  if(m.packet_kind==8w13){deny();}   /* command-bearing FIN/RST: rejected, never bypasses the mechanism */\n"
     "  else if((ig.ingress_port==RETURN_PORT&&m.stage==8w0)||"),
    # 10. Close path (route_ab_01/close_defect_01). The second FIN of a close finds N in phase 7 and leaves in ONE
    #     pass through first_event's catch-all close_forward. snapshot()'s default has already set
    #     bypass_egress=1 for a recirculation lap; close_forward re-targets the port but kept the bypass, so an
    #     outstation FIN or RST skipped pipe-0 egress and E never translated it: it reached the master at its
    #     native seq, behind the padded frontier the master had ACKed, and was ignored (prod_shape). Every close
    #     departure now crosses E, as route() already does in this profile (edit 1). A master->outstation
    #     departure finds no E conn row at the outstation port and passes unchanged.
    ("m.emit_loop=8w0;tm.ucast_egress_port=m.output_port;}",
     "m.emit_loop=8w0;tm.ucast_egress_port=m.output_port;tm.bypass_egress=1w0;}"),
    # 11. FIN accounting in N's sequence check. A FIN consumes one sequence number and N's stored native
    #     positions do not count it, so once a side has sent its FIN that side's diff is 1: the master's ACKs
    #     after its own FIN are (1,0), after both FINs (1,1), and its ACK of an outstation-first FIN is (0,1).
    #     They get their own code 5 (seq_fin), which no row outside phase 7 accepts (edit 12).
    ("action seq_replay(){m.sequence_valid=8w4;}",
     "action seq_replay(){m.sequence_valid=8w4;}\naction seq_fin(){m.sequence_valid=8w5;}   /* a FIN's sequence byte, phase 7 only */"),
    ("actions={seq_ok;seq_resent;seq_replay;NoAction;}size=3;const entries={(32w0,32w0):seq_ok();",
     "actions={seq_ok;seq_resent;seq_replay;seq_fin;NoAction;}size=6;const entries={(32w0,32w0):seq_ok();"
     "(32w1,32w0):seq_fin();(32w1,32w1):seq_fin();(32w0,32w1):seq_fin();"),
    # 12. ...and in phase 7 (closed) such a master ACK is forwarded unchanged (it was reverse-mapped on the lap),
    #     so the outstation sees its FIN acknowledged and stops retransmitting. Outstation ACKs already pass
    #     through the kind-10 forward_original catch-all.
    ("(8w3,8w1,8w0,32w0xc0000&&&32w0xffff0000):forward_original();",
     "(8w3,8w1,8w0,32w0xc0000&&&32w0xffff0000):forward_original();"
     "(8w3,8w5,8w0,32w0x70000&&&32w0xffff0000):forward_original();"),
    # 13. RESET event kind. emit_reset hands a close to T on T_IN with the event in wire bytes 12-13. Kind 4 made
    #     them 0x0401/0x0402, an 802.3 length; on a front-panel MAC-loopback T_IN the MAC counts it as received
    #     but not good (silicon p2_production_01: port 180 $OctetsReceived - $OctetsReceivedinGoodFrames = 80 B,
    #     one 76-byte RESET event + FCS). Kind 13 gives 0x0d01/0x0d02, in the EtherType range and not a
    #     reserved type, like every other event (0x0900..0x0c00). T's KIND_RESET (read_queue_timing.p4) is 13;
    #     compose.py refuses a build where the two differ.
    ("action emit_reset(){hdr.event.event=8w4++m.direction;",
     "action emit_reset(){hdr.event.event=8w13++m.direction;"),
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


TS_BLOCK = '32w0x0101080a'      # NOP, NOP, Timestamp (kind 8, length 10): the 12-byte option block of an offset-8 segment
IP4 = '(4w4,4w5,8w6,16w%d)'
TS_EDITS = [
    # the option bytes are carried as opaque headers after tcp (and after mss on the handshake), so the deparser
    # re-emits them in place and the TCP checksum residual still covers every byte of the segment
    ("header mss_h{bit<8> kind;bit<8> len;bit<16> value;}",
     "header mss_h{bit<8> kind;bit<8> len;bit<16> value;}\n"
     "header opt12_h{bit<32> a;bit<32> b;bit<32> c;}\nheader opt4_h{bit<32> v;}"),
    ("tcp_h tcp;mss_h mss;", "tcp_h tcp;mss_h mss;opt12_h tso;opt4_h oa;opt4_h ob;"),
    # exact IP lengths of the timestamped profile: 52 ACK / close, 64 SYN-ACK, 72 READ request, 101 READ response
    (IP4 % 41 + ":replay_ip_flags;default:accept;}}",
     IP4 % 41 + ":replay_ip_flags;" + IP4 % 52 + ":ts_ip_flags;" + IP4 % 64 + ":ts_synack_ip_flags;"
     + IP4 % 72 + ":ts_read_ip_flags;" + IP4 % 101 + ":ts_read_response_ip_flags;default:accept;}}"),
    # the timestamped SYN is 60 bytes of IP, the clean READ request's length: told apart by the TCP data offset
    ("(4w5,4w0,16w0,8w16):read_dl;(4w5,4w0,16w0,8w24):read_dl;default:accept;}}",
     "(4w5,4w0,16w0,8w16):read_dl;(4w5,4w0,16w0,8w24):read_dl;(4w10,4w0,16w0,8w2):ts_syn;default:accept;}}"),
    (" state finish{m.tcp_sum=tc.get();",
     " state ts_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):ts_tcp;(13w0,3w2):ts_tcp;default:accept;}}\n"
     " state ts_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.flags)"
     "{(4w8,8w16):ts_ack;(4w8,8w17):ts_close;(4w8,8w20):ts_close;default:accept;}}\n"
     " state ts_ack{pkt.extract(hdr.tso);tc.subtract(hdr.tso);transition select(hdr.tso.a){%(ts)s:ack;default:accept;}}\n"
     " state ts_close{pkt.extract(hdr.tso);tc.subtract(hdr.tso);transition select(hdr.tso.a){%(ts)s:close;default:accept;}}\n"
     " state ts_syn{pkt.extract(hdr.mss);tc.subtract(hdr.mss);pkt.extract(hdr.tso);tc.subtract(hdr.tso);"
     "pkt.extract(hdr.oa);tc.subtract(hdr.oa);m.packet_kind=8w1;transition mss_check;}\n"
     " state ts_synack_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):ts_synack_tcp;(13w0,3w2):ts_synack_tcp;default:accept;}}\n"
     " state ts_synack_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.flags)"
     "{(4w11,8w18):ts_synack;default:accept;}}\n"
     " state ts_synack{pkt.extract(hdr.mss);tc.subtract(hdr.mss);pkt.extract(hdr.tso);tc.subtract(hdr.tso);"
     "pkt.extract(hdr.oa);tc.subtract(hdr.oa);pkt.extract(hdr.ob);tc.subtract(hdr.ob);m.packet_kind=8w2;transition mss_check;}\n"
     " state ts_read_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):ts_read_tcp;(13w0,3w2):ts_read_tcp;default:accept;}}\n"
     " state ts_read_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags)"
     "{(4w8,4w0,16w0,8w16):ts_read_opt;(4w8,4w0,16w0,8w24):ts_read_opt;default:accept;}}\n"
     " state ts_read_opt{pkt.extract(hdr.tso);tc.subtract(hdr.tso);transition select(hdr.tso.a){%(ts)s:read_dl;default:accept;}}\n"
     " state ts_read_response_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):ts_read_response_tcp;(13w0,3w2):ts_read_response_tcp;default:accept;}}\n"
     " state ts_read_response_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags)"
     "{(4w8,4w0,16w0,8w16):ts_read_response_opt;(4w8,4w0,16w0,8w24):ts_read_response_opt;default:accept;}}\n"
     " state ts_read_response_opt{pkt.extract(hdr.tso);tc.subtract(hdr.tso);transition select(hdr.tso.a){%(ts)s:read_response_dl;default:accept;}}\n"
     " state finish{m.tcp_sum=tc.get();" % dict(ts=TS_BLOCK)),
]


def admit_timestamped_profile(text):
    """Edit 9: the real stack's TCP profile (timestamps, SACK-permitted, window scale), READ lane and handshake.
    Measured on Vision against the SEL-751 (protocol/evidence/hw_range_read_01/native_ip_retest_20261010.pcap):
    SYN data offset 10 / IP length 60, SYN-ACK 11 / 64, every later segment offset 8 with the 12-byte block
    NOP NOP Timestamp: ACK and FIN 52, READ request 72, READ response 101. Before this edit N parsed none of
    them (the SYN's length 60 is the clean READ request's, and read_tcp wants offset 5).

    Parser only. Exact (IP length, data offset, flags) triples, no wildcard; the clean profile's states are
    untouched. Offset 8: the block must begin 01 01 08 0a, is extracted and the existing ack / close / read_dl /
    read_response_dl states continue, so the DNP3 headers, their CRC checks, the connection key and every
    packet-length check are the same code as for the clean profile. Handshake: MSS is the first option in
    both directions and keeps its check (mss_check, syn_shapes); the remaining 16 (SYN) or 20 (SYN-ACK) option
    bytes are bounded by the exact offset and length and carried opaque. Every option byte is subtracted from
    the checksum residual, so `network` still compares m.tcp_sum with 16w0xffeb: that constant is the folded
    difference between hdr.ip.len (what the parser subtracts) and the TCP length (what the sender summed),
    ~20 for ihl 5, and does not depend on the options. An RST|ACK at offset 8 / length 52 is admitted with the
    FIN (same triple shape as the clean profile's close set); it is not in the capture."""
    for old, new in TS_EDITS:
        n = text.count(old)
        assert n == 1, (n, old[:80])
        text = text.replace(old, new)
    return text


def generate():
    text = binding_generate.generate(profile='response_only')
    for old, new in EDITS:
        n = text.count(old)
        assert n == 1, (n, old[:80])
        text = text.replace(old, new)
    text = guard_refuses_n_ack_return(text)
    text = admit_timestamped_profile(text)
    assert 'STEP3_M_PORT' not in text and 'emit_replay' not in text and 'bypass_egress=1w1' in text
    header = ('/* GENERATED by core/response_only/make_n.py from connection/binding/generate.py response_only (sha256 %s).\n'
              '   Response-only N for the B\' profile: no M, no request padding. Do not edit. */\n'
              % hashlib.sha256(SOURCE.read_bytes()).hexdigest())
    return header + text


if __name__ == '__main__':
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'n_response_only.p4'
    out.write_text(generate())
    print('wrote', out)

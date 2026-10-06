/* BMv2 response-ready artifact: the READ policy contract (framework/contract/POLICY_CONTRACT.md) on v1model.
 *
 * Emulation, stated plainly: BMv2 priority queues have one rate limiter per queue, so they do not gate a low-priority
 * queue behind a high-priority one (measured, exp_priority*). Gating is therefore EMULATED by counting live blocker tokens:
 * ACK and response are held in a real loop through the egress queue of port 2 (receiving at port 3), and a held packet
 * leaves only when its slot has no live token. Blocker tokens are real packets cloned from the request, each making a real
 * trip through the same queue every pass. Release granularity is one loop of the held packet itself, not one blocker slot.
 *
 * Modes (p_mode): 4 = dual (ACK held to max(t0 + D_A, t_R); response at ACK release + gap); 2 = response-focused (ACK
 * forwarded on arrival; response at max(t_R, t_A + gap)). D_A = 0 in mode 4 is the ACK-focused case.
 * Times are microseconds of ingress_global_timestamp (48 bit). One flow, one outstanding READ; a second request bypasses. */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETYPE_IPV4 = 0x0800;
const bit<16> ETYPE_HELD = 0x88C3;
const bit<16> ETYPE_BLK  = 0x88B5;
const bit<16> DNP3_PORT  = 20000;
const bit<9> PORT_MASTER = 0;
const bit<9> PORT_OUT = 1;
const bit<9> PORT_LOOP_TX = 2;
const bit<9> PORT_LOOP_RX = 3;
const bit<32> MIRROR_SESSION = 100;
const bit<8> KIND_ACK = 1;
const bit<8> KIND_RESP = 2;

header eth_t  { bit<48> dst; bit<48> src; bit<16> etype; }
header shim_t { bit<8> kind; bit<16> orig; }
header blk_t  { bit<8> slot; bit<32> budget; }
header ipv4_t { bit<4> ver; bit<4> ihl; bit<8> tos; bit<16> len; bit<16> id; bit<16> frag; bit<8> ttl; bit<8> proto; bit<16> csum; bit<32> src; bit<32> dst; }
header tcp_t  { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack; bit<4> doff; bit<4> res; bit<8> flags; bit<16> win; bit<16> csum; bit<16> urg; }
header tcp_ts_t { bit<96> opt; }
header link_t { bit<16> start; bit<8> len; bit<8> ctrl; bit<16> dst; bit<16> src; bit<16> crc; }
header app_t  { bit<8> transport; bit<8> appctl; bit<8> func; }
header iin_t  { bit<16> iin; }
header obj_t  { bit<8> group; bit<8> variation; }
header rest_a_t { bit<88> b; }      /* payload bytes 17..27 of an eligible 49-byte response */
header pl2_t  { bit<168> b; }       /* payload bytes 28..48 */

struct headers_t { eth_t eth; shim_t shim; blk_t blk; ipv4_t ip; tcp_t tcp; tcp_ts_t tcp_ts; link_t link; app_t app; iin_t iin; obj_t obj; rest_a_t rest_a; pl2_t pl2; }
struct meta_t { bit<16> rest; bit<1> supported; bit<1> held; bit<1> carved; bit<8> rid; bit<16> ptcp_len; }

parser P(packet_in pkt, out headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    state start { m.supported = 1; m.rest = 0; m.held = 0; m.carved = 0; m.rid = 0; m.ptcp_len = 0; pkt.extract(h.eth);
        transition select(h.eth.etype) { ETYPE_IPV4: parse_ip; ETYPE_HELD: parse_shim; ETYPE_BLK: parse_blk; default: unsupported; } }
    state parse_shim { pkt.extract(h.shim); transition parse_ip; }
    state parse_blk { pkt.extract(h.blk); transition accept; }
    state parse_ip { pkt.extract(h.ip);
        transition select(h.ip.ihl, h.ip.proto) { (5, 6): parse_tcp; default: unsupported; } }
    state parse_tcp { pkt.extract(h.tcp);
        transition select(h.tcp.doff) { 5: tcp_done; 8: parse_ts; default: unsupported; } }
    state parse_ts { pkt.extract(h.tcp_ts); transition tcp_done; }
    state tcp_done {
        m.rest = h.ip.len - (bit<16>)(((bit<16>)h.ip.ihl << 2) + ((bit<16>)h.tcp.doff << 2));
        transition select(h.tcp.sport, h.tcp.dport, m.rest) {
            (DNP3_PORT, _, 0): accept;
            (_, DNP3_PORT, 0): accept;
            (DNP3_PORT, _, _): parse_link;
            (_, DNP3_PORT, _): parse_link;
            default: accept; } }
    state parse_link { pkt.extract(h.link);
        transition select(h.link.start) { 0x0564: parse_app; default: unsupported; } }
    state parse_app { pkt.extract(h.app);
        transition select(h.app.func) { 0x81: parse_iin; default: parse_obj; } }
    state parse_iin { pkt.extract(h.iin); transition parse_obj; }
    state parse_obj { pkt.extract(h.obj); transition select(m.rest) { 49: parse_rest_a; default: accept; } }
    state parse_rest_a { pkt.extract(h.rest_a); pkt.extract(h.pl2); transition accept; }
    state unsupported { m.supported = 0; transition accept; }
}
control VC(inout headers_t h, inout meta_t m) { apply { } }

control Ing(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    /* policy parameters, written by the control plane */
    register<bit<48>>(1) p_da_us;  register<bit<48>>(1) p_gap_us;  register<bit<32>>(1) p_budget;  register<bit<8>>(1) p_mode;  register<bit<8>>(1) p_shape;  register<bit<8>>(1) p_dropreq;  register<bit<8>>(1) r_dropped;
    /* transaction state */
    register<bit<8>>(1)  r_armed;   register<bit<32>>(1) r_expect_ack;  register<bit<8>>(1) r_app;
    register<bit<48>>(1) r_t0;      register<bit<48>>(1) r_deadline;     register<bit<8>>(1) r_resp_seen;
    register<bit<8>>(1)  r_ack_held; register<bit<8>>(1) r_ack_seen;
    register<bit<8>>(1)  r_tresp_armed; register<bit<48>>(1) r_tresp;
    register<bit<8>>(1)  r_live_ack; register<bit<8>>(1) r_live_resp;
    /* evidence */
    register<bit<48>>(8) r_ev;       /* 0 t0, 1 ack release, 2 resp release, 3 ack arrival, 4 resp arrival, 5 tmo */
    counter(16, CounterType.packets) outcome;

    bit<8> armed; bit<8> mode; bit<48> now; bit<32> expect; bit<8> app; bit<8> live_a; bit<8> live_r;
    bit<8> shape; bit<8> dropreq; bit<8> dropped; bit<8> seen; bit<8> ack_held; bit<8> tr_armed; bit<48> tr; bit<48> dl; bit<32> budget;

    action fwd(bit<9> port) { sm.egress_spec = port; }
    action drop() { mark_to_drop(sm); }
    table dmac { key = { h.eth.dst : exact; } actions = { fwd; drop; } default_action = drop(); size = 16; }

    action to_loop() { sm.egress_spec = PORT_LOOP_TX; m.held = 1; }
    action split_to_master() { sm.mcast_grp = 2; }
    action release_to_master() { h.eth.etype = h.shim.orig; h.shim.setInvalid(); sm.egress_spec = PORT_MASTER; }

    action finish_transaction() {
        r_armed.write(0, 0); r_resp_seen.write(0, 0); r_ack_held.write(0, 0); r_ack_seen.write(0, 0);
        r_tresp_armed.write(0, 0); r_live_ack.write(0, 0); r_live_resp.write(0, 0);
    }
    action arm_response_deadline() {
        bit<48> gap; p_gap_us.read(gap, 0);
        r_tresp.write(0, now + gap); r_tresp_armed.write(0, 1);
    }

    apply {
        now = sm.ingress_global_timestamp;
        r_armed.read(armed, 0); p_mode.read(mode, 0);
        dmac.apply();                                            /* default forwarding; branches below override it */

        if (h.blk.isValid()) {
            /* ---- a blocker token arriving back from the loop ---- */
            bit<32> budget_left = h.blk.budget;
            if (armed == 0) {                                   /* transaction over: the token retires */
                if (h.blk.slot == 1) { r_live_ack.write(0, 0); } else { r_live_resp.write(0, 0); }
                mark_to_drop(sm); outcome.count(10);
            } else if (budget_left == 0) {                      /* watchdog: fail open */
                if (h.blk.slot == 1) { r_live_ack.write(0, 0); } else { r_live_resp.write(0, 0); }
                r_armed.write(0, 0);                            /* owner retired: later ACK/response go native */
                r_ev.write(5, now);
                mark_to_drop(sm); outcome.count(11);
            } else if (h.blk.slot == 1) {
                r_resp_seen.read(seen, 0); r_deadline.read(dl, 0);
                if (seen == 1 && now >= dl) { r_live_ack.write(0, 0); mark_to_drop(sm); outcome.count(12); }
                else { h.blk.budget = budget_left - 1; to_loop(); outcome.count(13); }
            } else {
                r_resp_seen.read(seen, 0); r_tresp_armed.read(tr_armed, 0); r_tresp.read(tr, 0);
                if (seen == 1 && tr_armed == 1 && now >= tr) { r_live_resp.write(0, 0); mark_to_drop(sm); outcome.count(14); }
                else { h.blk.budget = budget_left - 1; to_loop(); outcome.count(15); }
            }
        } else if (h.shim.isValid()) {
            /* ---- a held packet back from the loop ---- */
            if (h.shim.kind == KIND_ACK) {
                r_live_ack.read(live_a, 0);
                if (live_a == 0) { release_to_master(); r_ev.write(1, now); r_ack_held.write(0, 0); arm_response_deadline(); outcome.count(1); }
                else { to_loop(); }
            } else {
                r_live_resp.read(live_r, 0);
                if (live_r == 0) { release_to_master(); r_ev.write(2, now); finish_transaction(); outcome.count(2);
                    p_shape.read(shape, 0); if (shape == 1 && (h.pl2.isValid() && h.rest_a.isValid() && h.link.len == 38 && (h.tcp.flags & 0x16) == 0x10 && (h.ip.frag & 0x3FFF) == 0)) { split_to_master(); outcome.count(4 + 8); } }
                else { to_loop(); }
            }
        } else if (mode != 0 && m.supported == 1 && h.tcp.isValid() && sm.ingress_port == PORT_MASTER && h.app.isValid() && h.app.func == 0x01) {
            /* ---- READ request ---- */
            if (armed == 0) {
                bit<48> da; bit<32> bud; p_da_us.read(da, 0); p_budget.read(bud, 0);
                r_armed.write(0, 1); r_t0.write(0, now); r_deadline.write(0, now + da);
                r_expect_ack.write(0, h.tcp.seq + (bit<32>)m.rest); r_app.write(0, h.app.appctl & 0x0F);
                r_resp_seen.write(0, 0); r_ack_held.write(0, 0); r_ack_seen.write(0, 0); r_tresp_armed.write(0, 0);
                r_live_ack.write(0, (mode == 4) ? (bit<8>)1 : (bit<8>)0); r_live_resp.write(0, 1);
                r_ev.write(0, now);
                if (mode == 3) { r_ack_seen.write(0, 1); arm_response_deadline(); r_ev.write(3, now); }   /* generated ACK: its instant is now */

                clone(CloneType.I2E, MIRROR_SESSION);           /* two blockers: rid 1 = ACK slot, rid 2 = response slot */
                outcome.count(0);
            } else { outcome.count(9); }                         /* busy: bypass */
        } else if (m.supported == 1 && h.tcp.isValid() && sm.ingress_port == PORT_OUT && m.rest == 0 && armed == 1) {
            /* ---- candidate pure ACK from the outstation ---- */
            r_expect_ack.read(expect, 0); r_ack_held.read(ack_held, 0); r_ack_seen.read(seen, 0);
            if (h.tcp.ack == expect && seen == 0) {
                r_ack_seen.write(0, 1); r_ev.write(3, now);
                if (mode == 2) { arm_response_deadline(); outcome.count(3); }   /* forwarded unheld */
                else {
                    r_live_ack.read(live_a, 0);
                    if (live_a == 0) { arm_response_deadline(); outcome.count(4); }   /* token already gone: leaves now */
                    else { h.shim.setValid(); h.shim.kind = KIND_ACK; h.shim.orig = h.eth.etype; h.eth.etype = ETYPE_HELD;
                           r_ack_held.write(0, 1); to_loop(); outcome.count(5); }
                }
            } else if (h.tcp.ack == expect && seen == 1 && ack_held == 1) { mark_to_drop(sm); outcome.count(6); }   /* duplicate while held */
        } else if (m.supported == 1 && h.tcp.isValid() && sm.ingress_port == PORT_OUT && m.rest != 0 && armed == 1 && h.app.isValid() && h.app.func == 0x81) {
            /* ---- candidate response from the outstation ---- */
            r_expect_ack.read(expect, 0); r_app.read(app, 0); r_resp_seen.read(seen, 0);
            if (h.tcp.ack == expect && (h.app.appctl & 0x0F) == app && seen == 0) {
                r_resp_seen.write(0, 1); r_ev.write(4, now);
                h.shim.setValid(); h.shim.kind = KIND_RESP; h.shim.orig = h.eth.etype; h.eth.etype = ETYPE_HELD;
                to_loop(); outcome.count(7);
            } else { outcome.count(8); }                         /* stale / duplicate: forwarded unchanged */
        } else if (sm.ingress_port == PORT_LOOP_RX || sm.ingress_port == 4) {
            mark_to_drop(sm);
        }                                                        /* everything else keeps the dmac forwarding applied above */
        /* fault injection, every mode: the first READ request is lost on the switch -> outstation link, after any generated ACK */
        p_dropreq.read(dropreq, 0); r_dropped.read(dropped, 0);
        if (dropreq == 1 && dropped == 0 && sm.ingress_port == PORT_MASTER && h.app.isValid() && h.app.func == 0x01 && !h.shim.isValid() && !h.blk.isValid()) {
            r_dropped.write(0, 1); mark_to_drop(sm); outcome.count(11);
        }
        p_shape.read(shape, 0);
        if (shape == 1 && m.held == 0 && !h.blk.isValid() && !h.shim.isValid() && sm.ingress_port == PORT_OUT && h.app.isValid() && h.app.func == 0x81 && (h.pl2.isValid() && h.rest_a.isValid() && h.link.len == 38 && (h.tcp.flags & 0x16) == 0x10 && (h.ip.frag & 0x3FFF) == 0) && sm.egress_spec == PORT_MASTER) { split_to_master(); outcome.count(5); }
    }
}

control Egr(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    register<bit<32>>(1) e_budget;      /* mirrors p_budget for the blocker header; written by the control plane */
    counter(4, CounterType.packets) carve_ctr;
    register<bit<8>>(1) p_mode_e;      /* mirrors p_mode for the egress pipeline; written by the control plane */
    apply {
        if (sm.instance_type == 5 && h.pl2.isValid() && (sm.egress_rid == 1 || sm.egress_rid == 2)) {
            /* RID interpreter: rid 1 keeps payload[0:28], rid 2 keeps payload[28:49]; the rid is the whole instruction */
            bit<16> tcp_hdr = ((bit<16>)h.tcp.doff) << 2;
            m.carved = 1; m.rid = (bit<8>)sm.egress_rid;
            if (sm.egress_rid == 1) {
                h.pl2.setInvalid(); h.tcp.flags = h.tcp.flags & 0xF6;            /* clear PSH and FIN on the prefix */
                h.ip.len = h.ip.len - 21; m.ptcp_len = tcp_hdr + 28; carve_ctr.count(1);
            } else {
                h.link.setInvalid(); h.app.setInvalid(); h.iin.setInvalid(); h.obj.setInvalid(); h.rest_a.setInvalid();
                h.tcp.seq = h.tcp.seq + 28; h.ip.len = h.ip.len - 28; m.ptcp_len = tcp_hdr + 21; carve_ctr.count(2);
            }
        }
        bit<8> emode; p_mode_e.read(emode, 0);
        if (sm.instance_type == 1 && sm.egress_rid == 3 && emode != 3) { mark_to_drop(sm); }
        else if (sm.instance_type == 1 && sm.egress_rid == 3) {
            /* generated ACK for the request just seen: the switch speaks for the outstation. Window and options are the
             * switch's own invention (documented limitation); sequence numbers come from the request itself. */
            bit<48> tmp_mac = h.eth.src; h.eth.src = h.eth.dst; h.eth.dst = tmp_mac;
            bit<32> tmp_ip = h.ip.src; h.ip.src = h.ip.dst; h.ip.dst = tmp_ip;
            bit<16> tmp_p = h.tcp.sport; h.tcp.sport = h.tcp.dport; h.tcp.dport = tmp_p;
            bit<16> plen = h.ip.len - (((bit<16>)h.ip.ihl) << 2) - (((bit<16>)h.tcp.doff) << 2);
            bit<32> old_seq = h.tcp.seq;
            h.tcp.seq = h.tcp.ack; h.tcp.ack = old_seq + (bit<32>)plen; h.tcp.flags = 0x10; h.tcp.win = 16384;
            h.link.setInvalid(); h.app.setInvalid(); h.iin.setInvalid(); h.obj.setInvalid(); h.rest_a.setInvalid(); h.pl2.setInvalid();
            if (h.tcp_ts.isValid()) {
                h.tcp_ts.opt = h.tcp_ts.opt[95:64] ++ h.tcp_ts.opt[31:0] ++ h.tcp_ts.opt[63:32];   /* TSval <-> TSecr */
                h.ip.len = 52; m.ptcp_len = 32; truncate((bit<32>)66);
            } else { h.ip.len = 40; m.ptcp_len = 20; truncate((bit<32>)54); }
            m.carved = 1; m.rid = 3; carve_ctr.count(3);
        } else if (sm.instance_type == 1) {                      /* an ingress clone: turn it into a blocker */
            h.ip.setInvalid(); h.tcp.setInvalid(); h.tcp_ts.setInvalid(); h.link.setInvalid(); h.app.setInvalid();
            h.iin.setInvalid(); h.obj.setInvalid(); h.shim.setInvalid();
            h.eth.etype = ETYPE_BLK;
            h.blk.setValid(); h.blk.slot = (bit<8>)sm.egress_rid;
            e_budget.read(h.blk.budget, 0);
            truncate((bit<32>)23);
        }
    }
}
control CC(inout headers_t h, inout meta_t m) {
    apply {
        update_checksum(m.carved == 1, { h.ip.ver, h.ip.ihl, h.ip.tos, h.ip.len, h.ip.id, h.ip.frag, h.ip.ttl, h.ip.proto, h.ip.src, h.ip.dst }, h.ip.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 1 && !h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg,
              h.link.start, h.link.len, h.link.ctrl, h.link.dst, h.link.src, h.link.crc, h.app.transport, h.app.appctl, h.app.func, h.iin.iin, h.obj.group, h.obj.variation, h.rest_a.b },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 1 && h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg, h.tcp_ts.opt,
              h.link.start, h.link.len, h.link.ctrl, h.link.dst, h.link.src, h.link.crc, h.app.transport, h.app.appctl, h.app.func, h.iin.iin, h.obj.group, h.obj.variation, h.rest_a.b },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 2 && !h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg, h.pl2.b },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 3 && !h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 3 && h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg, h.tcp_ts.opt },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 2 && h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg, h.tcp_ts.opt, h.pl2.b },
            h.tcp.csum, HashAlgorithm.csum16);
    }
}
control Dep(packet_out pkt, in headers_t h) {
    apply { pkt.emit(h.eth); pkt.emit(h.shim); pkt.emit(h.blk); pkt.emit(h.ip); pkt.emit(h.tcp); pkt.emit(h.tcp_ts);
            pkt.emit(h.link); pkt.emit(h.app); pkt.emit(h.iin); pkt.emit(h.obj); pkt.emit(h.rest_a); pkt.emit(h.pl2); }
}
V1Switch(P(), VC(), Ing(), Egr(), CC(), Dep()) main;

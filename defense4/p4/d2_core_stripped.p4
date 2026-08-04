/* ============================================================================
 * d2_core_stripped.p4 — STRIPPED Defense 2 core for the Defense 4 feasibility
 *   (TASK 1). Derived by COPYING the frozen request-triggered pktgen Defense 2
 *   (research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4). The frozen file
 *   is NOT edited; this is a separate non-frozen probe under defense4/p4/.
 *
 * PURPOSE: obtain the ACTUAL compiler-proven ingress-stage / critical-path /
 *   resource cost of the Defense 2 TIMING MECHANISM ALONE, with the telemetry tail,
 *   the A/B host-injected blocker fallback, and the G-selection guard removed. This
 *   answers "what does the bare hold-and-release core cost" — no estimate is retained.
 *
 * RETAINED (the mechanism, verbatim from the frozen base):
 *   - ACK-relative deadline: reg_deadline, deadline_arm_once (first-ACK idempotent),
 *     deadline_rmw, tbl_deadline_expiry.
 *   - queue-resident response hold: to_resp() -> Q_RESP behind the Q_BLOCK reservoir.
 *   - blocker expiry / fail-open: pass-budget decrement + stale/deadline/timeout
 *     termination in the dequeued ROLE_BLOCK branch.
 *   - exact transaction matching + generation isolation: reg_tag, tbl_state_decode.
 *   - cleanup: ARM disarm, TAG_INACTIVE retire on budget exhaustion.
 *   - request-triggered pktgen blocker generation (the internal slot clock, directive
 *     §2): from_pgen parser, arm_clone(), tbl_pktgen_active, pktgen admission.
 *   - lightweight counters for the mechanism.
 *
 * REMOVED vs the frozen base (all telemetry / A-B, none load-bearing to the hold):
 *   - the 4 fixed-slot latency timestamp registers (reg_ts_first_block, reg_ts_ack_arm,
 *     reg_ts_block_term, reg_ts_first_resp_release), their RegisterActions, the ev_*
 *     event flags and the 4 sparse execute() call sites.
 *   - the entire G-selection guard: reg_t_ack (3 actions), reg_native_clrt,
 *     reg_protection, tbl_build_clrt_diff, tbl_clrt_guard, the six guard counters, and
 *     the is_fresh_resp / native_clrt / clrt_diff / protection metadata + apply block.
 *   - the A/B host-injected blocker fallback (the non-pktgen else branch that used
 *     ctr_block_enq); only the pktgen blocker path is kept.
 *
 * NOT CLAIMED: nothing here is loaded or run. Compile-fit only. bf-p4c 9.13.1 offline.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;
const bit<16> ETHERTYPE_IPV4        = 0x0800;
const bit<8>  IP_PROTO_TCP          = 8w6;

/* ---- DNP3 ---- */
const bit<16> DNP3_START       = 0x0564;
const bit<8>  DNP3_FC_READ     = 8w1;
const bit<8>  DNP3_FC_RESPONSE = 8w129;

/* ---- roles ---- */
const bit<8> ROLE_BYPASS = 0;
const bit<8> ROLE_BLOCK  = 1;
const bit<8> ROLE_RESP   = 2;
const bit<8> ROLE_ARM    = 6;
const bit<8> ROLE_ACK    = 7;

/* ---- direction ---- */
const bit<8> DIR_MASTER = 0;
const bit<8> DIR_OUT    = 1;

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;
const PortId_t PORT_VISION = 9w9;
const PortId_t PORT_HULK   = 9w11;
const PortId_t PORT_RELAY  = 9w64;

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;
const bit<5> QID_RESP  = 5w1;

/* ---- pktgen ---- */
const PortId_t PORT_PGEN = 9w68;
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_CLONE = 1;
const MirrorId_t CLONE_SESSION_ID = 10w7;
const bit<32> CLONE_TAG_MARKER = 32w0xE1000000;
const bit<32> PGEN_HDR_BITS = 32w48;
const bit<32> INITIAL_BUDGET = 32w100000;

/* ---- packed-state constants ---- */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;
const bit<32> ARMED_MARK   = 32w0x00000001;
const bit<32> UNARMED_WORD = 32w0x00000002;
const bit<32> DL_NO_WRITE  = 32w0;
const bit<8>  TAG_INACTIVE = 8w0xFF;
const bit<8>  TAG_NO_WRITE = 8w0;

const bit<32> G_DEFAULT_TICKS = 32w0x017D7800;

/* ---- packet classes ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;
const bit<8> CLASS_ACK       = 8w2;
const bit<8> CLASS_BLOCK_DEQ = 8w3;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header recirc_tag_h { bit<32> tag; }
header ibspg_h { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }
header ipv4_h {
    bit<4>  version; bit<4>  ihl;      bit<8>  diffserv;    bit<16> total_len;
    bit<16> identification; bit<3> flags; bit<13> frag_offset;
    bit<8>  ttl;     bit<8>  protocol; bit<16> hdr_checksum;
    bit<32> src_addr; bit<32> dst_addr;
}
header tcp_h {
    bit<16> src_port; bit<16> dst_port; bit<32> seq_no; bit<32> ack_no;
    bit<4>  data_offset; bit<4> res; bit<8> flags;
    bit<16> window; bit<16> checksum; bit<16> urgent_ptr;
}
header tcp_opt4_h  { bit<32> data; }
header tcp_opt8_h  { bit<64> data; }
header tcp_opt12_h { bit<96> data; }
header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }
header dnp3_app_h { bit<8> app_control; bit<8> func_code; }

struct headers_t {
    ethernet_h  eth;
    ibspg_h     ib;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt4_h  tcp_opt4;
    tcp_opt8_h  tcp_opt8;
    tcp_opt12_h tcp_opt12;
    dnp3_dl_h   dnp3_dl;
    dnp3_tp_h   dnp3_tp;
    dnp3_app_h  dnp3_app;
}

struct ig_meta_t {
    /* piece 1: parser-computed classification */
    bit<8>  role;
    bit<8>  dir;
    bit<9>  fwd_port;
    bit<8>  port_ok;
    bit<8>  gen_in;
    bit<8>  dequeued;

    bit<32> ts32;
    bit<8>  budget_zero;

    /* piece 2: packed transaction state */
    bit<32> ts_m;
    bit<32> seq_m;
    bit<32> now_word;
    bit<8>  pkt_class;
    bit<8>  tag_val;
    bit<32> dl_cand;
    bit<8>  tag_diff;
    bit<32> dl_val;
    bit<8>  tag_ok;
    bit<8>  ack_ok;
    bit<32> age;
    bit<8>  expired;

    /* pktgen */
    bit<8>     is_pktgen;
    bit<8>     cur_gen;
    bit<8>     txn_active;
    bit<32>    clone_tag;
    MirrorId_t clone_ses;
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    value_set<bit<8>>(1) pgen_recirc;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.ts_m            = 32w0;
        meta.seq_m           = 32w0;
        meta.now_word        = 32w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.tag_val         = TAG_NO_WRITE;
        meta.dl_cand         = 32w0;
        meta.tag_diff        = 8w0;
        meta.dl_val          = DL_NO_WRITE;
        meta.tag_ok          = 8w0;
        meta.ack_ok          = 8w0;
        meta.age             = 32w0;
        meta.expired         = 8w0;
        meta.cur_gen         = 8w0;
        meta.txn_active      = 8w0;
        meta.clone_tag       = 32w0;
        meta.clone_ses       = 10w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_L      : from_loopback;
            PORT_HULK   : from_outstation;
            PORT_RELAY  : from_outstation;
            PORT_VISION : from_master;
            PORT_PGEN   : from_pgen;
            default     : accept;
        }
    }

    state from_loopback   { meta.dequeued = 8w1; meta.dir = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_outstation { meta.dir      = DIR_OUT;    meta.fwd_port = PORT_VISION;
                            meta.port_ok  = 8w1; transition parse_eth; }
    state from_master     { meta.dir      = DIR_MASTER; meta.fwd_port = PORT_RELAY;
                            meta.port_ok  = 8w1; transition parse_eth; }

    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_recirc : parse_pktgen_token;
            default     : accept;
        }
    }
    state parse_pktgen_token {
        meta.is_pktgen = 8w1;
        meta.port_ok   = 8w1;
        meta.dir       = DIR_OUT;
        meta.fwd_port  = PORT_VISION;
        pkt.advance(PGEN_HDR_BITS);
        transition parse_eth;
    }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IBSPG_TOKEN : parse_token;
            ETHERTYPE_IPV4        : parse_ipv4;
            default               : accept;
        }
    }

    state parse_token {
        pkt.extract(hdr.ib);
        meta.role   = ROLE_BLOCK;
        meta.gen_in = hdr.ib.gen;
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;
            default             : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.flags, hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (8w0x10 &&& 8w0x17, 4w5,  16w40) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w6,  16w44) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w7,  16w48) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w8,  16w52) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w9,  16w56) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w10, 16w60) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w11, 16w64) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w12, 16w68) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w13, 16w72) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w14, 16w76) : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w15, 16w80) : set_role_ack;
            (8w0x00 &&& 8w0x07, 4w5,  16w53 .. 16w65535) : parse_dnp3_dl;
            (8w0x00 &&& 8w0x07, 4w6,  16w57 .. 16w65535) : opt4;
            (8w0x00 &&& 8w0x07, 4w7,  16w61 .. 16w65535) : opt8;
            (8w0x00 &&& 8w0x07, 4w8,  16w65 .. 16w65535) : opt12;
            default                                      : accept;
        }
    }

    state opt4  { pkt.extract(hdr.tcp_opt4);  transition parse_dnp3_dl; }
    state opt8  { pkt.extract(hdr.tcp_opt8);  transition parse_dnp3_dl; }
    state opt12 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }

    state set_role_ack { meta.role = ROLE_ACK; transition accept; }

    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start, hdr.dnp3_dl.length) {
            (DNP3_START, 8w8 .. 8w255) : parse_dnp3_tp;
            default                    : accept;
        }
    }

    state parse_dnp3_tp { pkt.extract(hdr.dnp3_tp); transition parse_dnp3_app; }

    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        meta.gen_in = hdr.dnp3_app.app_control;
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0x00 &&& 8w0x00, DNP3_FC_RESPONSE) : set_role_resp;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_READ)     : set_role_arm;
            default                               : accept;
        }
    }
    state set_role_resp { meta.role = ROLE_RESP; transition accept; }
    state set_role_arm  { meta.role = ROLE_ARM;  transition accept; }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ---- state register 1: TAG (generation + active) ---- */
    Register<bit<8>, bit<1>>(1, 0) reg_tag;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_read = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
        }
    };

    /* ---- state register 2: DEADLINE (ACK-relative) ---- */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val != DL_NO_WRITE) { v = meta.dl_val; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_arm_once = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (v == UNARMED_WORD) { v = meta.dl_val; }
        }
    };

    /* ---- lightweight counters (Stats ALU, multi-site OK) ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_deadline;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_release;
    Counter<bit<64>, bit<8>>(2, CounterType_t.PACKETS) ctr_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm_clone;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_pktgen_admit;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_pktgen_drop;

    /* ---- TM actions ---- */
    action to_block() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_fwd() {
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    action arm_clone() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.gen_in;
    }

    /* ---- guard interval G ---- */
    action set_guard(bit<32> g_ticks) { meta.seq_m = g_ticks; }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(G_DEFAULT_TICKS);
        size = 1;
    }

    action build_now() { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_build_now {
        actions = { build_now; }
        const default_action = build_now();
        size = 1;
    }

    action build_cand() { meta.dl_cand = meta.now_word + meta.seq_m; }
    table tbl_build_cand {
        actions = { build_cand; }
        const default_action = build_cand();
        size = 1;
    }

    /* ---- the ONE decode table ---- */
    action dec_arm()     { meta.dl_val = UNARMED_WORD; }
    action dec_ack_arm() { meta.dl_val = meta.dl_cand; meta.ack_ok = 8w1; }
    action dec_live()    { meta.dl_val = DL_NO_WRITE;  meta.tag_ok = 8w1; }
    action dec_none()    { meta.dl_val = DL_NO_WRITE; }
    table tbl_state_decode {
        key = {
            meta.pkt_class : exact;
            meta.tag_diff  : ternary;
        }
        actions = { dec_arm; dec_ack_arm; dec_live; dec_none; }
        const default_action = dec_none();
        const entries = {
            (CLASS_ARM,       8w0x00 &&& 8w0x00) : dec_arm();
            (CLASS_ACK,       8w0x00 &&& 8w0xFE) : dec_none();
            (CLASS_ACK,       8w0x00 &&& 8w0x00) : dec_ack_arm();
            (CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF) : dec_live();
        }
        size = 8;
    }

    /* ---- pktgen token active check ---- */
    action mark_txn_active()   { meta.txn_active = 8w1; }
    action mark_txn_inactive() { meta.txn_active = 8w0; }
    table tbl_pktgen_active {
        key = { meta.cur_gen : ternary; }
        actions = { mark_txn_active; mark_txn_inactive; }
        const default_action = mark_txn_inactive();
        const entries = {
            (8w0xC0 &&& 8w0xF0) : mark_txn_active();
        }
        size = 2;
    }

    /* ---- deadline expiry ---- */
    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = { meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = {
            (32w0x00000000 &&& 32w0x800000FF) : mark_expired();
        }
        size = 2;
    }

    apply {
        if (meta.port_ok == 8w0) {
            ctr_bypass.count(8w1);
            drop_pkt();
        } else {
            /* level 0: packet-derived */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }
            tbl_guard.apply();

            /* level 1: now-word, class, tag write driver */
            tbl_build_now.apply();
            if (meta.dequeued == 8w0) {
                if (meta.role == ROLE_ARM && meta.dir == DIR_MASTER) {
                    meta.pkt_class = CLASS_ARM;
                    meta.tag_val   = meta.gen_in;
                } else if (meta.role == ROLE_ACK && meta.dir == DIR_OUT) {
                    meta.pkt_class = CLASS_ACK;
                }
            } else if (meta.role == ROLE_BLOCK) {
                meta.pkt_class = CLASS_BLOCK_DEQ;
                if (meta.budget_zero == 8w1) {
                    meta.tag_val = TAG_INACTIVE;
                }
            }

            /* level 2: tag access (+ ACK candidate in parallel) */
            if (meta.is_pktgen == 8w1) {
                meta.cur_gen  = tag_read.execute(0);
            } else {
                meta.tag_diff = tag_rmw.execute(0);
            }
            tbl_build_cand.apply();

            /* level 3: decode */
            tbl_state_decode.apply();
            tbl_pktgen_active.apply();

            /* level 4: deadline access */
            if (meta.ack_ok == 8w1) {
                meta.age = deadline_arm_once.execute(0);
            } else {
                meta.age = deadline_rmw.execute(0);
            }

            /* level 5: expiry */
            tbl_deadline_expiry.apply();

            /* ACT */
            if (meta.dequeued == 8w0) {
                if (meta.role == ROLE_BLOCK) {
                    /* pktgen admission: admit only while a transaction is active */
                    if (meta.txn_active == 8w1) {
                        hdr.ib.role = ROLE_BLOCK;
                        hdr.ib.gen  = meta.cur_gen;
                        hdr.ib.seq  = INITIAL_BUDGET;
                        to_block();
                        ctr_pktgen_admit.count(0);
                    } else {
                        drop_pkt();
                        ctr_pktgen_drop.count(0);
                    }
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    to_resp();
                    ctr_resp_enq.count(0);
                } else if (meta.role == ROLE_ACK) {
                    to_fwd();
                    if (meta.ack_ok == 8w1) {
                        ctr_ack_arm.count(0);
                    } else {
                        ctr_ack_bypass.count(0);
                    }
                } else if (meta.role == ROLE_ARM) {
                    to_fwd();
                    ctr_arm.count(0);
                    if (meta.tag_diff != 8w0) {
                        arm_clone();
                        ctr_arm_clone.count(0);
                    }
                } else {
                    to_fwd();
                    ctr_bypass.count(8w0);
                }
            } else {
                /* DEQUEUED (looped back from dp8) */
                if (meta.role == ROLE_BLOCK) {
                    if (meta.tag_ok == 8w0) {
                        drop_pkt();
                        ctr_block_term_stale.count(0);
                    } else if (meta.expired == 8w1) {
                        drop_pkt();
                        ctr_block_term_deadline.count(0);
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt();
                        ctr_block_term_timeout.count(0);
                    } else {
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_block_loop.count(0);
                    }
                } else if (meta.role == ROLE_RESP) {
                    to_fwd();
                    ctr_resp_release.count(0);
                } else {
                    drop_pkt();
                }
            }
        }
    }
}

/* ============================ ingress deparser ========================== */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Mirror() clone_mirror;
    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) {
            clone_mirror.emit<recirc_tag_h>(meta.clone_ses, { meta.clone_tag });
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_opt4);
        pkt.emit(hdr.tcp_opt8);
        pkt.emit(hdr.tcp_opt12);
        pkt.emit(hdr.dnp3_dl);
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/* ============================ egress (byte-preserving pass-through) ===== */
struct eg_meta_t { }

parser EgParser(packet_in pkt,
                out headers_t hdr,
                out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition accept;
    }
}
control Egress(inout headers_t hdr,
               inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}
control EgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    eg_meta_t meta,
                   in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
    }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

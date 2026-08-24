/* ============================================================================
 * bootstrap_probe_v4.p4 — Defense 4 §3 reservoir bootstrap, v4
 *   SINGLE-PASS SHADOW STAGING with an AUTHORITATIVE packed population word.
 *
 * v3 (ead57b2) proved that DIRECTLY REUSING the authoritative packed population
 * register as the staged ACK-seed predicate creates an unsatisfiable single-pass
 * register-ordering cycle. It did NOT prove staged admission and atomic readiness are
 * inherently incompatible. v4 (Philip's construction) decouples them:
 *
 *   ACYCLIC STATE ORDER (a Register lives in one MAU stage; this order has no cycle):
 *     reg_gen < reg_ident_resp[64] < reg_resp_stage < reg_ident_ack[64] < reg_pop_packed
 *              < reg_resp_gen < reg_active < reg_failopen
 *
 *   - reg_ident_resp[64] / reg_ident_ack[64] : per-role token lifecycle + generation
 *       (cell = generation, bit31 = confirmed; EMPTY=0). Indexed by token_id[5:0].
 *   - reg_resp_stage : a RESPONSE-ONLY SHADOW count. Its SOLE job is to open the
 *       ACK-seeding stage. It NEVER authorizes a native packet.
 *   - reg_pop_packed : the AUTHORITATIVE packed {ack_count(hi16), resp_count(lo16)}.
 *       Native ACK/RESPONSE admission reads it ONCE (single-word atomic K/K). PRESERVED.
 *
 *   TRANSITIONS:
 *     1st RESPONSE confirm : confirm reg_ident_resp; ++reg_resp_stage; ++pop.RESP half.
 *     ACK seed            : admit ONLY when reg_resp_stage == K; then write reg_ident_ack.
 *     1st ACK confirm     : confirm reg_ident_ack; ++pop.ACK half.
 *     native ACK          : read reg_pop_packed once; hold ONLY iff == packed K/K AND
 *                           active AND fail-open NOT latched.
 *
 *   ATOMIC SAFETY (preserved): the shadow only gates WHEN ACK seeding may begin; it is
 *   NOT in the native decision at all (tbl_native_decide never reads reg_resp_stage), so
 *   it can never authorize a native packet by construction. Stronger: reg_resp_stage and
 *   pop.RESP are incremented in LOCKSTEP on the same first-RESP-confirm and reset together
 *   on a READ, so shadow == pop.RESP is an absolute invariant — they cannot diverge. Even
 *   under the defensive worst case (shadow ahead -> ACK tokens seed while pop.RESP < K, so
 *   no original can be held; shadow behind -> ACK seeding stays disabled, conservative
 *   fail-open) neither yields a false packed K/K.
 *
 * Also fixes two v3 semantic bugs (independent of the cycle):
 *   [FIX-ACK]  the native ACK now CHECKS the generation-qualified fail-open latch, so a
 *              duplicate ACK is NOT held after an earlier ACK failed open.
 *   [FIX-RESP] an UNREADY native RESPONSE now LATCHES fail-open before forwarding, so all
 *              subsequent packets of the generation bypass.
 *   reg_resp_gen is written gated on pop_packed==BOTH_READY, one stage BEFORE the active
 *   read (so resp_gen < active, breaking the resp_gen/active/failopen cycle). This is
 *   behaviour-equivalent only if an older held RESPONSE cannot coexist with the current
 *   generation. That invariant is ENVIRONMENTAL: DNP3 polling is single-outstanding (one
 *   request in flight). The READ path only DETECTS a violation (ctr_overlap is a canary,
 *   NOT a guard — it neither rejects the overlapping READ nor prevents the wrong clear);
 *   prevention rests on the single-outstanding assumption AND on the outcome being strictly
 *   FAIL-OPEN (an early active-clear only makes later native ACKs forward — nothing is
 *   stranded, lost, or misrouted). Robust overlapping-transaction handling would carry the
 *   generation in the loopback shim (a §4 mechanism, noted, not built here).
 *
 * SCOPE / NOT CLAIMED. §3 feasibility probe: NOT the timing core, does NOT patch
 * defense4_timing.p4, NOT loaded, NOT run. The deadline/release machinery is §4 (a held
 * packet loops on PORT_L; its FIRST loopback return models the release/completion point
 * so cleanup is placed correctly — the hold DURATION is §4). UNVERIFIED on silicon:
 * whether staged establishment reaches and holds K/K within the CLRT (continuity, R2/
 * R11). This shows the contract PLACES and is logically self-consistent; NOT that it
 * works on silicon. R11 stays OPEN.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

const bit<16> ETHERTYPE_TOKEN = 0x88C1;
const bit<16> ETHERTYPE_IPV4  = 0x0800;
const bit<8>  IP_PROTO_TCP     = 8w6;

const bit<16> DNP3_START       = 0x0564;
const bit<8>  DNP3_FC_READ      = 8w1;
const bit<8>  DNP3_FC_RESPONSE  = 8w129;

const PortId_t PORT_L      = 9w8;
const PortId_t PORT_MASTER = 9w9;
const PortId_t PORT_RELAY  = 9w64;
const PortId_t PORT_PGEN   = 9w68;

/* static strict-priority ladder 7 > 6 > 5 > 4 */
const bit<5> Q_ACK_BLOCK  = 5w7;
const bit<5> Q_ACK_HOLD    = 5w6;
const bit<5> Q_RESP_BLOCK = 5w5;
const bit<5> Q_RESP_HOLD    = 5w4;

const bit<16> K_TOKENS   = 16w64;
const bit<32> BOTH_READY = 32w0x00400040;   /* authoritative packed K/K */
const bit<32> DELTA_ACK_UP  = 32w0x00010000;
const bit<32> DELTA_RESP_UP = 32w0x00000001;

const bit<8> TOKEN_MARKER = 8w0xE1;
const bit<8> SD_LOOP      = 8w0x5A;
const bit<8> TOK_ACK      = 8w0xA1;
const bit<8> TOK_RESP     = 8w0xA2;

const bit<32> GEN_MAX     = 32w0x7FFFFFFF;
const bit<32> CONF_BIT    = 32w0x80000000;

const bit<8> R_SEEDED = 8w1;
const bit<8> R_DEDUP  = 8w0;
const bit<8> R_FIRST  = 8w1;
const bit<8> R_AGAIN  = 8w0;

const bit<8> ROLE_BYPASS  = 8w0;
const bit<8> ROLE_TOKEN   = 8w1;
const bit<8> ROLE_ACK     = 8w2;
const bit<8> ROLE_RESP    = 8w3;
const bit<8> ROLE_ARM     = 8w6;
const bit<8> ROLE_CLEANUP = 8w7;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header token_h {
    bit<8>  marker;
    bit<8>  sdomain;
    bit<8>  role;
    bit<32> generation;
    bit<16> token_id;
}
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
header tcp_opt12_h { bit<96> data; }
header dnp3_dl_h {
    bit<16> start; bit<8> length; bit<8> ctrl;
    bit<16> dst_addr; bit<16> src_addr; bit<16> crc;
}
header dnp3_tp_h  { bit<8> tp_ctrl; }
header dnp3_app_h { bit<8> app_control; bit<8> func_code; }

struct headers_t {
    pktgen_timer_header_t timer;
    ethernet_h  eth;
    token_h     token;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt12_h tcp_opt12;
    dnp3_dl_h   dnp3_dl;
    dnp3_tp_h   dnp3_tp;
    dnp3_app_h  dnp3_app;
}

struct ig_meta_t {
    /* origin/classification — written on EVERY parser path */
    bit<8>  role;
    bit<8>  port_ok;
    bit<9>  fwd_port;
    bit<8>  is_first;
    bit<8>  is_loop;
    bit<8>  from_out;

    /* MAU-derived (also init in start) */
    bit<8>  tok_valid;
    bit<1>  role_bit;
    bit<8>  tok_role;
    bit<16> token_id;
    bit<32> cur_gen;
    bit<32> cur_gen_conf; /* cur_gen | CONF_BIT — CONFIRMED(cur_gen) form for seed dedup */
    bit<16> stage_val;    /* reg_resp_stage read (shadow)         */
    bit<8>  ident_res;
    bit<32> pop_packed;
    bit<32> pop_delta;
    bit<8>  ready;        /* 1 = (pop_packed == BOTH_READY) && active; fail-open latches when ready==0 */
    bit<8>  active_val;
    bit<1>  fo_eq;        /* 1 = (failopen_old == cur_gen); native-decision table key */
    bit<32> failopen_old; /* scratch: reused to carry reg_resp_gen's value on the RESP
                           * loopback-completion path (the native path uses fo_eq now) */
}

/* ============================ ingress parser ============================ */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    value_set<bit<8>>(2) pgen_timer;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.tok_valid    = 8w0;
        meta.role_bit     = 1w0;
        meta.tok_role     = 8w0;
        meta.token_id     = 16w0;
        meta.cur_gen      = 32w0;
        meta.cur_gen_conf = 32w0;
        meta.stage_val    = 16w0;
        meta.ident_res    = 8w0;
        meta.pop_packed   = 32w0;
        meta.pop_delta    = 32w0;
        meta.ready        = 8w0;
        meta.active_val   = 8w0;
        meta.fo_eq        = 1w0;
        meta.failopen_old = 32w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_PGEN   : from_pgen;
            PORT_L      : from_loop;
            PORT_MASTER : from_master;
            PORT_RELAY  : from_relay;
            default     : bad_port;
        }
    }

    state bad_port {
        meta.role = ROLE_BYPASS; meta.port_ok = 8w0; meta.fwd_port = 9w0;
        meta.is_first = 8w0; meta.is_loop = 8w0; meta.from_out = 8w0;
        transition accept;
    }
    state from_loop {
        meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER;
        meta.is_first = 8w0; meta.is_loop = 8w1; meta.from_out = 8w0;
        transition parse_eth;
    }
    state from_master {
        meta.port_ok = 8w1; meta.fwd_port = PORT_RELAY;
        meta.is_first = 8w0; meta.is_loop = 8w0; meta.from_out = 8w0;
        transition parse_eth;
    }
    state from_relay {
        meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER;
        meta.is_first = 8w0; meta.is_loop = 8w0; meta.from_out = 8w1;
        transition parse_eth;
    }
    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_timer : parse_timer;
            default    : pgen_bad;
        }
    }
    state pgen_bad {
        meta.role = ROLE_BYPASS; meta.port_ok = 8w0; meta.fwd_port = 9w0;
        meta.is_first = 8w1; meta.is_loop = 8w0; meta.from_out = 8w0;
        transition accept;
    }
    state parse_timer {
        pkt.extract(hdr.timer);
        meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER;
        meta.is_first = 8w1; meta.is_loop = 8w0; meta.from_out = 8w0;
        transition parse_eth;
    }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_TOKEN : parse_token;
            ETHERTYPE_IPV4  : parse_ipv4;
            default         : set_bypass;
        }
    }
    state parse_token { pkt.extract(hdr.token); meta.role = ROLE_TOKEN; transition accept; }
    state set_bypass  { meta.role = ROLE_BYPASS; transition accept; }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;
            default             : set_bypass;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.flags, hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (8w0x01 &&& 8w0x01, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;
            (8w0x04 &&& 8w0x04, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;
            (8w0x10 &&& 8w0x17, 4w5, 16w40)                 : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w8, 16w52)                 : set_role_ack;
            (8w0x00 &&& 8w0x07, 4w5, 16w53 .. 16w65535)     : parse_dnp3_dl;
            (8w0x00 &&& 8w0x07, 4w8, 16w65 .. 16w65535)     : opt12_dnp3;
            default                                         : set_bypass;
        }
    }
    state opt12_dnp3 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }
    state set_role_ack     { meta.role = ROLE_ACK;     transition accept; }
    state set_role_cleanup { meta.role = ROLE_CLEANUP; transition accept; }
    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start, hdr.dnp3_dl.length) {
            (DNP3_START, 8w8 .. 8w255) : parse_dnp3_tp;
            default                    : set_bypass;
        }
    }
    state parse_dnp3_tp { pkt.extract(hdr.dnp3_tp); transition parse_dnp3_app; }
    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0x00 &&& 8w0x00, DNP3_FC_RESPONSE) : set_role_resp;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_READ)     : set_role_arm;
            default                               : set_bypass;
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

    /* ==== state order: gen < ident_resp < resp_stage < ident_ack < pop_packed
     *                       < resp_gen < active < failopen ==== */

    Register<bit<32>, bit<1>>(1, 0) reg_gen;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_gen) gen_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_gen) gen_bump = {
        void apply(inout bit<32> v, out bit<32> rv) {
            if (v == GEN_MAX) { v = 32w1; } else { v = v + 32w1; }
            rv = v;
        }
    };

    /* per-role identity cells (generation, bit31 = confirmed) */
    Register<bit<32>, bit<6>>(64, 0) reg_ident_resp;
    /* Seed dedup: overwrite iff the cell does NOT already hold this generation in
     * either SEEDED(cur_gen) or CONFIRMED(cur_gen) form. Written as two raw-value
     * comparators (v==cur_gen || v==cur_gen|CONF) rather than a masked compare
     * ((v & GEN_MAX)==cur_gen) because bf-asm cannot lower an AND on the register
     * operand inside a stateful compare. Bit-identical given v in {0,G,G|CONF}. */
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_resp) ident_resp_seed = {
        void apply(inout bit<32> v, out bit<8> rv) {
            /* Overwrite iff the cell does NOT already hold this generation (SEEDED or
             * CONFIRMED). Uses TWO full-word equalities — v==cur_gen (SEEDED(cur_gen)) or
             * v==cur_gen_conf (CONFIRMED(cur_gen)) — instead of the single masked compare
             * (v & GEN_MAX)==cur_gen, because bf-asm cannot lower an AND on the register
             * operand inside a stateful compare. Bit-identical for v in {0,G,G|CONF}. */
            if (v == meta.cur_gen)           { rv = R_DEDUP; }
            else if (v == meta.cur_gen_conf) { rv = R_DEDUP; }
            else { v = meta.cur_gen; rv = R_SEEDED; }
        }
    };
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_resp) ident_resp_confirm = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen) { v = meta.cur_gen | CONF_BIT; rv = R_FIRST; }
            else { rv = R_AGAIN; }
        }
    };

    /* RESP-only SHADOW count — opens ACK seeding ONLY */
    Register<bit<16>, bit<1>>(1, 0) reg_resp_stage;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_resp_stage) stage_incr = {
        void apply(inout bit<16> v, out bit<16> rv) { v = v + 16w1; rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_resp_stage) stage_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_resp_stage) stage_reset = {
        void apply(inout bit<16> v, out bit<16> rv) { v = 16w0; rv = v; }
    };

    Register<bit<32>, bit<6>>(64, 0) reg_ident_ack;
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_ack) ident_ack_seed = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen)           { rv = R_DEDUP; }
            else if (v == meta.cur_gen_conf) { rv = R_DEDUP; }
            else { v = meta.cur_gen; rv = R_SEEDED; }
        }
    };
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_ack) ident_ack_confirm = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen) { v = meta.cur_gen | CONF_BIT; rv = R_FIRST; }
            else { rv = R_AGAIN; }
        }
    };

    /* AUTHORITATIVE packed population {ack(hi16), resp(lo16)} */
    Register<bit<32>, bit<1>>(1, 0) reg_pop_packed;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_incr = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + meta.pop_delta; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };

    /* held-RESPONSE generation, for gen-qualified cleanup at loopback completion.
     * Written gated-on-ready BEFORE the active read, so resp_gen < active (no SCC). */
    Register<bit<32>, bit<1>>(1, 0) reg_resp_gen;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_resp_gen) resp_gen_set = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.cur_gen; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_resp_gen) resp_gen_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    Register<bit<8>, bit<1>>(1, 0) reg_active;
    /* open: read the old value (overlap guard) AND set active in ONE access */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_open  = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = 8w1; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_read  = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = v; }
    };

    /* generation-qualified fail-open latch. RMW: read old, set to cur_gen iff unready. */
    Register<bit<32>, bit<1>>(1, 0) reg_failopen;
    /* RMW: output fo_eq = (OLD failopen == cur_gen) directly (the native decision only
     * needs this bit, not the raw old value), then latch fail-open when NOT ready
     * (ready==0 is exactly the old unready==1). Returning the predicate instead of the
     * 32-bit old value removes the separate fo_eq compare stage in the tail. */
    RegisterAction<bit<32>, bit<1>, bit<8>>(reg_failopen) failopen_rmw = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen) { rv = 8w1; } else { rv = 8w0; }
            if (meta.ready == 8w0) { v = meta.cur_gen; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_failopen) failopen_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };

    /* ---- counters ----
     * Trimmed to the load-bearing observability set required by §3 (seed / confirm /
     * hold / failopen / stale) plus the overlap safety canary. Purely-diagnostic
     * event counters were removed to relieve mid-pipeline Stats-ALU / logical-table
     * width so the 8-register chain packs to its stage floor. Every dropped counter
     * gated NO control flow — each sat beside an unconditional drop_pkt()/to_fwd(). */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_new;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_confirm_resp;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_confirm_ack;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_complete_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_overlap;
    /* native ACK/RESPONSE hold / fail-open / bypass counts live in the direct counter
     * ctr_native attached to tbl_native_decide (one slot per matched decision entry). */

    /* ---- TM actions ---- */
    action to_ack_block()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_BLOCK;  ig_tm_md.bypass_egress = 1w1; }
    action to_ack_hold()   { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_HOLD;   ig_tm_md.bypass_egress = 1w1; }
    action to_resp_block() { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_BLOCK; ig_tm_md.bypass_egress = 1w1; }
    action to_resp_hold()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_HOLD;  ig_tm_md.bypass_egress = 1w1; }
    action to_fwd()        { ig_tm_md.ucast_egress_port = meta.fwd_port; ig_tm_md.qid = 5w0; ig_tm_md.bypass_egress = 1w0; }
    action drop_pkt()      { ig_dprsr_md.drop_ctl = 3w1; }

    action admit_stamp() {
        hdr.token.setValid();
        hdr.token.marker     = TOKEN_MARKER;
        hdr.token.sdomain    = SD_LOOP;
        hdr.token.role       = meta.tok_role;
        hdr.token.generation = meta.cur_gen;
        hdr.token.token_id   = meta.token_id;
        hdr.timer.setInvalid();
    }

    action app_ack()  { meta.tok_role = TOK_ACK;  meta.role_bit = 1w0; }
    action app_resp() { meta.tok_role = TOK_RESP; meta.role_bit = 1w1; }
    table tbl_app_role {
        key = { hdr.timer.app_id : exact; }
        actions = { app_ack; app_resp; }
        const default_action = app_ack();
        const entries = { (3w0) : app_ack(); (3w1) : app_resp(); }
        size = 2;
    }

    action mark_tokid_ok()  { meta.tok_valid = 8w1; }
    action mark_tokid_bad() { meta.tok_valid = 8w0; }
    table tbl_tokid_valid {
        key = { hdr.timer.packet_id : ternary; }
        actions = { mark_tokid_ok; mark_tokid_bad; }
        const default_action = mark_tokid_bad();
        const entries = { (16w0 &&& 16w0xFFC0) : mark_tokid_ok(); }
        size = 2;
    }

    action valid_ack()  { meta.tok_valid = 8w1; meta.role_bit = 1w0; }
    action valid_resp() { meta.tok_valid = 8w1; meta.role_bit = 1w1; }
    action valid_bad()  { meta.tok_valid = 8w0; }
    table tbl_token_valid {
        key = {
            hdr.token.marker   : exact;
            hdr.token.sdomain  : exact;
            hdr.token.role     : exact;
            hdr.token.token_id : ternary;
        }
        actions = { valid_ack; valid_resp; valid_bad; }
        const default_action = valid_bad();
        const entries = {
            (TOKEN_MARKER, SD_LOOP, TOK_ACK,  16w0 &&& 16w0xFFC0) : valid_ack();
            (TOKEN_MARKER, SD_LOOP, TOK_RESP, 16w0 &&& 16w0xFFC0) : valid_resp();
        }
        size = 4;
    }

    /* Native ACK/RESPONSE decision, collapsed from an if-else cascade into ONE table
     * keyed on {role, ready, fo_eq}. Semantically identical to the original branches:
     *   ACK  : hold iff ready && failopen_old!=cur_gen (fo_eq==0); else fwd (fail-open).
     *   RESP : fo_eq==1 -> fwd (already failed open); else ready -> hold; else fwd (latched). */
    /* per-outcome observability: one direct counter, one slot per matched entry
     * (hold vs fail-open vs bypass are distinct entries -> distinct counts). */
    DirectCounter<bit<64>>(CounterType_t.PACKETS) ctr_native;
    action nd_hold_ack()   { to_ack_hold();  ctr_native.count(); }
    action nd_fwd_ack()    { to_fwd();        ctr_native.count(); }
    action nd_hold_resp()  { to_resp_hold(); ctr_native.count(); }
    action nd_fwd_resp()   { to_fwd();        ctr_native.count(); }
    action nd_fwd_bypass() { to_fwd();        ctr_native.count(); }
    table tbl_native_decide {
        key = { meta.role : exact; meta.ready : exact; meta.fo_eq : exact; }
        actions = { nd_hold_ack; nd_fwd_ack; nd_hold_resp; nd_fwd_resp; nd_fwd_bypass; }
        counters = ctr_native;
        const default_action = nd_fwd_bypass();
        const entries = {
            (ROLE_ACK,  8w1, 1w0) : nd_hold_ack();
            (ROLE_ACK,  8w1, 1w1) : nd_fwd_ack();
            (ROLE_ACK,  8w0, 1w0) : nd_fwd_ack();
            (ROLE_ACK,  8w0, 1w1) : nd_fwd_ack();
            (ROLE_RESP, 8w1, 1w1) : nd_fwd_bypass();
            (ROLE_RESP, 8w0, 1w1) : nd_fwd_bypass();
            (ROLE_RESP, 8w1, 1w0) : nd_hold_resp();
            (ROLE_RESP, 8w0, 1w0) : nd_fwd_resp();
        }
        size = 8;
    }

    /* ---- @stage-pinned wrappers for the two registers whose multi-branch access sites
     * the placer could not co-locate once cur_gen_conf lengthened the chain (its greedy
     * pass is non-monotonic). Pinning removes the freedom to scatter a register's sites
     * across stages. The pins match the register chain's realised stages
     * (reg_ident_ack@4, reg_active@8); the unpinned registers place around them in order
     * (gen0 < ident_resp2 < resp_stage3 < ident_ack4 < pop6 < resp_gen7 < active8 < failopen10).
     * Each access is its own table so no table is applied from two branches (TF1 forbids
     * that); the two active_clear sites stay mutually exclusive (cleanup vs completion). */
    action ia_seed()    { meta.ident_res = ident_ack_seed.execute(meta.token_id[5:0]); }
    action ia_confirm() { meta.ident_res = ident_ack_confirm.execute(hdr.token.token_id[5:0]); }
    @stage(4) table tbl_ia_seed    { actions = { ia_seed; }    const default_action = ia_seed();    size = 1; }
    @stage(4) table tbl_ia_confirm { actions = { ia_confirm; } const default_action = ia_confirm(); size = 1; }

    action a_open()   { meta.active_val = active_open.execute(1w0); }
    action a_read()   { meta.active_val = active_read.execute(1w0); }
    action a_clear1() { active_clear.execute(1w0); }   /* FIN/RST cleanup */
    action a_clear2() { active_clear.execute(1w0); }   /* gen-qualified completion */
    @stage(8) table tbl_active_open   { actions = { a_open; }   const default_action = a_open();   size = 1; }
    @stage(8) table tbl_active_read   { actions = { a_read; }   const default_action = a_read();   size = 1; }
    @stage(8) table tbl_active_clear1 { actions = { a_clear1; } const default_action = a_clear1(); size = 1; }
    @stage(8) table tbl_active_clear2 { actions = { a_clear2; } const default_action = a_clear2(); size = 1; }

    apply {
        if (meta.port_ok == 8w0) {
            drop_pkt();
        } else {
          /* read the generation ONCE for every in-topology packet (bump on a READ), so
           * reg_gen has exactly two access sites (gen_bump / gen_read). */
          if (meta.role == ROLE_ARM) { meta.cur_gen = gen_bump.execute(1w0); }
          else                       { meta.cur_gen = gen_read.execute(1w0); }
          meta.cur_gen_conf = meta.cur_gen | CONF_BIT;   /* CONFIRMED(cur_gen) form for seed dedup */
          if (meta.role == ROLE_TOKEN) {
            if (meta.is_first == 8w1) {
                /* ===== PKTGEN ADMIT (staged, role-split) ===== */
                meta.token_id = (bit<16>)hdr.timer.packet_id;
                tbl_app_role.apply();
                tbl_tokid_valid.apply();
                if (meta.tok_valid == 8w1) {
                    if (meta.role_bit == 1w1) {
                        /* RESP seed: no stage gate. Index = token_id[5:0], folded in. */
                        meta.ident_res = ident_resp_seed.execute(meta.token_id[5:0]);
                        if (meta.ident_res == R_SEEDED) {
                            admit_stamp(); to_resp_block(); ctr_seed_new.count(1w0);
                        } else { drop_pkt(); }
                    } else {
                        /* ACK seed: gate on the RESP shadow reaching K */
                        meta.stage_val = stage_read.execute(1w0);
                        if (meta.stage_val == K_TOKENS) {
                            tbl_ia_seed.apply();
                            if (meta.ident_res == R_SEEDED) {
                                admit_stamp(); to_ack_block(); ctr_seed_new.count(1w0);
                            } else { drop_pkt(); }
                        } else {
                            drop_pkt();
                        }
                    }
                } else {
                    drop_pkt();
                }
            } else if (meta.is_loop == 8w1) {
                /* ===== LOOPBACK TOKEN ===== */
                tbl_token_valid.apply();
                if (meta.tok_valid == 8w1) {
                    if (hdr.token.generation == meta.cur_gen) {
                        if (meta.role_bit == 1w1) {
                            meta.ident_res = ident_resp_confirm.execute(hdr.token.token_id[5:0]);
                            if (meta.ident_res == R_FIRST) {
                                meta.stage_val = stage_incr.execute(1w0);   /* shadow ++ */
                                meta.pop_delta = DELTA_RESP_UP;
                                meta.pop_packed = pop_incr.execute(1w0);     /* authoritative ++ */
                                ctr_confirm_resp.count(1w0);
                            }
                            to_resp_block();
                        } else {
                            tbl_ia_confirm.apply();
                            if (meta.ident_res == R_FIRST) {
                                meta.pop_delta = DELTA_ACK_UP;
                                meta.pop_packed = pop_incr.execute(1w0);
                                ctr_confirm_ack.count(1w0);
                            }
                            to_ack_block();
                        }
                    } else {
                        drop_pkt(); ctr_term_stale.count(1w0);   /* stale gen: drop, no cell touch */
                    }
                } else {
                    drop_pkt();
                }
            } else {
                drop_pkt();
            }
        } else if (meta.role == ROLE_ARM) {
            /* ===== host READ: generation bumped above; reset population 0/0 + shadow ===== */
            stage_reset.execute(1w0);
            pop_reset.execute(1w0);
            tbl_active_open.apply();                            /* overlap guard + set, one access */
            if (meta.active_val == 8w1) { ctr_overlap.count(1w0); }
            failopen_reset.execute(1w0);
            to_fwd();
        } else if (meta.role == ROLE_CLEANUP) {
            /* FIN/RST teardown: clear reg_active (pinned, in-branch). */
            tbl_active_clear1.apply();
            to_fwd();
        } else if (meta.role == ROLE_RESP && meta.is_loop == 8w1) {
            /* ===== held RESPONSE completing (loopback): gen-qualified cleanup ===== */
            meta.failopen_old = resp_gen_read.execute(1w0);    /* reuse field: resp_gen value */
            if (meta.failopen_old == meta.cur_gen) {
                tbl_active_clear2.apply();       /* gen-qualified cleanup, in-branch */
            } else {
                ctr_resp_complete_stale.count(1w0);
            }
            to_fwd();
        } else if (meta.role == ROLE_ACK && meta.is_loop == 8w1) {
            to_fwd();
        } else if ((meta.role == ROLE_ACK || meta.role == ROLE_RESP) && meta.from_out == 8w1) {
            /* ===== native ACK / RESPONSE (shared state reads: pop, active, failopen) ===== */
            meta.pop_packed = pop_read.execute(1w0);
            /* RESP-only, gated-on-ready, BEFORE the active read (resp_gen < active) */
            if (meta.role == ROLE_RESP && meta.pop_packed == BOTH_READY) { resp_gen_set.execute(1w0); }
            tbl_active_read.apply();
            if (meta.pop_packed == BOTH_READY && meta.active_val == 8w1) { meta.ready = 8w1; }
            meta.fo_eq = (bit<1>)failopen_rmw.execute(1w0);    /* latch if ready==0; returns fo_eq */
            tbl_native_decide.apply();   /* hold/fwd + counter, per {role, ready, fo_eq} */
          } else if (meta.is_first == 8w1) {
            drop_pkt();
          } else {
            to_fwd();
          }
        }
    }
}

/* ============================ ingress deparser ========================== */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.token);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.tcp_opt12);
        pkt.emit(hdr.dnp3_dl);
        pkt.emit(hdr.dnp3_tp);
        pkt.emit(hdr.dnp3_app);
    }
}

/* ============================ egress pass-through ======================= */
struct eg_meta_t { }
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start { pkt.extract(eg_intr_md); transition parse_eth; }
    state parse_eth { pkt.extract(hdr.eth); transition accept; }
}
control Egress(inout headers_t hdr, inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t meta,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { pkt.emit(hdr.eth); }
}

Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

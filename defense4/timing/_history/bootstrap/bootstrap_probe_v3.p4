/* ============================================================================
 * bootstrap_probe_v3.p4 — Defense 4 §3 reservoir-bootstrap probe, v3
 *   STAGED RESPONSE-FIRST establishment under the STATIC ladder 7 > 6 > 5 > 4.
 *
 * PURPOSE. Implement the R11 contract as Philip specified after auditing v1
 * (d991944) and v2 (d67184f), both retained as PARTIAL NEGATIVE probes. v3 solves
 * the strict-priority starvation by ADMISSION ORDERING (not by co-equal priorities,
 * shaping, dynamic TM, or a per-transaction controller):
 *
 *   [S] A READ opens a new generation and atomically resets population to 0/0.
 *   [S] Periodic RESPONSE seeds are accepted first; ACK seeds are DROPPED until the
 *       RESP reservoir reaches K (state 0/K). Because Q_ACK_BLOCK (qid7) is empty
 *       during this phase, Q_RESP_BLOCK (qid5) dequeues freely and RESP tokens can
 *       loop and CONFIRM despite being the lower-priority block queue.
 *   [S] Only at 0/K may ACK seeds enter Q_ACK_BLOCK; ACK tokens confirm to K/K.
 *   [S] Only K/K admits the native ACK; otherwise the transaction latches fail-open.
 *   [S] At release (Gate 4/§4, out of scope) the static ladder naturally drains
 *       ACK-blocker -> ACK -> RESP-blocker -> RESP.
 *
 * The six v2 defects are addressed:
 *   [F-init]  every metadata field is written on every parser path (no reliance on
 *             default-0), so origin flags are never undefined (v2 G4).
 *   [F-pop]   reg_pop is RESET to 0/0 on a READ and only CURRENT-generation CONFIRMs
 *             increment it, so a stale K/K can never admit a new ACK (v2 G2).
 *   [F-cell]  each identity cell stores the GENERATION (with a confirmed bit): a
 *             stale token is dropped and never clears a cell; a re-seed lazily
 *             overwrites a stale cell only when its generation differs from current
 *             (v2 G5 — no unconditional clear, no ABA on the cell).
 *   [F-aba]   generation is 32-bit in [1, 0x7FFFFFFF] (skip 0), so reuse needs ~2.1e9
 *             transactions; and a stale token is dropped on its FIRST loopback return,
 *             so no token survives even one generation-reuse cycle (v2 wrap-ABA).
 *   [F-clean] cleanup runs at the generation-qualified LOOPBACK COMPLETION of the held
 *             RESPONSE (not at native admission), so it cannot precede release or
 *             break RESPONSE-before-ACK (v2 G7).
 *   [F-setup] bootstrap_setup.py is a complete, guarded, executable one-time setup on
 *             the fixed 7>6>5>4 ladder with shaping disabled (v2 G8).
 *
 * SCOPE / NOT CLAIMED. Still a §3 feasibility probe: NOT the timing core, does NOT
 * patch defense4_timing.p4, NOT loaded, NOT run. The deadline/release machinery is §4
 * (a held packet loops on PORT_L; this probe models its FIRST loopback return as the
 * release/completion point to place cleanup correctly — the hold DURATION is §4).
 * What stays UNVERIFIED (silicon): that the staged establishment actually reaches K/K
 * and holds it within the CLRT on hardware (continuity / establishment latency, R2/
 * R11). This probe shows the staged contract PLACES and is logically self-consistent;
 * it does NOT show it works on silicon. R11 stays OPEN.
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

/* static strict-priority ladder 7 > 6 > 5 > 4 (never changed at runtime) */
const bit<5> Q_ACK_BLOCK  = 5w7;
const bit<5> Q_ACK_HOLD    = 5w6;
const bit<5> Q_RESP_BLOCK = 5w5;
const bit<5> Q_RESP_HOLD    = 5w4;

const bit<16> K_TOKENS   = 16w64;
const bit<32> BOTH_READY = 32w0x00400040;   /* hi=ACK=K, lo=RESP=K */
const bit<32> DELTA_ACK_UP  = 32w0x00010000;
const bit<32> DELTA_RESP_UP = 32w0x00000001;

/* token identity */
const bit<8> TOKEN_MARKER = 8w0xE1;
const bit<8> SD_LOOP      = 8w0x5A;
const bit<8> TOK_ACK      = 8w0xA1;
const bit<8> TOK_RESP     = 8w0xA2;

/* generation: 32-bit, [1, GEN_MAX]; bit31 reserved as the cell "confirmed" flag */
const bit<32> GEN_MAX     = 32w0x7FFFFFFF;
const bit<32> CONF_BIT    = 32w0x80000000;

/* ident_seed / ident_confirm result codes */
const bit<8> R_SEEDED = 8w1;   /* seed overwrote a stale/empty cell */
const bit<8> R_DEDUP  = 8w0;   /* cell already current-gen          */
const bit<8> R_FIRST  = 8w1;   /* SEEDED -> CONFIRMED this pass      */
const bit<8> R_AGAIN  = 8w0;   /* already CONFIRMED                 */

/* host roles */
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
    /* origin/classification — written on EVERY parser path (F-init) */
    bit<8>  role;
    bit<8>  port_ok;
    bit<9>  fwd_port;
    bit<8>  is_first;
    bit<8>  is_loop;
    bit<8>  from_out;

    /* MAU-derived (also init in start) */
    bit<8>  tok_valid;
    bit<1>  role_bit;    /* 0 = ACK reservoir, 1 = RESP */
    bit<8>  tok_role;
    bit<16> token_id;
    bit<7>  pres_idx;
    bit<32> cur_gen;
    bit<8>  resp_ready;  /* 1 = pop.RESP == K (ACK-seed gate)   */
    bit<8>  ident_res;
    bit<32> pop_packed;
    bit<32> pop_delta;
    bit<8>  active_val;
    bit<32> failopen_val;
    bit<32> resp_gen;    /* held RESPONSE's generation (cleanup) */
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
        /* F-init: every MAU-scratch field explicitly initialized. The origin flags
         * (role/port_ok/fwd_port/is_first/is_loop/from_out) are NOT set here — Tofino
         * forbids re-assigning a parser field on the same path — instead each is set on
         * EVERY first-level path below, so none is ever read undefined. */
        meta.tok_valid    = 8w0;
        meta.role_bit     = 1w0;
        meta.tok_role     = 8w0;
        meta.token_id     = 16w0;
        meta.pres_idx     = 7w0;
        meta.cur_gen      = 32w0;
        meta.resp_ready   = 8w0;
        meta.ident_res    = 8w0;
        meta.pop_packed   = 32w0;
        meta.pop_delta    = 32w0;
        meta.active_val   = 8w0;
        meta.failopen_val = 32w0;
        meta.resp_gen     = 32w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_PGEN   : from_pgen;
            PORT_L      : from_loop;
            PORT_MASTER : from_master;
            PORT_RELAY  : from_relay;
            default     : bad_port;
        }
    }

    /* every first-level path sets the FULL origin-flag set exactly once (F-init) */
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

    /* ---- F-cell: identity cell = generation (bit31 = confirmed). EMPTY=0,
     * SEEDED(G)=G (G in [1,GEN_MAX], bit31=0), CONFIRMED(G)=G|CONF_BIT. ---- */
    Register<bit<32>, bit<7>>(128, 0) reg_ident;
    /* seed overwrites unless the cell is already claimed by the current generation
     * ((v masked of the confirmed bit) == cur_gen). A stale/empty cell is (re)seeded. */
    RegisterAction<bit<32>, bit<7>, bit<8>>(reg_ident) ident_seed = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if ((v & GEN_MAX) == meta.cur_gen) { rv = R_DEDUP; }
            else { v = meta.cur_gen; rv = R_SEEDED; }
        }
    };
    /* confirm advances SEEDED(cur_gen) -> CONFIRMED(cur_gen). Reached only when
     * token.generation == cur_gen, so the cell is this generation's. */
    RegisterAction<bit<32>, bit<7>, bit<8>>(reg_ident) ident_confirm = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen) { v = meta.cur_gen | CONF_BIT; rv = R_FIRST; }
            else { rv = R_AGAIN; }
        }
    };

    /* ---- F-pop: packed live counts, RESET on a READ, only current-gen confirms ---- */
    Register<bit<32>, bit<1>>(1, 0) reg_pop;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop) pop_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop) pop_incr = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + meta.pop_delta; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop) pop_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* ---- F-aba: 32-bit generation, skip 0, wrap at GEN_MAX (bit31 stays 0) ---- */
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

    /* ---- transaction active flag ---- */
    Register<bit<8>, bit<1>>(1, 0) reg_active;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_set   = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_read  = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = v; }
    };

    /* ---- generation-qualified fail-open latch ---- */
    Register<bit<32>, bit<1>>(1, 0) reg_failopen;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_failopen) failopen_set = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.cur_gen; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_failopen) failopen_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_failopen) failopen_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };

    /* ---- F-clean: held RESPONSE's generation, for cleanup at loopback completion ---- */
    Register<bit<32>, bit<1>>(1, 0) reg_resp_gen;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_resp_gen) resp_gen_set = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.cur_gen; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_resp_gen) resp_gen_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* ---- counters ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_new;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_dup;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_seed_early;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_bad_identity;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_badorigin;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_confirm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_persist;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_failopen;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_complete;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_failopen;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_complete;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_complete_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_cleanup;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drop_badport;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drop_pgen_anom;

    /* ---- TM actions (static ladder 7/6/5/4) ---- */
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
        const entries = { (16w0 &&& 16w0xFFC0) : mark_tokid_ok(); }   /* packet_id < 64 */
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

    /* ACK-seed gate: RESP reservoir at K iff pop lo16 == K (masked ternary) */
    action mark_resp_ready()  { meta.resp_ready = 8w1; }
    action mark_resp_notyet() { meta.resp_ready = 8w0; }
    table tbl_resp_ready {
        key = { meta.pop_packed : ternary; }
        actions = { mark_resp_ready; mark_resp_notyet; }
        const default_action = mark_resp_notyet();
        const entries = { (32w0x00000040 &&& 32w0x0000FFFF) : mark_resp_ready(); }
        size = 2;
    }

    action idx_from_timer() { meta.pres_idx = meta.role_bit ++ meta.token_id[5:0]; }
    action idx_from_token() { meta.pres_idx = meta.role_bit ++ hdr.token.token_id[5:0]; }
    table tbl_idx_timer { actions = { idx_from_timer; } const default_action = idx_from_timer(); size = 1; }
    table tbl_idx_token { actions = { idx_from_token; } const default_action = idx_from_token(); size = 1; }

    apply {
        if (meta.port_ok == 8w0) {
            ctr_drop_badport.count(1w0);
            drop_pkt();
        } else if (meta.role == ROLE_TOKEN) {
            if (meta.is_first == 8w1) {
                /* ===== PKTGEN ADMIT (staged) ===== */
                meta.token_id = (bit<16>)hdr.timer.packet_id;
                tbl_app_role.apply();
                tbl_tokid_valid.apply();
                if (meta.tok_valid == 8w1) {
                    tbl_idx_timer.apply();
                    meta.cur_gen    = gen_read.execute(1w0);
                    meta.pop_packed = pop_read.execute(1w0);
                    tbl_resp_ready.apply();
                    /* [S] ACK seeds are dropped until the RESP reservoir is at K */
                    if (meta.role_bit == 1w0 && meta.resp_ready == 8w0) {
                        drop_pkt();
                        ctr_ack_seed_early.count(1w0);
                    } else {
                        meta.ident_res = ident_seed.execute(meta.pres_idx);
                        if (meta.ident_res == R_SEEDED) {
                            admit_stamp();
                            if (meta.role_bit == 1w0) { to_ack_block(); }   /* qid7 */
                            else                      { to_resp_block(); }  /* qid5 */
                            ctr_seed_new.count(1w0);
                        } else {
                            drop_pkt();
                            ctr_seed_dup.count(1w0);
                        }
                    }
                } else {
                    drop_pkt();
                    ctr_bad_identity.count(1w0);
                }
            } else if (meta.is_loop == 8w1) {
                /* ===== LOOPBACK TOKEN ===== */
                tbl_token_valid.apply();
                if (meta.tok_valid == 8w1) {
                    tbl_idx_token.apply();
                    meta.cur_gen = gen_read.execute(1w0);
                    if (hdr.token.generation == meta.cur_gen) {
                        meta.ident_res = ident_confirm.execute(meta.pres_idx);
                        if (meta.ident_res == R_FIRST) {                    /* F-pop: count on CONFIRM */
                            if (meta.role_bit == 1w0) { meta.pop_delta = DELTA_ACK_UP; }
                            else                      { meta.pop_delta = DELTA_RESP_UP; }
                            meta.pop_packed = pop_incr.execute(1w0);
                            ctr_confirm.count(1w0);
                        } else {
                            ctr_persist.count(1w0);
                        }
                        if (meta.role_bit == 1w0) { to_ack_block(); } else { to_resp_block(); }
                    } else {
                        /* F-cell/F-aba: stale generation -> drop; never clear a cell */
                        drop_pkt();
                        ctr_term_stale.count(1w0);
                    }
                } else {
                    drop_pkt();
                    ctr_bad_identity.count(1w0);
                }
            } else {
                drop_pkt();
                ctr_seed_badorigin.count(1w0);
            }
        } else if (meta.role == ROLE_ARM) {
            /* ===== host READ: open generation + reset population 0/0 ===== */
            meta.cur_gen = gen_bump.execute(1w0);
            pop_reset.execute(1w0);
            active_set.execute(1w0);
            failopen_reset.execute(1w0);
            to_fwd();
            ctr_arm.count(1w0);
        } else if (meta.role == ROLE_CLEANUP) {
            active_clear.execute(1w0);          /* FIN/RST teardown */
            to_fwd();
            ctr_cleanup.count(1w0);
        } else if (meta.role == ROLE_RESP && meta.is_loop == 8w1) {
            /* ===== F-clean: held RESPONSE completing (loopback) ===== */
            meta.cur_gen  = gen_read.execute(1w0);
            meta.resp_gen = resp_gen_read.execute(1w0);
            if (meta.resp_gen == meta.cur_gen) {
                active_clear.execute(1w0);      /* generation-qualified cleanup at release */
                ctr_resp_complete.count(1w0);
            } else {
                ctr_resp_complete_stale.count(1w0);
            }
            to_fwd();                            /* release to master */
        } else if (meta.role == ROLE_ACK && meta.is_loop == 8w1) {
            to_fwd();                            /* held ACK completing -> release to master */
            ctr_ack_complete.count(1w0);
        } else if (meta.role == ROLE_ACK && meta.from_out == 8w1) {
            /* ===== native ACK: admit only at K/K ===== */
            meta.cur_gen    = gen_read.execute(1w0);
            meta.pop_packed = pop_read.execute(1w0);
            meta.active_val = active_read.execute(1w0);
            if (meta.pop_packed == BOTH_READY && meta.active_val == 8w1) {
                to_ack_hold();                   /* qid6 */
                ctr_ack_hold.count(1w0);
            } else {
                failopen_set.execute(1w0);
                to_fwd();
                ctr_ack_failopen.count(1w0);
            }
        } else if (meta.role == ROLE_RESP && meta.from_out == 8w1) {
            /* ===== native RESPONSE: bypass-if-failed-open, else hold ===== */
            meta.cur_gen      = gen_read.execute(1w0);
            meta.pop_packed   = pop_read.execute(1w0);
            meta.active_val   = active_read.execute(1w0);
            meta.failopen_val = failopen_read.execute(1w0);
            if (meta.failopen_val == meta.cur_gen) {
                to_fwd();
                ctr_resp_bypass.count(1w0);
            } else if (meta.pop_packed == BOTH_READY && meta.active_val == 8w1) {
                resp_gen_set.execute(1w0);       /* record gen for cleanup at completion */
                to_resp_hold();                  /* qid4 */
                ctr_resp_hold.count(1w0);
            } else {
                to_fwd();
                ctr_resp_failopen.count(1w0);
            }
        } else if (meta.is_first == 8w1) {
            drop_pkt();                          /* anomalous pktgen packet (not a token) */
            ctr_drop_pgen_anom.count(1w0);
        } else {
            to_fwd();
            ctr_bypass.count(1w0);
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

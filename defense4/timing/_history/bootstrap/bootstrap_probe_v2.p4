/* ============================================================================
 * bootstrap_probe_v2.p4 — Defense 4 §3 reservoir-bootstrap probe, v2 (R11 contract)
 *
 * PURPOSE. Answer the R11 kill-question OFFLINE, implementing the ACTUAL contract
 * (not eight isolated mechanisms). v1 (`bootstrap_probe.p4`, commit d991944) placed
 * mechanisms but did NOT implement the contract; it is retained as a PARTIAL NEGATIVE
 * probe. v2 corrects all eight gaps:
 *
 *   G1 four ISOLATED queues .......... Q_ACK_BLOCK(7) Q_ACK_HOLD(6) Q_RESP_BLOCK(5)
 *                                      Q_RESP_HOLD(4). ACK tokens -> qid7, RESP tokens ->
 *                                      qid5, held ACK -> qid6, held RESP -> qid4.
 *   G2 BOTH reservoirs ready before .. reg_pop packs BOTH domain counts in ONE 32-bit
 *      ACK admission                   word (hi=ACK, lo=RESP); a single pop_read tests
 *                                      BOTH == K atomically (BOTH_READY = 0x00400040).
 *   G3 TRANSACTION-level fail-open .... an unready ACK LATCHES reg_failopen = current
 *                                      generation; the RESPONSE of that generation then
 *                                      bypasses. Not just the ACK.
 *   G4 AUTHENTICATED token identity ... token = {marker, sdomain, role, generation,
 *                                      token_id}; EVERY field validated (tbl_token_valid:
 *                                      marker==0xE1, sdomain==SD_LOOP, role in {ACK,RESP},
 *                                      token_id < K). An invalid token is dropped; no
 *                                      unchecked domain/id bits can alias into a cell.
 *   G5 GENERATION-QUALIFIED stale ..... a loopback token with generation != current is
 *      termination                     TERMINATED in-band (drop + ident_clear + pop_decr),
 *                                      touching only its own cell and its own domain count.
 *                                      NO reg_retire; current-generation tokens never die.
 *   G6 TRUTHFUL establishment ......... identity state EMPTY -> SEEDED (admitted, enqueued
 *                                      to BLOCK) -> CONFIRMED (first AUTHENTICATED loopback
 *                                      return). readiness (pop) increments ONLY on
 *                                      SEEDED->CONFIRMED, i.e. proof the token actually
 *                                      circulates, not merely that ingress admitted it.
 *   G7 DATA-PLANE normal cleanup ...... the RESPONSE completes the transaction and clears
 *                                      active (active_read_clear) — works over a persistent
 *                                      TCP connection, every poll. FIN/RST is a separate
 *                                      teardown. reg_retire is NOT a correctness path.
 *   G8 reproducible one-time setup .... committed in `bootstrap_setup.py` (the exact two
 *                                      timer apps, templates, K, period, value-set entries,
 *                                      queue priorities, enable sequence). NOT executed.
 *
 * SCOPE. Still a §3 feasibility probe: NOT the timing core, does NOT patch
 * defense4_timing.p4, NOT loaded, NOT run. The deadline/release machinery is §4
 * (to_hold enqueues behind the reservoir; actual release is out of scope). What stays
 * UNVERIFIED and is NOT claimed: whether the periodic source RE-SEEDS a generation's K
 * tokens and CONFIRMS them (pop==K) within the CLRT after a READ turns the pool over —
 * that is the dual-reservoir CONTINUITY / establishment-latency obligation and is a
 * SILICON question (R2/R11). This probe shows the contract PLACES on Tofino-1 and is
 * logically self-consistent; it does NOT show it holds on silicon. R11 stays OPEN.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_TOKEN = 0x88C1;
const bit<16> ETHERTYPE_IPV4  = 0x0800;
const bit<8>  IP_PROTO_TCP     = 8w6;

/* ---- DNP3 (compact host classification subset) ---- */
const bit<16> DNP3_START       = 0x0564;
const bit<8>  DNP3_FC_READ      = 8w1;
const bit<8>  DNP3_FC_RESPONSE  = 8w129;

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;    /* internal loopback (four queues live here) */
const PortId_t PORT_MASTER = 9w9;
const PortId_t PORT_RELAY  = 9w64;
const PortId_t PORT_PGEN   = 9w68;   /* pktgen source (two one-time timer apps)   */

/* ---- G1: the FOUR isolated queues on PORT_L ---- */
const bit<5> Q_ACK_BLOCK  = 5w7;   /* ACK reservoir     (highest) */
const bit<5> Q_ACK_HOLD   = 5w6;   /* held ACK                    */
const bit<5> Q_RESP_BLOCK = 5w5;   /* RESPONSE reservoir          */
const bit<5> Q_RESP_HOLD  = 5w4;   /* held RESPONSE               */

/* ---- reservoirs ---- */
const bit<16> K_TOKENS  = 16w64;
/* G2: readiness word — hi16 = ACK live count, lo16 = RESP live count; both at K */
const bit<32> BOTH_READY = 32w0x00400040;   /* (64 << 16) | 64 */
const bit<32> DELTA_ACK_UP   = 32w0x00010000;
const bit<32> DELTA_RESP_UP  = 32w0x00000001;
const bit<32> DELTA_ACK_DN   = 32w0xFFFF0000;   /* -(1<<16) */
const bit<32> DELTA_RESP_DN  = 32w0xFFFFFFFF;   /* -1       */

/* ---- G4: token identity constants ---- */
const bit<8> TOKEN_MARKER = 8w0xE1;
const bit<8> SD_LOOP      = 8w0x5A;   /* the internal scheduler-domain identity */
const bit<8> TOK_ACK      = 8w0xA1;   /* ACK-reservoir token role  */
const bit<8> TOK_RESP     = 8w0xA2;   /* RESP-reservoir token role */

/* ---- G6: identity states ---- */
const bit<8> ID_EMPTY     = 8w0;
const bit<8> ID_SEEDED    = 8w1;
const bit<8> ID_CONFIRMED = 8w2;

/* ---- host roles ---- */
const bit<8> ROLE_BYPASS  = 8w0;
const bit<8> ROLE_TOKEN   = 8w1;
const bit<8> ROLE_ACK     = 8w2;
const bit<8> ROLE_RESP    = 8w3;
const bit<8> ROLE_ARM     = 8w6;
const bit<8> ROLE_CLEANUP = 8w7;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }

/* G4: fully-identified token, stamped and validated in the data plane */
header token_h {
    bit<8>  marker;    /* 0xE1                                */
    bit<8>  sdomain;   /* SD_LOOP scheduler-domain identity   */
    bit<8>  role;      /* TOK_ACK / TOK_RESP                  */
    bit<16> generation;/* stamped epoch                       */
    bit<16> token_id;  /* 0..K-1 (= pktgen packet_id)         */
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
    /* parser-set (assigned once per path) */
    bit<8>  role;
    bit<8>  port_ok;
    bit<9>  fwd_port;
    bit<8>  is_first;
    bit<8>  is_loop;
    bit<8>  from_out;

    /* MAU-derived */
    bit<8>  tok_valid;   /* identity validation result   */
    bit<1>  role_bit;    /* 0 = ACK reservoir, 1 = RESP  */
    bit<8>  tok_role;    /* TOK_ACK / TOK_RESP (admit stamp) */
    bit<16> token_id;
    bit<7>  pres_idx;    /* (role_bit, token_id) cell    */
    bit<16> cur_gen;
    bit<8>  ident_res;   /* reg_ident old state          */
    bit<32> pop_packed;
    bit<32> pop_delta;
    bit<8>  active_val;
    bit<16> failopen_val;
}

/* ============================ ingress parser ============================ */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    value_set<bit<8>>(2) pgen_timer;   /* leading byte of each reservoir app's packet */

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.tok_valid    = 8w0;
        meta.role_bit     = 1w0;
        meta.tok_role     = 8w0;
        meta.token_id     = 16w0;
        meta.pres_idx     = 7w0;
        meta.cur_gen      = 16w0;
        meta.ident_res    = 8w0;
        meta.pop_packed   = 32w0;
        meta.pop_delta    = 32w0;
        meta.active_val   = 8w0;
        meta.failopen_val = 16w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_PGEN   : from_pgen;
            PORT_L      : from_loop;
            PORT_MASTER : from_master;
            PORT_RELAY  : from_relay;
            default     : accept;
        }
    }

    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_timer : parse_timer;
            default    : accept;
        }
    }
    state parse_timer {
        pkt.extract(hdr.timer);
        meta.is_first = 8w1;
        meta.port_ok  = 8w1;
        transition parse_eth;
    }
    state from_loop   { meta.is_loop = 8w1; meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER;
                        transition parse_eth; }
    state from_master { meta.port_ok = 8w1; meta.fwd_port = PORT_RELAY;  transition parse_eth; }
    state from_relay  { meta.port_ok = 8w1; meta.fwd_port = PORT_MASTER; meta.from_out = 8w1;
                        transition parse_eth; }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_TOKEN : parse_token;
            ETHERTYPE_IPV4  : parse_ipv4;
            default         : accept;
        }
    }
    state parse_token { pkt.extract(hdr.token); meta.role = ROLE_TOKEN; transition accept; }

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
            (8w0x01 &&& 8w0x01, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;
            (8w0x04 &&& 8w0x04, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;
            (8w0x10 &&& 8w0x17, 4w5, 16w40)                 : set_role_ack;
            (8w0x10 &&& 8w0x17, 4w8, 16w52)                 : set_role_ack;
            (8w0x00 &&& 8w0x07, 4w5, 16w53 .. 16w65535)     : parse_dnp3_dl;
            (8w0x00 &&& 8w0x07, 4w8, 16w65 .. 16w65535)     : opt12_dnp3;
            default                                         : accept;
        }
    }
    state opt12_dnp3 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }
    state set_role_ack     { meta.role = ROLE_ACK;     transition accept; }
    state set_role_cleanup { meta.role = ROLE_CLEANUP; transition accept; }
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

    /* ---- G6: identity state cell per (role_bit, token_id) ---- */
    Register<bit<8>, bit<7>>(128, 0) reg_ident;
    RegisterAction<bit<8>, bit<7>, bit<8>>(reg_ident) ident_seed = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; if (v == ID_EMPTY) { v = ID_SEEDED; } }
    };
    RegisterAction<bit<8>, bit<7>, bit<8>>(reg_ident) ident_confirm = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; if (v == ID_SEEDED) { v = ID_CONFIRMED; } }
    };
    RegisterAction<bit<8>, bit<7>, bit<8>>(reg_ident) ident_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = ID_EMPTY; }
    };

    /* ---- G2/G3/G6: packed live counts (hi=ACK, lo=RESP) ---- */
    Register<bit<32>, bit<1>>(1, 0) reg_pop;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop) pop_update = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + meta.pop_delta; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop) pop_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* ---- G5: current epoch (16-bit, benign wrap) ---- */
    Register<bit<16>, bit<1>>(1, 0) reg_gen;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_gen) gen_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    /* G3 fix: SKIP generation 0 on wrap. Generation 0 is the "no live transaction"
     * value and reg_failopen resets to 0, so a live transaction whose generation were 0
     * would alias the fail-open "not-latched" sentinel and wrongly bypass its RESPONSE
     * (once per 65536 READs). Bumping 0xFFFF -> 1 keeps every live generation in
     * [1, 65535], so failopen==0 can never equal a live cur_gen. */
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_gen) gen_bump = {
        void apply(inout bit<16> v, out bit<16> rv) {
            if (v == 16w0xFFFF) { v = 16w1; } else { v = v + 16w1; }
            rv = v;
        }
    };

    /* ---- G7: transaction-active flag ---- */
    Register<bit<8>, bit<1>>(1, 0) reg_active;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_read_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = 8w0; }   /* G7: RESPONSE completes txn */
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = v; }   /* FIN/RST teardown */
    };

    /* ---- G3: generation-qualified fail-open latch ---- */
    Register<bit<16>, bit<1>>(1, 0) reg_failopen;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_failopen) failopen_set = {
        void apply(inout bit<16> v, out bit<16> rv) { v = meta.cur_gen; rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_failopen) failopen_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_failopen) failopen_reset = {
        void apply(inout bit<16> v, out bit<16> rv) { v = 16w0; rv = v; }
    };

    /* ---- counters ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_new;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_dup;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_bad_identity;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_badorigin;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_confirm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_persist;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_failopen;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_failopen;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_cleanup;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drop_badport;

    /* ---- G1: four-queue TM actions ---- */
    action to_ack_block()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_BLOCK;  ig_tm_md.bypass_egress = 1w1; }
    action to_ack_hold()   { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_HOLD;   ig_tm_md.bypass_egress = 1w1; }
    action to_resp_block() { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_BLOCK; ig_tm_md.bypass_egress = 1w1; }
    action to_resp_hold()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_HOLD;  ig_tm_md.bypass_egress = 1w1; }
    action to_fwd()        { ig_tm_md.ucast_egress_port = meta.fwd_port; ig_tm_md.qid = 5w0; ig_tm_md.bypass_egress = 1w0; }
    action drop_pkt()      { ig_dprsr_md.drop_ctl = 3w1; }

    /* G4: derive a token's reservoir from the pktgen app_id on the admit path */
    action app_ack()  { meta.tok_role = TOK_ACK;  meta.role_bit = 1w0; }
    action app_resp() { meta.tok_role = TOK_RESP; meta.role_bit = 1w1; }
    table tbl_app_role {
        key = { hdr.timer.app_id : exact; }
        actions = { app_ack; app_resp; }
        const default_action = app_ack();
        const entries = { (3w0) : app_ack(); (3w1) : app_resp(); }
        size = 2;
    }

    /* G4: admit-path token_id range check (packet_id < K via high-bits-zero) */
    action mark_tokid_ok()  { meta.tok_valid = 8w1; }
    action mark_tokid_bad() { meta.tok_valid = 8w0; }
    table tbl_tokid_valid {
        key = { hdr.timer.packet_id : ternary; }
        actions = { mark_tokid_ok; mark_tokid_bad; }
        const default_action = mark_tokid_bad();
        const entries = { (16w0 &&& 16w0xFFC0) : mark_tokid_ok(); }   /* packet_id < 64 */
        size = 2;
    }

    /* G4: loopback FULL identity validation — every field checked in one table */
    action valid_ack()  { meta.tok_valid = 8w1; meta.role_bit = 1w0; }
    action valid_resp() { meta.tok_valid = 8w1; meta.role_bit = 1w1; }
    action valid_bad()  { meta.tok_valid = 8w0; }
    table tbl_token_valid {
        key = {
            hdr.token.marker   : exact;
            hdr.token.sdomain  : exact;
            hdr.token.role     : exact;
            hdr.token.token_id : ternary;   /* < 64 */
        }
        actions = { valid_ack; valid_resp; valid_bad; }
        const default_action = valid_bad();
        const entries = {
            (TOKEN_MARKER, SD_LOOP, TOK_ACK,  16w0 &&& 16w0xFFC0) : valid_ack();
            (TOKEN_MARKER, SD_LOOP, TOK_RESP, 16w0 &&& 16w0xFFC0) : valid_resp();
        }
        size = 4;
    }

    /* G4: stamp a freshly admitted token entirely in the data plane */
    action admit_stamp() {
        hdr.token.setValid();
        hdr.token.marker     = TOKEN_MARKER;
        hdr.token.sdomain    = SD_LOOP;
        hdr.token.role       = meta.tok_role;
        hdr.token.generation = meta.cur_gen;
        hdr.token.token_id   = meta.token_id;
        hdr.timer.setInvalid();
    }
    /* build the (role_bit, token_id) cell index — one concat op */
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
                /* ============ PKTGEN ADMIT (SEEDED) ============ */
                meta.token_id = (bit<16>)hdr.timer.packet_id;
                tbl_app_role.apply();       /* tok_role + role_bit from app_id */
                tbl_tokid_valid.apply();    /* G4: packet_id < K */
                if (meta.tok_valid == 8w1) {
                    tbl_idx_timer.apply();
                    meta.cur_gen   = gen_read.execute(1w0);
                    meta.ident_res = ident_seed.execute(meta.pres_idx);   /* G6: EMPTY->SEEDED */
                    if (meta.ident_res == ID_EMPTY) {
                        admit_stamp();                                    /* G4: data-plane stamp */
                        if (meta.role_bit == 1w0) { to_ack_block(); }     /* G1: qid7 */
                        else                      { to_resp_block(); }    /* G1: qid5 */
                        ctr_seed_new.count(1w0);
                    } else {
                        drop_pkt();                                       /* dedup a live re-fire */
                        ctr_seed_dup.count(1w0);
                    }
                } else {
                    drop_pkt();
                    ctr_bad_identity.count(1w0);
                }
            } else if (meta.is_loop == 8w1) {
                /* ============ LOOPBACK RETURN ============ */
                tbl_token_valid.apply();    /* G4: validate marker/sdomain/role/token_id */
                if (meta.tok_valid == 8w1) {
                    tbl_idx_token.apply();
                    meta.cur_gen = gen_read.execute(1w0);
                    if (hdr.token.generation == meta.cur_gen) {
                        /* current epoch: confirm-or-persist, then re-enqueue to its BLOCK queue */
                        meta.ident_res = ident_confirm.execute(meta.pres_idx);  /* G6 */
                        if (meta.ident_res == ID_SEEDED) {                       /* first confirm */
                            if (meta.role_bit == 1w0) { meta.pop_delta = DELTA_ACK_UP; }
                            else                      { meta.pop_delta = DELTA_RESP_UP; }
                            meta.pop_packed = pop_update.execute(1w0);           /* G6: count on CONFIRM */
                            ctr_confirm.count(1w0);
                        } else {
                            ctr_persist.count(1w0);
                        }
                        if (meta.role_bit == 1w0) { to_ack_block(); } else { to_resp_block(); }
                    } else {
                        /* G5: generation-qualified stale termination (in-band; own cell only) */
                        meta.ident_res = ident_clear.execute(meta.pres_idx);
                        if (meta.ident_res == ID_CONFIRMED) {
                            if (meta.role_bit == 1w0) { meta.pop_delta = DELTA_ACK_DN; }
                            else                      { meta.pop_delta = DELTA_RESP_DN; }
                            meta.pop_packed = pop_update.execute(1w0);
                        }
                        drop_pkt();
                        ctr_term_stale.count(1w0);
                    }
                } else {
                    drop_pkt();                                           /* G4: bad identity */
                    ctr_bad_identity.count(1w0);
                }
            } else {
                drop_pkt();                                               /* G4/P1: token from a host port */
                ctr_seed_badorigin.count(1w0);
            }
        } else if (meta.role == ROLE_ARM) {
            /* ============ host READ: open a transaction ============ */
            meta.cur_gen    = gen_bump.execute(1w0);      /* G5: new epoch (turns the pool over) */
            meta.active_val = active_set.execute(1w0);
            failopen_reset.execute(1w0);                  /* new txn has not failed open */
            to_fwd();
            ctr_arm.count(1w0);
        } else if (meta.role == ROLE_CLEANUP) {
            /* ============ host FIN/RST: connection teardown ============ */
            meta.active_val = active_clear.execute(1w0);
            to_fwd();
            ctr_cleanup.count(1w0);
        } else if (meta.role == ROLE_ACK && meta.from_out == 8w1) {
            /* ============ host ACK: BOTH-reservoir-ready gate ============ */
            meta.cur_gen    = gen_read.execute(1w0);
            meta.pop_packed = pop_read.execute(1w0);      /* G2: read BOTH counts atomically */
            meta.active_val = active_read.execute(1w0);
            if (meta.pop_packed == BOTH_READY && meta.active_val == 8w1) {
                to_ack_hold();                            /* G1: qid6 */
                ctr_ack_hold.count(1w0);
            } else {
                failopen_set.execute(1w0);                /* G3: latch this generation as failed-open */
                to_fwd();
                ctr_ack_failopen.count(1w0);
            }
        } else if (meta.role == ROLE_RESP && meta.from_out == 8w1) {
            /* ============ host RESPONSE: bypass-if-failed-open, else hold; completes txn ============ */
            meta.cur_gen      = gen_read.execute(1w0);
            meta.pop_packed   = pop_read.execute(1w0);
            meta.active_val   = active_read_clear.execute(1w0);   /* G7: normal cleanup */
            meta.failopen_val = failopen_read.execute(1w0);
            if (meta.failopen_val == meta.cur_gen) {
                to_fwd();                                 /* G3: txn already failed open -> bypass */
                ctr_resp_bypass.count(1w0);
            } else if (meta.pop_packed == BOTH_READY && meta.active_val == 8w1) {
                to_resp_hold();                           /* G1: qid4 */
                ctr_resp_hold.count(1w0);
            } else {
                to_fwd();
                ctr_resp_failopen.count(1w0);
            }
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

/* ============================ egress (byte-preserving pass-through) ====== */
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

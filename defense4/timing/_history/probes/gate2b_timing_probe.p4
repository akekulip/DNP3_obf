/* ►► GATE-2B RESULT: FAIL the <=12-stage fit (PRESERVED NEGATIVE PROBE). Complete
 * reachable contract, 0 P4-language errors, but placement fails on reg_deadline
 * CO-LOCATION (4 access sites: reset@ARM / arm@ACK / read@ACK-loop / read@RESP-loop
 * > the 2-phase co-location budget) — NOT depth (critical path 9) and NOT capacity
 * (SRAM/TCAM/SALU under budget). Consolidation reduced count (9 vs 11) but concentrated
 * access sites, WORSENING co-location. See evidence/GATE2B_RESULT.md. Not loaded/run. */
/* ============================================================================
 * gate2b_timing_probe.p4 — Defense 4 §4 COMPLETE timing contract, Gate-2B probe
 *
 * QUESTION (Gate-2B): does the COMPLETE Defense-4 timing contract fit in <=12
 * ingress stages via STATE CONSOLIDATION + DEPENDENCY PARALLELIZATION, with NO
 * ingress->egress redistribution and NO two-pass? The prior full integration
 * (full_integration_wall_probe.p4, 11 registers) FAILED placement with a
 * register-ordering wall ("reg_exp_ack and reg_resp_stage cannot co-allocate").
 * This probe rebuilds the contract at 9 registers + one static flow table.
 *
 * DERIVED FROM the frozen bootstrap_probe_v5.p4 (proven 12/12) and
 * min_ack_deadline_probe.p4 (v5 + one ACK-deadline, proven 12/12). NOT loaded,
 * NOT run, does NOT patch defense4_timing.p4. Offline compiler-fit probe only.
 *
 * ============================ CONSOLIDATIONS ================================
 * C1  reg_failopen + reg_flags  ->  ONE reg_lifecycle word (bit<32>).
 *     Flag bits (high byte, one-shot): FAIL_OPEN, ACK_ADMITTED, RESP_PRESENT,
 *     ACK_COMMITTED, DRAIN(barrier), RESP_RELEASED. life_arm resets it at ARM;
 *     life_rmw reads-old + ORs a per-class precomputed meta.life_mask. Flags are
 *     tested via TERNARY match on the returned word (sub-field test = ternary on
 *     the whole container — bf-asm cannot do masked/slice STATEFUL compares).
 *     Generation-qualification is by CONSTRUCTION, not an in-word gen tag:
 *       (a) reset at every fresh ARM (one gen == one clean word),
 *       (b) every life_rmw call site is gated in control flow on the packet
 *           having matched the active gen (flow_owned && active && id-match, or
 *           a gen-matched loopback shim), so overlapping/duplicate/stale/
 *           nonmatching packets NEVER reach life_rmw,
 *       (c) one active protected transaction per scheduler domain.
 *     A 31-bit gen (reg_txn's, a FROZEN v5 invariant) + 6 flags does NOT fit 32
 *     bits without TRUNCATING the gen, which the directive FORBIDS; so the gen
 *     tag is NOT packed and the qualification above is used instead.
 * C2  reg_flow_fp (16-bit runtime hash) REMOVED -> static exact-match
 *     tbl_flow_own (control-plane installed; key = canonical bidirectional flow
 *     5-tuple; single domain). No per-transaction controller action, no runtime
 *     hash, no collision window.
 * C3  reg_exp_ack and reg_exp_seq kept as SEPARATE 32-bit registers (two
 *     independent TCP sequence spaces). Written at ARM; exp_ack validated on the
 *     native ACK (== tcp.ack_no), exp_seq on the native RESP (== tcp.seq_no).
 *
 * ============================ PARALLELIZATION ==============================
 * reg_deadline already co-locates with reg_pop_packed (v5/min_ack). reg_exp_ack
 * and reg_exp_seq are ROLE-EXCLUSIVE (exp_ack read only on the native ACK,
 * exp_seq only on the native RESP) and their expectations are written at ARM, so
 * they need NOT extend the serial ident_resp->resp_stage->ident_ack chain — they
 * are placed by the compiler's natural graph (NO @stage pins). No shared-metadata
 * write couples the ACK-only and RESP-only paths; lifecycle is never read earlier
 * than the native/loopback decision; exact-match state is off the token chain.
 *
 * ============================ 9 REGISTERS ==================================
 *   reg_txn(atomic {active,gen}) reg_ident_resp reg_resp_stage reg_ident_ack
 *   reg_pop_packed reg_deadline reg_exp_ack reg_exp_seq reg_lifecycle
 *   + static tbl_flow_own (replaces reg_flow_fp).
 *
 * SCOPE / NOT CLAIMED. Offline placement + model-level functional probe. Does
 * NOT prove silicon correctness, dual-reservoir readiness, TM ordering, real
 * release tails, or packet-level byte identity. Byte identity of released
 * originals is preserved BY CONSTRUCTION (shim stripped before the master hop)
 * pending packet-level verification. Single scheduler domain. R11 stays OPEN.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes / protocol ---- */
const bit<16> ETHERTYPE_TOKEN     = 0x88C1;   /* internal reservoir token */
const bit<16> ETHERTYPE_HELD      = 0x88C3;   /* held-original / retire / barrier shim */
const bit<16> ETHERTYPE_IPV4      = 0x0800;
const bit<8>  IP_PROTO_TCP         = 8w6;

const bit<16> DNP3_START       = 0x0564;
const bit<8>  DNP3_FC_READ      = 8w1;
const bit<8>  DNP3_FC_RESPONSE  = 8w129;

const PortId_t PORT_L      = 9w8;    /* internal loopback */
const PortId_t PORT_MASTER = 9w9;
const PortId_t PORT_RELAY  = 9w64;
const PortId_t PORT_PGEN   = 9w68;

/* static strict-priority ladder 7 > 6 > 5 > 4 (qid == max_priority set by CP) */
const bit<5> Q_ACK_BLOCK  = 5w7;
const bit<5> Q_ACK_HOLD    = 5w6;
const bit<5> Q_RESP_BLOCK = 5w5;
const bit<5> Q_RESP_HOLD    = 5w4;   /* lowest: held RESP + gen-qualified retirement barrier */

const bit<16> K_TOKENS   = 16w64;
const bit<32> BOTH_READY = 32w0x00400040;   /* authoritative packed K/K */
const bit<32> DELTA_ACK_UP  = 32w0x00010000;
const bit<32> DELTA_RESP_UP = 32w0x00000001;

const bit<8> TOKEN_MARKER = 8w0xE1;
const bit<8> SD_LOOP      = 8w0x5A;
const bit<8> TOK_ACK      = 8w0xA1;
const bit<8> TOK_RESP     = 8w0xA2;
const bit<16> BUDGET_INIT = 16w0x7FF0;   /* bounded token watchdog (CP-tunable); 0 -> barrier */

/* reg_txn packing: bit31 = active, bits[30:0] = generation in [1, 0x7FFFFFFF] */
const bit<32> GEN_MAX     = 32w0x7FFFFFFF;
const bit<32> CONF_BIT    = 32w0x80000000;
const bit<32> GEN_MASK    = 32w0x7FFFFFFF;
const bit<32> OPEN_ADD    = 32w0x80000001;

const bit<8> R_SEEDED = 8w1;
const bit<8> R_DEDUP  = 8w0;
const bit<8> R_FIRST  = 8w1;
const bit<8> R_AGAIN  = 8w0;

/* deadline: modular sign-bit compare, frozen D3/Part-12 idiom, mask 0x800000FF */
const bit<32> TICK_MASK   = 32w0xFFFFFF00;
const bit<32> ARMED_MARK  = 32w0x00000001;
const bit<32> D_A_DEFAULT = 32w0x00010000;   /* ACK hold offset  (mult of 256) */
const bit<32> D_R_DEFAULT = 32w0x00010000;   /* RESPONSE successor interval (mult of 256) */

/* modes (params) */
const bit<8> MODE_OFF      = 8w0;
const bit<8> MODE_D1       = 8w1;   /* event-governed ACK hold (NOT a deadline) */
const bit<8> MODE_D2       = 8w2;   /* RESPONSE deadline (t_A + D_R); ACK immediate */
const bit<8> MODE_D3       = 8w3;   /* ACK deadline (t_A + D_A) */
const bit<8> MODE_D4       = 8w4;   /* dual: T_A and T_RESP */
const bit<8> MODE_FAILOPEN = 8w5;   /* bounded release */

/* reg_lifecycle one-shot flag bits (tested by ternary on the returned word) */
const bit<32> LIFE_FAILOPEN     = 32w0x80000000;
const bit<32> LIFE_ACK_ADMITTED = 32w0x40000000;
const bit<32> LIFE_RESP_PRESENT = 32w0x20000000;
const bit<32> LIFE_ACK_COMMIT   = 32w0x10000000;
const bit<32> LIFE_DRAIN        = 32w0x08000000;
const bit<32> LIFE_RESP_RELEASE = 32w0x04000000;
const bit<32> LIFE_ZERO         = 32w0;

/* parser roles */
const bit<8> ROLE_BYPASS  = 8w0;
const bit<8> ROLE_TOKEN   = 8w1;
const bit<8> ROLE_ACK     = 8w2;
const bit<8> ROLE_RESP    = 8w3;
const bit<8> ROLE_ARM     = 8w6;
const bit<8> ROLE_CLEANUP = 8w7;
const bit<8> ROLE_COMBINED= 8w8;   /* combined TCP-ACK + DNP3-RESPONSE (Case B device) */

/* loopback shim kinds (shim.lrole) */
const bit<8> SHIM_NONE        = 8w0;
const bit<8> SHIM_ACK         = 8w0x51;   /* held ACK, self-clock qid7 */
const bit<8> SHIM_ACK_COMMIT  = 8w0x55;   /* ACK commitment loopback (sets ACK_COMMIT) */
const bit<8> SHIM_RESP        = 8w0x52;   /* held RESP, self-clock qid5 */
const bit<8> SHIM_RESP_RETIRE = 8w0x56;   /* RESP retire pass, qid4 (txn_complete at top) */
const bit<8> SHIM_BARF        = 8w0x53;   /* FIN/RST retirement barrier, qid4 */
const bit<8> SHIM_BART        = 8w0x54;   /* token-watchdog retirement barrier, qid4 */

/* ============================ headers ==================================== */
header shim_h {
    bit<48> dst; bit<48> src; bit<16> etype;
    bit<8>  lrole;      /* SHIM_* */
    bit<8>  lpad;
    bit<16> lbudget;
    bit<32> gen;        /* CONF|gen (stamped at hold/barrier creation) */
}
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header token_h {
    bit<8>  marker;
    bit<8>  sdomain;
    bit<8>  role;
    bit<32> generation;
    bit<16> token_id;
    bit<16> budget;     /* bounded watchdog: decremented each recirc, 0 -> barrier */
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
    shim_h      shim;
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
    /* classification — written on EVERY parser path */
    bit<8>  role;
    bit<8>  port_ok;
    bit<9>  fwd_port;
    bit<8>  is_first;
    bit<8>  is_loop;
    bit<8>  from_out;

    /* MAU-derived (init in start) */
    bit<8>  tok_valid;
    bit<1>  role_bit;
    bit<8>  tok_role;
    bit<16> token_id;
    bit<16> tok_budget;
    bit<32> txn_old;
    bit<32> cur_gen;
    bit<32> cur_gen_conf;
    bit<8>  active;
    bit<16> stage_val;
    bit<8>  ident_res;
    bit<32> pop_packed;
    bit<32> pop_delta;
    bit<8>  ready;

    /* flow ownership + params (single domain) */
    bit<8>  flow_owned;
    bit<8>  domain;
    bit<8>  mode;
    bit<32> d_a;
    bit<32> d_r;
    bit<32> d_pay;         /* expected READ payload length (CP param) */
    bit<8>  combined_dev;

    /* deadline (T_A stored; T_RESP = T_A + D_R derived at compare) */
    bit<32> now_word;
    bit<32> ts32;
    bit<32> dl_cand;
    bit<32> dl_age;
    bit<8>  dl_expired;
    bit<32> dl_resp_age;
    bit<8>  dl_resp_expired;

    /* exact transaction identity (C3) */
    bit<32> exp_ack_val;
    bit<32> exp_seq_val;
    bit<32> exp_ack_old;   /* native-ACK read scratch (kept SEPARATE — merging couples ACK/RESP paths) */
    bit<32> exp_seq_old;   /* native-RESP read scratch */
    bit<8>  id_ack_match;
    bit<8>  id_seq_match;

    /* consolidated lifecycle (C1) */
    bit<32> life_old;
    bit<32> life_mask;
    bit<8>  fo_latched;
    bit<8>  resp_present;
    bit<8>  ack_committed;
    bit<8>  drain_init;

    /* loopback shim */
    bit<8>  loop_kind;
    bit<32> shim_gen;

    /* decisions */
    bit<8>  ack_release;
    bit<8>  resp_release;
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
        meta.tok_valid    = 8w0;  meta.role_bit = 1w0; meta.tok_role = 8w0;
        meta.token_id     = 16w0; meta.tok_budget = 16w0;
        meta.txn_old      = 32w0; meta.cur_gen = 32w0; meta.cur_gen_conf = 32w0;
        meta.active       = 8w0;  meta.stage_val = 16w0; meta.ident_res = 8w0;
        meta.pop_packed   = 32w0; meta.pop_delta = 32w0; meta.ready = 8w0;
        meta.flow_owned   = 8w0;  meta.domain = 8w0; meta.mode = 8w0;
        meta.d_a          = 32w0; meta.d_r = 32w0; meta.d_pay = 32w0; meta.combined_dev = 8w0;
        meta.now_word     = 32w0; meta.ts32 = 32w0; meta.dl_cand = 32w0;
        meta.dl_age       = 32w0; meta.dl_expired = 8w0;
        meta.dl_resp_age  = 32w0; meta.dl_resp_expired = 8w0;
        meta.exp_ack_val  = 32w0; meta.exp_seq_val = 32w0;
        meta.exp_ack_old  = 32w0; meta.exp_seq_old = 32w0;
        meta.id_ack_match = 8w0;  meta.id_seq_match = 8w0;
        meta.life_old     = 32w0; meta.life_mask = 32w0;
        meta.fo_latched   = 8w0;  meta.resp_present = 8w0;
        meta.ack_committed= 8w0;  meta.drain_init = 8w0;
        meta.loop_kind    = SHIM_NONE; meta.shim_gen = 32w0;
        meta.ack_release  = 8w0;  meta.resp_release = 8w0;
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
        transition select(pkt.lookahead<ethernet_h>().etype) {
            ETHERTYPE_HELD : parse_shim;
            default        : parse_eth;
        }
    }
    state parse_shim {
        pkt.extract(hdr.shim);
        meta.loop_kind = hdr.shim.lrole;
        meta.shim_gen  = hdr.shim.gen;   /* stamped CONF|gen — completion clear key */
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
            (8w0x01 &&& 8w0x01, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;  /* FIN */
            (8w0x04 &&& 8w0x04, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;  /* RST */
            (8w0x10 &&& 8w0x17, 4w5, 16w40)                 : set_role_ack;       /* pure ACK */
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
        /* a DNP3 RESPONSE that also carries the PSH+ACK flags on an established
         * connection is a CANDIDATE combined-response; the ACK-bit alone cannot
         * distinguish Case A vs Case B, so the control plane's combined_dev param
         * (device type) is the authority — see the ingress combined branch. */
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

    /* ===================== reg_txn: atomic {active,generation} ============ */
    Register<bit<32>, bit<1>>(1, 0) reg_txn;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_open = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v < CONF_BIT) {
                if (v == GEN_MAX) { v = CONF_BIT | 32w1; }
                else              { v = v + OPEN_ADD; }
            }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    /* gen-qualified atomic clear (retire): v == shim.gen (== CONF|gen). Idempotent. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_complete = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v == meta.shim_gen) { v = v & GEN_MASK; }
        }
    };

    /* ===================== per-role identity cells ======================= */
    Register<bit<32>, bit<6>>(64, 0) reg_ident_resp;
    RegisterAction<bit<32>, bit<6>, bit<8>>(reg_ident_resp) ident_resp_seed = {
        void apply(inout bit<32> v, out bit<8> rv) {
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

    /* ===================== RESP-only shadow (gates ACK seeding) ========== */
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

    /* ===================== authoritative packed K/K ===================== */
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

    /* ===================== reg_deadline: T_A (one register, T_RESP derived) */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    /* one-shot arm: only if unarmed (v==0). A duplicate/retransmitted ACK sees
     * v!=0 and does NOT re-arm (idempotent bind). */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) dl_arm = {
        void apply(inout bit<32> v, out bit<32> rv) {
            if (v == 32w0) { v = meta.dl_cand; }
            rv = v;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) dl_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = meta.now_word - v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) dl_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };

    /* ===================== C3: exact-match expectations ================== */
    Register<bit<32>, bit<1>>(1, 0) reg_exp_ack;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_ack) exp_ack_write = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.exp_ack_val; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_ack) exp_ack_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_exp_seq;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_seq) exp_seq_write = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.exp_seq_val; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_seq) exp_seq_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* ===================== C1: consolidated lifecycle ==================== */
    Register<bit<32>, bit<1>>(1, 0) reg_lifecycle;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_lifecycle) life_arm = {
        void apply(inout bit<32> v, out bit<32> rv) { v = LIFE_ZERO; rv = v; }
    };
    /* read-old, then OR the per-class precomputed flag mask (one-shot: OR is
     * idempotent). meta.life_mask is 0 for a pure read. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_lifecycle) life_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = v | meta.life_mask; }
    };

    /* ---- counters (observability) ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_seed_new;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_confirm_resp;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_confirm_ack;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_overlap;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_barrier;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_failopen;

    /* ---- TM actions ---- */
    action to_ack_block()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_BLOCK;  ig_tm_md.bypass_egress = 1w1; }
    action to_ack_hold()   { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_HOLD;   ig_tm_md.bypass_egress = 1w1; }
    action to_resp_block() { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_BLOCK; ig_tm_md.bypass_egress = 1w1; }
    action to_resp_hold()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_HOLD;  ig_tm_md.bypass_egress = 1w1; }
    action to_barrier()    { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_HOLD;  ig_tm_md.bypass_egress = 1w1; }
    action to_fwd()        { ig_tm_md.ucast_egress_port = meta.fwd_port; ig_tm_md.qid = 5w0; ig_tm_md.bypass_egress = 1w0; }
    action drop_pkt()      { ig_dprsr_md.drop_ctl = 3w1; }

    action admit_stamp() {
        hdr.token.setValid();
        hdr.token.marker     = TOKEN_MARKER;
        hdr.token.sdomain    = SD_LOOP;
        hdr.token.role       = meta.tok_role;
        hdr.token.generation = meta.cur_gen;
        hdr.token.token_id   = meta.token_id;
        hdr.token.budget     = BUDGET_INIT;
        hdr.timer.setInvalid();
    }

    /* build a held/retire/barrier shim carrying {lrole, gen=CONF|gen} */
    action stamp_shim(bit<8> kind) {
        hdr.shim.setValid();
        hdr.shim.dst = 48w0; hdr.shim.src = 48w0; hdr.shim.etype = ETHERTYPE_HELD;
        hdr.shim.lrole = kind; hdr.shim.lpad = 8w0; hdr.shim.lbudget = 16w0;
        hdr.shim.gen = meta.cur_gen_conf;
    }

    /* ---- token stateless validation ---- */
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

    /* ---- C2: static flow ownership (control-plane installed; runtime entries so
     *      mode/domain stay runtime and no mode branch is const-folded away) ---- */
    action flow_own(bit<8> dom)  { meta.flow_owned = 8w1; meta.domain = dom; }
    action flow_unown()          { meta.flow_owned = 8w0; meta.domain = 8w0; }
    table tbl_flow_own {
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
            hdr.tcp.src_port  : exact;
            hdr.tcp.dst_port  : exact;
        }
        actions = { flow_own; flow_unown; }
        default_action = flow_unown();   /* both directions of the flow -> same domain, CP-installed */
        size = 16;
    }

    /* ---- params: mode + D_A + D_R + combined_dev, per domain (runtime) ---- */
    action set_params(bit<8> m, bit<32> da, bit<32> dr, bit<32> dpay, bit<8> comb) {
        meta.mode = m; meta.d_a = da; meta.d_r = dr; meta.d_pay = dpay; meta.combined_dev = comb;
    }
    table tbl_params {
        key = { meta.domain : exact; }
        actions = { set_params; }
        default_action = set_params(MODE_D4, D_A_DEFAULT, D_R_DEFAULT, 32w0, 8w0);
        size = 8;
    }

    /* ---- now-word build (frozen D3 idiom: mask, then OR marker) ---- */
    action mask_ts()  { meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK; }
    table tbl_mask_ts { actions = { mask_ts; } const default_action = mask_ts(); size = 1; }
    action or_mark()  { meta.now_word = meta.ts32 | ARMED_MARK; }
    table tbl_or_mark { actions = { or_mark; } const default_action = or_mark(); size = 1; }
    action build_cand() { meta.dl_cand = meta.now_word + meta.d_a; }   /* T_A candidate */
    table tbl_build_cand { actions = { build_cand; } const default_action = build_cand(); size = 1; }

    /* ---- exact-match expectation computation (ARM path) ----
     * exp_ack = READ.seq + expected_payload_len (CP param) — the byte the outstation
     * will ACK. exp_seq = READ.ack_no — the outstation's RESPONSE sequence. Full-width
     * 32-bit only (no narrow-field-into-arithmetic-word slicing). The production
     * per-flow payload-length derivation is a separable concern (TCP seq translator). */
    action calc_exp_ack() { meta.exp_ack_val = hdr.tcp.seq_no + meta.d_pay; }
    table tbl_calc_exp_ack { actions = { calc_exp_ack; } const default_action = calc_exp_ack(); size = 1; }
    action calc_exp_seq() { meta.exp_seq_val = hdr.tcp.ack_no; }
    table tbl_calc_exp_seq { actions = { calc_exp_seq; } const default_action = calc_exp_seq(); size = 1; }

    /* ---- deadline expiry (sign-bit + armed-marker, mask 0x800000FF) ---- */
    action mark_exp()  { meta.dl_expired = 8w1; }
    action mark_live() { meta.dl_expired = 8w0; }
    table tbl_dl_expiry {
        key = { meta.dl_age : ternary; }
        actions = { mark_exp; mark_live; }
        const default_action = mark_live();
        const entries = { (32w0x00000000 &&& 32w0x800000FF) : mark_exp(); }
        size = 2;
    }
    action mark_rexp()  { meta.dl_resp_expired = 8w1; }
    action mark_rlive() { meta.dl_resp_expired = 8w0; }
    table tbl_dl_resp_expiry {
        key = { meta.dl_resp_age : ternary; }
        actions = { mark_rexp; mark_rlive; }
        const default_action = mark_rlive();
        const entries = { (32w0x00000000 &&& 32w0x800000FF) : mark_rexp(); }
        size = 2;
    }
    action build_resp_age() { meta.dl_resp_age = meta.dl_age - meta.d_r; }   /* now - T_RESP */
    table tbl_build_resp_age { actions = { build_resp_age; } const default_action = build_resp_age(); size = 1; }

    /* ---- lifecycle flag tests (sub-field = ternary on the whole word) ---- */
    /* fail-open test — distinct instances per apply site (bf-p4c: one apply per table) */
    action fo_yes_a()  { meta.fo_latched = 8w1; }
    action fo_no_a()   { meta.fo_latched = 8w0; }
    table tbl_test_fo_ack {
        key = { meta.life_old : ternary; }
        actions = { fo_yes_a; fo_no_a; }
        const default_action = fo_no_a();
        const entries = { (LIFE_FAILOPEN &&& LIFE_FAILOPEN) : fo_yes_a(); }
        size = 2;
    }
    action fo_yes_r()  { meta.fo_latched = 8w1; }
    action fo_no_r()   { meta.fo_latched = 8w0; }
    table tbl_test_fo_resp {
        key = { meta.life_old : ternary; }
        actions = { fo_yes_r; fo_no_r; }
        const default_action = fo_no_r();
        const entries = { (LIFE_FAILOPEN &&& LIFE_FAILOPEN) : fo_yes_r(); }
        size = 2;
    }
    action rp_yes()  { meta.resp_present = 8w1; }
    action rp_no()   { meta.resp_present = 8w0; }
    table tbl_test_resp_present {
        key = { meta.life_old : ternary; }
        actions = { rp_yes; rp_no; }
        const default_action = rp_no();
        const entries = { (LIFE_RESP_PRESENT &&& LIFE_RESP_PRESENT) : rp_yes(); }
        size = 2;
    }
    action ac_yes()  { meta.ack_committed = 8w1; }
    action ac_no()   { meta.ack_committed = 8w0; }
    table tbl_test_ack_committed {
        key = { meta.life_old : ternary; }
        actions = { ac_yes; ac_no; }
        const default_action = ac_no();
        const entries = { (LIFE_ACK_COMMIT &&& LIFE_ACK_COMMIT) : ac_yes(); }
        size = 2;
    }
    /* drain test — distinct instances per apply site */
    action dr_yes_t()  { meta.drain_init = 8w1; }
    action dr_no_t()   { meta.drain_init = 8w0; }
    table tbl_test_drain_tok {
        key = { meta.life_old : ternary; }
        actions = { dr_yes_t; dr_no_t; }
        const default_action = dr_no_t();
        const entries = { (LIFE_DRAIN &&& LIFE_DRAIN) : dr_yes_t(); }
        size = 2;
    }
    action dr_yes_a()  { meta.drain_init = 8w1; }
    action dr_no_a()   { meta.drain_init = 8w0; }
    table tbl_test_drain_ack {
        key = { meta.life_old : ternary; }
        actions = { dr_yes_a; dr_no_a; }
        const default_action = dr_no_a();
        const entries = { (LIFE_DRAIN &&& LIFE_DRAIN) : dr_yes_a(); }
        size = 2;
    }
    action dr_yes_r()  { meta.drain_init = 8w1; }
    action dr_no_r()   { meta.drain_init = 8w0; }
    table tbl_test_drain_resp {
        key = { meta.life_old : ternary; }
        actions = { dr_yes_r; dr_no_r; }
        const default_action = dr_no_r();
        const entries = { (LIFE_DRAIN &&& LIFE_DRAIN) : dr_yes_r(); }
        size = 2;
    }

    /* ---- native ACK decision: hold (D1..D4 ready & !fo) vs fwd ---- */
    DirectCounter<bit<64>>(CounterType_t.PACKETS) ctr_nack;
    action nack_hold() { stamp_shim(SHIM_ACK); to_ack_block(); ctr_nack.count(); }  /* qid7 self-clock */
    action nack_fwd()  { to_fwd(); ctr_nack.count(); }
    table tbl_ack_native {
        key = { meta.mode : exact; meta.ready : exact; meta.fo_latched : exact; }
        actions = { nack_hold; nack_fwd; }
        counters = ctr_nack;
        const default_action = nack_fwd();
        const entries = {
            (MODE_D1, 8w1, 8w0) : nack_hold();
            (MODE_D2, 8w1, 8w0) : nack_hold();
            (MODE_D3, 8w1, 8w0) : nack_hold();
            (MODE_D4, 8w1, 8w0) : nack_hold();
        }
        size = 8;
    }

    /* ---- native RESP decision: hold (D1..D4 ready & !fo) vs fwd ---- */
    DirectCounter<bit<64>>(CounterType_t.PACKETS) ctr_nresp;
    action nresp_hold() { stamp_shim(SHIM_RESP); to_resp_block(); ctr_nresp.count(); }  /* qid5 self-clock */
    action nresp_fwd()  { to_fwd(); ctr_nresp.count(); }
    table tbl_resp_native {
        key = { meta.mode : exact; meta.ready : exact; meta.fo_latched : exact; }
        actions = { nresp_hold; nresp_fwd; }
        counters = ctr_nresp;
        const default_action = nresp_fwd();
        const entries = {
            (MODE_D1, 8w1, 8w0) : nresp_hold();
            (MODE_D2, 8w1, 8w0) : nresp_hold();
            (MODE_D3, 8w1, 8w0) : nresp_hold();
            (MODE_D4, 8w1, 8w0) : nresp_hold();
        }
        size = 8;
    }

    /* ---- held-ACK self-clock release predicate ----
     * D3/D4: deadline T_A expired.  D2: T_A==t_A (D_A=0) -> expired immediately.
     * D1: event = RESP present.  drain: always release. */
    action ackrel_yes() { meta.ack_release = 8w1; }
    action ackrel_no()  { meta.ack_release = 8w0; }
    table tbl_ack_release {
        key = { meta.mode : ternary; meta.dl_expired : ternary; meta.resp_present : ternary; meta.drain_init : ternary; }
        actions = { ackrel_yes; ackrel_no; }
        const default_action = ackrel_no();
        const entries = {
            (MODE_D2, 8w1, _, _) : ackrel_yes();
            (MODE_D3, 8w1, _, _) : ackrel_yes();
            (MODE_D4, 8w1, _, _) : ackrel_yes();
            (MODE_D1, _, 8w1, _) : ackrel_yes();
            (_, _, _, 8w1)       : ackrel_yes();   /* drain: always release held originals */
        }
        size = 16;
    }

    /* ---- held-RESP self-clock release predicate (§4) ----
     * predecessor_satisfied = ACK committed (separate-ACK).  D2/D3/D4: T_RESP
     * expired AND ack_committed.  D1: ack_committed (event).  drain: always. */
    action resprel_yes() { meta.resp_release = 8w1; }
    action resprel_no()  { meta.resp_release = 8w0; }
    table tbl_resp_release {
        key = { meta.mode : ternary; meta.dl_resp_expired : ternary; meta.ack_committed : ternary; meta.drain_init : ternary; }
        actions = { resprel_yes; resprel_no; }
        const default_action = resprel_no();
        const entries = {
            (MODE_D2, 8w1, 8w1, _) : resprel_yes();
            (MODE_D3, 8w1, 8w1, _) : resprel_yes();
            (MODE_D4, 8w1, 8w1, _) : resprel_yes();
            (MODE_D1, _, 8w1, _)   : resprel_yes();
            (_, _, _, 8w1)         : resprel_yes();   /* drain: always release held originals */
        }
        size = 16;
    }

    apply {
        if (meta.port_ok == 8w0) {
            drop_pkt();
        } else {
          /* ============ TOP: single reg_txn access per path (stage 0) ======= *
           * MATCH-BEFORE-MUTATION note: the txn open is gated by ROLE_ARM (a
           * master-side DNP3 READ) — the coarse single-domain ownership; exact
           * flow ownership (tbl_flow_own) then gates every downstream MUTATION
           * (exp arm, seed, hold, fail-open latch, lifecycle, retire).
           * Multi-flow robustness (gating the open itself on flow_owned) is a
           * documented extension that costs one front stage; out of scope for
           * the single-domain probe. */
          if (meta.role == ROLE_ARM && meta.from_out == 8w0) {
              meta.txn_old = txn_open.execute(1w0);
          } else if (meta.is_loop == 8w1 &&
                     (meta.loop_kind == SHIM_RESP_RETIRE ||
                      meta.loop_kind == SHIM_BARF ||
                      meta.loop_kind == SHIM_BART)) {
              meta.txn_old = txn_complete.execute(1w0);   /* gen-qualified retire (barrier) */
          } else {
              meta.txn_old = txn_read.execute(1w0);
          }
          meta.cur_gen      = (bit<32>)meta.txn_old[30:0];
          meta.cur_gen_conf = meta.txn_old | CONF_BIT;
          meta.active       = (bit<8>)meta.txn_old[31:31];

          /* front classify (parallel; no register deps) */
          tbl_flow_own.apply();
          tbl_params.apply();
          tbl_mask_ts.apply();
          tbl_or_mark.apply();
          tbl_build_cand.apply();

          /* ===== EARLY exact-match register access (PARALLELIZATION) =======
           * reg_exp_ack {ARM-write, native-ACK-read} and reg_exp_seq {ARM-write,
           * native-RESP-read} are hoisted to ONE shallow, mutually-exclusive
           * depth so each places at a single EARLY stage — role-exclusive and
           * independent of the ident/resp_stage/pop/lifecycle serial chain. This
           * is the dependency-audit's "place exp in parallel, not on the chain",
           * and it resolves the prior full-integration co-location wall (reg_exp_ack
           * vs reg_resp_stage) by equalizing access depth (rule: two accesses to
           * one register at different nesting depths cannot co-locate). */
          if (meta.role == ROLE_ARM && meta.from_out == 8w0 &&
              meta.active == 8w0 && meta.flow_owned == 8w1) {
              tbl_calc_exp_ack.apply();
              exp_ack_write.execute(1w0);                /* arm expected ACK number */
          } else if (meta.role == ROLE_ACK && meta.from_out == 8w1) {
              meta.exp_ack_old = exp_ack_read.execute(1w0);
              if (meta.exp_ack_old == hdr.tcp.ack_no) { meta.id_ack_match = 8w1; }
          }
          if (meta.role == ROLE_ARM && meta.from_out == 8w0 &&
              meta.active == 8w0 && meta.flow_owned == 8w1) {
              tbl_calc_exp_seq.apply();
              exp_seq_write.execute(1w0);                /* arm expected relay seq */
          } else if (meta.role == ROLE_RESP && meta.from_out == 8w1) {
              meta.exp_seq_old = exp_seq_read.execute(1w0);
              if (meta.exp_seq_old == hdr.tcp.seq_no) { meta.id_seq_match = 8w1; }
          }

          /* ===================== RETIRE / BARRIER passes (qid4) =========== */
          if (meta.is_loop == 8w1 &&
              (meta.loop_kind == SHIM_RESP_RETIRE ||
               meta.loop_kind == SHIM_BARF ||
               meta.loop_kind == SHIM_BART)) {
              /* txn_complete already ran at top (gen-qualified). */
              hdr.shim.setInvalid();                     /* strip -> byte-identical inner */
              ctr_barrier.count(1w0);
              if (meta.loop_kind == SHIM_BART) { drop_pkt(); }  /* internal token: nothing to emit */
              else { to_fwd(); }                                 /* RESP retire / FIN barrier -> master */

          /* ===================== reservoir tokens ======================== */
          } else if (meta.role == ROLE_TOKEN) {
            if (meta.is_first == 8w1) {
                /* pktgen seed */
                meta.token_id = (bit<16>)hdr.timer.packet_id;
                tbl_app_role.apply();
                tbl_tokid_valid.apply();
                if (meta.active == 8w0) {
                    drop_pkt();                          /* inactive: no seeding */
                } else if (meta.tok_valid == 8w1) {
                    if (meta.role_bit == 1w1) {
                        meta.ident_res = ident_resp_seed.execute(meta.token_id[5:0]);
                        if (meta.ident_res == R_SEEDED) {
                            admit_stamp(); to_resp_block(); ctr_seed_new.count(1w0);
                        } else { drop_pkt(); }
                    } else {
                        meta.stage_val = stage_read.execute(1w0);
                        if (meta.stage_val == K_TOKENS) {
                            meta.ident_res = ident_ack_seed.execute(meta.token_id[5:0]);
                            if (meta.ident_res == R_SEEDED) {
                                admit_stamp(); to_ack_block(); ctr_seed_new.count(1w0);
                            } else { drop_pkt(); }
                        } else { drop_pkt(); }
                    }
                } else { drop_pkt(); }
            } else if (meta.is_loop == 8w1) {
                /* loopback token: confirm + pop + bounded-watchdog budget */
                tbl_token_valid.apply();
                if (meta.active == 8w0) {
                    drop_pkt();                          /* inactive: drain, no re-enqueue */
                } else if (meta.tok_valid == 8w1) {
                    if (hdr.token.generation == meta.cur_gen) {
                        meta.tok_budget = hdr.token.budget;
                        if (meta.tok_budget == 16w0) {
                            /* ZERO-BUDGET WATCHDOG -> initiate bounded cleanup barrier (one-shot) */
                            meta.life_mask = LIFE_DRAIN;
                            meta.life_old  = life_rmw.execute(1w0);
                            tbl_test_drain_tok.apply();
                            if (meta.drain_init == 8w0) {
                                stamp_shim(SHIM_BART); to_barrier(); ctr_barrier.count(1w0);
                            } else {
                                drop_pkt();              /* already draining */
                            }
                        } else if (meta.role_bit == 1w1) {
                            meta.ident_res = ident_resp_confirm.execute(hdr.token.token_id[5:0]);
                            if (meta.ident_res == R_FIRST) {
                                meta.stage_val  = stage_incr.execute(1w0);
                                meta.pop_delta  = DELTA_RESP_UP;
                                meta.pop_packed = pop_incr.execute(1w0);
                                ctr_confirm_resp.count(1w0);
                            }
                            hdr.token.budget = meta.tok_budget - 16w1;
                            to_resp_block();
                        } else {
                            meta.ident_res = ident_ack_confirm.execute(hdr.token.token_id[5:0]);
                            if (meta.ident_res == R_FIRST) {
                                meta.pop_delta  = DELTA_ACK_UP;
                                meta.pop_packed = pop_incr.execute(1w0);
                                ctr_confirm_ack.count(1w0);
                            }
                            hdr.token.budget = meta.tok_budget - 16w1;
                            to_ack_block();
                        }
                    } else {
                        drop_pkt(); ctr_term_stale.count(1w0);
                    }
                } else { drop_pkt(); }
            } else { drop_pkt(); }

          /* ===================== master-side READ (ARM) ================== */
          } else if (meta.role == ROLE_ARM && meta.from_out == 8w0) {
            if (meta.active == 8w0) {                    /* fresh open (pre-open active) */
                stage_reset.execute(1w0);
                pop_reset.execute(1w0);
                dl_reset.execute(1w0);
                life_arm.execute(1w0);                   /* lifecycle reset for the new gen */
                /* exp_ack/exp_seq armed in the EARLY block above (same fresh-open
                 * + flow_owned gate) — MATCH (flow) BEFORE MUTATION preserved. */
                if (meta.flow_owned == 8w1) { ctr_arm.count(1w0); }
            } else {
                ctr_overlap.count(1w0);                  /* overlap: leave ALL state unchanged */
            }
            to_fwd();

          /* ===================== FIN / RST cleanup ======================= */
          } else if (meta.role == ROLE_CLEANUP) {
            if (meta.flow_owned == 8w1 && meta.active == 8w1) {
                meta.life_mask = LIFE_DRAIN;             /* latch drain (release held originals) */
                meta.life_old  = life_rmw.execute(1w0);
                stamp_shim(SHIM_BARF); to_barrier();     /* qid4 barrier: retires after qid5-7 drain */
                ctr_barrier.count(1w0);
            } else {
                to_fwd();
            }

          /* ===================== held-ACK self-clock (qid7) ============== */
          } else if (meta.is_loop == 8w1 && meta.loop_kind == SHIM_ACK) {
            if (meta.active == 8w1 && meta.shim_gen == meta.cur_gen_conf) {
                meta.dl_age = dl_read.execute(1w0);
                tbl_dl_expiry.apply();
                meta.life_mask = LIFE_ZERO;              /* pure read: resp_present + drain */
                meta.life_old  = life_rmw.execute(1w0);
                tbl_test_resp_present.apply();
                tbl_test_drain_ack.apply();
                tbl_ack_release.apply();
                if (meta.ack_release == 8w1) {
                    stamp_shim(SHIM_ACK_COMMIT); to_ack_block();  /* commit loopback sets ACK_COMMIT */
                } else {
                    stamp_shim(SHIM_ACK); to_ack_block();          /* keep self-clocking */
                }
            } else {
                drop_pkt();                              /* stale / forged: no state mutation */
            }

          /* ===================== ACK commitment loopback ================= */
          } else if (meta.is_loop == 8w1 && meta.loop_kind == SHIM_ACK_COMMIT) {
            if (meta.active == 8w1 && meta.shim_gen == meta.cur_gen_conf) {
                meta.life_mask = LIFE_ACK_COMMIT;        /* commitment = returned-from-loop + to master FIFO */
                meta.life_old  = life_rmw.execute(1w0);
                hdr.shim.setInvalid();
                to_fwd();                                /* assign to master-facing FIFO */
            } else {
                drop_pkt();
            }

          /* ===================== held-RESP self-clock (qid5) ============= */
          } else if (meta.is_loop == 8w1 && meta.loop_kind == SHIM_RESP) {
            if (meta.active == 8w1 && meta.shim_gen == meta.cur_gen_conf) {
                meta.dl_age = dl_read.execute(1w0);      /* now - T_A */
                tbl_build_resp_age.apply();              /* now - T_RESP = age - D_R */
                tbl_dl_resp_expiry.apply();
                meta.life_mask = LIFE_ZERO;              /* pure read: ack_committed + drain */
                meta.life_old  = life_rmw.execute(1w0);
                tbl_test_ack_committed.apply();
                tbl_test_drain_resp.apply();
                tbl_resp_release.apply();
                if (meta.resp_release == 8w1) {
                    stamp_shim(SHIM_RESP_RETIRE); to_barrier();   /* qid4 retire (after qid6 ACK drains) */
                } else {
                    stamp_shim(SHIM_RESP); to_resp_block();        /* keep self-clocking */
                }
            } else {
                drop_pkt();
            }

          /* ===================== native ACK / RESPONSE =================== */
          } else if ((meta.role == ROLE_ACK || meta.role == ROLE_RESP) && meta.from_out == 8w1) {
            /* readiness (authoritative K/K) — shared read */
            meta.pop_packed = pop_read.execute(1w0);
            if (meta.pop_packed == BOTH_READY && meta.active == 8w1) { meta.ready = 8w1; }

            if (meta.role == ROLE_ACK) {
                /* exact ACK match (id_ack_match computed in the EARLY block) */
                if (meta.flow_owned == 8w1 && meta.active == 8w1 && meta.id_ack_match == 8w1) {
                    /* MATCHED: arm T_A (one-shot) + lifecycle (ADMITTED or FAILOPEN).
                     * dl_cand (= now_word + D_A = T_A) precomputed at top by build_cand. */
                    dl_arm.execute(1w0);
                    if (meta.ready == 8w1) { meta.life_mask = LIFE_ACK_ADMITTED; }
                    else { meta.life_mask = LIFE_FAILOPEN; ctr_failopen.count(1w0); }
                    meta.life_old = life_rmw.execute(1w0);
                    tbl_test_fo_ack.apply();
                    tbl_ack_native.apply();              /* hold (D1..D4 ready & !fo) vs fwd */
                } else {
                    to_fwd();                            /* unmatched: bypass, no state mutation */
                }
            } else {
                /* ROLE_RESP native */
                if (meta.combined_dev == 8w1) {
                    /* combined TCP-ACK + DNP3-RESPONSE (Case B): bypass Q_ACK_HOLD,
                     * never fabricate an ACK; safe default = fail-open/bypass (PROPOSED). */
                    to_fwd();
                } else {
                    /* exact RESP match (id_seq_match computed in the EARLY block) */
                    if (meta.flow_owned == 8w1 && meta.active == 8w1 && meta.id_seq_match == 8w1) {
                        if (meta.ready == 8w1) { meta.life_mask = LIFE_RESP_PRESENT; }
                        else { meta.life_mask = LIFE_FAILOPEN; ctr_failopen.count(1w0); }
                        meta.life_old = life_rmw.execute(1w0);
                        tbl_test_fo_resp.apply();
                        tbl_resp_native.apply();         /* hold (D1..D4 ready & !fo) vs fwd */
                    } else {
                        to_fwd();                        /* unmatched: bypass */
                    }
                }
            }

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
        pkt.emit(hdr.shim);
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

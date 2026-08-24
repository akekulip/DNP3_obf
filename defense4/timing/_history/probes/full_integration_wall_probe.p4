/* NEGATIVE DIAGNOSTIC PROBE (does NOT compile — preserved per directive). Mid-work
 * full §4 integration (v5 bootstrap + full matching/dual-deadline/watchdog state,
 * 11 registers). FAILS table placement: register-ordering wall (reg_exp_ack /
 * reg_resp_stage cannot co-allocate). This is the preserved failed result that
 * establishes the dependency wall; see evidence/GATE2_INTEGRATION.md. Contains
 * leftover unused tables (measurement not clean — the minimal probe is the clean
 * measurement). Not the deliverable; not loaded, not run. */
/* ============================================================================
 * defense4_timing.p4 — Defense 4 unified timing core (Priority 1), Tofino-1 / TNA.
 *
 * This is the §4 Gate-2 INTEGRATED build: the proven v5 reservoir-bootstrap subsystem
 * (defense4/timing/bootstrap/bootstrap_probe_v5.p4, 11/12 ingress, 0 errors) UNIFIED with the
 * §4 deadline / transaction-lifecycle machinery specified in defense4/TIMING_SPEC.md. It replaces
 * the earlier flow-keyed WIP (commit b9ac9e8), which Gate 2 rejected as semantically incorrect
 * (defense4/timing/evidence/GATE2_EVIDENCE.md). TIMING ONLY: no size fields, slot bitmaps,
 * outer/encap headers, decoder pass, filler roles, or size state. The original ACK and RESPONSE
 * stay queue-resident; only internal blocker TOKENS recirculate; NO synthetic ACK/RESPONSE is
 * ever emitted.
 *
 * ---------------------------------------------------------------------------
 * MODEL — ONE SCHEDULER DOMAIN, ONE ACTIVE PROTECTED TRANSACTION (TIMING_SPEC §6, ARCHITECTURE)
 * ---------------------------------------------------------------------------
 * Like v5 and Defense 3, this is a SINGLE-DOMAIN design: scalar single-entry registers hold the
 * one active transaction's state, keyed by an INTERNAL generation (reg_txn), NOT a per-flow index.
 * "Exact flow + transaction matching" (§4.3) is therefore VALIDATION of an arriving ACK/RESPONSE
 * against the active transaction's stored expectations (canonical bidirectional flow fingerprint,
 * expected TCP ack number, expected relay sequence), NOT per-flow register indexing. A non-matching
 * ACK/RESPONSE fails open and NEVER binds to the active generation (§6 concurrency, directive 6).
 *
 * ---------------------------------------------------------------------------
 * PRESERVED v5 INVARIANTS (each mapped to code)
 * ---------------------------------------------------------------------------
 *  - reg_txn: atomic packed {active(bit31), generation[30:0]} READ-admission guard. txn_open is the
 *    unsigned-magnitude open (v < CONF_BIT) + single-add advance (v += OPEN_ADD, wrap GEN_MAX). An
 *    overlapping READ is a genuine side-effect-free NO-OP (resets gated on the pre-open active bit).
 *  - RESPONSE-first shadow staging: reg_resp_stage gates ONLY ACK seeding (ACK seed dropped until
 *    the RESP shadow reaches K).
 *  - reg_pop_packed: authoritative packed K/K readiness word (== BOTH_READY 0x00400040), read once
 *    by native admission.
 *  - Generation-qualified per-role identity cells reg_ident_resp / reg_ident_ack (two-comparator
 *    seed dedup — load-bearing, bf-asm cannot assemble the masked compare).
 *  - Loopback-generation shim (shim_h, etype 0x88C3): held/forwarded RESP carries its generation,
 *    validated on return, stripped before the master hop; from_loop distinguishes 0x88C3 shim /
 *    0x88C1 token / 0x0800 held-ACK.
 *  - Port-qualified arming: only a master-side READ (from_out==0) opens a transaction.
 *  - Static 7>6>5>4 TM policy (qids 7/6/5/4). P4 assigns qids; the control plane sets max_priority.
 *  - Queue-resident originals + blockers; data-plane operation; NO per-transaction controller
 *    action; NO dynamic TM reconfig; bounded cleanup; inactive-state drain (tokens stop recirc +
 *    seeds not admitted while inactive; stale tokens never alter current-gen state).
 *
 * ---------------------------------------------------------------------------
 * ADDED §4 LIFECYCLE (each mapped to code; see the numbered notes in Ingress.apply)
 * ---------------------------------------------------------------------------
 *  1. Modes OFF/D1_EVENT/D2_RESPONSE_DEADLINE/D3_ACK_DEADLINE/D4_DUAL_DEADLINE/FAIL_OPEN, selected
 *     per transaction from tbl_params (mode, D_A, D_R).
 *  2. Deadlines armed at NATIVE ACK arrival (single arm): T_A = t_A + D_A, T_RESP = T_A + D_R,
 *     stored in TWO separate registers so D4 preserves both. Modular sign-bit wrap comparison,
 *     mask 0x800000FF, low-tick byte encoding (frozen D3/Part-12 idiom). D_A, D_R low bytes MUST be
 *     zero (256 ns ticks); the horizon < 2^31 ticks; the control plane clamps (TIMING_SPEC §8).
 *  3. Exact matching: canonical BIDIRECTIONAL flow fingerprint (reg_flow_fp), expected TCP ack
 *     (reg_exp_ack), expected relay seq (reg_exp_seq), master/relay ports (folded into the
 *     fingerprint), generation (reg_txn); pure-ACK + DNP3-RESPONSE parser validation; one-shot
 *     admission (arm-once + identity dedup).
 *  4. ACK and RESPONSE may arrive in EITHER order (RESPONSE held until the ACK establishes
 *     T_A/T_RESP; a RESP arriving first sets resp_seen and holds, deadline-unarmed => not expired).
 *  5. RESPONSE release predicate: matching_generation AND response_present AND predecessor_satisfied
 *     AND deadline_or_event. predecessor_satisfied = ack_committed for separate-ACK; the combined
 *     case bypasses. ack_committed set when the released ACK returns from loopback and is assigned
 *     to the master FIFO (reg_flags bit0).
 *  6. Overlapping transactions bypass without changing the active transaction; a non-matching
 *     ACK/RESP is forwarded and does NOT bind the active generation.
 *  7. Bounded watchdogs via the per-token pass budget (H = B * K/rate): a budget-zero blocker
 *     fails open (drains its reservoir -> releases the held original) AND retire-shims to clear the
 *     stranded active (bounded, generation-qualified). This is the §4 resolution of v5's §3
 *     fail-closed wedge: a held RESP that never releases eventually watchdog-terminates -> fail-open
 *     -> the domain re-opens. deadline < poll interval is an OPERATING CONDITION, not the safety
 *     mechanism.
 *  8. Terminate BOTH blocker roles on fail-open / watchdog / FIN/RST / collision; forward any held
 *     original byte-identically (by construction, pending packet-level verification); kill stale
 *     internal tokens; clear state only generation-qualified; duplicate/retransmitted ACK/RESP bind
 *     idempotently (arm-once + identity dedup + gen-qualified writes).
 *  9. A held ACK/RESPONSE is released before generation-qualified retirement; authenticated
 *     loopback completion is the normal held-RESPONSE retirement point.
 * 10. Reject duplicate/late/stale-generation/forged/wrong-port loopback (token identity table +
 *     generation compare + port classification; 0x88C1 only from pktgen/loop).
 * 11. ACK-bearing RESPONSE (combined): classify as combined-response, bypass Q_ACK_HOLD, PROPOSED
 *     protected hold with a safe default of fail-open/bypass; NEVER fabricate an ACK.
 *
 * CLAIM BOUNDARY (TIMING_SPEC §12): a clean compile + offline synthetic tests give offline
 * compiler-fit and model-level functional evidence ONLY. They do NOT prove silicon logical
 * correctness, dual-reservoir readiness, real release tails, external ordering, or packet-level
 * byte identity. Not loaded. Complete Defense 4 is NOT demonstrated.
 *
 * TNA discipline (so the stage count is honest): each value that combines a just-read/just-computed
 * value lives in its own single-op table; sign/mask tests are whole-container ternary TCAM masks;
 * each Register has <=2 PHV inputs and <=4 RegisterActions; the atomic reg_txn magnitude open and
 * the two-comparator identity dedup are the load-bearing bf-asm workarounds (do not "clean up").
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes / protocols ---- */
const bit<16> ETHERTYPE_TOKEN     = 0x88C1;   /* internal blocker-token frame (loop/pgen only) */
const bit<16> ETHERTYPE_HELD_RESP = 0x88C3;   /* loopback held-RESP / retire shim (v5)         */
const bit<16> ETHERTYPE_IPV4      = 0x0800;
const bit<8>  IP_PROTO_TCP        = 8w6;

/* ---- DNP3 ---- */
const bit<16> DNP3_START        = 0x0564;
const bit<8>  DNP3_FC_READ       = 8w1;
const bit<8>  DNP3_FC_RESPONSE   = 8w129;

/* ---- ports (single loopback scheduler domain; front-panel roles control-plane wired) ---- */
const PortId_t PORT_L      = 9w8;    /* internal loopback (token recirculation)  */
const PortId_t PORT_MASTER = 9w9;
const PortId_t PORT_RELAY  = 9w64;
const PortId_t PORT_PGEN   = 9w68;

/* ---- four queues: qid AND max_priority are configured separately (control plane), 7>6>5>4 ---- */
const bit<5> Q_ACK_BLOCK  = 5w7;    /* ACK blocker reservoir  (starves Q_ACK_HOLD)  */
const bit<5> Q_ACK_HOLD   = 5w6;    /* queue-resident real ACK                      */
const bit<5> Q_RESP_BLOCK = 5w5;    /* RESP blocker reservoir (starves Q_RESP_HOLD) */
const bit<5> Q_RESP_HOLD  = 5w4;    /* queue-resident real RESPONSE                 */

/* ---- reservoir / token constants (v5) ---- */
const bit<16> K_TOKENS   = 16w64;
const bit<32> BOTH_READY = 32w0x00400040;   /* authoritative packed K/K {ack(hi16), resp(lo16)} */
const bit<32> DELTA_ACK_UP  = 32w0x00010000;
const bit<32> DELTA_RESP_UP = 32w0x00000001;

const bit<8> TOKEN_MARKER = 8w0xE1;
const bit<8> SD_LOOP      = 8w0x5A;
const bit<8> TOK_ACK      = 8w0xA1;
const bit<8> TOK_RESP     = 8w0xA2;

/* per-token fail-open pass budget (§4.7 watchdog). H = B * K/rate_dp8 (frozen D3 model). The value
 * is a compile-in default; the control plane rewrites tbl_params.budget so H sweeps without a
 * recompile. Sized to exceed the longest legitimate hold and stay well below the master TCP RTO. */
const bit<32> BUDGET_DEFAULT = 32w18000;

/* ---- reg_txn packing: bit31 = active, bits[30:0] = generation in [1, 0x7FFFFFFF] (v5) ---- */
const bit<32> GEN_MAX  = 32w0x7FFFFFFF;
const bit<32> CONF_BIT = 32w0x80000000;   /* active bit (also CONFIRMED marker on ident cells) */
const bit<32> GEN_MASK = 32w0x7FFFFFFF;
const bit<32> OPEN_ADD = 32w0x80000001;   /* +1 generation AND set active, in one SALU add    */

const bit<8> R_SEEDED = 8w1;
const bit<8> R_DEDUP  = 8w0;
const bit<8> R_FIRST  = 8w1;
const bit<8> R_AGAIN  = 8w0;

/* ---- roles (parser-assigned, once per path) ---- */
const bit<8> ROLE_BYPASS  = 8w0;
const bit<8> ROLE_TOKEN   = 8w1;   /* internal blocker token (ACK or RESP reservoir)   */
const bit<8> ROLE_ACK     = 8w2;   /* pure TCP ACK (queue-resident)                    */
const bit<8> ROLE_RESP    = 8w3;   /* DNP3 solicited RESPONSE, separate-ACK            */
const bit<8> ROLE_RESP_CMB= 8w4;   /* §4.11 combined-response (ACK-bearing RESPONSE)   */
const bit<8> ROLE_ARM     = 8w6;   /* DNP3 READ that opens a transaction               */
const bit<8> ROLE_CLEANUP = 8w7;   /* FIN/RST teardown                                 */

/* ---- release modes (tbl_params) ---- */
const bit<8> MODE_OFF       = 8w0;
const bit<8> MODE_D1_EVENT  = 8w1;
const bit<8> MODE_D2_RESP   = 8w2;   /* D2_RESPONSE_DEADLINE */
const bit<8> MODE_D3_ACK    = 8w3;   /* D3_ACK_DEADLINE      */
const bit<8> MODE_D4_DUAL   = 8w4;   /* D4_DUAL_DEADLINE     */
const bit<8> MODE_FAIL_OPEN = 8w5;   /* safety transition (test-only external trigger) */

/* ---- deadline word encoding (frozen D3/Part-12 idiom) ----
 * 24 bits of 256 ns ticks in [31:8]; bit0 is the ARMED marker; UNARMED_WORD's distinct low byte
 * makes an unarmed deadline fail the whole-container expiry mask, so no separate "armed" flag is
 * needed. D_A and D_R low bytes MUST be zero so the marker survives the add. */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;
const bit<32> ARMED_MARK   = 32w0x00000001;
const bit<32> UNARMED_WORD  = 32w0x00000002;   /* low byte 0x02 => age low byte != 0 => never due */
const bit<32> DL_NO_WRITE   = 32w0;

const bit<8> REL_HOLD    = 8w0;
const bit<8> REL_RELEASE = 8w1;

/* ---- indexed correctness counters (single access per packet at the ACT exit) ---- */
const bit<8> C_FWD          = 8w0;   /* forwarded transparently / bypass                */
const bit<8> C_BAD_PORT     = 8w1;
const bit<8> C_ARM_FRESH    = 8w2;   /* READ opened a new generation                    */
const bit<8> C_ARM_OVERLAP  = 8w3;   /* concurrent READ while active -> no-op            */
const bit<8> C_SEED_NEW     = 8w4;   /* pktgen token seeded a reservoir slot            */
const bit<8> C_SEED_DROP    = 8w5;   /* pktgen token dropped (inactive / dup / not-ready)*/
const bit<8> C_TOK_LOOP     = 8w6;   /* blocker token re-enqueued (one budget unit)     */
const bit<8> C_TOK_TERM     = 8w7;   /* blocker token terminated (deadline/event/stale) */
const bit<8> C_TOK_FAILOPEN = 8w8;   /* blocker token budget-zero -> fail-open watchdog */
const bit<8> C_ACK_HOLD     = 8w9;   /* native ACK held (Q_ACK_HOLD)                    */
const bit<8> C_ACK_FWD      = 8w10;  /* native ACK forwarded (OFF / not matching / !ready)*/
const bit<8> C_ACK_COMMIT   = 8w11;  /* held ACK returned from loopback -> master FIFO   */
const bit<8> C_RESP_HOLD    = 8w12;  /* native RESPONSE held (Q_RESP_HOLD)              */
const bit<8> C_RESP_RETIRE  = 8w13;  /* held/forwarded RESPONSE completed + retired     */
const bit<8> C_RESP_STALE   = 8w14;  /* loopback RESP with mismatched generation        */
const bit<8> C_CLEANUP      = 8w15;  /* FIN/RST teardown                                */

/* ============================ headers ==================================== */
header shim_h    { bit<48> dst; bit<48> src; bit<16> etype; bit<32> gen; }  /* loopback held-RESP */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header token_h {
    bit<8>  marker;
    bit<8>  sdomain;
    bit<8>  role;          /* TOK_ACK / TOK_RESP */
    bit<32> generation;
    bit<16> token_id;
    bit<32> budget;        /* §4.7: per-token pass budget (fail-open watchdog) */
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
    shim_h      shim;         /* valid only on held-RESP / retire loopback copies */
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
    /* origin / classification — written on EVERY parser path */
    bit<8>  role;
    bit<8>  port_ok;
    bit<9>  fwd_port;
    bit<8>  is_first;        /* pktgen-origin */
    bit<8>  is_loop;         /* loopback-origin */
    bit<8>  from_out;        /* 1 = relay side (native ACK/RESP direction) */

    /* reg_txn read (once per path) + slices */
    bit<8>  tok_valid;
    bit<1>  role_bit;        /* 0 = ACK reservoir, 1 = RESP reservoir */
    bit<8>  tok_role;
    bit<16> token_id;
    bit<32> txn_old;
    bit<32> cur_gen;         /* txn_old[30:0] */
    bit<32> cur_gen_conf;    /* txn_old | CONF_BIT */
    bit<8>  active;          /* txn_old[31:31] */
    bit<16> stage_val;
    bit<8>  ident_res;
    bit<32> pop_packed;
    bit<32> pop_delta;
    bit<8>  ready;           /* pop==K/K && active */
    bit<1>  fo_eq;           /* failopen latched for cur_gen */
    bit<32> shim_gen_active; /* shim.gen (= CONF|cur_gen) — completion clear key */

    /* §4 timestamp / deadline surface */
    bit<32> ts_m;            /* ingress_mac_tstamp[31:0] & TICK_MASK */
    bit<32> now_word;        /* ts_m | ARMED_MARK */
    bit<32> t_a;             /* T_A = now_word + D_A (T_RESP = T_A + D_R derived on the token path) */
    bit<32> age_dl;          /* now_word - stored deadline (blocker path) */
    bit<8>  expired;         /* 1 = armed AND due */

    /* §4 params */
    bit<8>  mode;
    bit<32> d_a;
    bit<32> d_r;
    bit<32> read_len;
    bit<32> exp_ack_cand;    /* READ.seq + read_len */
    bit<32> seq_w;           /* relay expected-seq write value (= READ.ack_no) */

    /* §4 exact matching results */
    bit<16> fp_wide;         /* canonical bidirectional flow fingerprint */
    bit<16> fp_diff;         /* 0 == flow matches the active transaction */
    bit<32> exp_ack_diff;    /* 0 == ACK.ack_no matches EXP_ACK */
    bit<32> exp_seq_diff;    /* 0 == RESP.seq matches EXP_RELAY_SEQ */
    bit<32> match_resid;     /* (fp_diff | role-diff); 0 == all conjuncts match (one 32b gateway) */
    bit<8>  match_ok;        /* 1 = flow + role conjuncts satisfied */

    /* §4 commitment / presence / event */
    bit<8>  flags_val;       /* reg_flags read: bit0=ack_committed, bit1=resp_seen */
    bit<8>  budget_zero;     /* 1 = token budget exhausted */

    bit<8>  ctr_idx;
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
        /* init only MAU-written metadata; per-path classification fields are assigned once below */
        meta.tok_valid       = 8w0;
        meta.role_bit        = 1w0;
        meta.tok_role        = 8w0;
        meta.token_id        = 16w0;
        meta.txn_old         = 32w0;
        meta.cur_gen         = 32w0;
        meta.cur_gen_conf    = 32w0;
        meta.active          = 8w0;
        meta.stage_val       = 16w0;
        meta.ident_res       = 8w0;
        meta.pop_packed      = 32w0;
        meta.pop_delta       = 32w0;
        meta.ready           = 8w0;
        meta.fo_eq           = 1w0;
        meta.shim_gen_active = 32w0;
        meta.ts_m            = 32w0;
        meta.now_word        = 32w0;
        meta.t_a             = 32w0;
        meta.age_dl          = 32w0;
        meta.expired         = 8w0;
        meta.mode            = MODE_OFF;
        meta.d_a             = 32w0;
        meta.d_r             = 32w0;
        meta.read_len        = 32w0;
        meta.exp_ack_cand    = 32w0;
        meta.seq_w           = 32w0;
        meta.fp_wide         = 16w0;
        meta.fp_diff         = 16w0;
        meta.exp_ack_diff    = 32w0;
        meta.exp_seq_diff    = 32w0;
        meta.match_resid     = 32w0;
        meta.match_ok        = 8w0;
        meta.flags_val       = 8w0;
        meta.budget_zero     = 8w0;
        meta.ctr_idx         = C_FWD;
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
            ETHERTYPE_HELD_RESP : parse_shim;
            default             : parse_eth;
        }
    }
    state parse_shim {
        pkt.extract(hdr.shim);
        meta.shim_gen_active = hdr.shim.gen;   /* stamped as CONF|cur_gen at admission */
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
        /* pure-ACK predicate: ACK flag set, FIN/RST/SYN/PSH clear, ip.total_len == 20 + 4*dofs */
        transition select(hdr.tcp.flags, hdr.tcp.data_offset, hdr.ipv4.total_len) {
            (8w0x01 &&& 8w0x01, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;   /* FIN */
            (8w0x04 &&& 8w0x04, 4w0 &&& 4w0, 16w0 &&& 16w0) : set_role_cleanup;   /* RST */
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
        /* solicited RESPONSE (FIR+FIN single-segment, CON clear) -> ROLE_RESP; READ -> ROLE_ARM.
         * §4.11: a solicited RESPONSE that also carries the piggybacked ACK bits would be routed by
         * a control-plane classifier; absent a separate-ACK anchor the safe default here is to
         * treat only the clean single-segment solicited RESPONSE as protectable and bypass others. */
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0xC0 &&& 8w0xF0, DNP3_FC_RESPONSE) : set_role_resp;
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

    /* ================= PRESERVED v5 STATE ================= */

    /* reg_txn: atomic packed {active(bit31), generation[30:0]} */
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
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_complete = {   /* gen-qualified retire */
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v == meta.shim_gen_active) { v = v & GEN_MASK; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_txn) txn_clear_fin = {  /* FIN/RST teardown */
        void apply(inout bit<32> v, out bit<32> rv) { v = v & GEN_MASK; rv = v; }
    };

    /* per-role generation-qualified identity cells (two-comparator dedup, load-bearing) */
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

    Register<bit<16>, bit<1>>(1, 0) reg_resp_stage;   /* RESP-only shadow (gates ACK seeding) */
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

    Register<bit<32>, bit<1>>(1, 0) reg_pop_packed;   /* authoritative packed K/K */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_incr = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + meta.pop_delta; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_pop_packed) pop_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };

    Register<bit<32>, bit<1>>(1, 0) reg_failopen;     /* generation-qualified fail-open latch */
    RegisterAction<bit<32>, bit<1>, bit<8>>(reg_failopen) failopen_rmw = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == meta.cur_gen) { rv = 8w1; } else { rv = 8w0; }
            if (meta.ready == 8w0) { v = meta.cur_gen; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<8>>(reg_failopen) failopen_note = {   /* watchdog note */
        void apply(inout bit<32> v, out bit<8> rv) { rv = 8w0; v = meta.cur_gen; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_failopen) failopen_reset = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = v; }
    };

    /* ================= ADDED §4 STATE ================= */

    /* §4.2: ONE deadline register stores T_A. T_RESP = T_A + D_R is derived on the fly by the
     * RESP-block token (age_resp = age_ack - D_R), so D4 preserves both deadlines with a single
     * register — halving this register's ARM-phase / token-phase placement pressure. init
     * UNARMED_WORD (low byte 0x02) so an unarmed deadline fails the whole-container expiry mask and
     * the encoding propagates through the -D_R subtract. 3 actions, 2 PHV inputs (now_word, t_a). */
    Register<bit<32>, bit<1>>(1, 32w2) reg_deadline;   /* T_A  (== UNARMED_WORD initially) */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) dl_age = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = meta.now_word - v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) dl_arm = {   /* arm-once */
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v == UNARMED_WORD) { v = meta.t_a; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) dl_disarm = {
        void apply(inout bit<32> v, out bit<32> rv) { v = UNARMED_WORD; rv = v; }
    };

    /* §4.3: canonical bidirectional flow fingerprint. Opener claims; native ACK/RESP checks via XOR
     * (0 == same flow). Whole-word compare-free; single 16-bit cell. */
    Register<bit<16>, bit<1>>(1, 0) reg_flow_fp;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_flow_fp) fp_claim = {
        void apply(inout bit<16> v, out bit<16> rv) { v = meta.fp_wide; rv = 16w0; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_flow_fp) fp_check = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v ^ meta.fp_wide; }
    };

    /* §4.3: EXP_ACK := READ.seq + read_len (one add); the native ACK tests ack_no against it. */
    Register<bit<32>, bit<1>>(1, 0) reg_exp_ack;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_ack) exp_ack_w = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.ack_no - v; v = meta.exp_ack_cand; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_ack) exp_ack_r = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.ack_no - v; }
    };

    /* §4.3: EXP_RELAY_SEQ := READ.ack_no (the relay's SND.NXT); the native RESP tests seq against it
     * (rejects the relay's byte-identical TCP keepalives, per the frozen D3 finding). */
    Register<bit<32>, bit<1>>(1, 0) reg_exp_seq;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_seq) exp_seq_w = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.seq_no - v; v = meta.seq_w; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_exp_seq) exp_seq_r = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.seq_no - v; }
    };

    /* §4.5: packed commitment flags {bit0 = ack_committed, bit1 = resp_seen(event/response_present)}.
     * Set on the ACK loopback commit / native RESP arrival; read by the blocker termination. */
    Register<bit<8>, bit<1>>(1, 0) reg_flags;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_flags) flags_set_ackc = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v | 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_flags) flags_set_resp = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v | 8w2; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_flags) flags_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_flags) flags_reset = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = v; }
    };

    /* ---- correctness counter (one indexed array, single access per packet) ---- */
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) ctr;

    /* ---- TM actions ---- */
    action to_ack_block()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_BLOCK;  ig_tm_md.bypass_egress = 1w1; }
    action to_ack_hold()   { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_HOLD;   ig_tm_md.bypass_egress = 1w1; }
    action to_resp_block() { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_BLOCK; ig_tm_md.bypass_egress = 1w1; }
    action to_fwd()        { ig_tm_md.ucast_egress_port = meta.fwd_port; ig_tm_md.qid = 5w0; ig_tm_md.bypass_egress = 1w0; }
    action drop_pkt()      { ig_dprsr_md.drop_ctl = 3w1; }

    action admit_stamp() {
        hdr.token.setValid();
        hdr.token.marker     = TOKEN_MARKER;
        hdr.token.sdomain    = SD_LOOP;
        hdr.token.role       = meta.tok_role;
        hdr.token.generation = meta.cur_gen;
        hdr.token.token_id   = meta.token_id;
        hdr.token.budget     = BUDGET_DEFAULT;
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

    /* §4.3: canonical bidirectional flow fold. Direction-normalize the 4-tuple to (master-side,
     * relay-side) using from_out, then hash the fixed ordered field list, so req(M->O) and
     * resp(O->M) yield the SAME fingerprint. One Hash instance, one fixed field list. */
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_flow;
    bit<32> nm_ip; bit<32> nr_ip; bit<16> nm_pt; bit<16> nr_pt;
    action fold_master() { nm_ip = hdr.ipv4.src_addr; nm_pt = hdr.tcp.src_port; nr_ip = hdr.ipv4.dst_addr; nr_pt = hdr.tcp.dst_port; }
    action fold_out()    { nm_ip = hdr.ipv4.dst_addr; nm_pt = hdr.tcp.dst_port; nr_ip = hdr.ipv4.src_addr; nr_pt = hdr.tcp.src_port; }
    table tbl_fold {
        key = { meta.from_out : exact; }
        actions = { fold_master; fold_out; }
        const default_action = fold_master();
        const entries = { (8w1) : fold_out(); }
        size = 2;
    }
    action do_flow_fp() { meta.fp_wide = h_flow.get({ nm_ip, nm_pt, nr_ip, nr_pt }); }
    table tbl_flow_fp { actions = { do_flow_fp; } const default_action = do_flow_fp(); size = 1; }

    /* §4.1: mode + D_A + D_R + read_len + budget, keyed on {role, from_out}. The control plane sets
     * ACK/RESP/ARM entries of a given flow to the SAME mode (one active transaction per domain). */
    action set_params(bit<8> mode, bit<32> d_a, bit<32> d_r, bit<32> read_len) {
        meta.mode = mode; meta.d_a = d_a; meta.d_r = d_r; meta.read_len = read_len;
    }
    table tbl_params {
        key = { meta.role : exact; meta.from_out : exact; }
        actions = { set_params; }
        default_action = set_params(MODE_OFF, 32w0, 32w0, 32w0);
        size = 32;
    }

    /* §4.2: single-op arithmetic tables (TNA one-op-per-action, whole-container). */
    action do_arm_now()    { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_arm_now      { actions = { do_arm_now; }    const default_action = do_arm_now();    size = 1; }
    action do_build_ta()   { meta.t_a = meta.now_word + meta.d_a; }
    table tbl_build_ta     { actions = { do_build_ta; }   const default_action = do_build_ta();   size = 1; }
    action do_exp_cand()   { meta.exp_ack_cand = hdr.tcp.seq_no + meta.read_len; }
    table tbl_exp_cand     { actions = { do_exp_cand; }   const default_action = do_exp_cand();   size = 1; }
    action do_seq_w()      { meta.seq_w = hdr.tcp.ack_no; }
    table tbl_seq_w        { actions = { do_seq_w; }      const default_action = do_seq_w();      size = 1; }

    /* §4.2: blocker-token expiry — whole-container sign+low-byte mask on age (armed AND due). */
    action set_expired()  { meta.expired = 8w1; }
    action set_live()     { meta.expired = 8w0; }
    table tbl_expiry {
        key = { meta.age_dl : ternary; }
        actions = { set_expired; set_live; }
        const default_action = set_live();
        const entries = { (32w0x00000000 &&& 32w0x800000FF) : set_expired(); }
        size = 2;
    }

    /* §4.3/§4.5: native match verdict, keyed on {role, flow-diff==0, id-conjunct==0, ready, fo}.
     * flow_diff and id_diff are pre-tested to 1-bit "zero?" flags in metadata to keep the key
     * narrow. Produces the hold/forward/retire decision for the native ACK / RESPONSE. */
    action nd_ack_hold()   { to_ack_hold();  meta.ctr_idx = C_ACK_HOLD; }
    action nd_ack_fwd()    { to_fwd();        meta.ctr_idx = C_ACK_FWD;  }
    action nd_resp_hold()  {                  /* held: shim + Q_RESP_HOLD; retire on completion */
        hdr.shim.setValid();
        hdr.shim.dst = 48w0; hdr.shim.src = 48w0;
        hdr.shim.etype = ETHERTYPE_HELD_RESP; hdr.shim.gen = meta.cur_gen_conf;
        ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_RESP_HOLD; ig_tm_md.bypass_egress = 1w1;
        meta.ctr_idx = C_RESP_HOLD;
    }
    action nd_resp_retire() {                 /* forwarded RESP (fail-open/bypass): shim -> retire */
        hdr.shim.setValid();
        hdr.shim.dst = 48w0; hdr.shim.src = 48w0;
        hdr.shim.etype = ETHERTYPE_HELD_RESP; hdr.shim.gen = meta.cur_gen_conf;
        ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = Q_ACK_BLOCK; ig_tm_md.bypass_egress = 1w1;
        meta.ctr_idx = C_RESP_RETIRE;
    }
    table tbl_native_decide {
        key = { meta.role : exact; meta.mode : exact; meta.match_ok : exact; meta.ready : exact; meta.fo_eq : exact; }
        actions = { nd_ack_hold; nd_ack_fwd; nd_resp_hold; nd_resp_retire; }
        const default_action = nd_ack_fwd();
        const entries = {
            /* ACK: OFF forwards; D1/D2/D3/D4 hold on Q_ACK_HOLD when matching+ready+!fo; else fwd */
            (ROLE_ACK,  MODE_OFF,     8w1, 8w1, 1w0) : nd_ack_fwd();
            (ROLE_ACK,  MODE_D1_EVENT,8w1, 8w1, 1w0) : nd_ack_hold();
            (ROLE_ACK,  MODE_D2_RESP, 8w1, 8w1, 1w0) : nd_ack_hold();
            (ROLE_ACK,  MODE_D3_ACK,  8w1, 8w1, 1w0) : nd_ack_hold();
            (ROLE_ACK,  MODE_D4_DUAL, 8w1, 8w1, 1w0) : nd_ack_hold();
            /* RESP: OFF/not-matching forward; protected modes hold when matching+ready+!fo; else
             * retire-shim (fail-open forward that also clears the active transaction). */
            (ROLE_RESP, MODE_OFF,     8w1, 8w1, 1w0) : nd_resp_retire();
            (ROLE_RESP, MODE_D1_EVENT,8w1, 8w1, 1w0) : nd_resp_hold();
            (ROLE_RESP, MODE_D2_RESP, 8w1, 8w1, 1w0) : nd_resp_hold();
            (ROLE_RESP, MODE_D3_ACK,  8w1, 8w1, 1w0) : nd_resp_hold();
            (ROLE_RESP, MODE_D4_DUAL, 8w1, 8w1, 1w0) : nd_resp_hold();
        }
        size = 32;
    }

    apply {
        if (meta.port_ok == 8w0) {
            drop_pkt(); meta.ctr_idx = C_BAD_PORT;
        } else {
          /* ---- timestamp / now_word (frozen idiom): mask (one op) then | ARMED (tbl_arm_now).
           * Use ingress_mac_tstamp (fresh per loopback pass); global_tstamp is stale on recirc. ---- */
          meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
          tbl_arm_now.apply();

          /* ===== single reg_txn access per path, at the TOP (v5) ===== */
          if (meta.role == ROLE_ARM && meta.from_out == 8w0) {
              meta.txn_old = txn_open.execute(1w0);
          } else if (meta.role == ROLE_RESP && meta.is_loop == 8w1) {
              meta.txn_old = txn_complete.execute(1w0);
          } else if (meta.role == ROLE_CLEANUP) {
              meta.txn_old = txn_clear_fin.execute(1w0);
          } else {
              meta.txn_old = txn_read.execute(1w0);
          }
          meta.cur_gen      = (bit<32>)meta.txn_old[30:0];
          meta.cur_gen_conf = meta.txn_old | CONF_BIT;
          meta.active       = (bit<8>)meta.txn_old[31:31];

          /* ---- params + flow fingerprint + deadline/matching arithmetic (parallel front) ---- */
          tbl_params.apply();
          tbl_fold.apply();
          tbl_flow_fp.apply();
          tbl_build_ta.apply();
          tbl_exp_cand.apply();
          tbl_seq_w.apply();

          if (meta.role == ROLE_TOKEN) {
            if (meta.is_first == 8w1) {
                /* ===== §4.3/§4.10 PKTGEN ADMIT (staged, role-split) ===== */
                meta.token_id = (bit<16>)hdr.timer.packet_id;
                tbl_app_role.apply();
                tbl_tokid_valid.apply();
                if (meta.active == 8w0) {
                    drop_pkt(); meta.ctr_idx = C_SEED_DROP;         /* inactive -> no seeding */
                } else if (meta.tok_valid == 8w1) {
                    if (meta.role_bit == 1w1) {
                        meta.ident_res = ident_resp_seed.execute(meta.token_id[5:0]);
                        if (meta.ident_res == R_SEEDED) {
                            admit_stamp(); to_resp_block(); meta.ctr_idx = C_SEED_NEW;
                        } else { drop_pkt(); meta.ctr_idx = C_SEED_DROP; }
                    } else {
                        meta.stage_val = stage_read.execute(1w0);   /* RESP-first staging gate */
                        if (meta.stage_val == K_TOKENS) {
                            meta.ident_res = ident_ack_seed.execute(meta.token_id[5:0]);
                            if (meta.ident_res == R_SEEDED) {
                                admit_stamp(); to_ack_block(); meta.ctr_idx = C_SEED_NEW;
                            } else { drop_pkt(); meta.ctr_idx = C_SEED_DROP; }
                        } else {
                            drop_pkt(); meta.ctr_idx = C_SEED_DROP;
                        }
                    }
                } else {
                    drop_pkt(); meta.ctr_idx = C_SEED_DROP;
                }
            } else if (meta.is_loop == 8w1) {
                /* ===== §4 LOOPBACK BLOCKER TOKEN: confirm (establish) then deadline release ===== */
                tbl_token_valid.apply();
                if (meta.active == 8w0) {
                    drop_pkt(); meta.ctr_idx = C_TOK_TERM;           /* inactive -> drain */
                } else if (meta.tok_valid == 8w1) {
                    if (hdr.token.generation == meta.cur_gen) {
                        /* establishment confirm (idempotent, gen-qualified) */
                        if (meta.role_bit == 1w1) {
                            meta.ident_res = ident_resp_confirm.execute(hdr.token.token_id[5:0]);
                            if (meta.ident_res == R_FIRST) {
                                meta.stage_val  = stage_incr.execute(1w0);
                                meta.pop_delta  = DELTA_RESP_UP;
                                meta.pop_packed = pop_incr.execute(1w0);
                            }
                            /* RESP-block: T_RESP = T_A + D_R  =>  age_resp = age(T_A) - D_R */
                            meta.age_dl = dl_age.execute(1w0);
                            meta.age_dl = meta.age_dl - meta.d_r;
                        } else {
                            meta.ident_res = ident_ack_confirm.execute(hdr.token.token_id[5:0]);
                            if (meta.ident_res == R_FIRST) {
                                meta.pop_delta  = DELTA_ACK_UP;
                                meta.pop_packed = pop_incr.execute(1w0);
                            }
                            meta.age_dl = dl_age.execute(1w0);        /* ACK deadline (T_A) */
                        }
                        tbl_expiry.apply();
                        /* §4.5: commitment/event flags gate the RESP reservoir's release.
                         *   ACK-block token  terminates on  expired(T_A)              OR (D1 event)
                         *   RESP-block token terminates on (expired(T_RESP) OR D1 event) AND ackc
                         * §4.7: budget-zero -> fail-open watchdog (note gen-qualified + drain). */
                        meta.flags_val = flags_read.execute(1w0);
                        if (hdr.token.budget == 32w0) { meta.budget_zero = 8w1; }
                        if (meta.budget_zero == 8w1) {
                            failopen_note.execute(1w0);
                            drop_pkt(); meta.ctr_idx = C_TOK_FAILOPEN;
                        } else if (meta.role_bit == 1w1) {
                            /* RESP-block: release only after the ACK has committed (§4.5) */
                            if (meta.flags_val[0:0] == 1w1 &&
                                (meta.expired == 8w1 ||
                                 (meta.mode == MODE_D1_EVENT && meta.flags_val[1:1] == 1w1))) {
                                drop_pkt(); meta.ctr_idx = C_TOK_TERM;
                            } else {
                                hdr.token.budget = hdr.token.budget - 32w1;
                                to_resp_block(); meta.ctr_idx = C_TOK_LOOP;
                            }
                        } else {
                            /* ACK-block: release at the ACK deadline or the D1 event */
                            if (meta.expired == 8w1 ||
                                (meta.mode == MODE_D1_EVENT && meta.flags_val[1:1] == 1w1)) {
                                drop_pkt(); meta.ctr_idx = C_TOK_TERM;
                            } else {
                                hdr.token.budget = hdr.token.budget - 32w1;
                                to_ack_block(); meta.ctr_idx = C_TOK_LOOP;
                            }
                        }
                    } else {
                        drop_pkt(); meta.ctr_idx = C_TOK_TERM;        /* stale gen: no cell touch */
                    }
                } else {
                    drop_pkt(); meta.ctr_idx = C_TOK_TERM;
                }
            } else {
                drop_pkt(); meta.ctr_idx = C_TOK_TERM;
            }
          } else if (meta.role == ROLE_ARM && meta.from_out == 8w0) {
            /* ===== master-side READ: reset ALL state ONLY on a fresh open (v5 + §4) ===== */
            if (meta.active == 8w0) {
                stage_reset.execute(1w0);
                pop_reset.execute(1w0);
                failopen_reset.execute(1w0);
                flags_reset.execute(1w0);
                dl_disarm.execute(1w0);
                fp_claim.execute(1w0);                    /* claim this flow */
                exp_ack_w.execute(1w0);                   /* install EXP_ACK  */
                exp_seq_w.execute(1w0);                   /* install EXP_RELAY_SEQ */
                meta.ctr_idx = C_ARM_FRESH;
            } else {
                meta.ctr_idx = C_ARM_OVERLAP;             /* overlap: leave ALL state unchanged */
            }
            to_fwd();
          } else if (meta.role == ROLE_CLEANUP) {
            to_fwd(); meta.ctr_idx = C_CLEANUP;           /* FIN/RST active cleared above */
          } else if (meta.role == ROLE_RESP && meta.is_loop == 8w1) {
            /* ===== held-RESP completion / fail-open-retire (loopback): reg_txn cleared above ===== */
            if (meta.txn_old == meta.shim_gen_active) {
                meta.ctr_idx = C_RESP_RETIRE;
            } else {
                meta.ctr_idx = C_RESP_STALE;
            }
            hdr.shim.setInvalid();                        /* STRIP shim -> byte-identical RESP */
            to_fwd();
          } else if (meta.role == ROLE_ACK && meta.is_loop == 8w1) {
            /* ===== held ACK release: commit to master FIFO (§4.5 ack_committed) ===== */
            flags_set_ackc.execute(1w0);
            to_fwd(); meta.ctr_idx = C_ACK_COMMIT;
          } else if ((meta.role == ROLE_ACK || meta.role == ROLE_RESP) && meta.from_out == 8w1) {
            /* ===== native ACK / RESPONSE (from the relay side) =====
             * All matching-register reads run at ONE uniform depth (co-locatable with the ARM-side
             * writes): both expected-value cells are read side-effect-free on every native packet;
             * only the role-appropriate residual is then used. */
            meta.pop_packed = pop_read.execute(1w0);
            if (meta.pop_packed == BOTH_READY && meta.active == 8w1) { meta.ready = 8w1; }
            meta.fo_eq = (bit<1>)failopen_rmw.execute(1w0);   /* latch if !ready; gen-qualified */
            meta.fp_diff      = fp_check.execute(1w0);        /* flow fingerprint (both roles) */
            meta.exp_ack_diff = exp_ack_r.execute(1w0);       /* ACK conjunct  (read always) */
            meta.exp_seq_diff = exp_seq_r.execute(1w0);       /* RESP conjunct (read always) */
            if (meta.role == ROLE_ACK) {
                meta.match_resid = (bit<32>)meta.fp_diff | meta.exp_ack_diff;
            } else {
                meta.match_resid = (bit<32>)meta.fp_diff | meta.exp_seq_diff;
            }
            if (meta.match_resid == 32w0) { meta.match_ok = 8w1; }
            /* §4.2 single arm at native ACK: arm T_A (arm-once). T_RESP = T_A + D_R is derived by
             * the RESP-block token, so one arm covers both deadlines. §4.4/§4.5: a matching RESP
             * records response_present / the D1 event (it does NOT arm — it waits for the ACK). */
            if (meta.role == ROLE_ACK) {
                if (meta.match_ok == 8w1 && meta.ready == 8w1) { dl_arm.execute(1w0); }
            } else {
                if (meta.match_ok == 8w1) { flags_set_resp.execute(1w0); }
            }
            tbl_native_decide.apply();
          } else if (meta.is_first == 8w1) {
            drop_pkt(); meta.ctr_idx = C_SEED_DROP;
          } else {
            to_fwd(); meta.ctr_idx = C_FWD;
          }
        }
        ctr.count(meta.ctr_idx);
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

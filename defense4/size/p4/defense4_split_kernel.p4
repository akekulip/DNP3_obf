/* ============================================================================
 * defense4_split_kernel.p4 — Defense 4 SIZE compile-probe: DNP3 PAD (grow to a
 *   shared block-aligned target) + fixed 2-way SPLIT (re-segment on a DNP3
 *   CRC-block boundary) composed on the Case-A timing core. Tofino-1 / TNA.
 *   COMPILE PROBE (software/model only — NOT silicon-validated).
 *
 * SIBLING of defense4/size/p4/defense4_cover_kernel.p4. The INGRESS (Case-A
 *   unified timing core) + its parser + deparser + all ingress constants,
 *   headers and metadata are copied VERBATIM from defense4_cover_kernel.p4
 *   (lines 46-130 and 212-638), byte-identical, NOT modified here. Only the
 *   EGRESS (a lean PAD + 2-way SPLIT size layer) and the egress-facing headers
 *   are new. The shipped cover kernel's egress is 12/12 full (it carries the
 *   V1->V3 canonicalizer), so SPLIT is a sibling kernel, not a patch.
 *
 * Reference model: defense4/size/readsbo_normalizer/readsbo_normalizer.py.
 * See the EGRESS banner below for the mechanism, the fail-open policy, the
 * compile-only replication caveat, and the deferred boundary-block / O2 hooks.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes / protocols ---- */
const bit<16> ETYPE_TOKEN = 0x88C1;    /* internal blocker-token frame (loopback only) */
const bit<16> ETYPE_IPV4  = 0x0800;
const bit<8>  IP_PROTO_TCP = 8w6;

/* ---- DNP3 function codes ---- */
const bit<16> DNP3_START     = 0x0564;
const bit<8>  DNP3_FC_READ   = 8w1;
const bit<8>  DNP3_FC_SELECT = 8w3;
const bit<8>  DNP3_FC_OPERATE = 8w4;
const bit<8>  DNP3_FC_RESP    = 8w129;

/* ---- roles ---- */
const bit<8> ROLE_BYPASS  = 0;
const bit<8> ROLE_TOKEN   = 1;   /* internal blocker token (ACK or RESP reservoir) */
const bit<8> ROLE_RESP    = 2;   /* DNP3 RESPONSE (queue-resident) */
const bit<8> ROLE_SELECT  = 3;
const bit<8> ROLE_OPERATE = 4;
const bit<8> ROLE_ARM     = 6;   /* eligible request that opens a transaction (READ/SELECT) */
const bit<8> ROLE_ACK     = 7;   /* pure TCP ACK (queue-resident) */

const bit<8> DIR_MASTER = 0;
const bit<8> DIR_OUT    = 1;

/* ---- ports (single loopback scheduler domain; front-panel roles are control-plane wired) ---- */
const PortId_t PORT_L      = 9w8;    /* internal loopback (token recirculation) */
const PortId_t PORT_MASTER = 9w9;
const PortId_t PORT_RELAY  = 9w64;
const PortId_t PORT_PGEN   = 9w68;

/* ---- four queues: qid AND max_priority are configured separately (control plane) ---- */
const bit<5> QID_ACK_BLOCK = 5w7;
const bit<5> QID_ACK_HOLD  = 5w6;
const bit<5> QID_RESP_BLOCK = 5w5;
const bit<5> QID_RESP_HOLD  = 5w4;

/* ---- token-role tag on the internal blocker token ---- */
const bit<8> TOK_ACK  = 8w1;
const bit<8> TOK_RESP = 8w2;

/* ---- release modes (params) ---- */
const bit<8> MODE_OFF       = 8w0;
const bit<8> MODE_D1_EVENT  = 8w1;
const bit<8> MODE_D2_RESP   = 8w2;   /* D2_RESPONSE_DEADLINE */
const bit<8> MODE_D3_ACK    = 8w3;   /* D3_ACK_DEADLINE      */
const bit<8> MODE_D4_DUAL   = 8w4;   /* D4_DUAL_DEADLINE     */
const bit<8> MODE_FAIL_OPEN = 8w5;   /* safety transition (test-only external trigger) */

const bit<8> REL_HOLD    = 8w0;
const bit<8> REL_RELEASE = 8w1;

/* ---- packed 32-bit deadline word: bit0 = ARMED marker; comparison masks the low byte ---- */
const bit<32> TICK_MASK   = 32w0xFFFFFF00;
const bit<32> ARMED_MARK  = 32w0x00000001;
const bit<32> UNARMED     = 32w0x00000002;
const bit<32> DL_NO_WRITE = 32w0;
const bit<32> INITIAL_BUDGET = 32w100000;
const bit<8>  TAG_NO_WRITE = 8w0;
const bit<8>  TAG_INACTIVE = 8w0xFF;

/* horizon clamp is a control-plane property (< 2^31 ticks) — documented in TIMING_SPEC §8. */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
/* internal blocker token: role(ACK/RESP) + generation + per-token pass budget. Loopback only;
 * the deparser NEVER emits this toward a master/relay port. */
header token_h { bit<8> trole; bit<8> gen; bit<32> budget; }
header ipv4_h {
    bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> total_len;
    bit<16> id; bit<3> flags; bit<13> frag; bit<8> ttl; bit<8> proto;
    bit<16> csum; bit<32> src; bit<32> dst;
}
header tcp_h {
    bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack;
    bit<4> dofs; bit<4> res; bit<8> flags; bit<16> win; bit<16> csum; bit<16> urg;
}
header tcp_opt4_h  { bit<32> data; }
header tcp_opt8_h  { bit<64> data; }
header tcp_opt12_h { bit<96> data; }
header dnp3_dl_h { bit<16> start; bit<8> len; bit<8> ctrl; bit<16> dst; bit<16> src; bit<16> crc; }
header dnp3_tp_h  { bit<8> tp; }
header dnp3_app_h { bit<8> app_ctrl; bit<8> func; }

/* ---- egress size-layer headers (parsed DNP3 data blocks + appended filler).
 *      Egress-only: the ingress never parses or emits these. The normalized
 *      target is bounded to 3 full 18-byte blocks by the Tofino egress parser
 *      depth (160 B): eth+ip+tcp+dl+3*blk = 118 B path; a 5-block frame overran
 *      it at 181 B. Larger targets need a shallower L2/L4 parse or a residual/
 *      truncation split (see report). ---- */
header pay18_h { bit<144> b; }   /* one 18-byte DNP3 CRC block (16 user + 2 CRC) */

struct headers_t {
    ethernet_h  eth;
    token_h     tok;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt4_h  o4;
    tcp_opt8_h  o8;
    tcp_opt12_h o12;
    dnp3_dl_h   dl;
    dnp3_tp_h   tp;
    dnp3_app_h  app;
    /* egress size layer: up to 3 parsed data blocks + up to 2 filler blocks */
    pay18_h     blk0;
    pay18_h     blk1;
    pay18_h     blk2;
    pay18_h     fill0;
    pay18_h     fill1;
}
struct ig_meta_t {
    bit<8>  role;
    bit<8>  dir;
    bit<9>  fwd_port;
    bit<8>  port_ok;
    bit<8>  from_loop;        /* arrived on the loopback (a returning token) */
    bit<32> ts_now;           /* ingress mac timestamp, low 32, masked + ARMED */
    /* canonical bidirectional flow identity: direction-normalized (master-side, relay-side) tuple */
    bit<32> nm_ip;            /* master-side IP  (src if from master, dst if from relay/loop) */
    bit<32> nr_ip;            /* relay-side  IP */
    bit<16> nm_pt;            /* master-side port */
    bit<16> nr_pt;            /* relay-side  port */
    bit<16> flow_wide;
    bit<10> flow_idx;
    bit<16> fp_wide;          /* collision fingerprint */
    bit<16> fp_diff;          /* fp_check XOR result (0 == owner match) */
    bit<8>  collision;
    /* generation + admission */
    bit<8>  gen_in;
    bit<8>  gen_cur;
    bit<8>  tag_diff;
    bit<8>  tag_val;
    bit<8>  admit_ok;
    /* params */
    bit<8>  mode;
    bit<32> d_a;              /* D_A ticks */
    bit<32> d_r;              /* D_R ticks */
    /* deadline surface */
    bit<32> t_a;             /* T_A = t_A + D_A (armed on ACK) */
    bit<32> t_resp;          /* T_RESP = T_A + D_R */
    bit<32> dl_write;        /* value to arm into reg_deadline */
    bit<32> age;             /* now - deadline (sign bit => expired) */
    bit<8>  expired;
    bit<8>  budget_zero;
    /* commitment / presence / event */
    bit<8>  ack_committed;
    bit<8>  response_present;
    bit<8>  predecessor_satisfied;
    bit<8>  event_due;       /* D1: matching RESPONSE observed */
    bit<8>  release;
    /* token */
    bit<8>  tok_role;
    bit<8>  is_token;
    bit<3>  ctr_idx;         /* consolidated correctness-counter index (single access point) */
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t m,
                out ingress_intrinsic_metadata_t ig) {
    state start {
        pkt.extract(ig);
        pkt.advance(PORT_METADATA_SIZE);
        /* dir / fwd_port / port_ok / from_loop are set ONLY in the per-path states below
         * (Tofino forbids re-assigning a start-initialized field). */
        m.role = ROLE_BYPASS; m.ts_now = 32w0;
        m.nm_ip = 32w0; m.nr_ip = 32w0; m.nm_pt = 16w0; m.nr_pt = 16w0; m.flow_wide = 16w0; m.flow_idx = 10w0;
        m.fp_wide = 16w0; m.fp_diff = 16w0; m.collision = 8w0;
        m.gen_in = 8w0; m.gen_cur = 8w0; m.tag_diff = 8w0; m.tag_val = TAG_NO_WRITE; m.admit_ok = 8w0;
        m.mode = MODE_OFF; m.d_a = 32w0; m.d_r = 32w0;
        m.t_a = 32w0; m.t_resp = 32w0; m.dl_write = DL_NO_WRITE; m.age = 32w0;
        m.expired = 8w0; m.budget_zero = 8w0;
        m.ack_committed = 8w0; m.response_present = 8w0; m.predecessor_satisfied = 8w0;
        m.event_due = 8w0; m.release = REL_HOLD; m.tok_role = 8w0; m.is_token = 8w0; m.ctr_idx = 3w0;
        transition select(ig.ingress_port) {
            PORT_L      : from_loop;
            PORT_MASTER : from_master;
            PORT_RELAY  : from_relay;
            default     : unclassified;
        }
    }
    state unclassified { m.port_ok = 8w0; m.dir = DIR_OUT; m.fwd_port = PORT_MASTER; m.from_loop = 8w0; transition accept; }
    state from_loop   { m.from_loop = 8w1; m.dir = DIR_OUT;    m.fwd_port = PORT_MASTER; m.port_ok = 8w1; transition parse_eth; }
    state from_master { m.from_loop = 8w0; m.dir = DIR_MASTER; m.fwd_port = PORT_RELAY;  m.port_ok = 8w1; transition parse_eth; }
    state from_relay  { m.from_loop = 8w0; m.dir = DIR_OUT;    m.fwd_port = PORT_MASTER; m.port_ok = 8w1; transition parse_eth; }

    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETYPE_TOKEN : parse_token;
            ETYPE_IPV4  : parse_ipv4;
            default     : accept;
        }
    }
    state parse_token {
        pkt.extract(hdr.tok);
        m.role = ROLE_TOKEN; m.is_token = 8w1; m.tok_role = hdr.tok.trole; m.gen_in = hdr.tok.gen;
        transition accept;
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.proto, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;
            default             : accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.flags, hdr.tcp.dofs, hdr.ipv4.total_len) {
            (8w0x10 &&& 8w0x17, 4w5,  16w40) : role_ack;
            (8w0x10 &&& 8w0x17, 4w8,  16w52) : role_ack;
            (8w0x10 &&& 8w0x17, 4w11, 16w64) : role_ack;
            (8w0x00 &&& 8w0x07, 4w5,  16w53 .. 16w65535) : parse_dl;
            (8w0x00 &&& 8w0x07, 4w8,  16w65 .. 16w65535) : opt12;
            default : accept;
        }
    }
    state opt12 { pkt.extract(hdr.o12); transition parse_dl; }
    state role_ack { m.role = ROLE_ACK; transition accept; }
    state parse_dl {
        pkt.extract(hdr.dl);
        transition select(hdr.dl.start, hdr.dl.len) {
            (DNP3_START, 8w8 .. 8w255) : parse_tp;
            default : accept;
        }
    }
    state parse_tp { pkt.extract(hdr.tp); transition parse_app; }
    state parse_app {
        pkt.extract(hdr.app);
        transition select(hdr.app.func) {
            DNP3_FC_RESP    : r_resp;
            DNP3_FC_READ    : r_arm;
            DNP3_FC_SELECT  : r_select;
            DNP3_FC_OPERATE : r_operate;
            default : accept;
        }
    }
    state r_resp    { m.role = ROLE_RESP;    transition accept; }
    state r_arm     { m.role = ROLE_ARM;     transition accept; }
    state r_select  { m.role = ROLE_SELECT;  transition accept; }
    state r_operate { m.role = ROLE_OPERATE; transition accept; }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr, inout ig_meta_t m,
                in ingress_intrinsic_metadata_t ig,
                in ingress_intrinsic_metadata_from_parser_t prsr,
                inout ingress_intrinsic_metadata_for_deparser_t dprsr,
                inout ingress_intrinsic_metadata_for_tm_t tm) {

    /* ===== reg_tag: internal per-transaction GENERATION + liveness ===== */
    Register<bit<8>, bit<10>>(1024, 0) reg_tag;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_open = {   /* request opens: bump generation */
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_get = {    /* token/passive read */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_match = {  /* liveness: 0 iff same generation */
        void apply(inout bit<8> v, out bit<8> rv) { rv = m.gen_in - v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_clear = {  /* FIN/RST/cleanup retire */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; if (m.tag_val != TAG_NO_WRITE) { v = TAG_INACTIVE; } }
    };

    /* ===== reg_fp: collision-guard fingerprint (canonical tuple) ===== */
    Register<bit<16>, bit<10>>(1024, 0) reg_fp;
    RegisterAction<bit<16>, bit<10>, bit<16>>(reg_fp) fp_claim = {  /* opener takes ownership */
        void apply(inout bit<16> v, out bit<16> rv) { v = m.fp_wide; rv = 16w0; }
    };
    RegisterAction<bit<16>, bit<10>, bit<16>>(reg_fp) fp_check = {  /* others verify: nonzero => collision */
        void apply(inout bit<16> v, out bit<16> rv) { rv = v ^ m.fp_wide; }
    };

    /* ===== reg_deadline: T_A / T_RESP arm (ACK-armed, NOT request-armed) ===== */
    Register<bit<32>, bit<10>>(1024, 0) reg_deadline;
    /* ONE reg_deadline access per packet: returns age = now - deadline, and writes dl_write when set
     * (dl_write = UNARMED on a request reset, T_A/T_RESP on the arming ACK/RESPONSE, DL_NO_WRITE for a
     * passive token read). Subsumes the former separate clear/age actions (single access point). */
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_deadline) dl_arm = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = m.ts_now - v; if (m.dl_write != DL_NO_WRITE) { v = m.dl_write; } }
    };

    /* ===== reg_ackc: ack_committed_to_master flag ===== */
    Register<bit<8>, bit<10>>(1024, 0) reg_ackc;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ackc) ackc_set = {   /* set on ACK loopback commit */
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w1; rv = 8w1; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ackc) ackc_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ackc) ackc_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = 8w0; }
    };

    /* ===== reg_resp: response_present flag ===== */
    Register<bit<8>, bit<10>>(1024, 0) reg_resp;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_resp) resp_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w1; rv = 8w1; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_resp) resp_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_resp) resp_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = 8w0; }
    };

    /* ===== reg_event: D1 matching-RESPONSE event ===== */
    Register<bit<8>, bit<10>>(1024, 0) reg_event;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_event) ev_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w1; rv = 8w1; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_event) ev_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* ===== lightweight correctness counters ===== */
    Counter<bit<64>, bit<3>>(6, CounterType_t.PACKETS) ctr;   /* [fwd, ack_commit, resp_release, token_loop, token_term, failopen] */

    /* ---- TM actions ---- */
    action to_fwd()       { tm.ucast_egress_port = m.fwd_port; tm.qid = 5w0; tm.bypass_egress = 1w0; }
    action to_ack_hold()  { tm.ucast_egress_port = PORT_L; tm.qid = QID_ACK_HOLD;  tm.bypass_egress = 1w1; }
    action to_resp_hold() { tm.ucast_egress_port = PORT_L; tm.qid = QID_RESP_HOLD; tm.bypass_egress = 1w1; }
    action to_ack_block() { tm.ucast_egress_port = PORT_L; tm.qid = QID_ACK_BLOCK; tm.bypass_egress = 1w1; }
    action to_resp_block(){ tm.ucast_egress_port = PORT_L; tm.qid = QID_RESP_BLOCK; tm.bypass_egress = 1w1; }
    action drop_pkt()     { dprsr.drop_ctl = 3w1; }

    /* ---- canonical bidirectional flow key ----
     * Direction-normalize the 4-tuple to (master-side endpoint, relay-side endpoint) using dir, then
     * hash the fixed normalized field list. Both directions of a flow yield the SAME normalized tuple,
     * so the same flow index + fingerprint. Two Hash instances, each with ONE fixed field list. */
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_flow;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_fp;
    action fold_master() { m.nm_ip = hdr.ipv4.src; m.nm_pt = hdr.tcp.sport; m.nr_ip = hdr.ipv4.dst; m.nr_pt = hdr.tcp.dport; }
    action fold_out()    { m.nm_ip = hdr.ipv4.dst; m.nm_pt = hdr.tcp.dport; m.nr_ip = hdr.ipv4.src; m.nr_pt = hdr.tcp.sport; }
    table tbl_fold {
        key = { m.dir : exact; }
        actions = { fold_master; fold_out; }
        const default_action = fold_master();
        const entries = { (DIR_OUT) : fold_out(); }
        size = 2;
    }
    action do_flow_idx() { m.flow_wide = h_flow.get({ m.nm_ip, m.nm_pt, m.nr_ip, m.nr_pt }); }
    table tbl_flow_idx { actions = { do_flow_idx; } const default_action = do_flow_idx(); size = 1; }
    action do_fp() { m.fp_wide = h_fp.get({ m.nm_ip, m.nm_pt, m.nr_ip, m.nr_pt }); }
    table tbl_fp { actions = { do_fp; } const default_action = do_fp(); size = 1; }
    action cut_idx() { m.flow_idx = m.flow_wide[9:0]; }
    table tbl_cut { actions = { cut_idx; } const default_action = cut_idx(); size = 1; }

    /* ---- params: mode + D_A + D_R ---- */
    action set_params(bit<8> mode, bit<32> d_a, bit<32> d_r) { m.mode = mode; m.d_a = d_a; m.d_r = d_r; }
    table tbl_params {
        key = { m.role : exact; m.dir : exact; }
        actions = { set_params; }
        default_action = set_params(MODE_OFF, 32w0, 32w0);
        size = 32;
    }

    /* ---- build T_A then T_RESP (each in its own single-action table) ---- */
    action build_ta()   { m.t_a = m.ts_now + m.d_a; }
    table tbl_build_ta   { actions = { build_ta; }   const default_action = build_ta();   size = 1; }
    action build_tresp() { m.t_resp = m.t_a + m.d_r; }
    table tbl_build_tresp{ actions = { build_tresp; } const default_action = build_tresp(); size = 1; }

    /* ---- pick the deadline to arm on the ACK: D3/D4 arm T_A on the ACK queue; the RESP deadline
     *      is armed on the RESPONSE side. Here the ACK arms its own hold deadline. ---- */
    action arm_ta()   { m.dl_write = m.t_a; }
    action arm_tresp(){ m.dl_write = m.t_resp; }
    action arm_none() { m.dl_write = DL_NO_WRITE; }
    table tbl_arm_select {
        key = { m.role : exact; m.mode : exact; }
        actions = { arm_ta; arm_tresp; arm_none; }
        const default_action = arm_none();
        const entries = {
            (ROLE_ACK,  MODE_D3_ACK)  : arm_ta();
            (ROLE_ACK,  MODE_D4_DUAL) : arm_ta();
            (ROLE_RESP, MODE_D2_RESP) : arm_tresp();
            (ROLE_RESP, MODE_D4_DUAL) : arm_tresp();
        }
        size = 16;
    }

    /* ---- expiry: sign bit of (now - deadline) over the whole 32-bit container ---- */
    action set_expired()  { m.expired = 8w1; }
    action set_live()     { m.expired = 8w0; }
    table tbl_expiry {
        key = { m.age : ternary; }
        actions = { set_expired; set_live; }
        const default_action = set_live();
        const entries = { (32w0x00000000 &&& 32w0x800000FF) : set_expired(); }
        size = 2;
    }

    /* ---- predecessor_satisfied: separate-ACK => ack_committed; combined-response => true (§10) ---- */
    action pred_from_commit() { m.predecessor_satisfied = m.ack_committed; }
    action pred_true()        { m.predecessor_satisfied = 8w1; }
    table tbl_predecessor {
        key = { m.role : exact; }
        actions = { pred_from_commit; pred_true; }
        const default_action = pred_from_commit();
        size = 4;
    }

    /* ---- collision detect: nonzero fingerprint XOR => a different flow owns this index ---- */
    /* set the ARMED marker bit on the masked timestamp (single-op table; TNA one-op-per-action) */
    action arm_now() { m.ts_now = m.ts_now | ARMED_MARK; }
    table tbl_arm_now { actions = { arm_now; } const default_action = arm_now(); size = 1; }

    action collision_no()  { m.collision = 8w0; }
    action collision_yes() { m.collision = 8w1; }
    table tbl_collision {
        key = { m.fp_diff : ternary; }
        actions = { collision_no; collision_yes; }
        const default_action = collision_yes();
        const entries = { (16w0 &&& 16w0xFFFF) : collision_no(); }
        size = 2;
    }

    /* ---- RESPONSE release predicate (§4): keyed on the four booleans ---- */
    action do_release() { m.release = REL_RELEASE; }
    action do_hold()    { m.release = REL_HOLD; }
    table tbl_release {
        key = {
            m.mode                 : exact;
            m.response_present      : ternary;
            m.predecessor_satisfied : ternary;
            m.expired               : ternary;
            m.event_due             : ternary;
            m.budget_zero           : ternary;
        }
        actions = { do_release; do_hold; }
        const default_action = do_hold();
        const entries = {
            /* deadline modes: response present AND predecessor satisfied AND now>=deadline */
            (MODE_D2_RESP, 8w1 &&& 8w1, 8w1 &&& 8w1, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            (MODE_D3_ACK,  8w1 &&& 8w1, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            (MODE_D4_DUAL, 8w1 &&& 8w1, 8w1 &&& 8w1, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            /* D1: response present AND predecessor satisfied AND event */
            (MODE_D1_EVENT,8w1 &&& 8w1, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0) : do_release();
            /* universal fail-open backstop: budget exhausted -> release under ANY mode */
            (MODE_D1_EVENT,8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w1 &&& 8w1) : do_release();
            (MODE_D2_RESP, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w1 &&& 8w1) : do_release();
            (MODE_D3_ACK,  8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w1 &&& 8w1) : do_release();
            (MODE_D4_DUAL, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w1 &&& 8w1) : do_release();
            (MODE_FAIL_OPEN,8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
        }
        size = 32;
    }

    apply {
        if (m.port_ok == 8w0) { drop_pkt(); return; }
        m.ts_now = ig.ingress_mac_tstamp[31:0] & TICK_MASK;   /* mask (one op) */
        tbl_arm_now.apply();                                  /* | ARMED_MARK (one op) */
        if (hdr.tok.budget == 32w0) { m.budget_zero = 8w1; }

        /* ---- flow identity (canonical bidirectional) + params ---- */
        tbl_fold.apply();
        tbl_flow_idx.apply();
        tbl_fp.apply();
        tbl_cut.apply();
        tbl_params.apply();
        tbl_build_ta.apply();
        tbl_build_tresp.apply();

        /* ---- deadline-write selection first (sets m.dl_write for the single reg_deadline access) ---- */
        tbl_arm_select.apply();                                    /* ACK->T_A, RESP->T_RESP (D2/D4) */
        if (m.role == ROLE_ARM || m.role == ROLE_SELECT) { m.dl_write = UNARMED; }  /* request resets */

        /* ---- register block: EACH register accessed at EXACTLY ONE point (role-selected) ---- */
        /* reg_tag: request bumps generation; token checks liveness; others read current generation */
        if (m.role == ROLE_ARM || m.role == ROLE_SELECT) { m.gen_cur = tag_open.execute(m.flow_idx); }
        else if (m.is_token == 8w1) { m.tag_diff = tag_match.execute(m.flow_idx); }
        else { m.gen_cur = tag_get.execute(m.flow_idx); }
        /* reg_fp: request claims ownership; non-token others verify; token skips */
        if (m.role == ROLE_ARM || m.role == ROLE_SELECT) { fp_claim.execute(m.flow_idx); }
        else if (m.is_token == 8w0) { m.fp_diff = fp_check.execute(m.flow_idx); }
        /* reg_deadline: single access (arm/reset/read-age) */
        m.age = dl_arm.execute(m.flow_idx);
        /* reg_ackc: ACK-from-loopback commits; request clears; others read */
        if (m.role == ROLE_ACK && m.from_loop == 8w1) { m.ack_committed = ackc_set.execute(m.flow_idx); }
        else if (m.role == ROLE_ARM || m.role == ROLE_SELECT) { ackc_clear.execute(m.flow_idx); }
        else { m.ack_committed = ackc_read.execute(m.flow_idx); }
        /* reg_resp: RESPONSE sets present; request clears; others read */
        if (m.role == ROLE_RESP && m.dir == DIR_OUT) { m.response_present = resp_set.execute(m.flow_idx); }
        else if (m.role == ROLE_ARM || m.role == ROLE_SELECT) { resp_clear.execute(m.flow_idx); }
        else { m.response_present = resp_read.execute(m.flow_idx); }
        /* reg_event (D1): RESPONSE posts the event; others read */
        if (m.role == ROLE_RESP && m.dir == DIR_OUT) { m.event_due = ev_set.execute(m.flow_idx); }
        else { m.event_due = ev_read.execute(m.flow_idx); }

        tbl_collision.apply();
        tbl_expiry.apply();
        tbl_predecessor.apply();
        tbl_release.apply();

        /* ---- ACT (single-exit; one consolidated counter access at the end) ---- */
        if (m.collision == 8w1) {                                       /* collision -> fail open */
            to_fwd(); m.ctr_idx = 3w5;
        } else if (m.is_token == 8w1) {
            /* blocker token: loop while live+unexpired+budget; else terminate (never egress out) */
            if (m.tag_diff != 8w0 || m.expired == 8w1 || m.budget_zero == 8w1) {
                drop_pkt(); m.ctr_idx = 3w4;
            } else {
                hdr.tok.budget = hdr.tok.budget - 32w1;
                if (m.tok_role == TOK_ACK) { to_ack_block(); } else { to_resp_block(); }
                m.ctr_idx = 3w3;
            }
        } else if (m.role == ROLE_ACK) {
            if (m.mode == MODE_D3_ACK || m.mode == MODE_D4_DUAL) {
                if (m.from_loop == 8w1) { to_fwd(); m.ctr_idx = 3w1; }  /* committed */
                else { to_ack_hold(); m.ctr_idx = 3w0; }
            } else { to_fwd(); m.ctr_idx = 3w0; }                       /* OFF/D2/D1: ACK immediate */
        } else if (m.role == ROLE_RESP) {
            if (m.release == REL_RELEASE) { to_fwd(); m.ctr_idx = 3w2; }/* release queue-resident RESPONSE */
            else { to_resp_hold(); m.ctr_idx = 3w0; }
        } else {
            to_fwd(); m.ctr_idx = 3w0;                                  /* requests + bypass forward */
        }
        ctr.count(m.ctr_idx);
    }
}

/* ============================ ingress deparser ========================== */
control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_meta_t m,
                   in ingress_intrinsic_metadata_for_deparser_t dprsr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.tok);      /* token only present on the internal loopback path */
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.o4);
        pkt.emit(hdr.o8);
        pkt.emit(hdr.o12);
        pkt.emit(hdr.dl);
        pkt.emit(hdr.tp);
        pkt.emit(hdr.app);
    }
}
/* ======================================================================== *
 *  EGRESS — Size Layer: DNP3 PAD (grow to block-aligned target) + fixed      *
 *  2-way SPLIT (CRC-block boundary) via mirror-to-multicast. Tofino-1 / TNA.  *
 *  COMPILE PROBE — sibling of defense4_cover_kernel.p4 (ingress VERBATIM).    *
 * ------------------------------------------------------------------------ *
 * Reference model: defense4/size/readsbo_normalizer/readsbo_normalizer.py
 *   (split_at_crc / pad_user_to / build_frame / crc_ok).
 *
 * DNP3 link framing (IEEE 1815 s9): 10-byte header block
 *   [05 64][LEN][CTRL][DEST 2 LE][SRC 2 LE][CRC 2 LE] then data blocks of
 *   <=16 user bytes + 2-byte block CRC (low byte first). A NORMALIZED frame
 *   is block-aligned: payload = 10 + 18*N, so every data block is a full 18 B.
 *   MVP target N = 3 blocks (payload 64, ip.total_len 104) — bounded by the
 *   egress parser depth (160 B).
 *
 * SPLIT (fixed 2-way, egress_rid-selected). The frozen ingress forwards the
 *   RESPONSE unicast to the master (egress_rid==0 = the SOURCE). On an eligible
 *   owner SPLIT flow the SOURCE emits the WHOLE frame, mirrors it to a 2-node
 *   multicast group (SPLIT_SESSION), and drops its own unicast copy (drop_ctl
 *   bit0). Each replica re-enters egress with egress_rid in {1,2}:
 *     rid==1 -> window0 = dl + blk0            (seq = base,      total_len 68)
 *     rid==2 -> window1 = blk1 + blk2          (seq = base + 28, total_len 76)
 *   Boundary 28 = 10 (header block) + 18 (blk0): a real DNP3 CRC-block boundary.
 *   Pure SPLIT is transport-STATELESS: join(windows) == frame, the master
 *   reassembles by seq, no ledger. IP/TCP checksums recomputed per window.
 *   NOTE (compile-only): the physical replication (mirror->mcast + drop-source)
 *   is COMPILE-verified here; its RUNTIME behavior needs silicon (see report).
 *
 * PAD (grow smaller response to the shared block-aligned target = 3 blocks/104 B).
 *   Appends (3-nblk) constant CRC-valid 0x00 filler blocks (block CRC over 16
 *   zero bytes = 0xFFFF, wire ff ff), rewrites the DNP3 header LEN (0x35) and
 *   recomputes the header-block DNP3 CRC via the native CRCPolynomial hash
 *   (poly 0x3D65 reflected, xorout 0xFFFF), and translates TCP seq/ack for the
 *   +Delta bytes with the single-insertion epoch (reg_pdelta/reg_pb0), exactly
 *   as the cover kernel does for its fixed insertion. Faithful to the reference
 *   for a BLOCK-ALIGNED real frame; a short trailing real block (mixed filler
 *   block) needs a per-flow boundary-block CRC and is DEFERRED (see report).
 *
 * FAIL-OPEN. Non-IPv4/non-TCP, IP options, fragments, TCP options (dofs>5),
 *   non-owner, or a payload that is not a clean 1..3 full-block DNP3 frame are
 *   passed NATIVE (original bytes + original checksum, no state touched).
 *
 * O2 request-direction parity-decoy injection is OUT of this MVP; it would hook
 *   as a master->outstation (DIR_MASTER) branch of t_policy, symmetric to PAD.
 * ======================================================================== */

/* ---- egress ports / classes ---- */
const bit<16> PORT_DNP3   = 16w20000;      /* outstation listen port -> DIR_OUT */

const bit<8> POL_NONE  = 8w0;
const bit<8> POL_PAD   = 8w1;
const bit<8> POL_SPLIT = 8w2;

const bit<32> PDELTA_CLOSED = 32w0;

/* normalized target: 3 full 18-byte blocks -> payload 64, ip.total_len 104 */
const bit<16> TLEN_1BLK = 16w68;
const bit<16> TLEN_2BLK = 16w86;
const bit<16> TLEN_3BLK = 16w104;          /* normalized / split input size    */
const bit<16> W0_TLEN   = 16w68;           /* window0 = 40 + dl(10) + blk0(18)  */
const bit<16> W1_TLEN   = 16w76;           /* window1 = 40 + 2*18(36)           */
const bit<32> W1_SEQOFF = 32w28;           /* window0 payload bytes = 10 + 18   */

/* filler data block: 16 user bytes = 0x00, block CRC-16/DNP over them = 0xFFFF
 * (wire ff ff). As a big-endian bit<144>: high 128 bits 0 (user), low 16 0xFFFF. */
const bit<144> FILL_BLOCK = 144w0xFFFF;
const bit<8>   DL_LEN_TGT  = 8w0x35;        /* LEN = 5 + 48 user bytes = 0x35    */

/* mirror plumbing */
typedef bit<10> mirror_sess_t;
const mirror_sess_t SPLIT_SESSION = 10w1;  /* CP: mirror -> mcast group {rid1,rid2} -> master */
const MirrorType_t  MIRR_SPLIT    = 3w1;

/* ============================= egress metadata ========================== */
struct eg_meta_t {
    bit<10> flow_idx;
    bit<32> nm_ip; bit<32> nr_ip; bit<16> nm_pt; bit<16> nr_pt;
    bit<16> flow_wide;
    bit<8>  dir;
    bit<8>  eligible;     /* IPv4/TCP, ihl==5, not fragmented, dofs==5           */
    bit<8>  has_opt;      /* dofs>5 (TCP options) on this packet                  */
    bit<8>  size_ok;      /* payload is a clean 1..3 full-block DNP3 frame        */
    bit<8>  is_ctl;       /* SYN/FIN/RST present                                  */
    bit<8>  is_syn; bit<8> is_rst;
    bit<8>  owner;        /* exact protected-flow match                           */
    bit<8>  policy;       /* POL_NONE / POL_PAD / POL_SPLIT                        */
    bit<3>  nblk;         /* number of data blocks parsed (1..3)                  */
    bit<16> rid;          /* egress_rid: 0 source, 1 window0, 2 window1           */
    bit<32> pad_add;      /* PAD: added wire bytes = (3-nblk)*18                   */
    bit<32> pdelta_old;   /* reg_pdelta before this packet (0 closed / pad_add)   */
    bit<32> pb0_old;      /* reg_pb0 before this packet (insertion boundary seq)  */
    bit<8>  is_fwd; bit<8> is_rev;
    bit<8>  open_req; bit<8> did_open;
    bit<32> d_seq; bit<32> a_diff; bit<32> seq_add; bit<32> ack_sub;
    mirror_sess_t mirror_session;
    bit<1>  translated;
    bit<16> tcp_len;
}

/* ============================== egress parser ===========================
 * Fail-closed gate, then parse the DNP3 link header + up to 3 full data blocks.
 * size_ok is set ONLY when ip.total_len equals a clean 1..3-block frame. */
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t m,
                out egress_intrinsic_metadata_t eg) {
    state start {
        pkt.extract(eg);
        m.flow_idx = 10w0; m.nm_ip = 32w0; m.nr_ip = 32w0; m.nm_pt = 16w0; m.nr_pt = 16w0;
        m.flow_wide = 16w0; m.dir = DIR_MASTER;
        m.eligible = 8w0; m.has_opt = 8w0; m.size_ok = 8w0;
        m.is_ctl = 8w0; m.is_syn = 8w0; m.is_rst = 8w0; m.owner = 8w0; m.policy = POL_NONE;
        m.nblk = 3w0; m.rid = 16w0;
        m.pad_add = 32w0; m.pdelta_old = 32w0; m.pb0_old = 32w0;
        m.is_fwd = 8w0; m.is_rev = 8w0; m.open_req = 8w0; m.did_open = 8w0;
        m.d_seq = 32w0; m.a_diff = 32w0; m.seq_add = 32w0; m.ack_sub = 32w0;
        m.mirror_session = 10w0; m.translated = 1w0; m.tcp_len = 16w0;
        m.rid = eg.egress_rid;
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) { ETYPE_IPV4 : parse_ipv4; default : accept; }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl, hdr.ipv4.proto) {
            (4w5, IP_PROTO_TCP) : parse_frag;
            default             : accept;
        }
    }
    state parse_frag {
        transition select(hdr.ipv4.flags, hdr.ipv4.frag) {
            (3w0b000, 13w0) : parse_tcp;
            (3w0b010, 13w0) : parse_tcp;
            default         : accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dofs) {
            4w5     : mark_eligible;
            default : tcp_opt;
        }
    }
    state tcp_opt { m.has_opt = 8w1; transition accept; }
    state mark_eligible { m.eligible = 8w1; transition parse_dl; }
    state parse_dl {
        pkt.extract(hdr.dl);
        transition select(hdr.dl.start) { DNP3_START : parse_b0; default : accept; }
    }
    /* block count is set ONCE per path in the terminal sz1/sz2/sz3 states
     * (Tofino forbids re-assigning the same field across successive parser states). */
    state parse_b0 {
        pkt.extract(hdr.blk0);
        transition select(hdr.ipv4.total_len) { TLEN_1BLK : sz1; default : parse_b1; }
    }
    state parse_b1 {
        pkt.extract(hdr.blk1);
        transition select(hdr.ipv4.total_len) { TLEN_2BLK : sz2; default : parse_b2; }
    }
    state parse_b2 {
        pkt.extract(hdr.blk2);
        transition select(hdr.ipv4.total_len) { TLEN_3BLK : sz3; default : accept; }
    }
    state sz1 { m.nblk = 3w1; m.size_ok = 8w1; transition accept; }
    state sz2 { m.nblk = 3w2; m.size_ok = 8w1; transition accept; }
    state sz3 { m.nblk = 3w3; m.size_ok = 8w1; transition accept; }
}

/* ============================== egress control ========================== */
control Egress(inout headers_t hdr, inout eg_meta_t m,
               in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t prsr,
               inout egress_intrinsic_metadata_for_deparser_t dprsr,
               inout egress_intrinsic_metadata_for_output_port_t oport) {

    /* ---- DNP3 CRC-16/DNP via the native CRCPolynomial hash (MAU) — PAD header block ---- */
    CRCPolynomial<bit<16>>(16w0x3D65, true, false, false, 16w0x0000, 16w0xFFFF) dnp3_poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, dnp3_poly) h_dlcrc;

    /* ---- direction + canonical bidirectional flow fold (keyed on the DNP3 port) ---- */
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_flow_e;
    action e_fold_master() { m.dir = DIR_MASTER; m.nm_ip = hdr.ipv4.src; m.nm_pt = hdr.tcp.sport; m.nr_ip = hdr.ipv4.dst; m.nr_pt = hdr.tcp.dport; }
    action e_fold_out()    { m.dir = DIR_OUT;    m.nm_ip = hdr.ipv4.dst; m.nm_pt = hdr.tcp.dport; m.nr_ip = hdr.ipv4.src; m.nr_pt = hdr.tcp.sport; }
    table e_fold {
        key = { hdr.tcp.sport : exact; }
        actions = { e_fold_master; e_fold_out; }
        const default_action = e_fold_master();
        const entries = { (PORT_DNP3) : e_fold_out(); }
        size = 2;
    }
    action e_do_flow_idx() { m.flow_idx = h_flow_e.get({ m.nm_ip, m.nm_pt, m.nr_ip, m.nr_pt })[9:0]; }
    table e_flow_idx { actions = { e_do_flow_idx; } const default_action = e_do_flow_idx(); size = 1; }

    action set_syn()  { m.is_syn = 8w1; m.is_ctl = 8w1; }
    action set_rst()  { m.is_rst = 8w1; m.is_ctl = 8w1; }
    action set_fin()  { m.is_ctl = 8w1; }
    action set_data() { m.is_ctl = 8w0; }
    table e_ctl {
        key = { hdr.tcp.flags : ternary; }
        actions = { set_syn; set_rst; set_fin; set_data; }
        const default_action = set_data();
        const entries = {
            (8w0x04 &&& 8w0x04) : set_rst();
            (8w0x02 &&& 8w0x02) : set_syn();
            (8w0x01 &&& 8w0x01) : set_fin();
        }
        size = 4;
    }

    /* ---- exact owner + per-flow policy (fails closed when empty) ---- */
    action set_policy(bit<8> pol) { m.owner = 8w1; m.policy = pol; }
    action clr_policy() { m.owner = 8w0; m.policy = POL_NONE; }
    table t_policy {
        key = { m.nm_ip : exact; m.nr_ip : exact; m.nm_pt : exact; m.nr_pt : exact; }
        actions = { set_policy; clr_policy; }
        const default_action = clr_policy();
        size = 64;
    }

    /* ---- PAD filler selection keyed on parsed block count (append 3-nblk fillers).
     * One unconditional action per count (bf-p4c forbids conditional setValid in an
     * action), each appending whole constant CRC-valid 0x00 filler blocks. ---- */
    action pad_2fill() { m.pad_add = 32w36;
        hdr.fill0.setValid(); hdr.fill0.b = FILL_BLOCK;
        hdr.fill1.setValid(); hdr.fill1.b = FILL_BLOCK; }
    action pad_1fill() { m.pad_add = 32w18;
        hdr.fill0.setValid(); hdr.fill0.b = FILL_BLOCK; }
    action pad_0fill() { m.pad_add = 32w0; }
    table t_pad {
        key = { m.nblk : exact; }
        actions = { pad_2fill; pad_1fill; pad_0fill; }
        const default_action = pad_0fill();
        const entries = {
            (3w1) : pad_2fill();
            (3w2) : pad_1fill();
            (3w3) : pad_0fill();
        }
        size = 4;
    }

    /* ---- PAD single-insertion epoch (reg_pdelta / reg_pb0), owner-gated ---- */
    Register<bit<32>, bit<10>>(1024, 0) reg_pdelta;
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_pdelta) pdelta_syn = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = PDELTA_CLOSED; }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_pdelta) pdelta_open = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; if (v == PDELTA_CLOSED) { v = m.pad_add; } }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_pdelta) pdelta_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    Register<bit<32>, bit<10>>(1024, 0) reg_pb0;
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_pb0) pb0_syn = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = 32w0; }
    };
    /* store this response's seq as the boundary. Gated on open_req at the CALL SITE (not on
     * did_open), so reg_pb0 does NOT depend on reg_pdelta's output and the two co-locate.
     * MVP single-insertion: open_req fires once per flow; multi-response would need the
     * did_open gate restored (costs the extra stage). */
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_pb0) pb0_open = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = hdr.tcp.seq; }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_pb0) pb0_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* forward addend: 0 at/below boundary, pad_add strictly after it */
    action dseq_after()  { m.seq_add = m.pdelta_old; }
    action dseq_zero()   { m.seq_add = 32w0; }
    action dseq_before() { m.seq_add = 32w0; }
    table t_dseq_cls {
        key = { m.d_seq : ternary; }
        actions = { dseq_zero; dseq_after; dseq_before; }
        const default_action = dseq_before();
        const entries = {
            (32w0 &&& 32w0xFFFFFFFF) : dseq_zero();
            (32w0 &&& 32w0x80000000) : dseq_after();
        }
        size = 4;
    }
    /* reverse subtrahend = clamp(a_diff, 0, pad_add) via sign + magnitude compares */
    action asub_zero() { m.ack_sub = 32w0; }
    action asub_snap() { m.ack_sub = m.a_diff; }
    action asub_full() { m.ack_sub = m.pdelta_old; }
    table t_adiff_cls {
        key = { m.a_diff : ternary; }
        actions = { asub_zero; asub_snap; asub_full; }
        const default_action = asub_zero();
        const entries = {
            (32w0 &&& 32w0xFFFFFFFF) : asub_zero();     /* a_diff == 0            */
            (32w0 &&& 32w0xFFFFFF80) : asub_snap();     /* 1..127 (inside pad)    */
            (32w0 &&& 32w0x80000000) : asub_full();     /* top bit 0 => past pad  */
        }
        size = 4;
    }

    apply {
        if (hdr.tcp.isValid()) {
            e_fold.apply();
            e_flow_idx.apply();
            e_ctl.apply();
            t_policy.apply();

            if (m.dir == DIR_OUT)    { m.is_fwd = 8w1; }
            if (m.dir == DIR_MASTER) { m.is_rev = 8w1; }

            m.rid = eg.egress_rid;

            if (m.rid == 16w0) {
                /* -------- SOURCE pass (unicast from the frozen ingress) -------- */
                if (m.owner == 8w1 && m.eligible == 8w1 && m.size_ok == 8w1 && m.is_ctl == 8w0) {
                    if (m.policy == POL_SPLIT) {
                        dprsr.mirror_type = MIRR_SPLIT;
                        m.mirror_session  = SPLIT_SESSION;
                        dprsr.drop_ctl    = 3w1;
                    } else if (m.policy == POL_PAD) {
                        t_pad.apply();
                        m.open_req = 8w1;
                    }
                }

                /* PAD single-insertion epoch (owner+eligible only) */
                if (m.owner == 8w1 && m.eligible == 8w1) {
                    if (m.is_syn == 8w1)        { m.pdelta_old = pdelta_syn.execute(m.flow_idx); }
                    else if (m.open_req == 8w1) { m.pdelta_old = pdelta_open.execute(m.flow_idx); }
                    else                        { m.pdelta_old = pdelta_read.execute(m.flow_idx); }
                    if (m.open_req == 8w1 && m.pdelta_old == PDELTA_CLOSED) { m.did_open = 8w1; }
                    if (m.is_syn == 8w1)        { m.pb0_old = pb0_syn.execute(m.flow_idx); }
                    else if (m.open_req == 8w1) { m.pb0_old = pb0_open.execute(m.flow_idx); }
                    else                        { m.pb0_old = pb0_read.execute(m.flow_idx); }
                }

                m.d_seq  = hdr.tcp.seq - m.pb0_old;
                m.a_diff = hdr.tcp.ack - m.pb0_old;
                t_dseq_cls.apply();
                t_adiff_cls.apply();

                if (m.policy == POL_PAD && m.owner == 8w1 && m.eligible == 8w1 && m.is_ctl == 8w0 && m.size_ok == 8w1) {
                    if (m.did_open == 8w1) {
                        hdr.dl.len = DL_LEN_TGT;
                        hdr.ipv4.total_len = hdr.ipv4.total_len + m.pad_add[15:0];
                        m.translated = 1w1;
                    } else {
                        if (m.is_fwd == 8w1 && m.pdelta_old != PDELTA_CLOSED && m.seq_add != 32w0) {
                            hdr.tcp.seq = hdr.tcp.seq + m.seq_add; m.translated = 1w1;
                        }
                    }
                }
                if (m.is_rev == 8w1 && m.owner == 8w1 && m.eligible == 8w1 && m.pdelta_old != PDELTA_CLOSED) {
                    if (m.ack_sub != 32w0) { hdr.tcp.ack = hdr.tcp.ack - m.ack_sub; m.translated = 1w1; }
                }

            } else if (m.rid == 16w1) {
                /* -------- replica -> window0 = dl + blk0 -------- */
                hdr.blk1.setInvalid(); hdr.blk2.setInvalid();
                hdr.ipv4.total_len = W0_TLEN;
                m.translated = 1w1;
            } else if (m.rid == 16w2) {
                /* -------- replica -> window1 = blk1 + blk2 -------- */
                hdr.dl.setInvalid(); hdr.blk0.setInvalid();
                hdr.tcp.seq = hdr.tcp.seq + W1_SEQOFF;
                hdr.ipv4.total_len = W1_TLEN;
                m.translated = 1w1;
            }

            /* recompute the DNP3 header-block CRC only when we rewrote its LEN (PAD opener) */
            if (m.translated == 1w1 && m.policy == POL_PAD && m.did_open == 8w1) {
                bit<16> c_dl = h_dlcrc.get({ hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src });
                hdr.dl.crc = c_dl[7:0] ++ c_dl[15:8];   /* DNP3 CRC is transmitted low byte first */
            }

            m.tcp_len = hdr.ipv4.total_len - 16w20;
        }
    }
}

/* ============================= egress deparser ==========================
 * Mirror the SOURCE (SPLIT) to the mcast group, then emit the (POV-selected)
 * headers with recomputed IPv4/TCP checksums. Emit order fixes the wire layout:
 *   eth, ipv4, tcp, dl, blk0..blk2, fill0..fill1. Any header left INVALID by the
 * control (window carving / no-pad) is skipped, so the TCP checksum sum below
 * naturally covers exactly the emitted bytes. */
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t m,
                   in egress_intrinsic_metadata_for_deparser_t dprsr) {
    Checksum() ipv4_csum;
    Checksum() tcp_csum;
    Mirror()   mirror;
    apply {
        if (dprsr.mirror_type == MIRR_SPLIT) {
            mirror.emit(m.mirror_session);
        }
        if (m.translated == 1w1) {
            hdr.ipv4.csum = ipv4_csum.update({
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.total_len,
                hdr.ipv4.id, hdr.ipv4.flags, hdr.ipv4.frag, hdr.ipv4.ttl, hdr.ipv4.proto,
                hdr.ipv4.src, hdr.ipv4.dst });
            hdr.tcp.csum = tcp_csum.update({
                hdr.ipv4.src, hdr.ipv4.dst, 8w0, hdr.ipv4.proto, m.tcp_len,
                hdr.tcp.sport, hdr.tcp.dport, hdr.tcp.seq, hdr.tcp.ack,
                hdr.tcp.dofs, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.win, hdr.tcp.urg,
                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,
                hdr.blk0.b, hdr.blk1.b, hdr.blk2.b,
                hdr.fill0.b, hdr.fill1.b });
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.dl);
        pkt.emit(hdr.blk0);
        pkt.emit(hdr.blk1);
        pkt.emit(hdr.blk2);
        pkt.emit(hdr.fill0);
        pkt.emit(hdr.fill1);
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

/* ============================================================================
 * defense4_crc_split_kernel.p4 — Defense 4 SIZE compile-probe: BYTE-PRESERVING
 *   native-parity DNP3 splitter. Given a native DNP3 RESPONSE, re-segment its TCP
 *   payload at completed DNP3 CRC-block boundaries into a fixed 2-way split,
 *   applying the SAME byte-preserving segment-length vector to both READ and SBO
 *   responses. NO byte is inserted or deleted, so there is NO sequence-space
 *   translation and NO multi-boundary ledger. Tofino-1 / TNA.
 *   COMPILE PROBE (software/model only — NOT silicon-validated).
 *
 * SIBLING of defense4/size/p4/defense4_split_kernel.p4. The INGRESS (Case-A
 *   unified timing core) — its constants, the ingress-referenced headers, the
 *   ingress metadata `ig_meta_t`, the ingress parser `IgParser`, the ingress
 *   control `Ingress`, and the ingress deparser `IgDeparser` — is copied VERBATIM,
 *   byte-identical, from defense4_split_kernel.p4 (its lines 19-103 and 131-557).
 *   The frozen ingress is NOT modified here. Only the EGRESS (a lean, transport-
 *   STATELESS byte-preserving splitter) and its egress-only headers are new.
 *
 * WHY A SEPARATE KERNEL. The shipped split_kernel egress carries a PAD path (grow
 *   to a block-aligned target) with a single-insertion transport epoch; the cover
 *   and padnorm kernels carry byte-INSERTION. All of those need transport state.
 *   This native-parity splitter needs none — it is a distinct, minimal egress and
 *   therefore a sibling kernel, not a patch on the shipped one.
 *
 * Reference model: defense4/size/readsbo_normalizer/readsbo_normalizer.py
 *   (build_frame / frame_blocks / crc_ok / split_at_crc). Behavioral emulator +
 *   conformance/mutation harness: defense4/size/native_parity/offline/.
 *
 * See the EGRESS banner (below the ingress) for the mechanism, the fail-open
 * policy, and the COMPILE-ONLY replication caveat (mirror -> multicast, UNPROVEN
 * on silicon until an authorized hardware gate).
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
/* ---- egress size-layer headers (parsed DNP3 CRC blocks). EGRESS-ONLY: the
 *      ingress never parses or emits these, so they consume NO ingress PHV/MAU.
 *
 *      A DNP3 link frame (IEEE 1815 s9) = a 10-byte header block (dl) followed by
 *      data blocks of <=16 user bytes each, each with a trailing 2-byte block CRC.
 *      The completed-block boundaries are therefore at wire offsets 10, 28, 46, 64.
 *      The two native-parity target sizes carry a SHORT final block:
 *        S=49 -> dl(10)+blk0(18)+blk1(18)+res3(3)   [33 user bytes]
 *        S=61 -> dl(10)+blk0(18)+blk1(18)+res15(15) [45 user bytes]
 *      Full-block frames are also recognized (S=46 = 2 data blocks, S=64 = 3).
 *      Egress parse depth is eth+ip+tcp+dl+blk0+blk1+blk2 = 46+18 = 64 B of DNP3
 *      (118 B total) < 160 B parser bound. The blocks are treated as OPAQUE byte
 *      runs: the splitter carves on block boundaries and never interprets DNP3
 *      object semantics, so the split is byte-exact. ---- */
header pay18_h { bit<144> b; }   /* one full 18-byte DNP3 CRC block (16 user + 2 CRC) */
header res3_h  { bit<24>  b; }   /* short final block: 1 user byte  + 2 CRC (S=49)    */
header res15_h { bit<120> b; }   /* short final block: 13 user bytes + 2 CRC (S=61)   */

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
    /* egress size layer: header block (dl, emitted by ingress) + up to 3 data
     * blocks, the last of which may be short (res3 / res15). */
    pay18_h     blk0;
    pay18_h     blk1;
    pay18_h     blk2;
    res3_h      res3;
    res15_h     res15;
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
 *  EGRESS — Native-parity SIZE layer: byte-preserving 2-way SPLIT of a DNP3   *
 *  RESPONSE at a completed DNP3 CRC-block boundary. Tofino-1 / TNA.            *
 *  COMPILE PROBE (software/model only — NOT silicon-validated).               *
 * ------------------------------------------------------------------------ *
 * WHY THIS FITS WHERE THE INSERTION KERNELS DID NOT. This splitter is
 *   BYTE-PRESERVING: it re-segments an existing TCP payload at DNP3 CRC-block
 *   boundaries without inserting or deleting a single byte. The concatenation of
 *   the emitted segments is byte-for-byte identical to the original payload.
 *   Because no bytes are added, there is NO sequence-space translation and NO
 *   multi-boundary ledger — the exact wall that the cover-frame / pad kernels
 *   (defense4_cover_kernel.p4, defense4_padnorm_kernel.p4) hit. The egress here
 *   holds NO transport state at all (no registers).
 *
 * MECHANISM (fixed 2-way split, egress_rid-selected).
 *   The frozen ingress forwards the released RESPONSE unicast to the master
 *   (egress_rid==0 = the SOURCE copy). On an eligible owner SPLIT flow the SOURCE
 *   emits the WHOLE frame, mirrors it to a 2-node multicast group (SPLIT_SESSION),
 *   and drops its own unicast copy (drop_ctl bit0). Each replica re-enters egress
 *   with egress_rid in {1,2} and carves ONE window on the configured CRC-block
 *   boundary `cut` (28 = header+blk0, or 46 = header+blk0+blk1):
 *     rid==1 -> window0 = frame[0 .. cut)      seq = base          (PSH/FIN cleared)
 *     rid==2 -> window1 = frame[cut .. end)    seq = base + cut     (PSH/FIN kept)
 *   join(window0, window1) == frame, exactly. The master's TCP stack reassembles
 *   by sequence number; no ledger, no state. IPv4 total_len + IPv4 csum + TCP csum
 *   are recomputed per window in the deparser (invalid block headers are skipped,
 *   so each checksum covers exactly the emitted window bytes).
 *
 * SAME VECTOR FOR READ AND SBO. READ and SBO share ONE TCP/DNP3 connection, hence
 *   ONE t_policy entry and ONE `cut`. Once the endpoint has natively enlarged both
 *   responses to the shared size S (decoy CROBs / status objects — an endpoint /
 *   config concern, OUT of this data-plane kernel), the switch emits the identical
 *   byte-preserving segment-length vector for both classes automatically.
 *
 * FAIL OPEN. Non-IPv4 / non-TCP, IP options (ihl>5), fragments, TCP options
 *   (dofs>5), SYN or RST, a non-owner flow, or a payload that is not a recognized
 *   splittable DNP3 frame (start != 05 64, or an unlisted size) are passed NATIVE:
 *   the SOURCE copy is forwarded unchanged (original bytes, original checksums, no
 *   mirror, no carve, no state). An exact native retransmission re-generates an
 *   identical pair of segments (the split is a pure function of the input bytes).
 *   A differently-segmented retransmission that cannot prove eligibility passes
 *   native — it may leak a size feature, but it can NEVER corrupt the stream.
 *
 * REPLICATION IS COMPILE-VERIFIED ONLY. The physical 1->2 replication (egress
 *   mirror -> multicast group, per-copy egress_rid, source-unicast drop) is
 *   COMPILE-checked here; its RUNTIME behavior on silicon is UNPROVEN and is
 *   deferred to an authorized hardware gate (see the report / setup script).
 *   Alternatives (recirculation with a pass counter; CLONE_E2E) are discussed in
 *   the report; the ingress is frozen, so ingress-side PRE multicast is not an
 *   option here.
 * ======================================================================== */

/* ---- egress ports / classes ---- */
const bit<16> PORT_DNP3 = 16w20000;        /* outstation listen port -> DIR_OUT */

const bit<8> POL_NONE  = 8w0;
const bit<8> POL_SPLIT = 8w1;

/* ---- cut boundary (per-flow policy value). A real completed DNP3 CRC-block
 *      boundary: 28 = header block(10) + blk0(18); 46 = + blk1(18). ---- */
const bit<8> CUT_NONE = 8w0;
const bit<8> CUT_28   = 8w28;
const bit<8> CUT_46   = 8w46;

/* ---- parsed size classes (ip.total_len = 40 + payload S) ---- */
const bit<16> TL_28 = 16w68;    /* S=28: dl+blk0 (1 data block) — too small to split */
const bit<16> TL_46 = 16w86;    /* S=46: dl+blk0+blk1 (2 full blocks)                */
const bit<16> TL_49 = 16w89;    /* S=49: dl+blk0+blk1+res3                            */
const bit<16> TL_61 = 16w101;   /* S=61: dl+blk0+blk1+res15                           */
const bit<16> TL_64 = 16w104;   /* S=64: dl+blk0+blk1+blk2 (3 full blocks)           */

/* window0 ip.total_len is a constant per cut (40 + cut); window1 is (orig - cut). */
const bit<16> W0_TL_C28 = 16w68;    /* 40 + 28 */
const bit<16> W0_TL_C46 = 16w86;    /* 40 + 46 */

/* clear PSH(0x08) + FIN(0x01) on the earlier segment: flags & 0xF6 */
const bit<8> CLR_PSH_FIN = 8w0xF6;

/* mirror plumbing: control plane binds SPLIT_SESSION -> mcast group {rid1, rid2}. */
typedef bit<10> mirror_sess_t;
const mirror_sess_t SPLIT_SESSION = 10w1;
const MirrorType_t  MIRR_SPLIT    = 3w1;

/* ============================= egress metadata ========================== */
struct eg_meta_t {
    bit<8>  dir;
    bit<32> nm_ip; bit<32> nr_ip; bit<16> nm_pt; bit<16> nr_pt;
    bit<8>  eligible;     /* IPv4/TCP, ihl==5, not fragmented, dofs==5 */
    bit<8>  has_opt;      /* dofs>5 (TCP options present)             */
    bit<8>  size_ok;      /* payload is a recognized splittable DNP3 frame */
    bit<8>  size_class;   /* parsed S (46/49/61/64), else 0           */
    bit<8>  is_syn; bit<8> is_rst;
    bit<8>  owner;        /* exact protected-flow match               */
    bit<8>  policy;       /* POL_NONE / POL_SPLIT                      */
    bit<8>  cut;          /* CUT_28 / CUT_46                          */
    bit<8>  do_split;     /* all source-pass eligibility ANDed (1 = split) */
    bit<16> rid;          /* egress_rid: 0 source, 1 window0, 2 window1 */
    mirror_sess_t mirror_session;
    bit<1>  translated;   /* a window was carved -> recompute checksums */
    bit<16> tcp_len;      /* TCP length for the pseudo-header          */
}

/* ============================== egress parser ===========================
 * Fail-closed gate, then parse the DNP3 header block + data blocks (last may be
 * short). size_ok is set ONLY for a recognized 2..3-block DNP3 frame. */
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t m,
                out egress_intrinsic_metadata_t eg) {
    state start {
        pkt.extract(eg);
        m.dir = DIR_MASTER;
        m.nm_ip = 32w0; m.nr_ip = 32w0; m.nm_pt = 16w0; m.nr_pt = 16w0;
        m.eligible = 8w0; m.has_opt = 8w0; m.size_ok = 8w0; m.size_class = 8w0;
        m.is_syn = 8w0; m.is_rst = 8w0; m.owner = 8w0;
        m.policy = POL_NONE; m.cut = CUT_NONE; m.rid = 16w0; m.do_split = 8w0;
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
    state tcp_opt { m.has_opt = 8w1; transition accept; }   /* TCP options -> fail open */
    state mark_eligible { m.eligible = 8w1; transition parse_dl; }
    state parse_dl {
        pkt.extract(hdr.dl);
        transition select(hdr.dl.start) { DNP3_START : parse_b0; default : accept; }
    }
    /* size_class / size_ok are set ONCE per path in the terminal states below
     * (Tofino forbids re-assigning the same field across successive parser states,
     * except a constant init in start). */
    state parse_b0 {
        pkt.extract(hdr.blk0);
        transition select(hdr.ipv4.total_len) {
            TL_28   : accept;          /* 1 data block: not splittable -> native */
            default : parse_b1;
        }
    }
    state parse_b1 {
        pkt.extract(hdr.blk1);
        transition select(hdr.ipv4.total_len) {
            TL_46   : sz46;
            TL_49   : parse_res3;
            TL_61   : parse_res15;
            TL_64   : parse_b2;
            default : accept;          /* unrecognized size -> native */
        }
    }
    state parse_res3  { pkt.extract(hdr.res3);  transition sz49; }
    state parse_res15 { pkt.extract(hdr.res15); transition sz61; }
    state parse_b2    { pkt.extract(hdr.blk2);  transition sz64; }
    state sz46 { m.size_class = 8w46; m.size_ok = 8w1; transition accept; }
    state sz49 { m.size_class = 8w49; m.size_ok = 8w1; transition accept; }
    state sz61 { m.size_class = 8w61; m.size_ok = 8w1; transition accept; }
    state sz64 { m.size_class = 8w64; m.size_ok = 8w1; transition accept; }
}

/* ============================== egress control ========================== */
control Egress(inout headers_t hdr, inout eg_meta_t m,
               in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t prsr,
               inout egress_intrinsic_metadata_for_deparser_t dprsr,
               inout egress_intrinsic_metadata_for_output_port_t oport) {

    /* ---- direction + canonical bidirectional flow fold (keyed on the DNP3 port).
     *      Both directions of a flow yield the SAME normalized (master,relay) tuple. */
    action e_fold_master() { m.dir = DIR_MASTER; m.nm_ip = hdr.ipv4.src; m.nm_pt = hdr.tcp.sport; m.nr_ip = hdr.ipv4.dst; m.nr_pt = hdr.tcp.dport; }
    action e_fold_out()    { m.dir = DIR_OUT;    m.nm_ip = hdr.ipv4.dst; m.nm_pt = hdr.tcp.dport; m.nr_ip = hdr.ipv4.src; m.nr_pt = hdr.tcp.sport; }
    table e_fold {
        key = { hdr.tcp.sport : exact; }
        actions = { e_fold_master; e_fold_out; }
        const default_action = e_fold_master();
        const entries = { (PORT_DNP3) : e_fold_out(); }
        size = 2;
    }

    /* ---- SYN / RST classify (FIN and PSH are ALLOWED and ride the final segment) ---- */
    action set_syn()  { m.is_syn = 8w1; }
    action set_rst()  { m.is_rst = 8w1; }
    action set_data() { }
    table e_ctl {
        key = { hdr.tcp.flags : ternary; }
        actions = { set_syn; set_rst; set_data; }
        const default_action = set_data();
        const entries = {
            (8w0x04 &&& 8w0x04) : set_rst();
            (8w0x02 &&& 8w0x02) : set_syn();
        }
        size = 4;
    }

    /* ---- exact owner + per-flow split policy (fails closed when empty). The
     *      action carries the CRC-block boundary `cut` to split on. ---- */
    action set_split(bit<8> cut) { m.owner = 8w1; m.policy = POL_SPLIT; m.cut = cut; }
    action clr_policy()          { m.owner = 8w0; m.policy = POL_NONE;  m.cut = CUT_NONE; }
    table t_policy {
        key = { m.nm_ip : exact; m.nr_ip : exact; m.nm_pt : exact; m.nr_pt : exact; }
        actions = { set_split; clr_policy; }
        const default_action = clr_policy();
        size = 64;
    }

    /* ---- fold the whole source-pass eligibility test into ONE table match, so
     *      the apply gateway tests a single bit (a 6-field AND overruns the 4B+12b
     *      gateway limit). do_split=1 iff owner SPLIT flow AND clean DNP3 data
     *      frame AND not SYN/RST. ---- */
    action mark_split()   { m.do_split = 8w1; }
    action mark_nosplit() { m.do_split = 8w0; }
    table t_eligible {
        key = { m.policy : exact; m.eligible : exact; m.size_ok : exact;
                m.is_syn : exact; m.is_rst : exact; }
        actions = { mark_split; mark_nosplit; }
        const default_action = mark_nosplit();
        const entries = { (POL_SPLIT, 8w1, 8w1, 8w0, 8w0) : mark_split(); }
        size = 4;
    }

    apply {
        if (hdr.tcp.isValid()) {
            e_fold.apply();
            e_ctl.apply();
            t_policy.apply();
            t_eligible.apply();

            m.rid = eg.egress_rid;

            if (m.rid == 16w0) {
                /* -------- SOURCE pass (unicast from the frozen ingress) -------- */
                if (m.do_split == 8w1) {
                    /* emit the whole frame to a 2-node mcast group; drop our own unicast */
                    dprsr.mirror_type = MIRR_SPLIT;
                    m.mirror_session  = SPLIT_SESSION;
                    dprsr.drop_ctl    = 3w1;
                }
                /* else: NATIVE passthrough (translated stays 0 -> original checksums) */

            } else if (m.rid == 16w1) {
                /* -------- replica -> window0 = frame[0 .. cut) -------- */
                if (m.cut == CUT_46) {
                    hdr.res3.setInvalid(); hdr.res15.setInvalid(); hdr.blk2.setInvalid();
                    hdr.ipv4.total_len = W0_TL_C46;
                } else {
                    hdr.blk1.setInvalid(); hdr.res3.setInvalid();
                    hdr.res15.setInvalid(); hdr.blk2.setInvalid();
                    hdr.ipv4.total_len = W0_TL_C28;
                }
                hdr.tcp.flags = hdr.tcp.flags & CLR_PSH_FIN;   /* not the final segment */
                m.translated = 1w1;

            } else if (m.rid == 16w2) {
                /* -------- replica -> window1 = frame[cut .. end) (final segment) -------- */
                if (m.cut == CUT_46) {
                    hdr.dl.setInvalid(); hdr.blk0.setInvalid(); hdr.blk1.setInvalid();
                    hdr.tcp.seq = hdr.tcp.seq + 32w46;
                    hdr.ipv4.total_len = hdr.ipv4.total_len - 16w46;
                } else {
                    hdr.dl.setInvalid(); hdr.blk0.setInvalid();
                    hdr.tcp.seq = hdr.tcp.seq + 32w28;
                    hdr.ipv4.total_len = hdr.ipv4.total_len - 16w28;
                }
                m.translated = 1w1;
            }

            m.tcp_len = hdr.ipv4.total_len - 16w20;
        }
    }
}

/* ============================= egress deparser ==========================
 * Mirror the SOURCE (SPLIT) to the mcast group, then emit the (window-carved)
 * headers with recomputed IPv4/TCP checksums when a window was carved. Emit order
 * fixes the wire layout: eth, ipv4, tcp, dl, blk0, blk1, res3, res15, blk2. Any
 * header left INVALID by the carve is skipped, so each checksum below naturally
 * covers exactly the emitted window bytes (and, for the residual, exactly one of
 * res3/res15/blk2 is ever valid). */
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
                hdr.blk0.b, hdr.blk1.b, hdr.res3.b, hdr.res15.b, hdr.blk2.b });
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.dl);
        pkt.emit(hdr.blk0);
        pkt.emit(hdr.blk1);
        pkt.emit(hdr.res3);
        pkt.emit(hdr.res15);
        pkt.emit(hdr.blk2);
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

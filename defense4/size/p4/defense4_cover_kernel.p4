/* ============================================================================
 * defense4_cover_kernel.p4 — Defense 4 SIZE compile-probe: DNP3 cover-frame
 *   PREPEND composed on the Case-A timing core. Tofino-1 / TNA. COMPILE PROBE.
 *
 * WHAT THIS IS: a COMPOSED probe. The INGRESS is the Case-A-derived unified timing
 *   core, taken VERBATIM from defense4/size/p4/defense4_joint_canon.p4 (itself the
 *   silicon-validated timing core copied from defense4/timing/p4/defense4_caseA.p4 /
 *   defense4_timing.p4 — NOT MODIFIED here). The EGRESS is a NEW size layer that
 *   PREPENDS one fixed CRC-valid DNP3 cover frame on the released response and runs
 *   the per-flow TCP transport epoch (seq/ack translation, retransmit re-emission,
 *   exact owner validation, MTU guard, retirement) modelled by the offline oracle
 *   defense4/size/offline/transport_oracle.py.
 *
 * WHAT A CLEAN COMPILE PROVES: the parser graph (cover headers + real residual), the
 *   bounded transport state (reg_delta / reg_last_resp_seq / reg_dlast), the full
 *   5-tuple owner-exact table, the MTU-guard range table, and the residual-preserving
 *   IPv4+TCP checksum recompute all FIT together with the frozen timing ingress on one
 *   Tofino-1 pipe, in the stage/PHV/TCAM/SRAM budget reported by the build.
 *
 * WHAT IT DOES NOT PROVE: nothing here is silicon-validated. A compile is not a run.
 *   The cover's DNP3 CRC-validity and byte-identical delivery were shown OFFLINE
 *   (defense4/size/evidence/cover_frame_gate); the transport translation was shown
 *   OFFLINE (transport_oracle.py). This probe does NOT re-verify those on hardware.
 *
 * The full egress mechanism, ordering rationale (size selected before timing;
 * prepend materialised post-TM in egress), and the checksum/MTU constraints are
 * documented at the EGRESS banner below.
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

/* ---- egress Layer-S headers (size layer). Egress-only: the ingress never parses
 *      or emits these, so they consume NO ingress PHV / MAU. ---- */
/* first DNP3 user-data CRC block of a RESPONSE: transport + app_ctrl + func + IIN(2)
 * + 11 object octets = 16 data bytes, then the 2-byte block CRC. */
header dnp3_blk_h { bit<8> transport; bit<8> app_ctrl; bit<8> func; bit<16> iin; bit<88> obj0; bit<16> bcrc; }
/* shared power-of-2 payload chunks (descending): empties the deparser residual so the
 * wholesale checksum is valid and so decoy objects can later be emitted among the payload. */
header pay16_h { bit<128> b; }
header pay8_h  { bit<64>  b; }
header pay4_h  { bit<32>  b; }
header pay2_h  { bit<16>  b; }
header pay1_h  { bit<8>   b; }

/* ---- egress canonicalizer headers (V1->V3 shrink path). Egress-only. ----
 * V1 INPUT carving: the 61 B G30/V1 response, cut on its wire block+CRC boundaries so the point
 * VALUES can be lifted out (flag octets discarded) and the residual left EMPTY. These headers are
 * parsed (to consume the bytes) but NEVER emitted — that is the -7 B shrink. Point 4's value
 * straddles crc1 (1 byte in block1, 3 bytes in block2), so it is carved as val4hi/val4lo. */
header v1b0_h { bit<8> t; bit<8> ac; bit<8> f; bit<16> iin;
                bit<8> grp; bit<8> var; bit<8> qual; bit<8> start; bit<8> stop;
                bit<8> flag0; bit<32> val0; bit<8> flag1; }          /* block0 data, 16 B */
header v1c0_h { bit<16> crc; }                                       /* block0 CRC (dropped) */
header v1b1_h { bit<32> val1; bit<8> flag2; bit<32> val2; bit<8> flag3;
                bit<32> val3; bit<8> flag4; bit<8> val4hi; }         /* block1 data, 16 B */
header v1c1_h { bit<16> crc; }                                       /* block1 CRC (dropped) */
header v1b2_h { bit<24> val4lo; bit<8> flag5; bit<32> val5; bit<8> flag6; bit<32> val6; } /* block2 data, 13 B */
header v1c2_h { bit<16> crc; }                                       /* block2 CRC (dropped) */

/* V3 OUTPUT: the public canonical 54 B frame, laid out on its OWN wire block+CRC boundaries.
 * Populated in egress from the V1 values + constant object header (var=03, stop=07); each block's
 * DNP3 CRC is recomputed over its exact byte group and emitted low-octet-first. A value that
 * straddles a public block boundary is split to match (v1hi/v1lo, v4hi/v4lo, v5hi/v5lo). */
header v3ba_h { bit<8> t; bit<8> ac; bit<8> f; bit<16> iin;
                bit<8> grp; bit<8> var; bit<8> qual; bit<8> start; bit<8> stop;
                bit<32> v0; bit<16> v1hi; }                          /* blockA data, 16 B */
header v3ca_h { bit<16> crc; }                                       /* blockA CRC */
header v3bb_h { bit<16> v1lo; bit<32> v2; bit<32> v3;
                bit<8> v4hi; bit<24> v4lo; bit<16> v5hi; }           /* blockB data, 16 B */
header v3cb_h { bit<16> crc; }                                       /* blockB CRC */
header v3bc_h { bit<16> v5lo; bit<32> v6; }                          /* blockC data, 6 B */
header v3cc_h { bit<16> crc; }                                       /* blockC CRC */

/* ---- egress cover-frame headers (size layer). Egress-only: the ingress never parses
 *      or emits these. One fixed 16-byte (EVEN) DNP3 unconfirmed-user-data link frame,
 *      addressed to an INDIVIDUAL non-endpoint link address, PREPENDED before the real
 *      DNP3 frame. All fields are constants; the two DNP3 CRC fields are compile-time
 *      constants (0 CRC ALUs). ---- */
header cover_dl_h { bit<16> start; bit<8> len; bit<8> ctrl; bit<16> dst; bit<16> src; bit<16> crc; } /* 10 B */
header cover_ud_h { bit<8> transport; bit<8> app_ctrl; bit<8> func; bit<8> pad; bit<16> bcrc; }       /* 6 B  */

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
    /* Layer-S (egress) — V3 passthrough chunking */
    dnp3_blk_h  db;
    pay16_h     p16;
    pay8_h      p8;
    pay4_h      p4;
    pay2_h      p2;
    pay1_h      p1;
    /* Layer-S (egress) — V1->V3 canonicalizer */
    v1b0_h      v1b0;  v1c0_h v1c0;
    v1b1_h      v1b1;  v1c1_h v1c1;
    v1b2_h      v1b2;  v1c2_h v1c2;
    v3ba_h      v3ba;  v3ca_h v3ca;
    v3bb_h      v3bb;  v3cb_h v3cb;
    v3bc_h      v3bc;  v3cc_h v3cc;
    /* egress cover-frame (size layer) — PREPENDED before the real DNP3 residual */
    cover_dl_h  cover_dl;
    cover_ud_h  cover_ud;
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
 *  EGRESS — Size Layer: DNP3 cover-frame PREPEND + per-flow transport epoch  *
 * ======================================================================== *
 * Applies the SIZE policy at RELEASE (post-TM), on the outstation->master
 * RESPONSE direction only. Prepend ONE fixed CRC-valid UNCONFIRMED-user-data
 * DNP3 cover link frame (dst = INDIVIDUAL non-endpoint 0x0032) in front of the
 * REAL DNP3 frame in the same TCP byte stream. The master's link layer discards
 * the cover (numUnknownDestination++, nothing pushed up, no link ACK) and delivers
 * the real frame byte-identically — proven offline in the cover-frame gate
 * (defense4/size/evidence/cover_frame_gate, OpenDNP3 3.1.2). A passive size
 * observer sees native + COVER_LEN bytes => one fixed, tunable public size.
 *
 * Transport epoch — mirrors defense4/size/offline/transport_oracle.py:
 *   - FWD (out->master response) : seq' = seq + Delta_prior ; Delta += COVER_LEN
 *     (prepend: the cover occupies [seq', seq'+COVER_LEN), real data follows).
 *   - REV (master->out)          : ack' = ack - Delta  (acks the padded stream).
 *   - committed_len vs inserted_len (the byte-stream invariant): a RETRANSMIT of the
 *     stored response seq RE-EMITS the cover (inserted_len>0) but does NOT re-bump
 *     Delta (committed_len=0); it renumbers with the EXACT Delta_at_last it was first
 *     sent with (reg_dlast). This reproduces the identical padded bytes on retransmit.
 *   - EXACT owner validation: a full 5-tuple exact-match table (t_owner). No hash
 *     aliasing is possible => it realises the oracle's verify_full_key=True model
 *     (zero undetected false hits). Per-flow transport state (Delta, last seq,
 *     Delta_at_last) is indexed by a bounded flow hash.
 *   - MTU guard: a cover that would push ip.total_len past the MTU is REFUSED
 *     (freeze) — the flow keeps translating with its existing Delta but adds no
 *     new cover (mirrors the oracle's _wrap_guard freeze-but-still-translate).
 *   - clean state retirement: SYN/FIN/RST resets the per-flow Delta ledger.
 *
 * Checksums — both offloaded to the parser+deparser checksum engines (NOT MAU):
 *   - IPv4: whole-header recompute with the new total_len (header fully parsed).
 *   - TCP : subtract_all_and_deposit captures the UNPARSED real-DNP3 residual in the
 *     egress parser; the deparser update() re-sums pseudo-hdr(new len) + tcp hdr(new
 *     seq/ack) + cover(new bytes) + residual. This is a residual-preserving
 *     (incremental) recompute: the real payload is NOT re-summed field by field, and
 *     it is never parsed. Correct ONLY because COVER_LEN is EVEN, so the residual's
 *     16-bit alignment inside the checksummed region is preserved (HARD constraint).
 *
 * ORDERING NOTE (size selected before timing; prepend materialised in egress):
 *   The size POLICY (which flows are covered, the template, the target size) is a
 *   static per-flow property, logically PRIOR to and independent of the timing hold.
 *   The physical prepend is done in EGRESS because (a) the timing hold/release is an
 *   ingress->TM decision and the released packet is only materialised in egress, and
 *   (b) TNA cannot emit a header AFTER the unparsed residual, so the cover must be
 *   inserted between the TCP header and the residual on the egress deparse path. The
 *   owner/policy lookup is re-derived in egress from the IMMUTABLE flow key, which is
 *   identical to bridging a policy bit set in ingress. CONSEQUENCE: TM enqueue
 *   accounting saw the PRE-COVER length — queue occupancy, shaping, and any
 *   byte-derived deadline reflect the native response size, and the cover's extra
 *   bytes/serialisation time are added only at dequeue. The padded frame must still
 *   fit the MTU (guarded here).
 * ======================================================================== */

/* ---- egress ports / classes ---- */
const bit<16> PORT_DNP3 = 16w20000;      /* outstation listen port -> DIR_OUT */

const bit<8> CLS_NONE     = 8w0;         /* non-TCP / unhandled -> fail open */
const bit<8> CLS_CTL      = 8w1;         /* SYN/FIN/RST -> retire, no translation */
const bit<8> CLS_RESP     = 8w2;         /* out->master DATA response -> cover + seq translate */
const bit<8> CLS_OUT_BARE = 8w3;         /* out->master no-payload seg -> seq translate only */
const bit<8> CLS_REV      = 8w4;         /* master->out (any) -> cumulative ACK translate */

/* ---- the ONE fixed cover: even 16-byte DNP3 unconfirmed-user-data link frame ---- */
const bit<32> COVER_LEN32 = 32w16;
const bit<16> COVER_LEN16 = 16w16;
const bit<16> MTU_MINUS_COVER = 16w1484; /* 1500 (IP MTU) - 16 (cover) */

/* Cover link header (dst = 0x0032 = an INDIVIDUAL, non-endpoint link address). The two
 * DNP3 CRC fields are COMPILE-TIME CONSTANTS (the frame is fixed) — 0 CRC ALUs are used.
 * The values below are illustrative placeholders; the real CRC-valid cover is the
 * constant validated by the offline cover-frame gate. The IPv4/TCP checksums are
 * computed over WHATEVER cover bytes are emitted, so the emitted packet is self-consistent. */
const bit<16> COVER_START   = 16w0x0564;
const bit<8>  COVER_DL_LEN   = 8w0x09;
const bit<8>  COVER_CTRL     = 8w0x44;    /* DIR|PRM|func=4 (unconfirmed user data) */
const bit<16> COVER_DST      = 16w0x0032; /* individual, non-endpoint */
const bit<16> COVER_SRC      = 16w0x0001;
const bit<16> COVER_DL_CRC   = 16w0xABCD; /* compile-time constant (placeholder) */
const bit<8>  COVER_TP       = 8w0xC0;    /* transport: FIR|FIN, seq 0 */
const bit<8>  COVER_AC       = 8w0xC1;    /* app control */
const bit<8>  COVER_FC       = 8w0x02;    /* app func (irrelevant; frame is discarded) */
const bit<16> COVER_BCRC     = 16w0xEF01; /* compile-time constant (placeholder) */

/* ============================= egress metadata ========================== */
struct eg_meta_t {
    bit<10> flow_idx;
    bit<32> nm_ip; bit<32> nr_ip; bit<16> nm_pt; bit<16> nr_pt;
    bit<16> flow_wide;
    bit<8>  dir;          /* DIR_MASTER / DIR_OUT */
    bit<8>  cls;          /* CLS_* */
    bit<8>  is_ctl;       /* SYN/FIN/RST present */
    bit<8>  owner;        /* 1 iff this is the protected flow (exact full-key match) */
    bit<8>  is_retx;      /* retransmit of the stored response seq */
    bit<8>  mtu_ok;       /* a cover would still fit the MTU */
    bit<8>  has_pay;      /* segment carries a TCP payload (total_len > 40) */
    bit<8>  cover_on;     /* a cover is emitted on this packet */
    bit<1>  translated;   /* seq or ack rewritten -> recompute checksums */
    bit<16> tcp_len;      /* pseudo-header TCP length (TCP header + emitted payload) */
    bit<32> delta;        /* cumulative delta read (OLD value on a bump) */
    bit<32> seq_add;      /* precomputed seq addend (delta_old, or Delta_at_last on retx) */
    bit<16> residual;     /* deposited checksum of the unparsed real-DNP3 residual */
}

/* ============================== egress parser =========================== */
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t m,
                out egress_intrinsic_metadata_t eg) {
    Checksum() resid_csum;               /* parser-side engine: capture the payload residual */
    state start {
        pkt.extract(eg);
        m.flow_idx = 10w0; m.nm_ip = 32w0; m.nr_ip = 32w0; m.nm_pt = 16w0; m.nr_pt = 16w0;
        m.flow_wide = 16w0; m.dir = DIR_MASTER; m.cls = CLS_NONE; m.is_ctl = 8w0;
        m.owner = 8w0; m.is_retx = 8w0; m.mtu_ok = 8w0; m.has_pay = 8w0; m.cover_on = 8w0; m.translated = 1w0;
        m.tcp_len = 16w0; m.delta = 32w0; m.seq_add = 32w0; m.residual = 16w0;
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) { ETYPE_IPV4 : parse_ipv4; default : accept; }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.proto, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;   /* bounded: no IP options */
            default             : accept;
        }
    }
    /* Bounded TCP eligibility: only dofs=5 (no TCP options) segments are cover-eligible.
     * A dofs>5 segment falls through to accept -> no residual captured, no translation,
     * original checksum passes through untouched. */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dofs) { 4w5 : tcp5; default : accept; }
    }
    state tcp5 {
        /* deposit the checksum of the real-DNP3 residual (everything after the TCP header),
         * so the deparser can re-sum without ever parsing the variable-length DNP3 payload. */
        resid_csum.subtract_all_and_deposit(m.residual);
        transition accept;
    }
}

/* ============================== egress control ========================== */
control Egress(inout headers_t hdr, inout eg_meta_t m,
               in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t prsr,
               inout egress_intrinsic_metadata_for_deparser_t dprsr,
               inout egress_intrinsic_metadata_for_output_port_t oport) {

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
    action e_do_flow_idx() { m.flow_wide = h_flow_e.get({ m.nm_ip, m.nm_pt, m.nr_ip, m.nr_pt }); }
    table e_flow_idx { actions = { e_do_flow_idx; } const default_action = e_do_flow_idx(); size = 1; }
    action e_cut() { m.flow_idx = m.flow_wide[9:0]; }
    table e_cut_tbl { actions = { e_cut; } const default_action = e_cut(); size = 1; }

    /* ---- control-flag detect (SYN/FIN/RST) via a whole-container ternary mask ---- */
    action set_ctl()   { m.is_ctl = 8w1; }
    action set_noctl() { m.is_ctl = 8w0; }
    table e_ctl {
        key = { hdr.tcp.flags : ternary; }
        actions = { set_ctl; set_noctl; }
        const default_action = set_ctl();
        const entries = { (8w0x00 &&& 8w0x07) : set_noctl(); }   /* no FIN/SYN/RST -> data */
        size = 2;
    }

    /* ---- EXACT owner validation: full direction-normalized 5-tuple exact match.
     *      The control plane installs the ONE protected flow's entry (both directions fold
     *      to the same normalized key). An exact match cannot alias => verify_full_key=True:
     *      a foreign flow that hash-collides in the transport-state array is NEVER treated as
     *      the owner (owner stays 0 -> it is passed through native, no translation). ---- */
    action set_owner() { m.owner = 8w1; }
    action clr_owner() { m.owner = 8w0; }
    table t_owner {
        key = { m.nm_ip : exact; m.nr_ip : exact; m.nm_pt : exact; m.nr_pt : exact; }
        actions = { set_owner; clr_owner; }
        const default_action = clr_owner();
        size = 64;
    }

    /* ---- MTU guard: cover eligible only if ip.total_len <= MTU - COVER_LEN ---- */
    action mtu_ok_a() { m.mtu_ok = 8w1; }
    action mtu_no_a() { m.mtu_ok = 8w0; }
    table e_mtu {
        key = { hdr.ipv4.total_len : range; }
        actions = { mtu_ok_a; mtu_no_a; }
        const default_action = mtu_no_a();
        const entries = { (16w0 .. MTU_MINUS_COVER) : mtu_ok_a(); }
        size = 2;
    }

    /* ---- payload-presence (total_len > 40) — kept OFF the classify gateway so the
     *      class decision uses only simple 8-bit equalities (gateway input limit) ---- */
    action pay_yes() { m.has_pay = 8w1; }
    action pay_no()  { m.has_pay = 8w0; }
    table e_haspay {
        key = { hdr.ipv4.total_len : range; }
        actions = { pay_yes; pay_no; }
        const default_action = pay_yes();
        const entries = { (16w0 .. 16w40) : pay_no(); }   /* 40 = 20 IP + 20 TCP, no payload */
        size = 2;
    }

    /* ---- reg_delta: cumulative per-flow byte offset (keyed flow_idx) ---- */
    Register<bit<32>, bit<10>>(1024, 0) reg_delta;
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_delta) delta_grow = {   /* fresh cover: +COVER_LEN, returns old */
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = v + COVER_LEN32; }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_delta) delta_read = {   /* retransmit / bare / reverse / read */
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_delta) delta_reset = { /* SYN/FIN/RST retirement */
        void apply(inout bit<32> v, out bit<32> rv) { rv = 32w0; v = 32w0; }
    };

    /* ---- reg_last_resp_seq: retransmit-of-last detection (keyed flow_idx). Returns 1 iff
     *      this response repeats the stored seq; else stores the new seq and returns 0. ---- */
    Register<bit<32>, bit<10>>(1024, 0) reg_last_resp_seq;
    RegisterAction<bit<32>, bit<10>, bit<8>>(reg_last_resp_seq) lastseq_update = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == hdr.tcp.seq) { rv = 8w1; }
            else { rv = 8w0; v = hdr.tcp.seq; }
        }
    };

    /* ---- reg_dlast = Delta_at_last: the exact delta_old a response was first sent with,
     *      so a retransmit renumbers IDENTICALLY (the spec's (last_seq, Delta_at_last) pair). ---- */
    Register<bit<32>, bit<10>>(1024, 0) reg_dlast;
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_dlast) dlast_store = { /* new response: save delta_old */
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = m.delta; }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_dlast) dlast_load = {  /* retransmit: reuse it */
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* ---- the fixed cover: one action sets every cover field (all constant) + grows total_len ---- */
    action emit_cover() {
        m.cover_on = 8w1;
        hdr.cover_dl.setValid();
        hdr.cover_dl.start = COVER_START;
        hdr.cover_dl.len   = COVER_DL_LEN;
        hdr.cover_dl.ctrl  = COVER_CTRL;
        hdr.cover_dl.dst   = COVER_DST;
        hdr.cover_dl.src   = COVER_SRC;
        hdr.cover_dl.crc   = COVER_DL_CRC;
        hdr.cover_ud.setValid();
        hdr.cover_ud.transport = COVER_TP;
        hdr.cover_ud.app_ctrl  = COVER_AC;
        hdr.cover_ud.func      = COVER_FC;
        hdr.cover_ud.pad       = 8w0;
        hdr.cover_ud.bcrc      = COVER_BCRC;
        hdr.ipv4.total_len = hdr.ipv4.total_len + COVER_LEN16;
    }
    table t_cover { actions = { emit_cover; } const default_action = emit_cover(); size = 1; }

    apply {
        e_fold.apply();          /* direction + normalized tuple */
        e_flow_idx.apply();
        e_cut_tbl.apply();
        e_ctl.apply();
        t_owner.apply();         /* exact full-key owner validation */
        e_mtu.apply();
        e_haspay.apply();

        /* ---- classify (only simple 8-bit equalities in the gateways) ---- */
        if (m.is_ctl == 8w1) {
            m.cls = CLS_CTL;
        } else if (m.dir == DIR_OUT) {
            if (m.has_pay == 8w1) { m.cls = CLS_RESP; }
            else                  { m.cls = CLS_OUT_BARE; }
        } else {
            m.cls = CLS_REV;
        }

        /* ---- retransmit-of-last (data responses on the owned flow only) ---- */
        if (m.cls == CLS_RESP && m.owner == 8w1) {
            m.is_retx = lastseq_update.execute(m.flow_idx);
        }

        /* ---- reg_delta: EXACTLY ONE access, role-selected ---- */
        if (m.is_ctl == 8w1) {
            m.delta = delta_reset.execute(m.flow_idx);                       /* retire */
        } else if (m.cls == CLS_RESP && m.owner == 8w1 && m.is_retx == 8w0 && m.mtu_ok == 8w1) {
            m.delta = delta_grow.execute(m.flow_idx);                        /* fresh cover: returns old, +COVER_LEN */
        } else {
            m.delta = delta_read.execute(m.flow_idx);                        /* retransmit / bare / reverse */
        }

        /* ---- seq addend: default cumulative delta_old; retransmit reuses Delta_at_last;
         *      a fresh eligible response stores its delta_old for a future retransmit. ---- */
        m.seq_add = m.delta;
        if (m.cls == CLS_RESP && m.owner == 8w1) {
            if (m.is_retx == 8w1)        { m.seq_add = dlast_load.execute(m.flow_idx); }
            else if (m.mtu_ok == 8w1)    { dlast_store.execute(m.flow_idx); }
        }

        /* ---- cover emission: a fresh eligible response, OR a retransmit of a covered one
         *      (byte-stream invariant: retransmit RE-EMITS the identical cover) ---- */
        if (m.cls == CLS_RESP && m.owner == 8w1 && (m.mtu_ok == 8w1 || m.is_retx == 8w1)) {
            t_cover.apply();
        }

        /* ---- direction-selected seq/ack translation ---- */
        if ((m.cls == CLS_RESP || m.cls == CLS_OUT_BARE) && m.owner == 8w1) {
            hdr.tcp.seq = hdr.tcp.seq + m.seq_add;      /* out->master: forward seq translate */
            m.translated = 1w1;
        } else if (m.cls == CLS_REV && m.owner == 8w1) {
            hdr.tcp.ack = hdr.tcp.ack - m.delta;        /* master->out: reverse cumulative ACK translate */
            m.translated = 1w1;
        }

        /* ---- pseudo-header TCP length (after any total_len bump) ---- */
        m.tcp_len = hdr.ipv4.total_len - 16w20;
    }
}

/* ============================= egress deparser ========================== */
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t m,
                   in egress_intrinsic_metadata_for_deparser_t dprsr) {
    Checksum() ipv4_csum;
    Checksum() tcp_csum;
    apply {
        if (m.translated == 1w1) {
            /* IPv4: whole-header recompute (header fully parsed; new total_len). */
            hdr.ipv4.csum = ipv4_csum.update({
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.total_len,
                hdr.ipv4.id, hdr.ipv4.flags, hdr.ipv4.frag, hdr.ipv4.ttl, hdr.ipv4.proto,
                hdr.ipv4.src, hdr.ipv4.dst });
            /* TCP: pseudo-hdr(new len) + tcp hdr(new seq/ack) + cover(new bytes, POV-gated) +
             * the deposited real-DNP3 residual. cover_dl/cover_ud are valid only on covered
             * responses -> excluded from the sum on reverse/bare packets. */
            hdr.tcp.csum = tcp_csum.update({
                hdr.ipv4.src, hdr.ipv4.dst, 8w0, hdr.ipv4.proto, m.tcp_len,
                hdr.tcp.sport, hdr.tcp.dport, hdr.tcp.seq, hdr.tcp.ack,
                hdr.tcp.dofs, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.win, hdr.tcp.urg,
                hdr.cover_dl.start, hdr.cover_dl.len, hdr.cover_dl.ctrl,
                hdr.cover_dl.dst, hdr.cover_dl.src, hdr.cover_dl.crc,
                hdr.cover_ud.transport, hdr.cover_ud.app_ctrl, hdr.cover_ud.func,
                hdr.cover_ud.pad, hdr.cover_ud.bcrc,
                m.residual });
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.cover_dl);   /* PREPENDED cover — valid only on covered responses */
        pkt.emit(hdr.cover_ud);
        /* the real DNP3 frame follows automatically as the unparsed residual */
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

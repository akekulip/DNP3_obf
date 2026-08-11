/* ============================================================================
 * defense4_joint_canon.p4 — Defense 4 JOINT timing + size core, Tofino-1 / TNA.
 * Successor of defense4_joint.p4 (SHA 55e6927e…): replaces the fixed-constant-pad
 * egress kernel with the REAL canonical size transform. Ground truth:
 * defense4/size/offline/canonical_response.py (canonicalize()); byte-proven by the
 * mirror emulator defense4/size/offline/p4_egress_emulator.py (3/3 vs the oracle).
 * Authority: defense4/size/JOINT_DEFENSE_SPEC.md.
 *
 * INGRESS (Layer 0): the silicon-validated unified timing core, COPIED VERBATIM
 *   from DNP3/defense4/timing/p4/defense4_timing.p4. NOT MODIFIED — the exhausted
 *   ingress PHV (B0-15 / W0-15) gains no new operand.
 *
 * EGRESS (Layer S): size-canonicalizer + per-flow SIGNED seq/ack translator.
 *   The response is rewritten to the ONE public canonical form (G30 variation V3,
 *   32-bit no-flag, fixed range [start,7], every DNP3 CRC recomputed) so the wire
 *   SHAPE no longer identifies the device model. Per-response byte delta Δ is now the
 *   REAL, VARIABLE, SIGNED value (not a compile-time constant):
 *     * CLS_RESP_V3 (sport 20000, ip.len 94): device already V3/54 B -> pass-through,
 *       Δ = 0; recompute link+block0 CRC (to the same value) and forward.
 *     * CLS_RESP_V1 (sport 20000, ip.len 101): device is V1/61 B -> SHRINK to V3/54 B
 *       by stripping the 7 interior per-point flag octets and re-blocking; Δ = -7.
 *       Interior byte removal via field-precise carving (v1b0/v1b1/v1b2); the value
 *       that straddles a DNP3 CRC block (point 4) is carved val4hi/val4lo. The 54 B
 *       V3 output (v3ba/v3bb/v3bc + CRCs) is populated from those values + constant
 *       object header, and the V1 input headers are NOT emitted (that IS the shrink).
 *   Mechanics:
 *     1. Re-hash the direction-normalized 5-tuple to flow_idx (egress Hash extern).
 *     2. reg_delta[flow_idx] (bit<32>, two's-complement): CLS_RESP_V1 bumps by
 *        DELTA_V1 = -7 (returns delta_old); CLS_RESP_V3/ACK read (no bump); reset on
 *        SYN/FIN/RST. The seq/ack fixup is a single signed add of a PRECOMPUTED
 *        addend — Δ is a register value, never an addend inside the checksum math,
 *        so the wholesale checksum sidesteps the runtime-carry ICE.
 *     3. reg_last_resp_seq + reg_dlast[flow_idx] = the spec's (reg_last_resp_seq,
 *        Δ_at_last) pair: a retransmit of the stored response seq does NOT re-bump
 *        reg_delta and reuses the EXACT delta_old it was first sent with (needed now
 *        that Δ is variable — the old "delta - CONST" trick no longer generalizes).
 *     4. Direction-selected: outstation->master seq += seq_add; master->outstation
 *        ack -= delta (signed; Δ<0 => ack grows back to the outstation's numbering).
 *     5. Deparser recomputes IPv4 + TCP checksums WHOLESALE over the emitted bytes
 *        (empty residual, both length classes POV-gated) + every DNP3 CRC.
 *
 * The joint program DELIBERATELY breaks the timing core's byte-preservation on the
 * response side; application correctness is a WIRE-gate obligation, not inherited.
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
 *              EGRESS  —  Layer S (canonical size + signed seq/ack)         *
 * ======================================================================== */
const bit<16> PORT_DNP3 = 16w20000;      /* outstation listen port */

/* ---- response length classes (ipv4.total_len, dofs=5, sport=20000) ---- */
const bit<16> LEN_BARE    = 16w40;       /* pure ACK / bare control: no TCP payload */
const bit<16> LEN_RESP_V3 = 16w94;       /* 54 B DNP3 V3 response (already canonical) */
const bit<16> LEN_RESP_V1 = 16w101;      /* 61 B DNP3 V1 response (shrinks to 54 B) */

const bit<8> CLS_NONE    = 8w0;          /* unhandled -> fail open */
const bit<8> CLS_RESP_V3 = 8w1;          /* V3 pass-through, Δ=0 */
const bit<8> CLS_BARE    = 8w2;          /* no-payload TCP segment */
const bit<8> CLS_RESP_V1 = 8w3;          /* V1 -> V3 shrink, Δ=-7 (ELIGIBLE G30/V1 object only) */
const bit<8> CLS_RESP_V1_PASS = 8w4;     /* 61 B V1-LENGTH but NON-eligible object -> pass through verbatim, Δ bump 0 */

/* ---- the REAL, VARIABLE, SIGNED per-response delta (two's complement) ---- */
const bit<32> DELTA_V1 = 32w0xFFFFFFF9;  /* -7: V1->V3 removes 7 interior flag octets */

/* ---- public canonical object-header constants (mirror canonical_response.py) ---- */
const bit<8> VAR3     = 8w0x03;          /* G30 variation 3 (32-bit, no per-point flag) */
const bit<8> PUB_STOP = 8w0x07;          /* public canonical stop index */
const bit<8> LEN_OCT_V3 = 8w0x2B;        /* DNP3 link length octet for the 54 B canonical frame */
const bit<16> IPLEN_V3  = 16w94;         /* ipv4.total_len of the 54 B canonical response */

struct eg_meta_t {
    bit<10> flow_idx;
    bit<32> nm_ip; bit<32> nr_ip; bit<16> nm_pt; bit<16> nr_pt;
    bit<16> flow_wide;
    bit<8>  cls;         /* CLS_* : which length class the parser matched */
    bit<8>  dir;         /* DIR_MASTER (master->out) / DIR_OUT (out->master) */
    bit<8>  is_ctl;      /* SYN/FIN/RST present */
    bit<8>  is_retx;     /* retransmit of the stored last-response seq */
    bit<1>  translated;  /* seq or ack rewritten -> recompute checksums (deparser cond is 1-bit) */
    bit<16> tcp_len;     /* pseudo-header TCP length (TCP header + OUTPUT payload) */
    bit<32> delta;       /* cumulative signed delta read from reg_delta (old value on a bump) */
    bit<32> seq_add;     /* seq addend, precomputed single-op (retx reuses stored Δ_at_last) */
}

/* ============================ egress parser ============================= */
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t m,
                out egress_intrinsic_metadata_t eg) {
    state start {
        pkt.extract(eg);
        m.flow_idx = 10w0; m.nm_ip = 32w0; m.nr_ip = 32w0; m.nm_pt = 16w0; m.nr_pt = 16w0;
        m.flow_wide = 16w0; m.cls = CLS_NONE; m.dir = DIR_MASTER; m.is_ctl = 8w0;
        m.is_retx = 8w0; m.translated = 1w0; m.tcp_len = 16w0; m.delta = 32w0; m.seq_add = 32w0;
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) { ETYPE_IPV4 : parse_ipv4; default : accept; }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.proto, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;
            default             : accept;
        }
    }
    /* Length-class select is placed IN the tcp-extract state (a post-tcp select on total_len is a
     * known bf-p4c 9.13.x parser failure mode). Classified by (dofs, total_len): a 94/101-byte dofs-5
     * segment is a V3/V1 outstation RESPONSE by the DNP3 poll contract (master->outstation carries only
     * small requests + ACKs, never these lengths). Direction is resolved in the control (e_dir/sport);
     * the seq/ack translation and reg_delta bump are dir-gated there. Adding sport to THIS select would
     * need a 2nd 16-bit parser match register (device has 1) — out of the contract's reach and
     * unnecessary. */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dofs, hdr.ipv4.total_len) {
            (4w5, LEN_RESP_V3) : c_resp_v3;
            (4w5, LEN_RESP_V1) : c_resp_v1;
            (4w5, LEN_BARE)    : c_bare;
            default            : accept;   /* fail open: no chunking, no rewrite */
        }
    }
    state c_bare { m.cls = CLS_BARE; m.tcp_len = 16w20; transition accept; }
    /* V3 pass-through: descending extraction dl(10)+db(18)+16+8+2 = 54 B -> residual EMPTY */
    state c_resp_v3 {
        pkt.extract(hdr.dl);
        pkt.extract(hdr.db);
        pkt.extract(hdr.p16);
        pkt.extract(hdr.p8);
        pkt.extract(hdr.p2);
        m.cls = CLS_RESP_V3; m.tcp_len = 16w74; transition accept;
    }
    /* V1 length class: carve the 61 B on its wire block+CRC boundaries -> residual EMPTY
     * (10 + (16+2) + (16+2) + (13+2) = 61 B), THEN gate on the parsed object header. The select is
     * placed RIGHT AFTER v1b0 so its match values (grp/var/qual/start, wire offsets 15..18) are fresh
     * in the match-register file ($half + 2x$byte8 = 32 bits). Only the EXACT eligible object
     * (G30 / var 0x01 / qual 0x00 / start 0x01) is the canonical-shrink class; every other 61 B
     * segment (G32, G30-but-V2, non-DNP3) is length-matched but NON-eligible and passes through
     * VERBATIM (matches canonical_response.transform_or_passthrough). stop is length-implied
     * (61 B => 7 points => stop = start + 6), so the select need not test it. */
    state c_resp_v1 {
        pkt.extract(hdr.dl);
        pkt.extract(hdr.v1b0);
        transition select(hdr.v1b0.grp, hdr.v1b0.var, hdr.v1b0.qual, hdr.v1b0.start) {
            (8w0x1E, 8w0x01, 8w0x00, 8w0x01) : c_v1_elig;
            default                          : c_v1_pass;
        }
    }
    /* eligible: the v1b/v1c carving is consumed then dropped by the deparser (that IS the -7 B shrink) */
    state c_v1_elig {
        pkt.extract(hdr.v1c0);
        pkt.extract(hdr.v1b1); pkt.extract(hdr.v1c1);
        pkt.extract(hdr.v1b2); pkt.extract(hdr.v1c2);
        m.cls = CLS_RESP_V1; m.tcp_len = 16w74;   /* OUTPUT is 54 B -> tcp_len = 20 + 54 */
        transition accept;
    }
    /* NON-eligible: identical carving, but the v1b/v1c headers are EMITTED verbatim (61 B out) */
    state c_v1_pass {
        pkt.extract(hdr.v1c0);
        pkt.extract(hdr.v1b1); pkt.extract(hdr.v1c1);
        pkt.extract(hdr.v1b2); pkt.extract(hdr.v1c2);
        m.cls = CLS_RESP_V1_PASS; m.tcp_len = 16w81;   /* OUTPUT is 61 B verbatim -> tcp_len = 20 + 61 */
        transition accept;
    }
}

/* ============================ egress control =========================== */
control Egress(inout headers_t hdr, inout eg_meta_t m,
               in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t prsr,
               inout egress_intrinsic_metadata_for_deparser_t dprsr,
               inout egress_intrinsic_metadata_for_output_port_t oport) {

    /* ---- direction + canonical bidirectional flow fold in ONE table (keyed on the DNP3 port), so
     *      the direction bit and the direction-normalized (master-side, relay-side) tuple are set
     *      together — saves a serial stage vs a separate e_dir table. Both directions of a flow yield
     *      the SAME normalized tuple, hence the same flow_idx / reg_delta cell. ---- */
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

    /* ---- reg_delta: cumulative per-flow SIGNED byte offset (keyed flow_idx) ---- */
    Register<bit<32>, bit<10>>(1024, 0) reg_delta;
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_delta) delta_bump_v1 = { /* V1 response: shrink -7 */
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = v + DELTA_V1; }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_delta) delta_read = {    /* ACK / V3 / retransmit */
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_delta) delta_reset = {   /* SYN/FIN/RST */
        void apply(inout bit<32> v, out bit<32> rv) { rv = 32w0; v = 32w0; }
    };

    /* ---- reg_last_resp_seq: retransmit-of-last detection (keyed flow_idx) ----
     * returns 1 iff this response repeats the stored seq (a retransmit); otherwise stores the new
     * seq and returns 0. On a retransmit the delta is NOT re-bumped. */
    Register<bit<32>, bit<10>>(1024, 0) reg_last_resp_seq;
    RegisterAction<bit<32>, bit<10>, bit<8>>(reg_last_resp_seq) lastseq_update = {
        void apply(inout bit<32> v, out bit<8> rv) {
            if (v == hdr.tcp.seq) { rv = 8w1; }
            else { rv = 8w0; v = hdr.tcp.seq; }
        }
    };

    /* ---- reg_dlast = Δ_at_last: the exact delta_old a response was first sent with, so a
     * retransmit renumbers identically even though Δ is now variable (spec's (last_seq, Δ_at_last)) ---- */
    Register<bit<32>, bit<10>>(1024, 0) reg_dlast;
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_dlast) dlast_store = { /* new response: save delta_old */
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = m.delta; }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_dlast) dlast_load = {  /* retransmit: reuse it */
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* ---- DNP3 CRC-16/DNP via the native CRCPolynomial hash extern (MAU). A CUSTOM (dynamic) hash
     *      instance must be called with a SINGLE get(), so the two response classes use DISTINCT
     *      instances for their (identical-field-list) link CRC. ---- */
    CRCPolynomial<bit<16>>(16w0x3D65, true, false, false, 16w0x0000, 16w0xFFFF) dnp3_poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, dnp3_poly) h_dlcrc;    /* V3: 8-byte link header */
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, dnp3_poly) h_blkcrc;   /* V3: first 16-byte user block */
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, dnp3_poly) h_dlcrc_v1; /* V1->V3: 8-byte link header */
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, dnp3_poly) h_ba;       /* V1->V3: canonical block A */
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, dnp3_poly) h_bb;       /* V1->V3: canonical block B */
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, dnp3_poly) h_bc;       /* V1->V3: canonical block C */

    /* ---- V1->V3 field fill, split per block so no single action mixes constant action-data with a
     *      hash (a keyless table cannot host both). Each populates one canonical block + its POV. ---- */
    action fill_a() {
        hdr.v3ba.setValid(); hdr.v3ca.setValid();
        hdr.v3ba.t     = hdr.v1b0.t;
        hdr.v3ba.ac    = hdr.v1b0.ac;
        hdr.v3ba.f     = hdr.v1b0.f;
        hdr.v3ba.iin   = hdr.v1b0.iin;
        hdr.v3ba.grp   = hdr.v1b0.grp;            /* preserved (0x1E) */
        hdr.v3ba.var   = VAR3;                    /* rewritten 0x01 -> 0x03 */
        hdr.v3ba.qual  = hdr.v1b0.qual;           /* preserved (0x00) */
        hdr.v3ba.start = hdr.v1b0.start;          /* preserved */
        hdr.v3ba.stop  = PUB_STOP;                /* public canonical stop */
        hdr.v3ba.v0    = hdr.v1b0.val0;
        hdr.v3ba.v1hi  = hdr.v1b1.val1[31:16];
        hdr.v1b2.setInvalid(); hdr.v1c2.setInvalid();   /* drop V1 input (not read here) -> the shrink */
    }
    table t_fill_a { actions = { fill_a; } const default_action = fill_a(); size = 1; }
    action fill_b() {
        hdr.v3bb.setValid(); hdr.v3cb.setValid();
        hdr.v3bb.v1lo = hdr.v1b1.val1[15:0];
        hdr.v3bb.v2   = hdr.v1b1.val2;
        hdr.v3bb.v3   = hdr.v1b1.val3;
        hdr.v3bb.v4hi = hdr.v1b1.val4hi;          /* the byte before crc1 */
        hdr.v3bb.v4lo = hdr.v1b2.val4lo;          /* the 3 bytes after crc1 */
        hdr.v3bb.v5hi = hdr.v1b2.val5[31:16];
        hdr.v1b0.setInvalid(); hdr.v1c0.setInvalid();   /* drop V1 input (not read here) -> the shrink */
    }
    table t_fill_b { actions = { fill_b; } const default_action = fill_b(); size = 1; }
    action fill_c() {
        hdr.v3bc.setValid(); hdr.v3cc.setValid();
        hdr.v3bc.v5lo      = hdr.v1b2.val5[15:0];
        hdr.v3bc.v6        = hdr.v1b2.val6;
        hdr.dl.len         = LEN_OCT_V3;          /* 54 B canonical link length octet */
        hdr.ipv4.total_len = IPLEN_V3;            /* 94 B canonical ip.total_len */
        hdr.v1b1.setInvalid(); hdr.v1c1.setInvalid();   /* drop V1 input (not read here) -> the shrink */
    }
    table t_fill_c { actions = { fill_c; } const default_action = fill_c(); size = 1; }

    apply {
        e_fold.apply();          /* direction + normalized tuple (folds the old e_dir stage in) */
        e_flow_idx.apply();
        e_cut_tbl.apply();
        e_ctl.apply();

        /* ---- retransmit-of-last detection: only outstation->master responses probe it ---- */
        if ((m.cls == CLS_RESP_V3 || m.cls == CLS_RESP_V1) && m.is_ctl == 8w0 && m.dir == DIR_OUT) {
            m.is_retx = lastseq_update.execute(m.flow_idx);
        }

        /* ---- reg_delta: EXACTLY ONE access, role-selected (mirrors the ingress discipline) ---- */
        if (m.is_ctl == 8w1) {
            m.delta = delta_reset.execute(m.flow_idx);
        } else if (m.cls == CLS_RESP_V1 && m.is_retx == 8w0 && m.dir == DIR_OUT) {
            m.delta = delta_bump_v1.execute(m.flow_idx);   /* returns delta_old, adds -7 */
        } else {
            m.delta = delta_read.execute(m.flow_idx);      /* V3 responses, ACKs, requests, retransmits */
        }

        /* ---- seq addend: default = cumulative delta_old; a retransmit reuses the stored Δ_at_last;
         *      a fresh response stores its delta_old for a future retransmit. ONE reg_dlast access. ---- */
        m.seq_add = m.delta;
        if ((m.cls == CLS_RESP_V3 || m.cls == CLS_RESP_V1) && m.is_ctl == 8w0 && m.dir == DIR_OUT) {
            if (m.is_retx == 8w1) { m.seq_add = dlast_load.execute(m.flow_idx); }
            else                  { dlast_store.execute(m.flow_idx); }
        }

        /* ---- direction-selected SIGNED seq/ack translation (skip control packets) ----
         * CLS_RESP_V1_PASS (non-eligible passthrough) is INCLUDED here: its Δ contribution is 0 (it took
         * delta_read above, no bump), but the flow's ACCUMULATED delta from prior real transforms must
         * still shift its seq/ack so the master's sequence space stays consistent. Only the CONTENT
         * rewrite and the Δ bump are skipped for a passthrough packet, never the seq translation. */
        if (m.is_ctl == 8w0 && (m.cls == CLS_RESP_V3 || m.cls == CLS_RESP_V1 || m.cls == CLS_RESP_V1_PASS || m.cls == CLS_BARE)) {
            if (m.dir == DIR_OUT) {
                hdr.tcp.seq = hdr.tcp.seq + m.seq_add;      /* single signed add (addend precomputed) */
            } else {
                hdr.tcp.ack = hdr.tcp.ack - m.delta;        /* Δ<0 => ack grows back to outstation view */
            }
            m.translated = 1w1;
        }

        /* ==================== V1 -> V3 CANONICALIZE (the shrink) ==================== *
         * Lift the 7 point VALUES out of the V1 carving (flags discarded) into the public V3 blocks
         * with a constant object header (var=03, stop=07), rewrite the link length octet + ip.total_len
         * to the 54 B canonical size, and recompute every DNP3 block CRC. The V1 input headers are left
         * un-emitted by the deparser -> the frame shrinks by exactly 7 B. Fills are in their own tables
         * (constant action-data); the CRC hashes are separate MAU hash ops (no action-data). */
        if (m.cls == CLS_RESP_V1) {
            t_fill_a.apply();
            t_fill_b.apply();
            t_fill_c.apply();
            bit<16> ca = h_ba.get({ hdr.v3ba.t, hdr.v3ba.ac, hdr.v3ba.f, hdr.v3ba.iin,
                                    hdr.v3ba.grp, hdr.v3ba.var, hdr.v3ba.qual, hdr.v3ba.start,
                                    hdr.v3ba.stop, hdr.v3ba.v0, hdr.v3ba.v1hi });
            hdr.v3ca.crc = ca[7:0] ++ ca[15:8];
            bit<16> cb = h_bb.get({ hdr.v3bb.v1lo, hdr.v3bb.v2, hdr.v3bb.v3,
                                    hdr.v3bb.v4hi, hdr.v3bb.v4lo, hdr.v3bb.v5hi });
            hdr.v3cb.crc = cb[7:0] ++ cb[15:8];
            bit<16> cc = h_bc.get({ hdr.v3bc.v5lo, hdr.v3bc.v6 });
            hdr.v3cc.crc = cc[7:0] ++ cc[15:8];
            bit<16> cl = h_dlcrc_v1.get({ hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src });
            hdr.dl.crc = cl[7:0] ++ cl[15:8];
        }
        /* ==================== V3 pass-through: re-CRC link + block0 (to the same value) ==== *
         * No DNP3 byte changes (device already emits the public canonical form), so the recompute
         * reproduces the original CRC; it proves the V3 CRC path co-compiles and keeps the output a
         * well-formed frame. Blocks 1..2 (p16/p8/p2) are MAU-untouched and their CRCs stay valid. */
        else if (m.cls == CLS_RESP_V3) {
            bit<16> c_dl = h_dlcrc.get({ hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src });
            hdr.dl.crc = c_dl[7:0] ++ c_dl[15:8];
            bit<16> c_bk = h_blkcrc.get({ hdr.db.transport, hdr.db.app_ctrl, hdr.db.func, hdr.db.iin, hdr.db.obj0 });
            hdr.db.bcrc = c_bk[7:0] ++ c_bk[15:8];
        }
    }
}

/* ============================ egress deparser ========================== */
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t m,
                   in egress_intrinsic_metadata_for_deparser_t dprsr) {
    Checksum() ipv4_csum;
    Checksum() tcp_csum;
    apply {
        /* Wholesale recompute only when we rewrote a header field. The residual is EMPTY for every
         * translated class (bare = no payload; V3 = fully chunked; V1 = canonical blocks), so update()
         * covers the whole segment; invalid chunk/canonical headers are POV-excluded automatically. */
        if (m.translated == 1w1) {
            hdr.ipv4.csum = ipv4_csum.update({
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.total_len,
                hdr.ipv4.id, hdr.ipv4.flags, hdr.ipv4.frag, hdr.ipv4.ttl, hdr.ipv4.proto,
                hdr.ipv4.src, hdr.ipv4.dst });
            hdr.tcp.csum = tcp_csum.update({
                /* TCP pseudo-header */
                hdr.ipv4.src, hdr.ipv4.dst, 8w0, hdr.ipv4.proto, m.tcp_len,
                /* TCP header (checksum field excluded) */
                hdr.tcp.sport, hdr.tcp.dport, hdr.tcp.seq, hdr.tcp.ack,
                hdr.tcp.dofs, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.win, hdr.tcp.urg,
                /* TCP payload (POV-gated; exactly one payload class is valid per packet): the V1
                 * VERBATIM passthrough carving, the V3-passthrough chunks, AND the V1->V3 canonical
                 * blocks. Listed in wire order so the non-eligible class (dl + v1b/v1c = 61 B) sums
                 * with correct byte alignment. */
                hdr.dl,
                hdr.v1b0, hdr.v1c0, hdr.v1b1, hdr.v1c1, hdr.v1b2, hdr.v1c2,
                hdr.db, hdr.p16, hdr.p8, hdr.p4, hdr.p2, hdr.p1,
                hdr.v3ba, hdr.v3ca, hdr.v3bb, hdr.v3cb, hdr.v3bc, hdr.v3cc });
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.dl);      /* link header: present for every response class */
        /* NON-eligible 61 B V1-length passthrough: emit the carved input VERBATIM. These are valid ONLY
         * on CLS_RESP_V1_PASS; on the eligible-shrink class they are setInvalid in the fills, and on the
         * V3 class they are never extracted -> POV-excluded here. */
        pkt.emit(hdr.v1b0);
        pkt.emit(hdr.v1c0);
        pkt.emit(hdr.v1b1);
        pkt.emit(hdr.v1c1);
        pkt.emit(hdr.v1b2);
        pkt.emit(hdr.v1c2);
        /* V3 pass-through payload (invalid on a V1 packet) */
        pkt.emit(hdr.db);
        pkt.emit(hdr.p16);
        pkt.emit(hdr.p8);
        pkt.emit(hdr.p4);
        pkt.emit(hdr.p2);
        pkt.emit(hdr.p1);
        /* V1->V3 canonical payload (invalid unless eligible-shrink). On the eligible class the v1b/v1c
         * inputs are dropped (setInvalid in the fills) -> the frame shrinks by exactly 7 B. */
        pkt.emit(hdr.v3ba);
        pkt.emit(hdr.v3ca);
        pkt.emit(hdr.v3bb);
        pkt.emit(hdr.v3cb);
        pkt.emit(hdr.v3bc);
        pkt.emit(hdr.v3cc);
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

/* ============================================================================
 * mb1_v2_unified_core.p4 — MB-1 v2, the SEMANTICALLY-COMPLETE combined INGRESS
 *   compile for the Defense 4 feasibility. NON-FROZEN probe under defense4/p4/.
 *   Nothing is loaded or run; this answers ONE question: does the corrected,
 *   semantically-complete unified timing + SBO + slot + SIZE-CONTROL ingress core
 *   fit the Tofino-1 ingress, and in how many stages?
 *
 * This is the corrected successor to mb1_unified_skeleton.p4 (10 ing / CP 9), which
 * a 2026-08-04 review found to be a PLACEHOLDER: its 10-stage number is only a lower
 * bound. This file applies ALL nine required corrections (each tagged "CORRECTION N"
 * inline). If the honest stage count exceeds 12 that is a VALID, important result and
 * is reported as-is; no required semantic is dropped to force it under 12.
 *
 * DESIGN DISCIPLINE (kept from the skeleton so the stage count is honest, not a
 * placement artifact):
 *   - every value that COMBINES a just-read/just-computed value lives in its OWN
 *     single-action table (bf-p4c else merges consecutive statements into one action
 *     and rejects the intra-action dependency as "action spanning multiple stages").
 *   - sign / mask tests are ternary TCAM masks over a WHOLE container, never a
 *     bit-slice of an arithmetic field.
 *   - each Register has <=2 PHV inputs per RegisterAction and ONE access per packet.
 *
 * WHAT IS PRESENT (all size-control CONTROL surface, as in the skeleton): configurable
 * release predicates, READ/SELECT/OPERATE phase FSM, SELECT->OPERATE linkage by
 * internal generation, generation-safe matching + cleanup, slot bitmap + slot-clock,
 * size_profile + per-slot size lookup, outer-header field writes, real/filler tag.
 * WHAT IS EXCLUDED (permitted): the PHYSICAL padding byte-append (egress; the memory
 * result [[tofino1-egress-size-normalization-coresidency]] prices it at ~2-4 egress
 * stages, ZERO ingress) and detailed latency telemetry.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;
const bit<16> ETHERTYPE_IPV4        = 0x0800;
const bit<8>  IP_PROTO_TCP          = 8w6;

/* ---- DNP3 function codes ---- */
const bit<16> DNP3_START        = 0x0564;
const bit<8>  DNP3_FC_READ      = 8w1;
const bit<8>  DNP3_FC_SELECT    = 8w3;    /* SBO SELECT   */
const bit<8>  DNP3_FC_OPERATE   = 8w4;    /* SBO OPERATE  */
const bit<8>  DNP3_FC_RESPONSE  = 8w129;  /* both SELECT-response AND OPERATE-response */

/* ---- roles ---- */
const bit<8> ROLE_BYPASS   = 0;
const bit<8> ROLE_BLOCK    = 1;   /* ACK-reservoir blocker token   */
const bit<8> ROLE_RESP     = 2;   /* DNP3 func-129 (O->M)          */
const bit<8> ROLE_SELECT   = 3;   /* DNP3 SELECT  (M->O)           */
const bit<8> ROLE_OPERATE  = 4;   /* DNP3 OPERATE (M->O)           */
const bit<8> ROLE_RESP_BLK = 5;   /* RESPONSE-reservoir blocker token (CORRECTION 8) */
const bit<8> ROLE_ARM      = 6;   /* DNP3 READ    (M->O)           */
const bit<8> ROLE_ACK      = 7;   /* pure TCP ACK (O->M)           */

/* ---- direction ---- */
const bit<8> DIR_MASTER = 0;
const bit<8> DIR_OUT    = 1;

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;
const PortId_t PORT_VISION = 9w9;
const PortId_t PORT_HULK   = 9w11;
const PortId_t PORT_RELAY  = 9w64;
const PortId_t PORT_PGEN   = 9w68;

/* ---- CORRECTION 8: FOUR queues, strict priority 7 > 5 > 3 > 0 ----
 * QID_ACK_BLOCK  holds the ACK's reservoir (highest, so the ACK-hold cannot dequeue
 *   past its own blockers), QID_ACK_HOLD parks the held ACK, then the RESPONSE pair
 *   below it — encoding the ACK-before-RESPONSE ordering invariant on one port. */
const bit<5> QID_ACK_BLOCK  = 5w7;
const bit<5> QID_ACK_HOLD   = 5w5;
const bit<5> QID_RESP_BLOCK  = 5w3;
const bit<5> QID_RESP_HOLD   = 5w0;

/* ---- pktgen ---- */
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
const bit<32> DL_CLEAR     = 32w0;
const bit<8>  TAG_INACTIVE = 8w0xFF;

/* ---- packet classes (timing decode) ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;
const bit<8> CLASS_ACK       = 8w2;
const bit<8> CLASS_BLOCK_DEQ = 8w3;

/* ---- SBO phase FSM states (CORRECTION 3) ---- */
const bit<8> PH_IDLE         = 8w0;
const bit<8> PH_SELECT_SEEN  = 8w1;
const bit<8> PH_OPERATE_SEEN = 8w2;

/* ---- release modes (selected by tbl_params) ---- */
const bit<8> MODE_IMMEDIATE    = 8w0;  /* D1a: forward now                        */
const bit<8> MODE_MATCH_EVENT  = 8w1;  /* D1b: hold until matching response event */
const bit<8> MODE_ABS_DEADLINE = 8w2;  /* D2 / D3: hold until t_ack + G           */
const bit<8> MODE_PRED_OFFSET  = 8w3;  /* grid: release at predecessor + offset   */
const bit<8> MODE_FAIL_OPEN    = 8w4;  /* bounded backstop override               */

/* ---- release decision ---- */
const bit<8> REL_HOLD    = 8w0;
const bit<8> REL_RELEASE = 8w1;

/* ---- real / filler tag ---- */
const bit<8> RF_FILL = 8w0;
const bit<8> RF_REAL = 8w1;

/* ---- booleans ---- */
const bit<8> B_TRUE  = 8w1;
const bit<8> B_FALSE = 8w0;

/* ---- slot geometry: 32 slots per epoch ---- */
const bit<8>  SLOT_MASK = 8w0x1F;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header recirc_tag_h { bit<32> tag; }

/* CORRECTION 1/8: the blocker token now carries its own flow id (16b, low 10 used) so
 * the recirculating/dequeued reservoir path can index the SAME per-flow registers the
 * host path armed — without recomputing a hash it cannot (no IP/TCP on a token). */
header ibspg_h { bit<8> role; bit<8> slot; bit<8> gen; bit<16> flow; bit<32> seq; }

/* prepended outer encapsulation carrying the SIZE-CONTROL representation (control only;
 * the physical byte-append lives in egress and is excluded here). */
header outer_encap_h {
    bit<8>  direction;    /* DIR_MASTER / DIR_OUT                 */
    bit<8>  txn_tag;      /* internal transaction generation     */
    bit<8>  slot_id;      /* assigned grid slot                  */
    bit<8>  realfill;     /* RF_REAL / RF_FILL                   */
    bit<16> size_bytes;   /* per-slot target size (control only) */
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
    outer_encap_h outer;
    ethernet_h    eth;
    ibspg_h       ib;
    ipv4_h        ipv4;
    tcp_h         tcp;
    tcp_opt4_h    tcp_opt4;
    tcp_opt8_h    tcp_opt8;
    tcp_opt12_h   tcp_opt12;
    dnp3_dl_h     dnp3_dl;
    dnp3_tp_h     dnp3_tp;
    dnp3_app_h    dnp3_app;
}

struct ig_meta_t {
    /* parser classification */
    bit<8>  role;
    bit<8>  dir;
    bit<9>  fwd_port;
    bit<8>  port_ok;
    bit<8>  dequeued;
    bit<8>  is_pktgen;
    bit<8>  budget_zero;

    /* CORRECTION 1: flow key */
    bit<16> flow_wide;       /* 16-bit flow carrier (host: CRC hash; token: hdr.ib.flow) */
    bit<10> flow_idx;        /* flow_wide[9:0], the 1024-entry register index            */

    /* CORRECTION 2: internal generation (from reg_tag), NOT DNP3 app_control */
    bit<8>  gen_cur;         /* current internal generation for this flow                */
    bit<8>  tokgen;          /* a dequeued token's carried generation                    */
    bit<8>  app_seq;         /* parsed DNP3 app_control — kept for reference, NOT a key   */

    /* timing core */
    bit<32> ts_m;
    bit<32> now_word;
    bit<32> guard_ticks;
    bit<8>  pkt_class;
    bit<32> dl_cand_abs;
    bit<32> dl_cand_slot;
    bit<32> dl_cand;
    bit<8>  tag_diff;        /* reg_tag SALU result (token liveness on block path)       */
    bit<32> dl_val;          /* value to arm reg_deadline with                           */
    bit<8>  ack_ok;
    bit<32> age;
    bit<8>  expired;

    /* CORRECTION 3: SBO phase FSM */
    bit<8>  phase_old;       /* reg_phase pre-state (drives SELECT-resp vs OPERATE-resp) */
    bit<8>  phase_next;      /* FSM target for the parameterized write (role/dir-derived) */
    bit<8>  linkage_ok;      /* OPERATE matched an outstanding SELECT                     */
    bit<8>  is_response;     /* ROLE_RESP, for the release predicate                     */

    /* CORRECTION 4: ack_gone */
    bit<8>  ack_released;    /* reg_ack_gone read: the flow's ACK reservoir has drained  */

    /* release-mode surface */
    bit<8>  mode;
    bit<32> slot_off_ticks;
    bit<8>  event_diff;
    bit<8>  event_due;
    bit<8>  release;

    /* cleanup */
    bit<8>  cleanup_trig;    /* CORRECTION 9: FIN/RST -> wipe this flow's per-txn state   */

    /* slot surface */
    bit<8>  is_real;         /* CORRECTION 6: role-based, gates the bitmap (breaks cycle) */
    bit<8>  cur_slot;
    bit<8>  slot_id;
    bit<32> slot_onehot;
    bit<8>  slot_occupied;   /* CORRECTION 6: the ACTUAL bitmap result                    */
    bit<8>  epoch_rollover;  /* CORRECTION 7: slot clock wrapped -> clear bitmap          */

    /* size surface */
    bit<8>  size_profile;
    bit<16> size_bytes;

    /* trusted-representation tag + pktgen */
    bit<8>     realfill;
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
        /* whole-struct zero-init in the start block: this is the parser-only fix for the
         * uninitialized_out_param warning class, and (measured on 9.13.1) reassigning
         * these paths later is NOT a double-assign error. */
        /* NB: fields that a parser STATE also assigns (role, dir, fwd_port, port_ok,
         * dequeued, is_pktgen, flow_wide, tokgen, app_seq) are deliberately NOT
         * initialized here — the Tofino parser forbids writing the same field twice
         * (clear-on-write), and several of these overlay deparsed header fields. They are
         * assigned exactly once on each path below; their zero defaults are the safe ones
         * (ROLE_BYPASS==0, port_ok==0 => drop). Only MAU-written metadata is zeroed here. */
        meta.budget_zero     = 8w0;
        meta.flow_idx        = 10w0;
        meta.gen_cur         = 8w0;
        meta.ts_m            = 32w0;
        meta.now_word        = 32w0;
        meta.guard_ticks     = 32w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.dl_cand_abs     = 32w0;
        meta.dl_cand_slot    = 32w0;
        meta.dl_cand         = 32w0;
        meta.tag_diff        = 8w0;
        meta.dl_val          = DL_NO_WRITE;
        meta.ack_ok          = 8w0;
        meta.age             = 32w0;
        meta.expired         = 8w0;
        meta.phase_old       = PH_IDLE;
        meta.phase_next      = PH_IDLE;
        meta.linkage_ok      = 8w0;
        meta.is_response     = 8w0;
        meta.ack_released    = 8w0;
        meta.mode            = MODE_IMMEDIATE;
        meta.slot_off_ticks  = 32w0;
        meta.event_diff      = 8w0;
        meta.event_due       = 8w0;
        meta.release         = REL_HOLD;
        meta.cleanup_trig    = 8w0;
        meta.is_real         = 8w0;
        meta.cur_slot        = 8w0;
        meta.slot_id         = 8w0;
        meta.slot_onehot     = 32w0;
        meta.slot_occupied   = 8w0;
        meta.epoch_rollover  = 8w0;
        meta.size_profile    = 8w0;
        meta.size_bytes      = 16w0;
        meta.realfill        = RF_FILL;
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

    /* CORRECTION 1: a dequeued/generated blocker carries its flow + generation, so the
     * reservoir path indexes the same per-flow reg_tag/reg_deadline the host armed. */
    state parse_token {
        pkt.extract(hdr.ib);
        meta.role      = hdr.ib.role;      /* ROLE_BLOCK (ACK res.) or ROLE_RESP_BLK (RESP res.) */
        meta.tokgen    = hdr.ib.gen;
        meta.flow_wide = hdr.ib.flow;
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

    /* CORRECTION 2: app_control is captured for reference only (meta.app_seq); it is
     * NEVER the linkage key. Role comes from func_code; the generation used for linkage,
     * timing, and cleanup is the INTERNAL counter read from reg_tag in the MAU. */
    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        meta.app_seq = hdr.dnp3_app.app_control;
        transition select(hdr.dnp3_app.func_code) {
            DNP3_FC_RESPONSE : set_role_resp;
            DNP3_FC_READ     : set_role_arm;
            DNP3_FC_SELECT   : set_role_select;
            DNP3_FC_OPERATE  : set_role_operate;
            default          : accept;
        }
    }
    state set_role_resp    { meta.role = ROLE_RESP;    transition accept; }
    state set_role_arm     { meta.role = ROLE_ARM;     transition accept; }
    state set_role_select  { meta.role = ROLE_SELECT;  transition accept; }
    state set_role_operate { meta.role = ROLE_OPERATE; transition accept; }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ===================== CORRECTION 1: flow hash ===================== *
     * ONE Hash instance, ONE tuple shape (constraint-class 7). CRC over the connection
     * 5-tuple, folded to the 1024-entry register space. */
    CRCPolynomial<bit<16>>(coeff=16w0x1021, reversed=false, msb=false, extended=false,
                           init=16w0xFFFF, xor=16w0x0000) flow_poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, flow_poly) flow_hash;
    action do_flow_hash() {
        meta.flow_wide = flow_hash.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
                                         hdr.tcp.src_port, hdr.tcp.dst_port,
                                         hdr.ipv4.protocol });
    }
    table tbl_flow_hash {
        actions = { do_flow_hash; }
        const default_action = do_flow_hash();
        size = 1;
    }
    /* fold to the 10-bit index in its own table (pure slice; no arithmetic combine) */
    action fold_flow() { meta.flow_idx = meta.flow_wide[9:0]; }
    table tbl_flow_fold {
        actions = { fold_flow; }
        const default_action = fold_flow();
        size = 1;
    }

    /* ============ CORRECTION 1 + 2 + 9: reg_tag ============ *
     * MERGED role: (a) per-flow INTERNAL GENERATION counter — incremented at a
     * transaction-opening request (READ or SELECT), read elsewhere; and (b) the armed
     * generation the reservoir tokens match against. Flow-indexed (1024). This replaces
     * the skeleton's depth-1 reg_tag AND removes any use of DNP3 app_control as a key. */
    Register<bit<8>, bit<10>>(1024, 0) reg_tag;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_open = {   /* READ/SELECT open */
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_get = {    /* host passive read */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_match = {  /* token liveness    */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v - meta.tokgen; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_clear = {  /* FIN/RST reset      */
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = 8w0; }
    };

    /* ============ CORRECTION 3: reg_phase — SBO FSM {IDLE, SELECT_SEEN, OPERATE_SEEN} ==
     * The func-129 handling is decided by the CURRENT state read here: phase_resp clears
     * to IDLE ONLY when the outstanding state is OPERATE_SEEN (that func-129 is the
     * OPERATE-response); when SELECT_SEEN it PRESERVES the state (that func-129 is the
     * SELECT-response — the skeleton wrongly cleared here). Single compare, fits a SALU. */
    /* NOTE: Tofino-1 allows at most 4 RegisterActions per Register. The SELECT / OPERATE
     * / READ / FIN-RST transitions all reduce to "write a role/dir-derived target", so
     * they collapse into ONE parameterized phase_set (target precomputed in meta.phase_next
     * at level 1 from constants — no just-read value combined). phase_resp (the func-129
     * SELECT-vs-OPERATE decision) and phase_read (passive) stay distinct => 3 actions. */
    Register<bit<8>, bit<10>>(1024, 0) reg_phase;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_phase) phase_set = {  /* SELECT/OPERATE/READ/FIN */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = meta.phase_next; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_phase) phase_resp = {     /* func-129 */
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (v == PH_OPERATE_SEEN) { v = PH_IDLE; }   /* OPERATE-resp completes txn   */
            /* else SELECT_SEEN/IDLE: PRESERVE the linkage (CORRECTION 3)                 */
        }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_phase) phase_read = {     /* passive */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* ============ reg_event — MATCH_EVENT (D1b), flow-indexed ============ *
     * The RESPONSE posts its generation; the OPERATE-response case (phase_old ==
     * OPERATE_SEEN) instead CLEARS (txn complete, CORRECTION 9). The ACK checks its
     * generation against the posted one. <=2 PHV inputs (phase_old, gen_cur). */
    Register<bit<8>, bit<10>>(1024, 0) reg_event;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_event) event_resp = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = 8w0;
            if (meta.phase_old == PH_OPERATE_SEEN) { v = 8w0; }        /* complete: clear */
            else                                   { v = meta.gen_cur; } /* post event    */
        }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_event) event_check = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = meta.gen_cur - v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_event) event_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = 8w0; }
    };

    /* ============ CORRECTION 4: reg_ack_gone — flow-indexed ============ *
     * Set to 1 on the ACK reservoir's terminate pass (its budget drained -> the held ACK
     * is dequeuing). Read on the RESPONSE pass, so the response-release predicate can
     * ANCHOR to the ACK's departure. Cleared on txn-complete / txn-open / FIN-RST. */
    Register<bit<8>, bit<10>>(1024, 0) reg_ack_gone;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ack_gone) ackgone_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = B_TRUE; rv = B_TRUE; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ack_gone) ackgone_resp = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;                                                   /* -> ack_released */
            if (meta.phase_old == PH_OPERATE_SEEN) { v = B_FALSE; }   /* complete: clear */
        }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ack_gone) ackgone_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = B_FALSE; rv = B_FALSE; }
    };

    /* ============ reg_deadline — ABS_DEADLINE / PRED_OFFSET, flow-indexed ============ */
    Register<bit<32>, bit<10>>(1024, 0) reg_deadline;
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val != DL_NO_WRITE) { v = meta.dl_val; }
        }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_deadline) deadline_arm_once = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (v == UNARMED_WORD) { v = meta.dl_val; }
        }
    };
    RegisterAction<bit<32>, bit<10>, bit<32>>(reg_deadline) deadline_clear = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = 32w0; v = DL_CLEAR; }
    };

    /* ============ reg_slot_clock — GLOBAL grid epoch (scheduler domain) ============ *
     * Justified global (per CORRECTION 1's allowance): the slot grid is one scheduler
     * domain shared by all flows; it is a phase reference, not per-transaction state. */
    Register<bit<8>, bit<1>>(1, 0) reg_slot_clock;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_slot_clock) slot_advance = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_slot_clock) slot_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* ============ reg_slot_bitmap — GLOBAL one-hot occupancy ============ *
     * CORRECTION 6: the return value is now CAPTURED into meta.slot_occupied.
     * CORRECTION 7: bitmap_clear rotates the grid at epoch rollover so occupancy does
     * not accumulate forever. */
    Register<bit<32>, bit<1>>(1, 0) reg_slot_bitmap;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_slot_bitmap) bitmap_test_set = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v & meta.slot_onehot;          /* nonzero => slot already occupied */
            v  = v | meta.slot_onehot;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_slot_bitmap) bitmap_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v & meta.slot_onehot; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_slot_bitmap) bitmap_clear = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = 32w0; }
    };

    /* ============ reg_active_flow — GLOBAL pktgen->flow bridge ============ *
     * A transaction-opening host request records its flow here; the in-switch pktgen
     * blocker generator (which has no 5-tuple) reads it to STAMP hdr.ib.flow onto the
     * tokens it emits, so the reservoir it creates indexes the right per-flow registers.
     * This is the single-active-transaction (scheduler-domain) binding — documented, and
     * the honest place where per-flow state meets a flow-blind token generator. */
    Register<bit<16>, bit<1>>(1, 0) reg_active_flow;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_active_flow) actflow_write = {
        void apply(inout bit<16> v, out bit<16> rv) { v = meta.flow_wide; rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_active_flow) actflow_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };

    /* ===== counters ===== */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_fwd;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_sbo_linked;
    Counter<bit<64>, bit<8>>(2, CounterType_t.PACKETS) ctr_bypass;

    /* ===== CORRECTION 8: FOUR TM queue actions ===== */
    action to_ack_block()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = QID_ACK_BLOCK;
                             ig_tm_md.bypass_egress = 1w1; }
    action to_ack_hold()   { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = QID_ACK_HOLD;
                             ig_tm_md.bypass_egress = 1w1; }
    action to_resp_block() { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = QID_RESP_BLOCK;
                             ig_tm_md.bypass_egress = 1w1; }
    action to_resp_hold()  { ig_tm_md.ucast_egress_port = PORT_L; ig_tm_md.qid = QID_RESP_HOLD;
                             ig_tm_md.bypass_egress = 1w1; }
    action to_fwd() {
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    action arm_clone() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.gen_cur;
    }

    /* ===== params: mode + size_profile + slot offset ===== */
    action set_params(bit<8> mode, bit<8> size_profile, bit<32> off_ticks) {
        meta.mode           = mode;
        meta.size_profile   = size_profile;
        meta.slot_off_ticks = off_ticks;
    }
    table tbl_params {
        key = { meta.role : exact; meta.dir : exact; }
        actions = { set_params; }
        default_action = set_params(MODE_ABS_DEADLINE, 8w0, 32w0);
        size = 32;
    }

    /* ===== guard interval G ===== */
    action set_guard(bit<32> g_ticks) { meta.guard_ticks = g_ticks; }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(32w0x017D7800);
        size = 1;
    }

    /* ===== CORRECTION 6: is_real from ROLE alone (available early, breaks the cycle) === */
    action mark_real() { meta.is_real = RF_REAL; }
    action mark_fill() { meta.is_real = RF_FILL; }
    table tbl_isreal {
        key = { meta.role : exact; }
        actions = { mark_real; mark_fill; }
        const default_action = mark_fill();
        const entries = {
            (ROLE_RESP)    : mark_real();
            (ROLE_ACK)     : mark_real();
            (ROLE_ARM)     : mark_real();
            (ROLE_SELECT)  : mark_real();
            (ROLE_OPERATE) : mark_real();
        }
        size = 16;
    }

    /* ===== CORRECTION 9: FIN/RST detect -> per-flow cleanup trigger ===== */
    action mark_cleanup()   { meta.cleanup_trig = B_TRUE; }
    table tbl_fin_rst {
        key = { hdr.tcp.flags : ternary; }
        actions = { mark_cleanup; NoAction; }
        const default_action = NoAction();
        const entries = {
            (8w0x01 &&& 8w0x01) : mark_cleanup();   /* FIN */
            (8w0x04 &&& 8w0x04) : mark_cleanup();   /* RST */
        }
        size = 4;
    }

    action build_now() { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_build_now {
        actions = { build_now; }
        const default_action = build_now();
        size = 1;
    }

    /* two candidate deadlines (parallel; both depend only on now_word) */
    action build_abs()  { meta.dl_cand_abs  = meta.now_word + meta.guard_ticks; }
    table tbl_build_abs {
        actions = { build_abs; }
        const default_action = build_abs();
        size = 1;
    }
    action build_slot() { meta.dl_cand_slot = meta.now_word + meta.slot_off_ticks; }
    table tbl_build_slot {
        actions = { build_slot; }
        const default_action = build_slot();
        size = 1;
    }

    /* mode picks which candidate the ACK arms with */
    action pick_abs()  { meta.dl_cand = meta.dl_cand_abs;  }
    action pick_slot() { meta.dl_cand = meta.dl_cand_slot; }
    table tbl_cand_select {
        key = { meta.mode : exact; }
        actions = { pick_abs; pick_slot; }
        const default_action = pick_abs();
        const entries = { (MODE_PRED_OFFSET) : pick_slot(); }
        size = 8;
    }

    /* ===== timing decode (arm / qualify / disarm / live) ===== */
    action dec_arm()     { meta.dl_val = UNARMED_WORD; }
    action dec_ack_arm() { meta.dl_val = meta.dl_cand; meta.ack_ok = 8w1; }
    action dec_live()    { meta.dl_val = DL_NO_WRITE; }
    action dec_none()    { meta.dl_val = DL_NO_WRITE; }
    table tbl_state_decode {
        key = { meta.pkt_class : exact; meta.tag_diff : ternary; }
        actions = { dec_arm; dec_ack_arm; dec_live; dec_none; }
        const default_action = dec_none();
        const entries = {
            (CLASS_ARM,       8w0x00 &&& 8w0x00) : dec_arm();
            (CLASS_ACK,       8w0x00 &&& 8w0x00) : dec_ack_arm();
            (CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF) : dec_live();   /* token live: tag_diff==0 */
        }
        size = 8;
    }

    /* ===== CORRECTION 3: OPERATE linkage from the phase FSM pre-state ===== *
     * OPERATE is linked iff an outstanding SELECT is present (phase_old == SELECT_SEEN).
     * Because OPERATE does tag_get (does NOT increment), the SELECT's internal generation
     * persists across the pair — the linkage is bound by flow + phase + internal
     * generation, NEVER the DNP3 app-seq (CORRECTION 2). */
    action ph_link_ok()  { meta.linkage_ok = 8w1; }
    action ph_link_bad() { meta.linkage_ok = 8w0; }
    table tbl_phase_decode {
        key = { meta.role : exact; meta.phase_old : ternary; }
        actions = { ph_link_ok; ph_link_bad; }
        const default_action = ph_link_bad();
        const entries = {
            (ROLE_OPERATE, PH_SELECT_SEEN &&& 8w0xFF) : ph_link_ok();
        }
        size = 4;
    }

    /* ===== pktgen token active check ===== */
    action mark_txn_active()   { meta.txn_active = 8w1; }
    action mark_txn_inactive() { meta.txn_active = 8w0; }
    table tbl_pktgen_active {
        key = { meta.gen_cur : ternary; }
        actions = { mark_txn_active; mark_txn_inactive; }
        const default_action = mark_txn_inactive();
        const entries = { (8w0x01 &&& 8w0x01) : mark_txn_active(); }
        size = 2;
    }

    /* ===== slot assign: slot_id = cur_slot & MASK ===== */
    action assign_slot() { meta.slot_id = meta.cur_slot & SLOT_MASK; }
    table tbl_slot_assign {
        actions = { assign_slot; }
        const default_action = assign_slot();
        size = 1;
    }

    /* ===== CORRECTION 7: epoch rollover = the slot clock wrapped (slot_id == 0) ===== */
    action mark_rollover()  { meta.epoch_rollover = B_TRUE; }
    action mark_norollover(){ meta.epoch_rollover = B_FALSE; }
    table tbl_rollover {
        key = { meta.slot_id : exact; }
        actions = { mark_rollover; mark_norollover; }
        const default_action = mark_norollover();
        const entries = { (8w0) : mark_rollover(); }
        size = 2;
    }

    /* ===== one-hot(slot_id) for the bitmap ===== */
    action set_onehot(bit<32> oh) { meta.slot_onehot = oh; }
    table tbl_slot_onehot {
        key = { meta.slot_id : exact; }
        actions = { set_onehot; }
        default_action = set_onehot(32w1);
        size = 32;
    }

    /* ===== deadline expiry ===== */
    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = { meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = { (32w0x00000000 &&& 32w0x800000FF) : mark_expired(); }
        size = 2;
    }

    /* ===== matching-response event decode ===== */
    action ev_seen()   { meta.event_due = 8w1; }
    action ev_unseen() { meta.event_due = 8w0; }
    table tbl_event_decode {
        key = { meta.event_diff : ternary; }
        actions = { ev_seen; ev_unseen; }
        const default_action = ev_unseen();
        const entries = { (8w0x00 &&& 8w0xFF) : ev_seen(); }
        size = 2;
    }

    /* ===== per-slot size lookup (size_profile, slot_id) -> size_bytes ===== */
    action set_size(bit<16> sz) { meta.size_bytes = sz; }
    table tbl_slot_size {
        key = { meta.size_profile : exact; meta.slot_id : exact; }
        actions = { set_size; }
        default_action = set_size(16w0);
        size = 256;
    }

    /* ===== CORRECTION 5 + 4: release predicate =====
     * UNIVERSAL fail-open: budget-exhaustion OR absolute-deadline expiry force RELEASE
     * under EVERY mode (the two mode-wildcard backstops, highest priority). MATCH_EVENT
     * for a RESPONSE additionally ANCHORS to ack_released (CORRECTION 4). */
    action do_release() { meta.release = REL_RELEASE; }
    action do_hold()    { meta.release = REL_HOLD; }
    table tbl_release_select {
        key = {
            meta.is_response  : ternary;
            meta.mode         : ternary;
            meta.expired      : ternary;
            meta.event_due    : ternary;
            meta.budget_zero  : ternary;
            meta.ack_released : ternary;
        }
        actions = { do_release; do_hold; }
        const default_action = do_hold();
        const entries = {
            /* CORRECTION 5: universal backstops — ALL modes */
            (8w0 &&& 8w0, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release(); /* abs-deadline */
            (8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0) : do_release(); /* budget      */
            /* per-mode predicates */
            (8w0 &&& 8w0, MODE_IMMEDIATE   &&& 8w0xFF, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            (8w0 &&& 8w0, MODE_ABS_DEADLINE &&& 8w0xFF, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            (8w0 &&& 8w0, MODE_PRED_OFFSET  &&& 8w0xFF, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            /* MATCH_EVENT: ACK releases on the event; RESPONSE also needs its ACK gone */
            (8w0 &&& 8w1, MODE_MATCH_EVENT  &&& 8w0xFF, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            (8w1 &&& 8w1, MODE_MATCH_EVENT  &&& 8w0xFF, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w1 &&& 8w1) : do_release();
        }
        size = 32;
    }

    /* ===== CORRECTION 6: real/filler tag — now reads the ACTUAL bitmap result ===== *
     * Ordered AFTER the bitmap access (which writes meta.slot_occupied); keyed on the
     * role-based is_real plus the occupancy the bitmap actually returned. */
    action tag_real() { meta.realfill = RF_REAL; }
    action tag_fill() { meta.realfill = RF_FILL; }
    table tbl_realfill {
        key = { meta.is_real : exact; meta.slot_occupied : ternary; }
        actions = { tag_real; tag_fill; }
        const default_action = tag_fill();
        const entries = { (RF_REAL, 8w0x00 &&& 8w0x00) : tag_real(); }
        size = 8;
    }

    /* ===== outer encapsulation field write (control surface; no byte-append) ===== */
    action set_encap() {
        hdr.outer.setValid();
        hdr.outer.direction  = meta.dir;
        hdr.outer.txn_tag    = meta.gen_cur;
        hdr.outer.slot_id    = meta.slot_id;
        hdr.outer.realfill   = meta.realfill;
        hdr.outer.size_bytes = meta.size_bytes;
    }
    table tbl_encap {
        actions = { set_encap; }
        const default_action = set_encap();
        size = 1;
    }

    apply {
        if (meta.port_ok == 8w0) {
            ctr_bypass.count(8w1);
            drop_pkt();
        } else {
            /* ---------- level 0: packet-derived + params + flow key + classify ---------- */
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }
            tbl_params.apply();
            tbl_guard.apply();
            tbl_isreal.apply();
            /* CORRECTION 1: host packets derive the flow from the 5-tuple hash; token
             * packets already carry it (parser), so only hash when IP/TCP is present. */
            if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
                tbl_flow_hash.apply();
                tbl_fin_rst.apply();                 /* CORRECTION 9: FIN/RST cleanup trig */
            }
            tbl_flow_fold.apply();

            /* ---------- level 1: now-word + class/phase drivers ---------- */
            tbl_build_now.apply();
            if (meta.dequeued == 8w0 && meta.is_pktgen == 8w0) {
                if (meta.role == ROLE_ARM && meta.dir == DIR_MASTER) {
                    meta.pkt_class = CLASS_ARM;      /* READ opens a transaction          */
                } else if (meta.role == ROLE_ACK && meta.dir == DIR_OUT) {
                    meta.pkt_class = CLASS_ACK;
                }
            } else if (meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) {
                meta.pkt_class = CLASS_BLOCK_DEQ;
            }
            /* CORRECTION 3: phase FSM target (constants only; consumed by phase_set L2) */
            if (meta.cleanup_trig == B_TRUE) {
                meta.phase_next = PH_IDLE;                                  /* FIN/RST     */
            } else if (meta.role == ROLE_SELECT && meta.dir == DIR_MASTER) {
                meta.phase_next = PH_SELECT_SEEN;
            } else if (meta.role == ROLE_OPERATE && meta.dir == DIR_MASTER) {
                meta.phase_next = PH_OPERATE_SEEN;
            } else {
                meta.phase_next = PH_IDLE;                                  /* READ        */
            }

            /* ---------- level 2: primary registers (flow-indexed / global) ----------
             * reg_tag serves BOTH the internal-generation counter (CORRECTION 2) and the
             * armed-generation match; reg_phase runs the SBO FSM (CORRECTION 3). */
            if (meta.is_pktgen == 8w1) {
                meta.flow_wide = actflow_read.execute(0);      /* pktgen learns the flow  */
                meta.cur_slot  = slot_advance.execute(0);      /* pktgen drives the clock */
            } else if (meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) {
                meta.tag_diff  = tag_match.execute(meta.flow_idx);   /* token liveness    */
                meta.cur_slot  = slot_read.execute(0);
            } else {
                /* host packet */
                if (meta.cleanup_trig == B_TRUE) {
                    meta.gen_cur = tag_clear.execute(meta.flow_idx);      /* FIN/RST reset */
                } else if ((meta.role == ROLE_ARM && meta.dir == DIR_MASTER) ||
                           (meta.role == ROLE_SELECT && meta.dir == DIR_MASTER)) {
                    meta.gen_cur = tag_open.execute(meta.flow_idx);      /* CORRECTION 2: open */
                    actflow_write.execute(0);                            /* record active flow */
                } else {
                    meta.gen_cur = tag_get.execute(meta.flow_idx);       /* passive read  */
                }
                /* phase FSM transition (CORRECTION 3): phase_set writes meta.phase_next
                 * (SELECT/OPERATE/READ/FIN-RST); phase_resp decides SELECT-resp vs
                 * OPERATE-resp internally; phase_read is passive. */
                if (meta.cleanup_trig == B_TRUE ||
                    (meta.role == ROLE_ARM && meta.dir == DIR_MASTER) ||
                    (meta.role == ROLE_SELECT && meta.dir == DIR_MASTER) ||
                    (meta.role == ROLE_OPERATE && meta.dir == DIR_MASTER)) {
                    meta.phase_old = phase_set.execute(meta.flow_idx);
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    meta.phase_old = phase_resp.execute(meta.flow_idx);  /* SEL vs OPER resp */
                } else {
                    meta.phase_old = phase_read.execute(meta.flow_idx);
                }
                meta.cur_slot = slot_read.execute(0);
            }

            /* ---------- level 3: secondary registers + slot assign ---------- */
            if (meta.is_pktgen == 8w0) {
                if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    meta.event_diff   = event_resp.execute(meta.flow_idx);  /* post/clear  */
                    meta.ack_released = ackgone_resp.execute(meta.flow_idx);/* CORRECTION 4 */
                } else if (meta.role == ROLE_ACK && meta.dir == DIR_OUT) {
                    meta.event_diff   = event_check.execute(meta.flow_idx);
                } else if (meta.role == ROLE_ARM && meta.dir == DIR_MASTER) {
                    event_clear.execute(meta.flow_idx);                     /* new txn      */
                    ackgone_clear.execute(meta.flow_idx);
                } else if ((meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK)
                           && meta.budget_zero == 8w1) {
                    ackgone_set.execute(meta.flow_idx);   /* CORRECTION 4: reservoir drained */
                }
            }
            tbl_slot_assign.apply();

            /* ---------- level 4: decodes + candidate select + size lookup ---------- */
            tbl_cand_select.apply();
            tbl_build_abs.apply();
            tbl_build_slot.apply();
            tbl_state_decode.apply();
            tbl_phase_decode.apply();
            tbl_pktgen_active.apply();
            tbl_event_decode.apply();
            tbl_rollover.apply();
            tbl_slot_onehot.apply();
            tbl_slot_size.apply();

            /* ---------- level 5: deadline + bitmap (CORRECTION 6/7 ordering) ----------
             * Bitmap accessed BEFORE tbl_realfill and its return CAPTURED; gate is the
             * role-based is_real (not the yet-uncomputed realfill), breaking the cycle. */
            if (meta.ack_ok == 8w1) {
                meta.age = deadline_arm_once.execute(meta.flow_idx);
            } else if (meta.role == ROLE_RESP && meta.phase_old == PH_OPERATE_SEEN) {
                meta.age = deadline_clear.execute(meta.flow_idx);   /* txn complete       */
            } else {
                meta.age = deadline_rmw.execute(meta.flow_idx);
            }
            if (meta.epoch_rollover == B_TRUE && meta.is_pktgen == 8w1) {
                meta.slot_occupied = (bit<8>)bitmap_clear.execute(0)[7:0];   /* CORRECTION 7 */
            } else if (meta.is_real == RF_REAL) {
                meta.slot_occupied = (bit<8>)bitmap_test_set.execute(0)[7:0];/* CORRECTION 6 */
            } else {
                meta.slot_occupied = (bit<8>)bitmap_read.execute(0)[7:0];
            }

            /* ---------- level 6: expiry + realfill ---------- */
            tbl_deadline_expiry.apply();
            if (meta.role == ROLE_RESP) { meta.is_response = B_TRUE; }
            tbl_realfill.apply();

            /* ---------- level 7: release decision + encap field write ---------- */
            tbl_release_select.apply();
            tbl_encap.apply();

            /* ---------- ACT ---------- */
            if (meta.dequeued == 8w0) {
                if (meta.is_pktgen == 8w1) {
                    /* pktgen-generated blocker: stamp flow (CORRECTION 1) + gen, enqueue */
                    if (meta.txn_active == 8w1) {
                        hdr.ib.role = ROLE_BLOCK;
                        hdr.ib.gen  = meta.gen_cur;
                        hdr.ib.flow = meta.flow_wide;
                        hdr.ib.seq  = INITIAL_BUDGET;
                        to_ack_block();                        /* CORRECTION 8: qid 7      */
                    } else {
                        drop_pkt();
                    }
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    if (meta.linkage_ok == 8w1) { ctr_sbo_linked.count(0); }
                    if (meta.release == REL_RELEASE) { to_fwd();      ctr_fwd.count(0); }
                    else                             { to_resp_hold(); ctr_hold.count(0); } /* qid 0 */
                } else if (meta.role == ROLE_ACK) {
                    if (meta.release == REL_RELEASE) { to_fwd();      ctr_fwd.count(0); }
                    else                             { to_ack_hold(); ctr_hold.count(0); }  /* qid 5 */
                } else if (meta.role == ROLE_ARM) {
                    to_fwd();
                    if (meta.gen_cur != 8w0) { arm_clone(); }   /* trigger the reservoir   */
                } else if (meta.role == ROLE_SELECT) {
                    to_fwd();
                } else if (meta.role == ROLE_OPERATE) {
                    to_fwd();
                    if (meta.linkage_ok == 8w1) { ctr_sbo_linked.count(0); }
                } else {
                    to_fwd();
                    ctr_bypass.count(8w0);
                }
            } else {
                /* dequeued blocker token: terminate on stale-gen / expiry / budget, else
                 * decrement budget and re-enqueue to its OWN reservoir queue. */
                if (meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) {
                    if (meta.tag_diff != 8w0) {
                        drop_pkt();      ctr_block_term.count(0);   /* superseded txn      */
                    } else if (meta.expired == 8w1) {
                        drop_pkt();      ctr_block_term.count(0);
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt();      ctr_block_term.count(0);
                    } else {
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        if (meta.role == ROLE_BLOCK) { to_ack_block(); }   /* qid 7        */
                        else                         { to_resp_block(); }  /* qid 3        */
                        ctr_block_loop.count(0);
                    }
                } else if (meta.role == ROLE_RESP) {
                    to_fwd();
                    ctr_fwd.count(0);
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
        pkt.emit(hdr.outer);     /* prepended encap (control representation) */
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

/* ============================ egress (skeleton pass-through) ============
 * The physical size padding lives here in the real Defense 4 (excluded from this
 * ingress-feasibility probe; ~2-4 egress stages, ZERO ingress). */
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

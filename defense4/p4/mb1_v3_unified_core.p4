/* ============================================================================
 * mb1_v3_unified_core.p4 — MB-1 v3, the DEFECT-REPAIRED unified INGRESS core for
 *   the Defense 4 feasibility. NON-FROZEN probe under defense4/p4/. Nothing is
 *   loaded or run; this is an OFFLINE bf-p4c compile only.
 *
 * v3 is the successor to mb1_v2_unified_core.p4 (10 ing / CP 8 / 96 tbl / 8 SALU),
 * which a 2026-08-04 design review found had TEN concrete LOGIC defects (the v2
 * "CORRECTION N" tags addressed structure/placement, not these ten). Each fix below
 * is tagged "FIX N" inline and cross-referenced to the review item. If the honest
 * stage count exceeds 12 that is a VALID result and is reported as-is; no required
 * fix is dropped to force the program under 12.
 *
 * DESIGN DISCIPLINE (kept from v2 so the stage count stays honest):
 *   - every value that COMBINES a just-read/just-computed value lives in its OWN
 *     single-action table (bf-p4c else merges statements and rejects the intra-action
 *     dependency as "action spanning multiple stages").
 *   - sign / mask tests are ternary TCAM masks over a WHOLE container, never a
 *     bit-slice of an arithmetic field.
 *   - each Register has <=2 PHV inputs per RegisterAction, <=4 RegisterActions, and
 *     ONE access per packet.
 *
 * THE TEN FIXES (summary; details at each tag):
 *   FIX 1  canonical bidirectional flow key (order endpoints, then hash).
 *   FIX 2  collision-guarded fingerprint (parallel reg_fp; mismatch => fail open).
 *   FIX 3  pktgen path reads reg_active_flow -> flow index -> valid generation, IN ORDER.
 *   FIX 4  explicit per-flow validity bit (reg_valid), never generation parity.
 *   FIX 5  pktgen seeds BOTH reservoirs (ROLE_BLOCK->qid7 AND ROLE_RESP_BLK->qid3).
 *   FIX 6  retire ALL per-flow state on terminal completion, fail-open, and FIN/RST.
 *   FIX 7  slot occupancy matched with FULL mask + operation->expected-slot enforcement.
 *   FIX 8  8-byte D4 outer header carrying the TRUE inner frame length (inner_len).
 *   FIX 9  explicit do_release() entry for MODE_FAIL_OPEN.
 *   FIX 10 safe parser init: every safety-governing field deterministically assigned.
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
const bit<8> ROLE_RESP_BLK = 5;   /* RESPONSE-reservoir blocker token (FIX 5) */
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

/* ---- FOUR queues, strict priority 7 > 5 > 3 > 0 (unchanged from v2) ----
 * QID_ACK_BLOCK  holds the ACK's reservoir (highest), QID_ACK_HOLD parks the held
 * ACK, then the RESPONSE reservoir/hold below it. FIX 5 finally SEEDS qid 3. */
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

/* ---- SBO phase FSM states ---- */
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
const bit<8>  EXP_SLOT_ANY = 8w0xFF;   /* FIX 7: sentinel "any slot" expected-slot policy */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header recirc_tag_h { bit<32> tag; }

/* The blocker token carries its own flow id (16b, low 10 used) + generation, so the
 * recirculating/dequeued reservoir path can index the SAME per-flow registers the host
 * path armed — without recomputing a hash it cannot (no IP/TCP on a token). */
header ibspg_h { bit<8> role; bit<8> slot; bit<8> gen; bit<16> flow; bit<32> seq; }

/* FIX 8: 8-byte D4 control header (format (b): outer Ethernet + 8-byte D4 header +
 * complete inner frame). inner_len carries the TRUE inner frame length so the far
 * decoder can strip fixed-size padding byte-exactly. 8 bytes total:
 *   direction(1) txn_tag(1) slot_id(1) realfill(1) inner_len(2) size_bytes(2) = 8. */
header outer_encap_h {
    bit<8>  direction;    /* DIR_MASTER / DIR_OUT                     */
    bit<8>  txn_tag;      /* internal transaction generation          */
    bit<8>  slot_id;      /* assigned grid slot                       */
    bit<8>  realfill;     /* RF_REAL / RF_FILL                        */
    bit<16> inner_len;    /* FIX 8: TRUE inner frame length (bytes)   */
    bit<16> size_bytes;   /* per-slot target size (control only)      */
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
    /* parser classification (each assigned exactly once per path — FIX 10) */
    bit<8>  role;
    bit<8>  dir;
    bit<9>  fwd_port;
    bit<8>  port_ok;
    bit<8>  dequeued;
    bit<8>  is_pktgen;
    bit<8>  budget_zero;

    /* FIX 1: canonical (direction-independent) flow key */
    bit<32> ip_diff;         /* src_addr - dst_addr (signed compare via sign bit)        */
    bit<16> pt_diff;         /* src_port - dst_port (tie-break)                          */
    bit<32> ip_lo;           /* ordered endpoint IPs                                     */
    bit<32> ip_hi;
    bit<16> pt_lo;           /* ordered endpoint ports                                   */
    bit<16> pt_hi;
    bit<10> flow_idx;        /* 1024-entry register index (host: canon hash; token/pktgen: below) */
    bit<16> flow_wide;       /* pktgen: reg_active_flow read-back, folded to flow_idx (FIX 3) */

    /* FIX 2: collision-guarded fingerprint */
    bit<16> fp_cur;          /* wide fingerprint of THIS packet's canonical key           */
    bit<16> fp_diff;         /* reg_fp compare (0 == fingerprint matches stored owner)     */
    bit<8>  collision;       /* 1 == hash index owned by a DIFFERENT flow => FAIL OPEN     */

    /* internal generation (from reg_tag), NOT DNP3 app_control */
    bit<8>  gen_cur;         /* current internal generation for this flow                 */

    /* FIX 4: explicit per-flow validity */
    bit<8>  valid_cur;       /* reg_valid read: 1 == a transaction is live on this flow    */

    /* timing core */
    bit<32> ts_m;
    bit<32> now_word;
    bit<32> guard_ticks;
    bit<8>  pkt_class;
    bit<32> dl_cand_abs;
    bit<32> dl_cand_slot;
    bit<32> dl_cand;
    bit<8>  tag_diff;        /* reg_tag SALU result (token liveness on block path)        */
    bit<32> dl_val;          /* value to arm reg_deadline with                            */
    bit<8>  ack_ok;
    bit<32> age;
    bit<8>  expired;

    /* SBO phase FSM */
    bit<8>  phase_old;       /* reg_phase pre-state (drives SELECT-resp vs OPERATE-resp)  */
    bit<8>  phase_next;      /* FSM target for the parameterized write (role/dir-derived)  */
    bit<8>  linkage_ok;      /* OPERATE matched an outstanding SELECT                      */
    bit<8>  is_response;     /* ROLE_RESP, for the release predicate                      */

    /* ack_gone */
    bit<8>  ack_released;    /* reg_ack_gone read: the flow's ACK reservoir has drained    */

    /* release-mode surface */
    bit<8>  mode;
    bit<32> slot_off_ticks;
    bit<8>  event_diff;
    bit<8>  event_due;
    bit<8>  release;

    /* cleanup */
    bit<8>  cleanup_trig;    /* FIN/RST -> hard-wipe this flow's per-txn state             */

    /* slot surface */
    bit<8>  is_real;         /* role-based, gates the bitmap (breaks the cycle)            */
    bit<8>  cur_slot;
    bit<8>  slot_id;
    bit<32> slot_onehot;
    bit<32> slot_hit;        /* FIX 7: FULL 32-bit bitmap AND result (0 == slot was free)  */
    bit<8>  exp_slot;        /* FIX 7: operation -> expected slot                          */
    bit<8>  slot_diff;       /* FIX 7: slot_id - exp_slot                                  */
    bit<8>  slot_ok;         /* FIX 7: 1 == real unit is in its expected slot              */
    bit<8>  epoch_rollover;  /* slot clock wrapped -> clear bitmap                         */

    /* size surface */
    bit<8>  size_profile;
    bit<16> size_bytes;
    bit<16> inner_len;       /* FIX 8: TRUE inner frame length written to outer header      */

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
        /* FIX 10: initialize every MAU-written metadata field AND every new
         * safety-governing scalar to its SAFE zero-encoding here. Fields that a parser
         * STATE assigns (role, dir, fwd_port, port_ok, dequeued, is_pktgen) are NOT
         * init'd here: start-init + later reassignment is a MEASURED hard error on
         * bf-p4c 9.13.1 for dir/fwd_port (clear-on-write). Instead each of those is
         * assigned EXACTLY ONCE on EVERY path below (incl. from_unclassified /
         * accept_bypass), so the parser leaves no safety field indeterminate and the
         * uninitialized_out_param warning is eliminated without a double-assign. */
        meta.budget_zero     = 8w0;
        meta.ip_diff         = 32w0;
        meta.pt_diff         = 16w0;
        meta.ip_lo           = 32w0;
        meta.ip_hi           = 32w0;
        meta.pt_lo           = 16w0;
        meta.pt_hi           = 16w0;
        meta.flow_idx        = 10w0;
        meta.flow_wide       = 16w0;
        meta.fp_cur          = 16w0;
        meta.fp_diff         = 16w0;
        meta.collision       = 8w0;        /* SAFE: 0 => no collision (openers/tokens skip fp) */
        meta.gen_cur         = 8w0;
        meta.valid_cur       = 8w0;        /* SAFE: 0 => flow invalid => pktgen emits no blocker */
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
        meta.release         = REL_HOLD;   /* SAFE: hold until a release predicate fires */
        meta.cleanup_trig    = 8w0;
        meta.is_real         = 8w0;
        meta.cur_slot        = 8w0;
        meta.slot_id         = 8w0;
        meta.slot_onehot     = 32w0;
        meta.slot_hit        = 32w0;
        meta.exp_slot        = EXP_SLOT_ANY;
        meta.slot_diff       = 8w0;
        meta.slot_ok         = 8w0;
        meta.epoch_rollover  = 8w0;
        meta.size_profile    = 8w0;
        meta.size_bytes      = 16w0;
        meta.inner_len       = 16w0;
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
            default     : from_unclassified;   /* FIX 10: deterministic drop for unknown ports */
        }
    }

    /* Each port-entry state assigns dequeued, is_pktgen, dir, fwd_port, port_ok ONCE. */
    state from_loopback   { meta.dequeued = 8w1; meta.is_pktgen = 8w0; meta.dir = DIR_OUT;
                            meta.fwd_port = PORT_VISION; meta.port_ok = 8w1; transition parse_eth; }
    state from_outstation { meta.dequeued = 8w0; meta.is_pktgen = 8w0; meta.dir = DIR_OUT;
                            meta.fwd_port = PORT_VISION; meta.port_ok = 8w1; transition parse_eth; }
    state from_master     { meta.dequeued = 8w0; meta.is_pktgen = 8w0; meta.dir = DIR_MASTER;
                            meta.fwd_port = PORT_RELAY;  meta.port_ok = 8w1; transition parse_eth; }
    /* FIX 10: unknown port -> assign ALL classification fields to fail-safe values, drop. */
    state from_unclassified { meta.dequeued = 8w0; meta.is_pktgen = 8w0; meta.dir = DIR_MASTER;
                              meta.fwd_port = 9w0; meta.port_ok = 8w0; meta.role = ROLE_BYPASS;
                              transition accept; }

    state from_pgen {
        meta.dequeued = 8w0;   /* pktgen seed is NOT a loopback dequeue */
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_recirc : parse_pktgen_token;
            default     : pgen_drop;
        }
    }
    /* FIX 10: unrecognized pktgen packet -> fail-safe drop, all fields assigned once. */
    state pgen_drop { meta.is_pktgen = 8w0; meta.dir = DIR_MASTER; meta.fwd_port = 9w0;
                      meta.port_ok = 8w0; meta.role = ROLE_BYPASS; transition accept; }
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
            default               : accept_bypass;
        }
    }

    /* A dequeued/pktgen blocker carries its flow + generation; the reservoir path reads
     * hdr.ib.flow / hdr.ib.gen DIRECTLY in the MAU (no meta copy) so those helper fields
     * never become an uninitialized-metadata source (FIX 10). role from hdr.ib.role. */
    state parse_token {
        pkt.extract(hdr.ib);
        meta.role = hdr.ib.role;      /* ROLE_BLOCK (ACK res.) or ROLE_RESP_BLK (RESP res.) */
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl) {
            (IP_PROTO_TCP, 4w5) : parse_tcp;
            default             : accept_bypass;
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
            default                                      : accept_bypass;
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
            default                    : accept_bypass;
        }
    }

    state parse_dnp3_tp { pkt.extract(hdr.dnp3_tp); transition parse_dnp3_app; }

    /* Role from func_code only (never DNP3 app_control — that is not a linkage key). */
    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        transition select(hdr.dnp3_app.func_code) {
            DNP3_FC_RESPONSE : set_role_resp;
            DNP3_FC_READ     : set_role_arm;
            DNP3_FC_SELECT   : set_role_select;
            DNP3_FC_OPERATE  : set_role_operate;
            default          : accept_bypass;
        }
    }
    state set_role_resp    { meta.role = ROLE_RESP;    transition accept; }
    state set_role_arm     { meta.role = ROLE_ARM;     transition accept; }
    state set_role_select  { meta.role = ROLE_SELECT;  transition accept; }
    state set_role_operate { meta.role = ROLE_OPERATE; transition accept; }

    /* FIX 10: every early-accept leaf assigns role exactly once (ROLE_BYPASS = safe
     * unshaped forward), so role is defined on ALL paths => no uninitialized_out_param. */
    state accept_bypass { meta.role = ROLE_BYPASS; transition accept; }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ===================== FIX 1: canonical flow key ===================== *
     * TWO hashes over the ORDERED endpoint tuple {ip_lo,pt_lo,ip_hi,pt_hi,proto}. Because
     * the endpoints are ordered (min/max), a request (M->O) and its response (O->M) hash
     * to the SAME flow_idx and share transaction state. flow_hash -> 10-bit index;
     * fp_hash -> 16-bit fingerprint for the collision guard (FIX 2). */
    CRCPolynomial<bit<16>>(coeff=16w0x1021, reversed=false, msb=false, extended=false,
                           init=16w0xFFFF, xor=16w0x0000) idx_poly;
    CRCPolynomial<bit<16>>(coeff=16w0x8005, reversed=true, msb=false, extended=false,
                           init=16w0x0000, xor=16w0x0000) fp_poly;
    Hash<bit<10>>(HashAlgorithm_t.CUSTOM, idx_poly) flow_hash;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, fp_poly)  fp_hash;

    /* reg_tag: per-flow INTERNAL GENERATION counter (open-increment) + armed-generation
     * the reservoir tokens match against. Flow-indexed (1024). tag_match reads the token's
     * generation straight from hdr.ib.gen (no meta copy -> FIX 10 keeps meta clean). */
    Register<bit<8>, bit<10>>(1024, 0) reg_tag;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_open = {   /* READ/SELECT open */
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_get = {    /* host passive read */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_match = {  /* token liveness    */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v - hdr.ib.gen; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_tag) tag_clear = {  /* FIN/RST reset      */
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = 8w0; }
    };

    /* FIX 2: reg_fp — per-index flow FINGERPRINT (collision guard). An opening request
     * CLAIMS the index (writes fp_cur); every other host packet CHECKS (reads, returns
     * stored - fp_cur). fp_diff != 0 => the index is owned by a DIFFERENT flow => the
     * packet FAILS OPEN (bypass unshaped) instead of corrupting the owner's state.
     * FIN/RST frees ownership. This makes the 10-bit hash a "hash index + collision-
     * guarded fingerprint", NOT the exact match v2 mislabeled it. */
    Register<bit<16>, bit<10>>(1024, 0) reg_fp;
    RegisterAction<bit<16>, bit<10>, bit<16>>(reg_fp) fp_claim = {  /* opener takes ownership */
        void apply(inout bit<16> v, out bit<16> rv) { v = meta.fp_cur; rv = 16w0; }
    };
    RegisterAction<bit<16>, bit<10>, bit<16>>(reg_fp) fp_check = {  /* others verify owner    */
        void apply(inout bit<16> v, out bit<16> rv) { rv = v - meta.fp_cur; }
    };
    RegisterAction<bit<16>, bit<10>, bit<16>>(reg_fp) fp_clear = {  /* FIN/RST frees index    */
        void apply(inout bit<16> v, out bit<16> rv) { v = 16w0; rv = 16w0; }
    };

    /* FIX 4: reg_valid — EXPLICIT per-flow validity flag (never generation parity). Set on
     * a transaction open, read by the pktgen path to decide whether to emit a blocker,
     * cleared on completion / fail-open / FIN/RST. */
    Register<bit<8>, bit<10>>(1024, 0) reg_valid;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_valid) valid_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = B_TRUE; rv = B_TRUE; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_valid) valid_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_valid) valid_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = B_FALSE; rv = B_FALSE; }
    };

    /* reg_phase — SBO FSM {IDLE, SELECT_SEEN, OPERATE_SEEN}. phase_resp clears to IDLE
     * ONLY when the pre-state is OPERATE_SEEN (OPERATE-response completes the txn); when
     * SELECT_SEEN it PRESERVES the linkage (that func-129 is the SELECT-response). */
    Register<bit<8>, bit<10>>(1024, 0) reg_phase;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_phase) phase_set = {  /* SELECT/OPERATE/READ/FIN */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = meta.phase_next; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_phase) phase_resp = {     /* func-129 */
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (v == PH_OPERATE_SEEN) { v = PH_IDLE; }   /* OPERATE-resp completes txn */
        }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_phase) phase_read = {     /* passive */
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* reg_event — MATCH_EVENT (D1b). The RESPONSE posts its generation, or CLEARS on a
     * terminal response (FIX 6). The ACK checks its generation against the posted one.
     * event_clear also serves the SELECT/READ open and FIN/RST cleanup (FIX 6). */
    Register<bit<8>, bit<10>>(1024, 0) reg_event;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_event) event_resp = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = 8w0;
            /* FIX 6: terminal response (OPERATE-resp OR READ-resp, i.e. pre-state not
             * SELECT_SEEN) CLEARS; a SELECT-response (SELECT_SEEN) POSTS the event. */
            if (meta.phase_old == PH_SELECT_SEEN) { v = meta.gen_cur; }
            else                                  { v = 8w0; }
        }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_event) event_check = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = meta.gen_cur - v; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_event) event_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = 8w0; rv = 8w0; }
    };

    /* reg_ack_gone — set when the ACK reservoir drains; read on the RESPONSE pass so the
     * response-release can anchor to the ACK's departure. Cleared on terminal / open /
     * FIN-RST (FIX 6). */
    Register<bit<8>, bit<10>>(1024, 0) reg_ack_gone;
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ack_gone) ackgone_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = B_TRUE; rv = B_TRUE; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ack_gone) ackgone_resp = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            /* FIX 6: terminal response clears; SELECT-response preserves. */
            if (meta.phase_old != PH_SELECT_SEEN) { v = B_FALSE; }
        }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(reg_ack_gone) ackgone_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { v = B_FALSE; rv = B_FALSE; }
    };

    /* reg_deadline — ABS_DEADLINE / PRED_OFFSET, flow-indexed. */
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

    /* reg_slot_clock — GLOBAL grid epoch (scheduler domain; a phase reference, not
     * per-transaction state). */
    Register<bit<8>, bit<1>>(1, 0) reg_slot_clock;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_slot_clock) slot_advance = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_slot_clock) slot_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* reg_slot_bitmap — GLOBAL one-hot occupancy. bitmap_test_set returns the PRE-value
     * ANDed with the one-hot (0 == slot was free). bitmap_clear rotates the grid at epoch
     * rollover; bitmap_free (FIX 6) retires a terminal transaction's slot bit. */
    Register<bit<32>, bit<1>>(1, 0) reg_slot_bitmap;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_slot_bitmap) bitmap_test_set = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v & meta.slot_onehot;
            v  = v | meta.slot_onehot;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_slot_bitmap) bitmap_read = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v & meta.slot_onehot; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_slot_bitmap) bitmap_clear = {
        void apply(inout bit<32> v, out bit<32> rv) { v = 32w0; rv = 32w0; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_slot_bitmap) bitmap_free = {  /* FIX 6 */
        void apply(inout bit<32> v, out bit<32> rv) { v = v & ~meta.slot_onehot; rv = 32w0; }
    };

    /* reg_active_flow — GLOBAL pktgen->flow bridge. A transaction-opening host request
     * records its flow INDEX here (zero-extended to 16b — TF1 Registers only allow
     * 1/8/16/32/64-bit elements, so the 10-bit index rides a bit<16> cell). The flow-blind
     * pktgen reads it back (FIX 3) and folds the low 10 bits to a usable index. Cleared on
     * FIN/RST (FIX 6). */
    Register<bit<16>, bit<1>>(1, 0) reg_active_flow;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_active_flow) actflow_write = {
        void apply(inout bit<16> v, out bit<16> rv) { v = (bit<16>)meta.flow_idx; rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_active_flow) actflow_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_active_flow) actflow_clear = {  /* FIX 6 */
        void apply(inout bit<16> v, out bit<16> rv) { v = 16w0; rv = 16w0; }
    };

    /* ===== counters ===== */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_fwd;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_sbo_linked;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_collision;   /* FIX 2 */
    Counter<bit<64>, bit<8>>(2, CounterType_t.PACKETS) ctr_bypass;

    /* ===== TM queue actions (four queues 7>5>3>0) ===== */
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

    /* ===== params: mode + size_profile + slot offset + expected slot (FIX 7) ===== */
    action set_params(bit<8> mode, bit<8> size_profile, bit<32> off_ticks, bit<8> exp_slot) {
        meta.mode           = mode;
        meta.size_profile   = size_profile;
        meta.slot_off_ticks = off_ticks;
        meta.exp_slot       = exp_slot;    /* FIX 7: operation -> expected grid slot */
    }
    table tbl_params {
        key = { meta.role : exact; meta.dir : exact; }
        actions = { set_params; }
        /* default exp_slot = EXP_SLOT_ANY => the enforcement is a no-op until a policy
         * entry pins a slot; the DATAPLANE mechanism is always present (FIX 7). */
        default_action = set_params(MODE_ABS_DEADLINE, 8w0, 32w0, EXP_SLOT_ANY);
        size = 32;
    }

    /* ===== guard interval G ===== */
    action set_guard(bit<32> g_ticks) { meta.guard_ticks = g_ticks; }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(32w0x017D7800);
        size = 1;
    }

    /* ===== FIX 1: canonical endpoint compare + ordering ===== */
    action calc_key_cmp() {
        meta.ip_diff = hdr.ipv4.src_addr - hdr.ipv4.dst_addr;   /* signed compare via sign bit */
        meta.pt_diff = hdr.tcp.src_port  - hdr.tcp.dst_port;    /* tie-break when IPs equal     */
    }
    table tbl_key_diff {
        actions = { calc_key_cmp; }
        const default_action = calc_key_cmp();
        size = 1;
    }
    action order_keep() {   /* src endpoint is the LOW endpoint */
        meta.ip_lo = hdr.ipv4.src_addr; meta.pt_lo = hdr.tcp.src_port;
        meta.ip_hi = hdr.ipv4.dst_addr; meta.pt_hi = hdr.tcp.dst_port;
    }
    action order_swap() {   /* dst endpoint is the LOW endpoint */
        meta.ip_lo = hdr.ipv4.dst_addr; meta.pt_lo = hdr.tcp.dst_port;
        meta.ip_hi = hdr.ipv4.src_addr; meta.pt_hi = hdr.tcp.src_port;
    }
    /* Signed lexicographic order on (ip,port). Direction-independent: swapping src/dst
     * flips both diffs' signs, flipping the decision, yielding the SAME (lo,hi). The IP-tie
     * entries (full 32-bit mask on ip_diff==0) are listed FIRST so they win over the
     * MSB-only IP entries. */
    table tbl_key_order {
        key = { meta.ip_diff : ternary; meta.pt_diff : ternary; }
        actions = { order_keep; order_swap; }
        const default_action = order_keep();
        const entries = {
            (32w0 &&& 32w0xFFFFFFFF, 16w0x8000 &&& 16w0x8000) : order_keep();  /* ip==, sport<dport */
            (32w0 &&& 32w0xFFFFFFFF, 16w0x0000 &&& 16w0x8000) : order_swap();  /* ip==, sport>=dport */
            (32w0x80000000 &&& 32w0x80000000, 16w0 &&& 16w0)  : order_keep();  /* src < dst (signed) */
            (32w0x00000000 &&& 32w0x80000000, 16w0 &&& 16w0)  : order_swap();  /* src > dst (signed) */
        }
        size = 8;
    }
    action do_flow_hash() {
        meta.flow_idx = flow_hash.get({ meta.ip_lo, meta.pt_lo, meta.ip_hi, meta.pt_hi,
                                        hdr.ipv4.protocol });
    }
    table tbl_flow_hash {
        actions = { do_flow_hash; }
        const default_action = do_flow_hash();
        size = 1;
    }
    action do_fp_hash() {
        meta.fp_cur = fp_hash.get({ meta.ip_lo, meta.pt_lo, meta.ip_hi, meta.pt_hi,
                                    hdr.ipv4.protocol });
    }
    table tbl_fp_hash {
        actions = { do_fp_hash; }
        const default_action = do_fp_hash();
        size = 1;
    }
    /* token flow index comes from the carried hdr.ib.flow (low 10 bits). */
    action fold_token_flow() { meta.flow_idx = hdr.ib.flow[9:0]; }
    table tbl_flow_fold {
        actions = { fold_token_flow; }
        const default_action = fold_token_flow();
        size = 1;
    }
    /* FIX 3: pktgen folds the reg_active_flow read-back to its 10-bit index. */
    action fold_pktgen_flow() { meta.flow_idx = meta.flow_wide[9:0]; }
    table tbl_pktgen_fold {
        actions = { fold_pktgen_flow; }
        const default_action = fold_pktgen_flow();
        size = 1;
    }

    /* ===== FIX 2: collision decision (fp_diff != 0 => owned by another flow) ===== */
    action set_collision()   { meta.collision = 8w1; }
    action clear_collision() { meta.collision = 8w0; }
    table tbl_collision {
        key = { meta.fp_diff : ternary; }
        actions = { set_collision; clear_collision; }
        /* openers/tokens/pktgen never run fp_check => fp_diff stays 0 => clear (matched);
         * a checking packet whose stored fp differs has fp_diff != 0 => default set. */
        const default_action = set_collision();
        const entries = { (16w0 &&& 16w0xFFFF) : clear_collision(); }
        size = 2;
    }

    /* ===== is_real from ROLE alone (available early, breaks the bitmap cycle) ===== */
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

    /* ===== FIN/RST detect -> per-flow cleanup trigger (FIX 6 hard reset) ===== */
    action mark_cleanup() { meta.cleanup_trig = B_TRUE; }
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

    /* ===== OPERATE linkage from the phase FSM pre-state ===== */
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

    /* ===== FIX 4: pktgen token active check keyed on the EXPLICIT validity bit ===== */
    action mark_txn_active()   { meta.txn_active = 8w1; }
    action mark_txn_inactive() { meta.txn_active = 8w0; }
    table tbl_pktgen_active {
        key = { meta.valid_cur : exact; }
        actions = { mark_txn_active; mark_txn_inactive; }
        const default_action = mark_txn_inactive();
        const entries = { (B_TRUE) : mark_txn_active(); }   /* validity == 1 => emit blocker */
        size = 2;
    }

    /* ===== slot assign: slot_id = cur_slot & MASK ===== */
    action assign_slot() { meta.slot_id = meta.cur_slot & SLOT_MASK; }
    table tbl_slot_assign {
        actions = { assign_slot; }
        const default_action = assign_slot();
        size = 1;
    }

    /* ===== FIX 7: expected-slot compare (slot_diff = slot_id - exp_slot) ===== */
    action calc_slot_diff() { meta.slot_diff = meta.slot_id - meta.exp_slot; }
    table tbl_slot_diff {
        actions = { calc_slot_diff; }
        const default_action = calc_slot_diff();
        size = 1;
    }
    action set_slot_ok()    { meta.slot_ok = B_TRUE; }
    action set_slot_notok() { meta.slot_ok = B_FALSE; }
    table tbl_slot_ok {
        key = { meta.exp_slot : ternary; meta.slot_diff : ternary; }
        actions = { set_slot_ok; set_slot_notok; }
        const default_action = set_slot_notok();
        const entries = {
            (EXP_SLOT_ANY &&& 8w0xFF, 8w0 &&& 8w0)   : set_slot_ok();  /* policy = any slot */
            (8w0 &&& 8w0, 8w0x00 &&& 8w0xFF)         : set_slot_ok();  /* assigned == expected */
        }
        size = 4;
    }

    /* ===== epoch rollover = slot clock wrapped (slot_id == 0) ===== */
    action mark_rollover()   { meta.epoch_rollover = B_TRUE; }
    action mark_norollover() { meta.epoch_rollover = B_FALSE; }
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

    /* ===== per-slot size lookup ===== */
    action set_size(bit<16> sz) { meta.size_bytes = sz; }
    table tbl_slot_size {
        key = { meta.size_profile : exact; meta.slot_id : exact; }
        actions = { set_size; }
        default_action = set_size(16w0);
        size = 256;
    }

    /* ===== FIX 8: TRUE inner frame length = eth(14) + ipv4.total_len ===== */
    action calc_inner_len() { meta.inner_len = hdr.ipv4.total_len + 16w14; }
    table tbl_inner_len {
        actions = { calc_inner_len; }
        const default_action = calc_inner_len();
        size = 1;
    }

    /* ===== FIX 9: release predicate — MODE_FAIL_OPEN now has a do_release() entry =====
     * UNIVERSAL fail-open backstops (expiry OR budget) force RELEASE under EVERY mode.
     * MODE_FAIL_OPEN itself now releases explicitly instead of falling through to hold. */
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
            /* universal backstops — ALL modes */
            (8w0 &&& 8w0, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release(); /* abs-deadline */
            (8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0) : do_release(); /* budget      */
            /* FIX 9: explicit MODE_FAIL_OPEN release */
            (8w0 &&& 8w0, MODE_FAIL_OPEN    &&& 8w0xFF, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            /* per-mode predicates */
            (8w0 &&& 8w0, MODE_IMMEDIATE    &&& 8w0xFF, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            (8w0 &&& 8w0, MODE_ABS_DEADLINE &&& 8w0xFF, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            (8w0 &&& 8w0, MODE_PRED_OFFSET  &&& 8w0xFF, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            /* MATCH_EVENT: ACK releases on the event; RESPONSE also needs its ACK gone */
            (8w0 &&& 8w1, MODE_MATCH_EVENT  &&& 8w0xFF, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w0 &&& 8w0) : do_release();
            (8w1 &&& 8w1, MODE_MATCH_EVENT  &&& 8w0xFF, 8w0 &&& 8w0, 8w1 &&& 8w1, 8w0 &&& 8w0, 8w1 &&& 8w1) : do_release();
        }
        size = 32;
    }

    /* ===== FIX 7: real/filler tag — FULL-mask occupancy AND expected-slot enforcement ===
     * A unit is REAL only if: role says real (is_real) AND the slot was FREE (slot_hit==0,
     * full 32-bit mask) AND it is in its expected slot (slot_ok). Otherwise -> filler. v2
     * matched slot_hit with a 0 (wildcard) mask, tagging everything real regardless. */
    action tag_real() { meta.realfill = RF_REAL; }
    action tag_fill() { meta.realfill = RF_FILL; }
    table tbl_realfill {
        key = { meta.is_real : exact; meta.slot_hit : ternary; meta.slot_ok : exact; }
        actions = { tag_real; tag_fill; }
        const default_action = tag_fill();
        const entries = {
            (RF_REAL, 32w0 &&& 32w0xFFFFFFFF, B_TRUE) : tag_real();
        }
        size = 8;
    }

    /* ===== outer encapsulation field write (FIX 8: 8-byte header incl inner_len) ===== */
    action set_encap() {
        hdr.outer.setValid();
        hdr.outer.direction  = meta.dir;
        hdr.outer.txn_tag    = meta.gen_cur;
        hdr.outer.slot_id    = meta.slot_id;
        hdr.outer.realfill   = meta.realfill;
        hdr.outer.inner_len  = meta.inner_len;   /* FIX 8: TRUE inner frame length */
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
            /* ---------- level 0: packet scalars + params + early classify ---------- */
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            /* budget_zero is a RESERVOIR-TOKEN concept only. Guarding it to tokens keeps a
             * host ACK/RESPONSE (whose hdr.ib is invalid) from spuriously tripping the
             * budget fail-open backstop and releasing before its deadline (FIX 6/10). */
            if ((meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) && hdr.ib.seq == 32w0) {
                meta.budget_zero = 8w1;
            }
            tbl_params.apply();      /* FIX 7: also yields exp_slot */
            tbl_guard.apply();
            tbl_isreal.apply();
            /* FIX 1: host packets derive the canonical key; token/pktgen carry theirs. */
            if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
                tbl_key_diff.apply();
                tbl_fin_rst.apply();                 /* FIN/RST cleanup trigger */
                tbl_inner_len.apply();               /* FIX 8: TRUE inner length */
            }
            if (meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) {
                tbl_flow_fold.apply();               /* token/pktgen flow_idx from hdr.ib.flow */
            }

            /* ---------- level 1: canonical order + now-word + class/phase drivers ---------- */
            if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
                tbl_key_order.apply();               /* FIX 1: ip_lo/hi, pt_lo/hi */
            }
            tbl_build_now.apply();
            if (meta.dequeued == 8w0 && meta.is_pktgen == 8w0) {
                if (meta.role == ROLE_ARM && meta.dir == DIR_MASTER) {
                    meta.pkt_class = CLASS_ARM;      /* READ opens a transaction */
                } else if (meta.role == ROLE_ACK && meta.dir == DIR_OUT) {
                    meta.pkt_class = CLASS_ACK;
                }
            } else if (meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) {
                meta.pkt_class = CLASS_BLOCK_DEQ;
            }
            /* phase FSM target (constants only; consumed by phase_set at L4) */
            if (meta.cleanup_trig == B_TRUE) {
                meta.phase_next = PH_IDLE;                                  /* FIN/RST */
            } else if (meta.role == ROLE_SELECT && meta.dir == DIR_MASTER) {
                meta.phase_next = PH_SELECT_SEEN;
            } else if (meta.role == ROLE_OPERATE && meta.dir == DIR_MASTER) {
                meta.phase_next = PH_OPERATE_SEEN;
            } else {
                meta.phase_next = PH_IDLE;                                  /* READ */
            }

            /* ---------- level 2: canonical host hash -> flow_idx + fingerprint ---------- */
            if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
                tbl_flow_hash.apply();               /* FIX 1: flow_idx (bit<10>) */
                tbl_fp_hash.apply();                 /* FIX 2: fp_cur (bit<16>) */
            }
            tbl_build_abs.apply();
            tbl_build_slot.apply();

            /* ---------- level 3: ownership guard (FIX 2) + active-flow binding (FIX 3) ----
             * The pktgen path reads reg_active_flow HERE to learn the flow INDEX before it
             * reads that flow's generation/validity at L4 — the ordering v2 got wrong. */
            if (meta.is_pktgen == 8w1) {
                meta.flow_wide = actflow_read.execute(0);  /* FIX 3: learn flow (wide) FIRST */
                meta.cur_slot  = slot_advance.execute(0);  /* pktgen drives the grid clock  */
            } else if (meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) {
                meta.cur_slot = slot_read.execute(0);      /* dequeued token */
            } else {
                /* host packet: claim/check/free the fingerprint that owns this index */
                if (meta.cleanup_trig == B_TRUE) {
                    fp_clear.execute(meta.flow_idx);       /* FIX 6: FIN/RST frees ownership */
                    actflow_clear.execute(0);              /* FIX 6: drop active-flow binding */
                } else if ((meta.role == ROLE_ARM    && meta.dir == DIR_MASTER) ||
                           (meta.role == ROLE_SELECT && meta.dir == DIR_MASTER)) {
                    fp_claim.execute(meta.flow_idx);       /* FIX 2: opener claims the index */
                    actflow_write.execute(0);              /* FIX 3: record active flow index */
                } else {
                    meta.fp_diff = fp_check.execute(meta.flow_idx);  /* FIX 2: verify owner */
                }
                meta.cur_slot = slot_read.execute(0);
            }
            tbl_collision.apply();                   /* FIX 2: fp_diff != 0 => collision */
            if (meta.is_pktgen == 8w1) {
                tbl_pktgen_fold.apply();             /* FIX 3: fold learned flow -> flow_idx */
            }

            /* ---------- level 4: primary state machine (gated on !collision) ----------
             * FIX 2: on a collision the host packet writes NO per-flow state and fails open
             * (handled in the ACT block), so it cannot corrupt the owning flow. */
            if (meta.collision == 8w0) {
                if (meta.is_pktgen == 8w1) {
                    /* FIX 3: now read the LEARNED flow's current generation + validity */
                    meta.gen_cur   = tag_get.execute(meta.flow_idx);
                    meta.valid_cur = valid_read.execute(meta.flow_idx);   /* FIX 4 */
                } else if (meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) {
                    meta.tag_diff = tag_match.execute(meta.flow_idx);     /* token liveness */
                } else {
                    /* host packet */
                    if (meta.cleanup_trig == B_TRUE) {
                        meta.gen_cur = tag_clear.execute(meta.flow_idx);  /* FIN/RST reset */
                        valid_clear.execute(meta.flow_idx);               /* FIX 6 */
                    } else if ((meta.role == ROLE_ARM    && meta.dir == DIR_MASTER) ||
                               (meta.role == ROLE_SELECT && meta.dir == DIR_MASTER)) {
                        meta.gen_cur = tag_open.execute(meta.flow_idx);   /* internal gen++ */
                        valid_set.execute(meta.flow_idx);                 /* FIX 4: validity=1 */
                    } else {
                        meta.gen_cur = tag_get.execute(meta.flow_idx);    /* passive read */
                    }
                    /* phase FSM transition */
                    if (meta.cleanup_trig == B_TRUE ||
                        (meta.role == ROLE_ARM     && meta.dir == DIR_MASTER) ||
                        (meta.role == ROLE_SELECT  && meta.dir == DIR_MASTER) ||
                        (meta.role == ROLE_OPERATE && meta.dir == DIR_MASTER)) {
                        meta.phase_old = phase_set.execute(meta.flow_idx);
                    } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                        meta.phase_old = phase_resp.execute(meta.flow_idx);
                    } else {
                        meta.phase_old = phase_read.execute(meta.flow_idx);
                    }
                }

                /* ---------- level 5: secondary registers (FIX 6 cleanup breadth) ---------- */
                if (meta.is_pktgen == 8w0 &&
                    !(meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK)) {
                    if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                        meta.event_diff   = event_resp.execute(meta.flow_idx);
                        meta.ack_released = ackgone_resp.execute(meta.flow_idx);
                    } else if (meta.role == ROLE_ACK && meta.dir == DIR_OUT) {
                        meta.event_diff   = event_check.execute(meta.flow_idx);
                    } else if (meta.cleanup_trig == B_TRUE ||
                               (meta.role == ROLE_ARM    && meta.dir == DIR_MASTER) ||
                               (meta.role == ROLE_SELECT && meta.dir == DIR_MASTER)) {
                        /* FIX 6: a new SELECT/READ open AND FIN/RST clear event + ack_gone
                         * BEFORE the transaction starts (covers the fail-open residue too). */
                        event_clear.execute(meta.flow_idx);
                        ackgone_clear.execute(meta.flow_idx);
                    }
                } else if ((meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK)
                           && meta.budget_zero == 8w1) {
                    ackgone_set.execute(meta.flow_idx);   /* reservoir drained */
                }
            }
            tbl_slot_assign.apply();
            tbl_slot_diff.apply();                   /* FIX 7 */

            /* ---------- level 6: decodes + candidate select + size lookup ---------- */
            tbl_cand_select.apply();
            tbl_state_decode.apply();
            tbl_phase_decode.apply();
            tbl_pktgen_active.apply();               /* FIX 4: keyed on validity */
            tbl_event_decode.apply();
            tbl_rollover.apply();
            tbl_slot_onehot.apply();
            tbl_slot_size.apply();
            tbl_slot_ok.apply();                     /* FIX 7 */

            /* ---------- level 7: deadline + bitmap (gated !collision) ----------
             * FIX 6: a TERMINAL response (pre-state IDLE=READ-resp OR OPERATE_SEEN=OPERATE-
             * resp, i.e. NOT SELECT_SEEN) and a FIN/RST both clear the deadline; a terminal
             * response also FREES its grid slot. */
            if (meta.collision == 8w0) {
                if (meta.ack_ok == 8w1) {
                    meta.age = deadline_arm_once.execute(meta.flow_idx);
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT
                           && meta.phase_old != PH_SELECT_SEEN) {
                    meta.age = deadline_clear.execute(meta.flow_idx);        /* FIX 6 terminal */
                } else if (meta.cleanup_trig == B_TRUE) {
                    meta.age = deadline_clear.execute(meta.flow_idx);        /* FIX 6 FIN/RST */
                } else {
                    meta.age = deadline_rmw.execute(meta.flow_idx);
                }
                if (meta.epoch_rollover == B_TRUE && meta.is_pktgen == 8w1) {
                    meta.slot_hit = bitmap_clear.execute(0);
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT
                           && meta.phase_old != PH_SELECT_SEEN) {
                    meta.slot_hit = bitmap_free.execute(0);                  /* FIX 6 slot retire */
                } else if (meta.is_real == RF_REAL) {
                    meta.slot_hit = bitmap_test_set.execute(0);
                } else {
                    meta.slot_hit = bitmap_read.execute(0);
                }
            }

            /* ---------- level 8: expiry + realfill ---------- */
            tbl_deadline_expiry.apply();
            if (meta.role == ROLE_RESP) { meta.is_response = B_TRUE; }
            tbl_realfill.apply();                    /* FIX 7 */

            /* ---------- level 9: release decision + encap field write ---------- */
            tbl_release_select.apply();              /* FIX 9 */
            tbl_encap.apply();                       /* FIX 8 */

            /* ---------- ACT ---------- */
            if (meta.collision == 8w1) {
                /* FIX 2: index owned by another flow -> forward unshaped (fail open). No
                 * per-flow state was written above, so the owning flow is uncorrupted. */
                to_fwd();
                ctr_collision.count(0);
            } else if (meta.dequeued == 8w0 && meta.is_pktgen == 8w0) {
                /* ---- host packets ---- */
                if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    if (meta.linkage_ok == 8w1) { ctr_sbo_linked.count(0); }
                    if (meta.release == REL_RELEASE) { to_fwd();       ctr_fwd.count(0); }
                    else                             { to_resp_hold(); ctr_hold.count(0); }  /* qid 0 */
                } else if (meta.role == ROLE_ACK) {
                    if (meta.release == REL_RELEASE) { to_fwd();      ctr_fwd.count(0); }
                    else                             { to_ack_hold(); ctr_hold.count(0); }   /* qid 5 */
                } else if (meta.role == ROLE_ARM) {
                    to_fwd();
                    if (meta.gen_cur != 8w0) { arm_clone(); }   /* trigger the reservoir seeding */
                } else if (meta.role == ROLE_SELECT) {
                    to_fwd();
                } else if (meta.role == ROLE_OPERATE) {
                    to_fwd();
                    if (meta.linkage_ok == 8w1) { ctr_sbo_linked.count(0); }
                } else {
                    to_fwd();
                    ctr_bypass.count(8w0);
                }
            } else if (meta.is_pktgen == 8w1) {
                /* ---- FIX 5: pktgen seed -> create a blocker into the RIGHT reservoir ----
                 * The seed packet carries its target role (ROLE_BLOCK or ROLE_RESP_BLK).
                 * Both reservoirs are seeded, and each blocker role provably routes to its
                 * own QID (qid 7 for the ACK reservoir, qid 3 for the RESPONSE reservoir). */
                if (meta.txn_active == 8w1) {
                    hdr.ib.gen  = meta.gen_cur;
                    hdr.ib.flow = (bit<16>)meta.flow_idx;
                    hdr.ib.seq  = INITIAL_BUDGET;
                    if (meta.role == ROLE_RESP_BLK) {
                        hdr.ib.role = ROLE_RESP_BLK; to_resp_block();   /* qid 3 */
                    } else {
                        hdr.ib.role = ROLE_BLOCK;    to_ack_block();    /* qid 7 */
                    }
                } else {
                    drop_pkt();
                }
            } else {
                /* ---- dequeued blocker token: loop or terminate ---- */
                if (meta.role == ROLE_BLOCK || meta.role == ROLE_RESP_BLK) {
                    if (meta.tag_diff != 8w0) {
                        drop_pkt();      ctr_block_term.count(0);   /* superseded generation */
                    } else if (meta.expired == 8w1) {
                        drop_pkt();      ctr_block_term.count(0);
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt();      ctr_block_term.count(0);
                    } else {
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        if (meta.role == ROLE_BLOCK) { to_ack_block(); }    /* qid 7 */
                        else                         { to_resp_block(); }   /* qid 3 */
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
        pkt.emit(hdr.outer);     /* FIX 8: 8-byte prepended D4 control header */
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

/* ============================ egress (pass-through) ====================
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

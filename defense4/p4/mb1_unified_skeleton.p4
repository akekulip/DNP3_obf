/* ============================================================================
 * mb1_unified_skeleton.p4 — MB-1, the decisive combined INGRESS compile for the
 *   Defense 4 feasibility (TASK 2 / directive §5). NON-FROZEN probe under
 *   defense4/p4/. Nothing loaded or run; this answers ONE question: does the unified
 *   timing + SBO + slot + SIZE-CONTROL surface fit the Tofino-1 ingress, and in how
 *   many stages?
 *
 * INCLUDES (all mandatory per directive §5 — the whole point of the compile):
 *   - configurable release predicates over a params table:
 *       IMMEDIATE / MATCHING_RESPONSE_EVENT / ABSOLUTE_DEADLINE /
 *       PREDECESSOR_PLUS_OFFSET / bounded FAIL_OPEN                    (tbl_params,
 *       tbl_cand_select, reg_event, tbl_release_select)
 *   - READ / SELECT / OPERATE phase state                              (reg_phase)
 *   - SELECT->OPERATE linkage bound by flow+phase+generation, NOT app-seq
 *                                                                      (reg_phase diff
 *                                                                       + tbl_phase_decode)
 *   - generation-safe matching and cleanup                            (reg_tag, resets)
 *   - slot bitmap and slot-clock (grid epoch) state    (reg_slot_clock, reg_slot_bitmap)
 *   - size_profile selection                                          (tbl_params)
 *   - per-slot size lookup                                            (tbl_slot_size)
 *   - outer-header fields (prepend encap: direction, txn_tag, slot_id)(outer_encap_h,
 *                                                                       tbl_encap)
 *   - real/filler tagging inside the trusted representation           (tbl_realfill)
 *   - fail-open logic                                    (budget termination + MODE)
 *
 * EXCLUDED (permitted by directive §5): detailed telemetry (no latency-timestamp
 *   registers, no G-selection guard) and the PHYSICAL padding action (the egress
 *   byte-append that would grow the frame to size_bytes). The size-CONTROL surface —
 *   selecting the profile, looking up the per-slot target size, writing it and the
 *   slot/direction/txn/real-filler fields into the trusted representation — IS present.
 *
 * DESIGN NOTE — the TNA traps this skeleton respects (so the stage count is honest,
 *   not a placement artifact): every value that COMBINES a just-read/just-computed
 *   value lives in its OWN single-action table (bf-p4c merges consecutive
 *   unconditional statements into one action and then rejects the intra-action
 *   dependency as "action spanning multiple stages" — measured on 9.13.1). Sign / mask
 *   tests are ternary TCAM masks over a WHOLE container, never a bit-slice of an
 *   arithmetic field. Each register has <=2 PHV inputs and one access per packet.
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
const bit<8>  DNP3_FC_RESPONSE  = 8w129;

/* ---- roles ---- */
const bit<8> ROLE_BYPASS  = 0;
const bit<8> ROLE_BLOCK   = 1;
const bit<8> ROLE_RESP    = 2;
const bit<8> ROLE_SELECT  = 3;   /* DNP3 SELECT  */
const bit<8> ROLE_OPERATE = 4;   /* DNP3 OPERATE */
const bit<8> ROLE_ARM     = 6;   /* DNP3 READ    */
const bit<8> ROLE_ACK     = 7;   /* pure TCP ACK */

/* ---- direction ---- */
const bit<8> DIR_MASTER = 0;
const bit<8> DIR_OUT    = 1;

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;
const PortId_t PORT_VISION = 9w9;
const PortId_t PORT_HULK   = 9w11;
const PortId_t PORT_RELAY  = 9w64;
const PortId_t PORT_PGEN   = 9w68;

/* ---- queues ---- */
const bit<5> QID_BLOCK = 5w7;
const bit<5> QID_RESP  = 5w1;

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
const bit<8>  TAG_INACTIVE = 8w0xFF;
const bit<8>  TAG_NO_WRITE = 8w0;
const bit<32> G_DEFAULT_TICKS = 32w0x017D7800;

/* ---- packet classes (timing decode) ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;
const bit<8> CLASS_ACK       = 8w2;
const bit<8> CLASS_BLOCK_DEQ = 8w3;

/* ---- SBO phase classes (phase decode) ---- */
const bit<8> PCLASS_NONE    = 8w0;
const bit<8> PCLASS_SELECT  = 8w1;
const bit<8> PCLASS_OPERATE = 8w2;
const bit<8> PCLASS_CLEAR   = 8w3;   /* READ / RESPONSE clears the SBO state */

const bit<8> PH_NO_WRITE = 8w0;      /* reg_phase SALU sentinel: leave state    */
const bit<8> PH_IDLE     = 8w0xFE;   /* explicit "no SELECT outstanding"        */

/* ---- release modes (selected by tbl_params) ---- */
const bit<8> MODE_IMMEDIATE    = 8w0;  /* D1a: forward now                       */
const bit<8> MODE_MATCH_EVENT  = 8w1;  /* D1b: hold until matching response event*/
const bit<8> MODE_ABS_DEADLINE = 8w2;  /* D2 / D3: hold until t_ack + G          */
const bit<8> MODE_PRED_OFFSET  = 8w3;  /* grid: release at predecessor + offset  */
const bit<8> MODE_FAIL_OPEN    = 8w4;  /* bounded backstop override              */

/* ---- release decision ---- */
const bit<8> REL_HOLD    = 8w0;
const bit<8> REL_RELEASE = 8w1;

/* ---- real / filler tag ---- */
const bit<8> RF_FILL = 8w0;
const bit<8> RF_REAL = 8w1;

/* ---- slot geometry ---- */
const bit<8>  SLOT_MASK = 8w0x1F;      /* 32 slots per epoch */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header recirc_tag_h { bit<32> tag; }
header ibspg_h { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

/* the prepended outer encapsulation carrying the SIZE-CONTROL representation. The
 * PHYSICAL padding (growing the frame to size_bytes) is excluded from this skeleton;
 * the CONTROL fields it carries are written in ingress and are what cost stages. */
header outer_encap_h {
    bit<8>  direction;    /* DIR_MASTER / DIR_OUT                 */
    bit<8>  txn_tag;      /* transaction generation              */
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
    /* piece 1: parser classification */
    bit<8>  role;
    bit<8>  dir;
    bit<9>  fwd_port;
    bit<8>  port_ok;
    bit<8>  gen_in;
    bit<8>  dequeued;
    bit<32> ts32;
    bit<8>  budget_zero;

    /* timing core */
    bit<32> ts_m;
    bit<32> seq_m;           /* G in ticks (tbl_guard)                     */
    bit<32> now_word;
    bit<8>  pkt_class;
    bit<8>  tag_val;
    bit<32> dl_cand_abs;     /* now + G          (ABS_DEADLINE candidate)  */
    bit<32> dl_cand_slot;    /* now + slot off   (PRED_OFFSET candidate)   */
    bit<32> dl_cand;         /* mode-selected candidate                    */
    bit<8>  tag_diff;
    bit<32> dl_val;
    bit<8>  tag_ok;
    bit<8>  ack_ok;
    bit<32> age;
    bit<8>  expired;

    /* pktgen */
    bit<8>     is_pktgen;
    bit<8>     cur_gen;
    bit<8>     txn_active;
    bit<32>    clone_tag;
    MirrorId_t clone_ses;

    /* release-mode surface */
    bit<8>  mode;            /* tbl_params                                 */
    bit<32> slot_off_ticks;  /* tbl_params (PRED_OFFSET)                    */
    bit<8>  event_diff;      /* reg_event SALU result                      */
    bit<8>  event_due;       /* matching response event seen               */
    bit<8>  release;         /* REL_HOLD / REL_RELEASE                      */

    /* SBO phase surface */
    bit<8>  phase_class;     /* PCLASS_*                                    */
    bit<8>  phase_val;       /* reg_phase write driver                      */
    bit<8>  phase_diff;      /* reg_phase SALU result                       */
    bit<8>  linkage_ok;      /* OPERATE matched its SELECT (gen+phase)      */

    /* slot surface */
    bit<8>  cur_slot;        /* reg_slot_clock                             */
    bit<8>  slot_id;         /* cur_slot & SLOT_MASK                        */
    bit<32> slot_onehot;     /* one-hot(slot_id) for the bitmap            */
    bit<8>  slot_occupied;   /* bitmap test result                         */

    /* size surface */
    bit<8>  size_profile;    /* tbl_params                                 */
    bit<16> size_bytes;      /* tbl_slot_size(size_profile, slot_id)        */

    /* trusted-representation tag */
    bit<8>  realfill;
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
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.ts_m            = 32w0;
        meta.seq_m           = 32w0;
        meta.now_word        = 32w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.tag_val         = TAG_NO_WRITE;
        meta.dl_cand_abs     = 32w0;
        meta.dl_cand_slot    = 32w0;
        meta.dl_cand         = 32w0;
        meta.tag_diff        = 8w0;
        meta.dl_val          = DL_NO_WRITE;
        meta.tag_ok          = 8w0;
        meta.ack_ok          = 8w0;
        meta.age             = 32w0;
        meta.expired         = 8w0;
        meta.cur_gen         = 8w0;
        meta.txn_active      = 8w0;
        meta.clone_tag       = 32w0;
        meta.clone_ses       = 10w0;
        meta.mode            = MODE_IMMEDIATE;
        meta.slot_off_ticks  = 32w0;
        meta.event_diff      = 8w0;
        meta.event_due       = 8w0;
        meta.release         = REL_HOLD;
        meta.phase_class     = PCLASS_NONE;
        meta.phase_val       = PH_NO_WRITE;
        meta.phase_diff      = 8w0;
        meta.linkage_ok      = 8w0;
        meta.cur_slot        = 8w0;
        meta.slot_id         = 8w0;
        meta.slot_onehot     = 32w0;
        meta.slot_occupied   = 8w0;
        meta.size_profile    = 8w0;
        meta.size_bytes      = 16w0;
        meta.realfill        = RF_FILL;
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

    state parse_token {
        pkt.extract(hdr.ib);
        meta.role   = ROLE_BLOCK;
        meta.gen_in = hdr.ib.gen;
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

    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        meta.gen_in = hdr.dnp3_app.app_control;
        transition select(hdr.dnp3_app.app_control, hdr.dnp3_app.func_code) {
            (8w0x00 &&& 8w0x00, DNP3_FC_RESPONSE) : set_role_resp;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_READ)     : set_role_arm;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_SELECT)   : set_role_select;
            (8w0xC0 &&& 8w0xF0, DNP3_FC_OPERATE)  : set_role_operate;
            default                               : accept;
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

    /* ===== register 1: TAG (generation + active) — timing match + gen safety ===== */
    Register<bit<8>, bit<1>>(1, 0) reg_tag;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* ===== register 2: DEADLINE (ACK-relative) — ABS_DEADLINE / PRED_OFFSET ===== */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val != DL_NO_WRITE) { v = meta.dl_val; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_arm_once = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (v == UNARMED_WORD) { v = meta.dl_val; }
        }
    };

    /* ===== register 3: SBO PHASE — SELECT->OPERATE linkage by generation ===== */
    /* stores the SELECT's generation; OPERATE's linkage_ok comes from the SALU
     * difference (0 <=> same generation, i.e. this OPERATE matches its SELECT). Bound
     * by flow(single relay)+phase+generation — NOT the DNP3 app-seq. */
    Register<bit<8>, bit<1>>(1, 0) reg_phase;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_phase) phase_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;               /* 0 <=> OPERATE matches SELECT gen */
            if (meta.phase_val != PH_NO_WRITE) { v = meta.phase_val; }
        }
    };

    /* ===== register 4: MATCHING-RESPONSE EVENT — MODE_MATCH_EVENT (D1b) ===== */
    Register<bit<8>, bit<1>>(1, 0) reg_event;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_event) event_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = meta.gen_in; rv = 8w0; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_event) event_check = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = meta.gen_in - v; }
    };

    /* ===== register 5: SLOT-CLOCK (grid epoch) ===== */
    Register<bit<8>, bit<1>>(1, 0) reg_slot_clock;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_slot_clock) slot_advance = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 8w1; rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_slot_clock) slot_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* ===== register 6: SLOT BITMAP (one-hot occupancy) ===== */
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

    /* ===== counters (lightweight) ===== */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_fwd;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_hold;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_sbo_linked;
    Counter<bit<64>, bit<8>>(2, CounterType_t.PACKETS) ctr_bypass;

    /* ===== TM actions ===== */
    action to_block() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_fwd() {
        ig_tm_md.ucast_egress_port = meta.fwd_port;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    action arm_clone() {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.gen_in;
    }

    /* ===== params: mode + size_profile + slot offset (the release-predicate selector) ===== */
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
    action set_guard(bit<32> g_ticks) { meta.seq_m = g_ticks; }
    table tbl_guard {
        actions = { set_guard; }
        default_action = set_guard(G_DEFAULT_TICKS);
        size = 1;
    }

    action build_now() { meta.now_word = meta.ts_m | ARMED_MARK; }
    table tbl_build_now {
        actions = { build_now; }
        const default_action = build_now();
        size = 1;
    }

    /* two candidate deadlines (parallel; both depend only on now_word) */
    action build_abs()  { meta.dl_cand_abs  = meta.now_word + meta.seq_m; }
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
        const entries = {
            (MODE_PRED_OFFSET) : pick_slot();
        }
        size = 8;
    }

    /* ===== the timing decode table (arm / qualify / disarm / live) ===== */
    action dec_arm()     { meta.dl_val = UNARMED_WORD; }
    action dec_ack_arm() { meta.dl_val = meta.dl_cand; meta.ack_ok = 8w1; }
    action dec_live()    { meta.dl_val = DL_NO_WRITE;  meta.tag_ok = 8w1; }
    action dec_none()    { meta.dl_val = DL_NO_WRITE; }
    table tbl_state_decode {
        key = { meta.pkt_class : exact; meta.tag_diff : ternary; }
        actions = { dec_arm; dec_ack_arm; dec_live; dec_none; }
        const default_action = dec_none();
        const entries = {
            (CLASS_ARM,       8w0x00 &&& 8w0x00) : dec_arm();
            (CLASS_ACK,       8w0x00 &&& 8w0xFE) : dec_none();
            (CLASS_ACK,       8w0x00 &&& 8w0x00) : dec_ack_arm();
            (CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF) : dec_live();
        }
        size = 8;
    }

    /* ===== SBO phase decode: linkage + generation-safe cleanup ===== */
    action ph_link_ok()  { meta.linkage_ok = 8w1; }
    action ph_link_bad() { meta.linkage_ok = 8w0; }
    table tbl_phase_decode {
        key = { meta.phase_class : exact; meta.phase_diff : ternary; }
        actions = { ph_link_ok; ph_link_bad; }
        const default_action = ph_link_bad();
        const entries = {
            /* OPERATE whose generation matches the outstanding SELECT (diff == 0) */
            (PCLASS_OPERATE, 8w0x00 &&& 8w0xFF) : ph_link_ok();
        }
        size = 4;
    }

    /* ===== pktgen token active check ===== */
    action mark_txn_active()   { meta.txn_active = 8w1; }
    action mark_txn_inactive() { meta.txn_active = 8w0; }
    table tbl_pktgen_active {
        key = { meta.cur_gen : ternary; }
        actions = { mark_txn_active; mark_txn_inactive; }
        const default_action = mark_txn_inactive();
        const entries = { (8w0xC0 &&& 8w0xF0) : mark_txn_active(); }
        size = 2;
    }

    /* ===== slot assign: slot_id = cur_slot & MASK ===== */
    action assign_slot() { meta.slot_id = meta.cur_slot & SLOT_MASK; }
    table tbl_slot_assign {
        actions = { assign_slot; }
        const default_action = assign_slot();
        size = 1;
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
        const entries = { (8w0x00 &&& 8w0xFF) : ev_seen(); }   /* diff==0 => response seen */
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

    /* ===== release select: the configurable predicate ===== */
    action do_release() { meta.release = REL_RELEASE; }
    action do_hold()    { meta.release = REL_HOLD; }
    table tbl_release_select {
        key = {
            meta.mode        : exact;
            meta.expired     : ternary;   /* ABS_DEADLINE / PRED_OFFSET due */
            meta.event_due   : ternary;   /* MATCH_EVENT due               */
            meta.budget_zero : ternary;   /* FAIL_OPEN backstop            */
        }
        actions = { do_release; do_hold; }
        const default_action = do_hold();
        const entries = {
            (MODE_IMMEDIATE,    8w0x00 &&& 8w0x00, 8w0x00 &&& 8w0x00, 8w0x00 &&& 8w0x00) : do_release();
            (MODE_ABS_DEADLINE, 8w0x01 &&& 8w0x01, 8w0x00 &&& 8w0x00, 8w0x00 &&& 8w0x00) : do_release();
            (MODE_PRED_OFFSET,  8w0x01 &&& 8w0x01, 8w0x00 &&& 8w0x00, 8w0x00 &&& 8w0x00) : do_release();
            (MODE_MATCH_EVENT,  8w0x00 &&& 8w0x00, 8w0x01 &&& 8w0x01, 8w0x00 &&& 8w0x00) : do_release();
            (MODE_FAIL_OPEN,    8w0x00 &&& 8w0x00, 8w0x00 &&& 8w0x00, 8w0x01 &&& 8w0x01) : do_release();
        }
        size = 16;
    }

    /* ===== real / filler tag (trusted representation) ===== */
    action tag_real() { meta.realfill = RF_REAL; }
    action tag_fill() { meta.realfill = RF_FILL; }
    table tbl_realfill {
        key = { meta.role : exact; meta.slot_occupied : ternary; }
        actions = { tag_real; tag_fill; }
        const default_action = tag_fill();
        const entries = {
            (ROLE_RESP,    8w0x00 &&& 8w0x00) : tag_real();
            (ROLE_ACK,     8w0x00 &&& 8w0x00) : tag_real();
            (ROLE_ARM,     8w0x00 &&& 8w0x00) : tag_real();
            (ROLE_SELECT,  8w0x00 &&& 8w0x00) : tag_real();
            (ROLE_OPERATE, 8w0x00 &&& 8w0x00) : tag_real();
        }
        size = 16;
    }

    /* ===== outer encapsulation field write (control surface; no byte-append) ===== */
    action set_encap() {
        hdr.outer.setValid();
        hdr.outer.direction  = meta.dir;
        hdr.outer.txn_tag    = meta.gen_in;
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
            /* ---- level 0: packet-derived ---- */
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }
            tbl_params.apply();
            tbl_guard.apply();

            /* ---- level 1: now-word, class drivers ---- */
            tbl_build_now.apply();
            if (meta.dequeued == 8w0) {
                if (meta.role == ROLE_ARM && meta.dir == DIR_MASTER) {
                    meta.pkt_class   = CLASS_ARM;
                    meta.tag_val     = meta.gen_in;
                    meta.phase_class = PCLASS_CLEAR;      /* a READ clears SBO state  */
                    meta.phase_val   = PH_IDLE;
                } else if (meta.role == ROLE_ACK && meta.dir == DIR_OUT) {
                    meta.pkt_class   = CLASS_ACK;
                } else if (meta.role == ROLE_SELECT && meta.dir == DIR_MASTER) {
                    meta.phase_class = PCLASS_SELECT;     /* SELECT stores its gen    */
                    meta.phase_val   = meta.gen_in;
                } else if (meta.role == ROLE_OPERATE && meta.dir == DIR_MASTER) {
                    meta.phase_class = PCLASS_OPERATE;    /* OPERATE checks linkage   */
                    meta.phase_val   = PH_NO_WRITE;
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    meta.phase_class = PCLASS_CLEAR;      /* RESPONSE clears SBO state */
                    meta.phase_val   = PH_IDLE;
                }
            } else if (meta.role == ROLE_BLOCK) {
                meta.pkt_class = CLASS_BLOCK_DEQ;
                if (meta.budget_zero == 8w1) { meta.tag_val = TAG_INACTIVE; }
            }

            /* ---- level 2: register reads (parallel; independent registers) ---- */
            if (meta.is_pktgen == 8w1) {
                meta.cur_gen  = tag_read.execute(0);
            } else {
                meta.tag_diff = tag_rmw.execute(0);
            }
            meta.phase_diff = phase_rmw.execute(0);
            if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                meta.event_diff = event_set.execute(0);      /* response posts the event */
            } else {
                meta.event_diff = event_check.execute(0);
            }
            if (meta.is_pktgen == 8w1) {
                meta.cur_slot = slot_advance.execute(0);      /* pktgen drives the clock  */
            } else {
                meta.cur_slot = slot_read.execute(0);
            }
            tbl_build_abs.apply();
            tbl_build_slot.apply();

            /* ---- level 3: decodes + slot assign + mode candidate select ---- */
            tbl_cand_select.apply();
            tbl_state_decode.apply();
            tbl_phase_decode.apply();
            tbl_pktgen_active.apply();
            tbl_event_decode.apply();
            tbl_slot_assign.apply();

            /* ---- level 4: one-hot, size lookup, deadline + bitmap access ---- */
            tbl_slot_onehot.apply();
            tbl_slot_size.apply();
            if (meta.ack_ok == 8w1) {
                meta.age = deadline_arm_once.execute(0);
            } else {
                meta.age = deadline_rmw.execute(0);
            }

            /* ---- level 5: expiry + bitmap test/set ---- */
            tbl_deadline_expiry.apply();
            if (meta.realfill == RF_REAL) {
                bitmap_test_set.execute(0);
            } else {
                bitmap_read.execute(0);
            }

            /* ---- level 6: release decision + realfill + encap field write ---- */
            tbl_release_select.apply();
            tbl_realfill.apply();
            tbl_encap.apply();

            /* ---- ACT ---- */
            if (meta.dequeued == 8w0) {
                if (meta.role == ROLE_BLOCK) {
                    if (meta.txn_active == 8w1) {
                        hdr.ib.role = ROLE_BLOCK;
                        hdr.ib.gen  = meta.cur_gen;
                        hdr.ib.seq  = INITIAL_BUDGET;
                        to_block();
                    } else {
                        drop_pkt();
                    }
                } else if (meta.role == ROLE_RESP && meta.dir == DIR_OUT) {
                    if (meta.release == REL_RELEASE) { to_fwd();  ctr_fwd.count(0); }
                    else                             { to_resp(); ctr_hold.count(0); }
                } else if (meta.role == ROLE_ACK) {
                    if (meta.release == REL_RELEASE) { to_fwd();  ctr_fwd.count(0); }
                    else                             { to_resp(); ctr_hold.count(0); }
                } else if (meta.role == ROLE_ARM) {
                    to_fwd();
                    if (meta.tag_diff != 8w0) { arm_clone(); }
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
                if (meta.role == ROLE_BLOCK) {
                    if (meta.tag_ok == 8w0) {
                        drop_pkt();      ctr_block_term.count(0);
                    } else if (meta.expired == 8w1) {
                        drop_pkt();      ctr_block_term.count(0);
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt();      ctr_block_term.count(0);
                    } else {
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();      ctr_block_loop.count(0);
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

/* ============================ egress (skeleton pass-through) ============ */
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

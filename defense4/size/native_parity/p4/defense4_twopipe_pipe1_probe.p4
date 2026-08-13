/* ============================================================================
 * ►►►► defense4_twopipe_pipe1_probe.p4 — BOR OPERATE HOLD/RELEASE, PIPE 1 ONLY ◄◄◄◄
 *
 * TWO-PIPE SPLIT, pipe-1 half (compile probe, bf-p4c 9.13.1, --target tofino --arch tna).
 * The frozen RRC kernel + T0-admission live on PIPE 0 (defense4_twopipe_pipe0_probe.p4).
 * This program runs on PIPE 1 and does ONE thing: receive the protected OPERATE that
 * pipe 0 routed across the internal cross-pipe loopback (carrying T0 in an internal
 * xpipe header), select a leak-safe hold J, hold the ORIGINAL bytes to T0+J using pipe
 * 1's OWN blocker reservoir + hold queues, then release the byte-identical OPERATE to
 * the relay EXACTLY ONCE. No RRC transaction engine, no ACK/response hold, no PRE carve
 * on this pipe — those stay on pipe 0. Tofino state is per-pipe: T0 arrives in the
 * packet header, never in a shared register.
 *
 * WHY A SEPARATE PROGRAM: the faithful one-pipe RRC+BOR build is 13 ingress stages, one
 * over budget (BOR_STAGE_RECOVERY_RESULT.md). The chip has num_pipes=2, so BOR is split
 * onto pipe 1 and re-measured. This half is the OPERATE hold/release CORE alone; standing
 * on its own (no RRC 12-stage tail underneath it) it is expected to fit with wide margin.
 *
 * MECHANISM (blocker-reservoir hold, proven in Defense 2/3):
 *   qid3 = OPERATE blocker reservoir (K tokens, strict-HIGH), drains at T0+J
 *   qid2 = held original OPERATE     (strict-LOW), starved by qid3 until it drains
 * A fresh OPERATE arrives on PORT_X1 (pipe-1 cross-pipe entry), arms reg_topj = T0+J and
 * seeds qid3, and is held in qid2 (xpipe stripped -> byte-identical original in the queue).
 * qid3 blocker tokens loop on PORT_L1 (pipe-1 hold ring); when T0+J passes they terminate,
 * qid2 dequeues the held OPERATE ONCE, and it is forwarded to PORT_RELAY (dp64, pipe 0).
 *
 * READINESS RACE (BOR_RRC_DESIGN.md §3): the OPERATE is held only when a confirmed-resident
 * qid3 flag (reg_ready, this generation) is set; otherwise it FAILS OPEN WITHOUT HOLDING
 * (forwards immediately, counted). A hold that races its own reservoir is never taken.
 *
 * COMPILE PROBE ONLY — NOT silicon. A behavioral model is not a compile; a compile is not
 * silicon. The physical divergence floor needs an authorized physical campaign.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---------------- pipe-1 ports (dev_port = (pipe<<7) | local; pipe 1 => >=128) ----------
 * Representative pipe-1 dev_ports; the exact front-panel<->dev_port map for pipe-1 ports
 * comes from the box port map (see the proposal, "cross-pipe route"). All that matters for
 * the compile is that they are valid 9-bit pipe-1 port ids. */
const PortId_t PORT_X1     = 9w144;  /* pipe-1 cross-pipe ENTRY (MAC loopback): fresh OPERATE from pipe 0 */
const PortId_t PORT_L1     = 9w136;  /* pipe-1 BOR HOLD RING (MAC loopback): qid3 blocker + qid2 hold     */
const PortId_t PORT_PGEN1  = 9w196;  /* pipe-1 pktgen/recirc port: seeds the qid3 reservoir              */
const PortId_t PORT_RELAY  = 9w64;   /* release target: the relay leg on pipe 0 (cross-pipe egress ok)   */

/* ---------------- strict-priority queue ladder on PORT_L1 (qid == max_priority) ---------- */
const bit<5> QID_OP_BLOCK = 5w3;   /* OPERATE blocker reservoir (HIGH) : loops, drains at T0+J */
const bit<5> QID_OP_HOLD  = 5w2;   /* held original OPERATE      (LOW)  : starved until qid3 drains */
const bit<5> QID_FWD      = 5w0;   /* normal final FIFO toward the relay                          */

/* ---------------- ethertypes ---------------- */
const bit<16> ETYPE_IPV4   = 16w0x0800;
const bit<16> ETYPE_TOKEN  = 16w0x88C1;  /* internal blocker token (as in RRC)                 */
const bit<16> ETYPE_XPIPE  = 16w0x88C2;  /* internal cross-pipe carrier set by pipe 0 on the OPERATE */

const bit<8>  IP_PROTO_TCP  = 8w6;
const bit<16> DNP3_START    = 16w0x0564;
const bit<8>  DNP3_FC_OPERATE = 8w4;

/* ---------------- deadline-word arithmetic (identical to RRC) ---------------- */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;  /* keep 24 tick bits, clear the marker byte */
const bit<32> ARMED_MARK   = 32w0x00000001;  /* bit 0 of the deadline word = armed       */
const bit<32> DL_NO_WRITE  = 32w0;           /* SALU sentinel: leave the deadline be     */
const bit<8>  GEN_INACTIVE = 8w0x00;         /* no active OPERATE transaction            */

/* ---------------- roles / verdicts ---------------- */
const bit<8> ROLE_BYPASS = 8w0;
const bit<8> ROLE_ARM    = 8w1;   /* the (cross-pipe or held) OPERATE                     */
const bit<8> ROLE_BLOCK  = 8w2;   /* a qid3 blocker token                                 */

const bit<8> V_NONE      = 8w0;
const bit<8> V_OP_FRESH  = 8w1;   /* fresh OPERATE, generation newly armed                */
const bit<8> V_OP_DUP    = 8w2;   /* exact retransmit of the held OPERATE (same gen)      */
const bit<8> V_OP_BUSY   = 8w3;   /* a different generation is already active             */
const bit<8> V_BLK_LIVE  = 8w4;   /* qid3 token of the current generation                 */

/* ---------------- pktgen slot + defaults ---------------- */
const bit<8>  SLOT_OP    = 8w2;
const bit<32> J_DEFAULT_TICKS   = 32w0x00002800;  /* ~2.7 ms in 256 ns ticks (low byte 0)  */
const bit<32> BUDGET_DEFAULT    = 32w64;          /* K=64 reservoir pass budget            */
const bit<32> PGEN_HDR_BITS     = 32w48;

/* ---------------- mirror (reservoir seed), as in RRC ---------------- */
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_CLONE = 1;
const MirrorId_t    CLONE_SESSION_ID  = 10w7;      /* pipe-1 mirror session -> PORT_PGEN1 */
const bit<32>       CLONE_TAG_MARKER  = 32w0xE1000000;
const bit<8>        CLONE_TAG_BYTE    = 8w0xE1;

/* ---------------- counters (indexed; CP aggregates a slot across replicated stages) ------ */
const bit<8> CF_BAD_PORT      = 8w0;
const bit<8> CF_OP_HOLD       = 8w1;   /* OPERATE held in qid2 (request-hold armed)         */
const bit<8> CF_OP_FAILOPEN   = 8w2;   /* residency unconfirmed -> forwarded, no hold        */
const bit<8> CF_OP_RETRANS    = 8w3;   /* retransmit while held -> dropped (exactly-once)     */
const bit<8> CF_OP_BUSY       = 8w4;   /* concurrent generation -> forwarded unprotected      */
const bit<8> CF_PKTGEN_ADMIT  = 8w5;   /* qid3 token admitted                                 */
const bit<8> CF_PKTGEN_DROP   = 8w6;   /* qid3 token dropped (no active txn / invalid)        */
const bit<8> CF_CLONE_SEEN    = 8w7;   /* the reservoir-trigger clone came back: dropped      */
const bit<8> CD_OP_LOOP       = 8w0;   /* qid3 token re-enqueued                              */
const bit<8> CD_OP_TERM_STALE = 8w1;   /* qid3 token terminated: not this generation          */
const bit<8> CD_OP_TERM_DL    = 8w2;   /* qid3 token terminated: T0+J reached (drain->release)*/
const bit<8> CD_OP_TERM_TMO   = 8w3;   /* qid3 token terminated: fail-open horizon             */
const bit<8> CD_OP_RELEASE    = 8w4;   /* held OPERATE released to the relay (exactly once)    */

/* ================================ headers ================================ */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
/* internal cross-pipe carrier, sits AFTER eth (eth.etype == ETYPE_XPIPE). orig_etype
 * restores byte identity on release; t0 is the pipe-0 ingress MAC timestamp tick. */
header xpipe_h { bit<16> orig_etype; bit<32> t0; }
header recirc_tag_h { bit<32> tag; }
header ibspg_h { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }
header ipv4_h {
    bit<4>  version; bit<4>  ihl;      bit<8>  diffserv;    bit<16> total_len;
    bit<16> identification; bit<16> flags_frag;
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
header pktgen_hdr_h { bit<8> pipe_app; bit<24> key_or_batch; bit<16> packet_id; }

struct headers_t {
    pktgen_hdr_h pgen;    /* consumed on the pktgen path; NEVER emitted */
    ethernet_h  eth;
    xpipe_h     xpipe;    /* valid only on the cross-pipe leg; stripped at hold/release */
    ibspg_h     ib;
    ipv4_h      ipv4;
    tcp_h       tcp;
    tcp_opt4_h  tcp_opt4;
    tcp_opt8_h  tcp_opt8;
    tcp_opt12_h tcp_opt12;
    dnp3_dl_h   dnp3_dl;
    dnp3_tp_h   dnp3_tp;
    dnp3_app_h  dnp3_app;
}

/* ================================ metadata ============================== */
struct ig_meta_t {
    bit<8>  role;
    bit<8>  dequeued;      /* 1 if ingress_port == PORT_L1 (a looped-back frame)     */
    bit<8>  is_pktgen;     /* 1 if admitted from PORT_PGEN1                          */
    bit<8>  is_xpipe;      /* 1 if the frame carried a valid xpipe header (fresh OP) */
    bit<8>  port_ok;

    bit<32> ts_m;          /* now ticks (masked)                                    */
    bit<32> t0_m;          /* xpipe.t0 & TICK_MASK                                   */
    bit<32> now_word;      /* ts_m | ARMED_MARK  (built at level 1, own stage)       */
    bit<32> t0_word;       /* t0_m | ARMED_MARK  (built at level 1, own stage)       */

    bit<8>  gen_in;        /* generation carried by this frame                      */
    bit<8>  gen_stored;    /* reg_gen pre-state                                     */
    bit<8>  tag_val;       /* reg_gen write operand                                 */
    bit<8>  verdict;
    bit<8>  txn_active;    /* 1 if a generation is active                           */
    bit<8>  budget_zero;   /* 1 if hdr.ib.seq == 0 (fail-open watchdog)             */

    bit<32> j_ticks;       /* selected hold J (leak-safe codebook)                  */
    bit<32> budget_init;   /* K reservoir pass budget                               */
    bit<32> topj_cand;     /* t0_word + j_ticks = the armed T0+J word               */
    bit<32> dl_val_topj;   /* reg_topj write operand (DL_NO_WRITE = read)           */
    bit<32> age_topj;      /* now_word - reg_topj                                   */
    bit<16> expired_topj;  /* 1 = T0+J armed AND due                                */
    bit<8>  op_ready;      /* reg_ready read: residency proven for this generation  */

    bit<8>  ev_block_term;
    bit<32> clone_tag;
    MirrorId_t clone_ses;
}

/* ================================ parser ================================ */
parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    value_set<bit<8>>(1) pgen_recirc;   /* pipe-1 pktgen leading byte (CP-loaded, exact 0xFF) */

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.role = ROLE_BYPASS; meta.dequeued = 8w0; meta.is_pktgen = 8w0; meta.is_xpipe = 8w0;
        meta.port_ok = 8w0; meta.ts_m = 32w0; meta.t0_m = 32w0; meta.now_word = 32w0; meta.t0_word = 32w0;
        meta.gen_in = 8w0; meta.gen_stored = 8w0; meta.tag_val = 8w0; meta.verdict = V_NONE;
        meta.txn_active = 8w0; meta.budget_zero = 8w0; meta.j_ticks = 32w0; meta.budget_init = 32w0;
        meta.topj_cand = 32w0; meta.dl_val_topj = DL_NO_WRITE; meta.age_topj = 32w0;
        meta.expired_topj = 16w0; meta.op_ready = 8w0; meta.ev_block_term = 8w0;
        meta.clone_tag = 32w0; meta.clone_ses = 10w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_X1    : from_xpipe;     /* fresh OPERATE from pipe 0 */
            PORT_L1    : from_loop;      /* looped-back: qid3 token or held OPERATE */
            PORT_PGEN1 : from_pgen;      /* pktgen token seed */
            default    : accept;         /* off-topology -> port_ok 0 -> dropped in MAU */
        }
    }
    state from_xpipe { meta.port_ok = 8w1;                       transition parse_eth; }
    state from_loop  { meta.port_ok = 8w1; meta.dequeued = 8w1;  transition parse_eth; }
    state from_pgen {
        transition select(pkt.lookahead<bit<8>>()) {
            pgen_recirc    : parse_pktgen_token;
            CLONE_TAG_BYTE : parse_clone;
            default        : accept;
        }
    }
    state parse_clone { meta.role = ROLE_BYPASS; meta.port_ok = 8w1; transition accept; }
    state parse_pktgen_token {
        meta.is_pktgen = 8w1; meta.port_ok = 8w1;
        pkt.extract(hdr.pgen);          /* NEVER emitted */
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETYPE_TOKEN : parse_token;   /* qid3 blocker */
            ETYPE_XPIPE : parse_xpipe;   /* fresh cross-pipe OPERATE */
            ETYPE_IPV4  : parse_ipv4;    /* the byte-identical held OPERATE on the L1 loop */
            default     : accept;
        }
    }
    state parse_token {
        pkt.extract(hdr.ib);
        meta.role = ROLE_BLOCK; meta.gen_in = hdr.ib.gen;
        transition accept;
    }
    state parse_xpipe {
        pkt.extract(hdr.xpipe);
        meta.is_xpipe = 8w1;
        transition parse_ipv4;
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
        transition select(hdr.tcp.data_offset) {
            4w5 : parse_dnp3_dl;
            4w6 : opt4;
            4w7 : opt8;
            4w8 : opt12;
            default : accept;
        }
    }
    state opt4  { pkt.extract(hdr.tcp_opt4);  transition parse_dnp3_dl; }
    state opt8  { pkt.extract(hdr.tcp_opt8);  transition parse_dnp3_dl; }
    state opt12 { pkt.extract(hdr.tcp_opt12); transition parse_dnp3_dl; }
    state parse_dnp3_dl {
        pkt.extract(hdr.dnp3_dl);
        transition select(hdr.dnp3_dl.start) {
            DNP3_START : parse_dnp3_tp;
            default    : accept;
        }
    }
    state parse_dnp3_tp { pkt.extract(hdr.dnp3_tp); transition parse_dnp3_app; }
    state parse_dnp3_app {
        pkt.extract(hdr.dnp3_app);
        meta.gen_in = hdr.dnp3_app.app_control;
        transition select(hdr.dnp3_app.func_code) {
            DNP3_FC_OPERATE : set_role_operate;
            default         : accept;
        }
    }
    state set_role_operate { meta.role = ROLE_ARM; transition accept; }
}

/* ================================ ingress ============================== */
control Ingress(inout headers_t hdr, inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) ctr_fresh;
    Counter<bit<64>, bit<8>>(8,  CounterType_t.PACKETS) ctr_deq;

    /* ---- reg_gen: the active OPERATE generation (0 = inactive) ---- */
    Register<bit<8>, bit<1>>(1, 0) reg_gen;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_arm = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;                                  /* pre-state: 0 fresh, ==gen dup, else busy */
            if (v == GEN_INACTIVE) { v = meta.gen_in; }
        }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_retire = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = GEN_INACTIVE; }
    };

    /* ---- reg_topj: the OPERATE request-hold deadline T0+J ---- */
    Register<bit<32>, bit<1>>(1, 0) reg_topj;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_topj) topj_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;                  /* age for the qid3 expiry test */
            if (meta.dl_val_topj != DL_NO_WRITE) { v = meta.dl_val_topj; }
        }
    };

    /* ---- reg_ready: qid3 residency confirmation (readiness race) ---- */
    Register<bit<8>, bit<1>>(1, 0) reg_ready;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_ready) ready_confirm = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = meta.gen_in; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_ready) ready_read = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = 8w0;
            if (v == meta.gen_in) { rv = 8w1; }      /* residency proven for THIS generation */
        }
    };

    /* ================= TM enqueue actions ================= */
    action to_op_block() {                    /* qid3 reservoir, loops on the hold ring */
        ig_tm_md.ucast_egress_port = PORT_L1;
        ig_tm_md.qid               = QID_OP_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_op_hold() {                     /* qid2 held OPERATE, starved on the hold ring */
        ig_tm_md.ucast_egress_port = PORT_L1;
        ig_tm_md.qid               = QID_OP_HOLD;
        ig_tm_md.bypass_egress     = 1w1;
    }
    #define OP_RELEASE()  { ig_tm_md.ucast_egress_port = PORT_RELAY; \
                            ig_tm_md.qid               = QID_FWD;    \
                            ig_tm_md.bypass_egress     = 1w0; }
    #define OP_FWD_RELAY() { ig_tm_md.ucast_egress_port = PORT_RELAY; \
                             ig_tm_md.qid               = QID_FWD;    \
                             ig_tm_md.bypass_egress     = 1w0; }
    #define OP_DROP()      { ig_dprsr_md.drop_ctl = 3w1; }
    #define STRIP_XPIPE()  { hdr.eth.etype = hdr.xpipe.orig_etype; hdr.xpipe.setInvalid(); }

    action arm_clone() {                      /* seed the qid3 reservoir via one mirror burst */
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.gen_in;
    }

    /* ---- level 0: runtime params (keyless) + leak-safe J codebook (keyed) ---- */
    action set_params(bit<32> budget) { meta.budget_init = budget; }
    table tbl_params {
        actions = { set_params; }
        const default_action = set_params(BUDGET_DEFAULT);
        size = 1;
    }
    /* the bounded delay codebook: a per-flow J profile, keyed on the relay-facing dst_port,
     * NEVER on any public DNP3 application-sequence value (anti-subtraction §7). The
     * production build swaps this for a leak-safe Random<>/salt source; the codebook is the
     * control-plane interface either way. */
    action set_j(bit<32> j_ticks) { meta.j_ticks = j_ticks; }
    table tbl_bor_codebook {
        key = { hdr.tcp.dst_port : exact; }
        actions = { set_j; }
        const default_action = set_j(J_DEFAULT_TICKS);
        size = 64;
    }

    /* ---- level 1: build the deadline-aligned "now" and T0 words (mask at L0, OR here so
     * each field is a single-op action in its own stage — the RRC tbl_build_now idiom). ---- */
    action build_words() {
        meta.now_word = meta.ts_m | ARMED_MARK;
        meta.t0_word  = meta.t0_m | ARMED_MARK;
    }
    table tbl_build_words {
        actions = { build_words; }
        const default_action = build_words();
        size = 1;
    }

    /* ---- level 3: T0+J expiry (armed AND due), whole-container mask (as in RRC) ---- */
    action mark_expired_topj()     { meta.expired_topj = 16w1; }
    action mark_not_expired_topj() { meta.expired_topj = 16w0; }
    table tbl_topj_expiry {
        key = { meta.age_topj : ternary; }
        actions = { mark_expired_topj; mark_not_expired_topj; }
        const default_action = mark_not_expired_topj();
        const entries = { (32w0x00000000 &&& 32w0x800000FF) : mark_expired_topj(); }
        size = 2;
    }

    apply {
        if (meta.port_ok == 8w0) {
            ctr_fresh.count(CF_BAD_PORT);
            OP_DROP()
        } else {
            /* ---------- level 0: packet-derived + params (single-op masks) ---------- */
            meta.ts_m = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            /* T0 travels in the packet header (per-pipe state cannot be shared). */
            meta.t0_m = hdr.xpipe.t0 & TICK_MASK;
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }   /* only meaningful under ROLE_BLOCK */
            tbl_params.apply();
            tbl_bor_codebook.apply();

            /* ---------- level 1: build now_word / t0_word (OR in their own stage) ---------- */
            tbl_build_words.apply();

            /* ---------- level 2: generation binding (one reg_gen access per packet) ------ */
            if (meta.dequeued == 8w0 && meta.role == ROLE_ARM && meta.is_xpipe == 8w1) {
                meta.tag_val    = meta.gen_in;
                meta.gen_stored = gen_arm.execute(0);       /* fresh: arm-if-inactive, return pre */
            } else if (meta.dequeued == 8w1 && meta.role == ROLE_ARM) {
                meta.gen_stored = gen_retire.execute(0);    /* held OPERATE release: retire the gen */
            } else {
                meta.gen_stored = gen_read.execute(0);      /* token / bypass: pure read           */
            }
            meta.txn_active = 8w0;
            if (meta.gen_stored != GEN_INACTIVE) { meta.txn_active = 8w1; }

            /* ---------- level 2: T0+J candidate (one add) ---------- */
            meta.topj_cand = meta.t0_word + meta.j_ticks;

            /* ---------- level 3: verdict ---------- */
            if (meta.dequeued == 8w0 && meta.role == ROLE_ARM && meta.is_xpipe == 8w1) {
                if (meta.gen_stored == GEN_INACTIVE) {
                    meta.verdict     = V_OP_FRESH;
                    meta.dl_val_topj = meta.topj_cand;      /* reg_topj := T0 + J */
                } else if (meta.gen_stored == meta.gen_in) {
                    meta.verdict = V_OP_DUP;
                } else {
                    meta.verdict = V_OP_BUSY;
                }
            } else if (meta.dequeued == 8w1 && meta.role == ROLE_BLOCK) {
                /* a qid3 token is LIVE iff it carries the current generation */
                if (meta.gen_in == meta.gen_stored && meta.txn_active == 8w1) {
                    meta.verdict = V_BLK_LIVE;
                } else {
                    meta.verdict = V_NONE;                  /* stale */
                }
            }

            /* ---------- level 4: reg_topj (arm on fresh OPERATE, else age) ------ */
            meta.age_topj = topj_rmw.execute(0);

            /* ---------- level 4/5: reg_ready — confirm on a live qid3 token, read on a
             * fresh OPERATE (mutually exclusive, one pipeline depth => co-located stage) --- */
            if (meta.dequeued == 8w1 && meta.role == ROLE_BLOCK && meta.verdict == V_BLK_LIVE) {
                ready_confirm.execute(0);
            } else if (meta.dequeued == 8w0 && meta.role == ROLE_ARM && meta.is_xpipe == 8w1) {
                meta.op_ready = ready_read.execute(0);
            }

            /* ---------- level 5: expiry ---------- */
            tbl_topj_expiry.apply();

            /* ================= ACT ================= */
            if (meta.dequeued == 8w0) {
                if (meta.role == ROLE_ARM && meta.is_xpipe == 8w1) {
                    /* ---- the fresh cross-pipe OPERATE ---- */
                    if (meta.verdict == V_OP_FRESH) {
                        arm_clone();                        /* seed the qid3 reservoir (this gen) */
                        if (meta.op_ready == 8w1) {
                            STRIP_XPIPE()                   /* byte-identical original into qid2 */
                            to_op_hold();
                            ctr_fresh.count(CF_OP_HOLD);
                        } else {
                            /* readiness NOT proven -> fail open WITHOUT holding (no race) */
                            STRIP_XPIPE()
                            OP_FWD_RELAY()
                            ctr_fresh.count(CF_OP_FAILOPEN);
                        }
                    } else if (meta.verdict == V_OP_DUP) {
                        OP_DROP()                            /* retransmit while held: exactly-once */
                        ctr_fresh.count(CF_OP_RETRANS);
                    } else {
                        STRIP_XPIPE()                        /* concurrent gen: forward unprotected */
                        OP_FWD_RELAY()
                        ctr_fresh.count(CF_OP_BUSY);
                    }
                } else if (meta.role == ROLE_BLOCK && meta.is_pktgen == 8w1) {
                    /* ---- pktgen admission: seed qid3 while a transaction is active ---- */
                    if (meta.txn_active == 8w1) {
                        hdr.ib.role = ROLE_BLOCK;
                        hdr.ib.slot = SLOT_OP;
                        hdr.ib.gen  = meta.gen_stored;      /* current generation */
                        hdr.ib.seq  = meta.budget_init;     /* K pass budget      */
                        to_op_block();
                        ctr_fresh.count(CF_PKTGEN_ADMIT);
                    } else {
                        OP_DROP()
                        ctr_fresh.count(CF_PKTGEN_DROP);
                    }
                } else if (meta.role == ROLE_BLOCK) {
                    OP_DROP()                                /* a fresh non-generated token: reject */
                    ctr_fresh.count(CF_CLONE_SEEN);
                } else {
                    OP_DROP()                                /* nothing else is admitted on pipe 1 */
                    ctr_fresh.count(CF_CLONE_SEEN);
                }
            } else {
                /* ---------- DEQUEUED (looped back on PORT_L1) ---------- */
                if (meta.role == ROLE_BLOCK) {
                    /* the qid3 OPERATE blocker reservoir */
                    if (meta.verdict != V_BLK_LIVE) {
                        OP_DROP()                            /* stale generation: terminate */
                        ctr_deq.count(CD_OP_TERM_STALE);
                        meta.ev_block_term = 8w1;
                    } else if (meta.expired_topj == 16w1) {
                        OP_DROP()                            /* T0+J reached: drain -> release */
                        ctr_deq.count(CD_OP_TERM_DL);
                        meta.ev_block_term = 8w1;
                    } else if (meta.budget_zero == 8w1) {
                        OP_DROP()                            /* fail-open horizon */
                        ctr_deq.count(CD_OP_TERM_TMO);
                        meta.ev_block_term = 8w1;
                    } else {
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_op_block();                       /* re-enqueue qid3 */
                        ctr_deq.count(CD_OP_LOOP);
                    }
                } else if (meta.role == ROLE_ARM) {
                    /* ►► THE OP_RELEASE PASS. qid3 drained at T0+J, so the qid2-held original
                     * OPERATE is back on the hold ring. It carries no xpipe (stripped at
                     * enqueue) and is byte-identical. Forward to the relay EXACTLY ONCE. */
                    OP_RELEASE()
                    ctr_deq.count(CD_OP_RELEASE);
                } else {
                    OP_DROP()
                }
            }
        }
    }
}

/* ================================ deparser ============================= */
control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_meta_t meta,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Mirror() clone_mirror;
    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_CLONE) {
            clone_mirror.emit<recirc_tag_h>(meta.clone_ses, { meta.clone_tag });
        }
        pkt.emit(hdr.eth);
        pkt.emit(hdr.xpipe);     /* valid only on the cross-pipe leg; invalid => not emitted */
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

/* ================================ egress (trivial) ====================
 * Pipe 1's bypass_egress=1 hold loop never runs egress; the only egress packets are the
 * released/failed-open/bypassed OPERATEs to the relay, emitted byte-identically. */
struct eg_meta_t { bit<1> unused; }
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t m,
                out egress_intrinsic_metadata_t eg) {
    state start { pkt.extract(eg); m.unused = 1w0; transition parse_eth; }
    state parse_eth { pkt.extract(hdr.eth); transition accept; }   /* residual re-emitted */
}
control Egress(inout headers_t hdr, inout eg_meta_t m,
               in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t prsr,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr,
               inout egress_intrinsic_metadata_for_output_port_t oport) {
    apply { }
}
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t m,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr) {
    apply { pkt.emit(hdr.eth); }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

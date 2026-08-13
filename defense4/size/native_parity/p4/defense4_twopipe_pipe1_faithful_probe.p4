/* ============================================================================
 * ►►►► defense4_twopipe_pipe1_faithful_probe.p4 — FAITHFUL BOR, PIPE 1 ONLY ◄◄◄◄
 *
 * TWO-PIPE SPLIT, pipe-1 half, with FAITHFUL SELECT-prepared readiness
 * (BOR_RRC_DESIGN.md §3, "Faithful readiness — SELECT prepares a BOR epoch").
 * bf-p4c 9.13.1, --target tofino --arch tna. The frozen RRC kernel + T0-admission +
 * the SELECT-prepare / OPERATE-handoff crossings live on PIPE 0
 * (defense4_twopipe_pipe0_probe.p4 built with -DPIPE0_SELECT_PREP). This program runs
 * on PIPE 1 and makes the FIRST OPERATE genuinely HELD (not fail-opened).
 *
 * WHY THIS EXISTS. The sibling probe defense4_twopipe_pipe1_probe.p4 carries the
 * fail-open-FIRST readiness: it reads an op_ready flag on the OPERATE BEFORE the qid3
 * reservoir it depends on exists, so the FIRST real OPERATE always reads 0 and FAILS
 * OPEN (safe bypass, UNSHAPED). That is a resource probe, not a faithful hold. This
 * program prepares the reservoir DURING the SELECT (SBO always SELECTs before OPERATE),
 * so qid3 is resident BEFORE the OPERATE and the first OPERATE is held on its first try.
 *
 * THE FAITHFUL MECHANISM (all on pipe 1's OWN per-pipe state; T0 + epoch arrive IN the
 * packet, never in a shared register):
 *   SELECT-prepare (a crossed DNP3 SELECT, func 0x03, on PORT_X1, carrying a FRESH BOR
 *     epoch in xpipe.epoch — NOT the 4-bit DNP3 generation):
 *       -> reg_epoch := epoch                     (BOR_PENDING(epoch), persists across SELECT)
 *       -> reg_ready := 0, reg_gen := 0           (a clean epoch: nothing confirmed/held yet)
 *       -> arm_clone()                            (seed the qid3 reservoir for THIS epoch)
 *       -> forward the SELECT byte-identically to the relay (SBO needs it)
 *     qid3 tokens (stamped with the epoch) loop on PORT_L1; a live token confirms
 *     residency (reg_ready := epoch). Residency becomes true BEFORE the OPERATE arrives.
 *   OPERATE-handoff (a crossed DNP3 OPERATE, func 0x04, on PORT_X1, carrying T0 + the
 *     SAME epoch):
 *       -> REQUIRE reg_epoch == epoch (BOR_PENDING match) AND reg_ready == epoch (residency)
 *          else FORWARD the original immediately to the relay + ++CF_OP_FAILOPEN (never
 *          enqueue on a stale/absent flag).
 *       -> on match: select a leak-safe J (codebook / random; the epoch is NEVER the source
 *          of J), arm reg_topj = T0+J, hold the byte-identical original in qid2, release it
 *          to the relay EXACTLY ONCE at T0+J.
 *   Retransmit while held  -> reg_gen dedup -> DROP (exactly-once, defence in depth for a
 *          pipe-0 dup-drop miss / the cross-pipe double-cross).
 *   Missing-OPERATE watchdog -> the qid3 reservoir exhausts its bounded budget and, on that
 *          termination, RETIRES the epoch (reg_epoch := 0), so a late OPERATE fails open.
 *   Retire (OPERATE release / fail-open) -> reg_epoch := 0, reg_ready := 0, reg_gen := 0,
 *          so a later stray OPERATE (incl. a 4-bit DNP3 sequence WRAP with no fresh SELECT)
 *          finds no live epoch and FAILS OPEN — the internal epoch identity gates the hold,
 *          never the public sequence.
 *
 * COMPILE PROBE ONLY — NOT silicon. A behavioral model is not a compile; a compile is not
 * silicon. The physical divergence floor needs an authorized physical campaign. The qid3
 * budget/rate sizing (residency continuity) is a control-plane / hardware question.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---------------- pipe-1 ports (dev_port = (pipe<<7) | local; pipe 1 => >=128) ----------
 * Representative pipe-1 dev_ports; the exact front-panel<->dev_port map is a deployment
 * detail (see BOR_TWO_PIPE_PROPOSAL.md §3). The compile needs only valid pipe-1 (>=128) ids. */
const PortId_t PORT_X1     = 9w144;  /* pipe-1 cross-pipe ENTRY (MAC loopback): SELECT-prepare + OPERATE from pipe 0 */
const PortId_t PORT_L1     = 9w136;  /* pipe-1 BOR HOLD RING (MAC loopback): qid3 blocker + qid2 hold             */
const PortId_t PORT_PGEN1  = 9w196;  /* pipe-1 pktgen/recirc port: seeds the qid3 reservoir                       */
const PortId_t PORT_RELAY  = 9w64;   /* release/forward target: the relay leg on pipe 0 (cross-pipe egress ok)    */

/* ---------------- strict-priority queue ladder on PORT_L1 (qid == max_priority) ---------- */
const bit<5> QID_OP_BLOCK = 5w3;   /* OPERATE blocker reservoir (HIGH) : loops, drains at T0+J     */
const bit<5> QID_OP_HOLD  = 5w2;   /* held original OPERATE      (LOW)  : starved until qid3 drains */
const bit<5> QID_FWD      = 5w0;   /* normal final FIFO toward the relay                           */

/* ---------------- ethertypes ---------------- */
const bit<16> ETYPE_IPV4   = 16w0x0800;
const bit<16> ETYPE_TOKEN  = 16w0x88C1;  /* internal blocker token (as in RRC)                       */
const bit<16> ETYPE_XPIPE  = 16w0x88C2;  /* internal cross-pipe carrier set by pipe 0                */

const bit<8>  IP_PROTO_TCP    = 8w6;
const bit<16> DNP3_START      = 16w0x0564;
const bit<8>  DNP3_FC_SELECT  = 8w3;   /* master -> outstation : SELECT (SBO phase 1) -> PREPARE     */
const bit<8>  DNP3_FC_OPERATE = 8w4;   /* master -> outstation : OPERATE (SBO phase 2) -> HOLD       */

/* ---------------- deadline-word arithmetic (identical to RRC) ---------------- */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;  /* keep 24 tick bits, clear the marker byte */
const bit<32> ARMED_MARK   = 32w0x00000001;  /* bit 0 of the deadline word = armed       */
const bit<32> DL_NO_WRITE  = 32w0;           /* SALU sentinel: leave the deadline be     */
const bit<16> EPOCH_NONE   = 16w0;           /* reg_epoch == 0  <=>  no prepared epoch    */
const bit<8>  GEN_INACTIVE = 8w0x00;         /* reg_gen == 0    <=>  no OPERATE held       */

/* ---------------- roles / verdicts ---------------- */
const bit<8> ROLE_BYPASS  = 8w0;
const bit<8> ROLE_PREPARE = 8w1;   /* the crossed SELECT: prepare the BOR epoch + reservoir */
const bit<8> ROLE_ARM     = 8w2;   /* the crossed / held OPERATE                            */
const bit<8> ROLE_BLOCK   = 8w3;   /* a qid3 blocker token                                  */

/* compact packet class, computed ONCE by tbl_classify at level 0 so every register access is
 * gated by a single-field (pclass) gateway — this is what lets reg_epoch/reg_ready/reg_gen each
 * co-locate with their (few, tiny) dispatch gateways in one stage. */
const bit<8> PC_OTHER   = 8w0;
const bit<8> PC_PREPARE = 8w1;   /* crossed SELECT (is_xpipe, ROLE_PREPARE)              */
const bit<8> PC_OPERATE = 8w2;   /* crossed OPERATE (is_xpipe, ROLE_ARM)                 */
const bit<8> PC_TOKEN   = 8w3;   /* dequeued qid3 token (ROLE_BLOCK, dequeued)           */
const bit<8> PC_PKTGEN  = 8w4;   /* pktgen admission (ROLE_BLOCK, is_pktgen)             */
const bit<8> PC_RELEASE = 8w5;   /* dequeued held OPERATE (ROLE_ARM, dequeued)           */

const bit<8> V_NONE      = 8w0;
const bit<8> V_OP_FRESH  = 8w1;   /* fresh OPERATE, generation newly armed                */
const bit<8> V_OP_DUP    = 8w2;   /* exact retransmit of the held OPERATE (same gen)      */
const bit<8> V_OP_BUSY   = 8w3;   /* a different generation is already active             */
const bit<8> V_BLK_LIVE  = 8w4;   /* qid3 token of the current BOR epoch                  */

/* ---------------- pktgen slot + defaults ---------------- */
const bit<8>  SLOT_OP    = 8w2;
const bit<32> J_DEFAULT_TICKS   = 32w0x00002800;  /* ~2.7 ms in 256 ns ticks (low byte 0)  */
const bit<32> BUDGET_DEFAULT    = 32w64;          /* K=64 reservoir pass budget            */

/* ---------------- mirror (reservoir seed), as in RRC ---------------- */
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_CLONE = 1;
const MirrorId_t    CLONE_SESSION_ID  = 10w7;      /* pipe-1 mirror session -> PORT_PGEN1 */
const bit<32>       CLONE_TAG_MARKER  = 32w0xE1000000;
const bit<8>        CLONE_TAG_BYTE    = 8w0xE1;

/* ---------------- counters (indexed; CP aggregates a slot across replicated stages) ------ */
const bit<8> CF_BAD_PORT      = 8w0;
const bit<8> CF_SEL_PREPARE   = 8w1;   /* SELECT crossed -> epoch prepared + reservoir seeded + fwd relay */
const bit<8> CF_OP_HOLD       = 8w2;   /* OPERATE held in qid2 (first-try shaped hold committed)          */
const bit<8> CF_OP_FAILOPEN   = 8w3;   /* no live/resident epoch match -> forwarded once, no hold          */
const bit<8> CF_OP_RETRANS    = 8w4;   /* retransmit while held -> dropped (exactly-once)                  */
const bit<8> CF_OP_BUSY       = 8w5;   /* concurrent generation -> forwarded unprotected                   */
const bit<8> CF_PKTGEN_ADMIT  = 8w6;   /* qid3 token admitted (epoch-stamped)                              */
const bit<8> CF_PKTGEN_DROP   = 8w7;   /* qid3 token dropped (no prepared epoch)                           */
const bit<8> CF_CLONE_SEEN    = 8w8;   /* the reservoir-trigger clone came back: dropped                   */
const bit<8> CD_OP_LOOP       = 8w0;   /* qid3 token re-enqueued                              */
const bit<8> CD_OP_TERM_STALE = 8w1;   /* qid3 token terminated: not the current epoch        */
const bit<8> CD_OP_TERM_DL    = 8w2;   /* qid3 token terminated: T0+J reached (drain->release)*/
const bit<8> CD_OP_TERM_TMO   = 8w3;   /* qid3 token terminated: budget/watchdog (epoch retired) */
const bit<8> CD_OP_RELEASE    = 8w4;   /* held OPERATE released to the relay (exactly once)    */
const bit<8> CD_SEL_FWD       = 8w5;   /* SELECT-prepare forwarded to the relay               */

/* ================================ headers ================================ */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
/* internal cross-pipe carrier, sits AFTER eth (eth.etype == ETYPE_XPIPE). orig_etype
 * restores byte identity on release; epoch is the FRESH BOR epoch pipe 0 allocated; t0 is
 * the pipe-0 ingress MAC timestamp tick. Stripped at pipe-1 hold/forward/release. */
header xpipe_h { bit<16> orig_etype; bit<16> epoch; bit<32> t0; }
header recirc_tag_h { bit<32> tag; }
/* internal blocker token: seq = pass budget, epoch = the BOR epoch the reservoir belongs to
 * (NOT a DNP3 generation). role/slot kept for wire compat with the Part 9/11/12 injector. */
header ibspg_h { bit<8> role; bit<8> slot; bit<16> epoch; bit<32> seq; }
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
    xpipe_h     xpipe;    /* valid only on the cross-pipe leg; stripped at prepare/hold/release */
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
    bit<8>  is_xpipe;      /* 1 if the frame carried a valid xpipe header            */
    bit<8>  port_ok;
    bit<8>  pclass;        /* PC_* compact packet class (tbl_classify, level 0)      */

    bit<32> ts_m;          /* now ticks (masked)                                    */
    bit<32> t0_m;          /* xpipe.t0 & TICK_MASK                                   */
    bit<32> now_word;      /* ts_m | ARMED_MARK  (built at level 1, own stage)       */
    bit<32> t0_word;       /* t0_m | ARMED_MARK  (built at level 1, own stage)       */

    bit<16> epoch_in;      /* xpipe.epoch (PREPARE/OPERATE) OR ib.epoch (token)     */
    bit<16> epoch_stored;  /* reg_epoch pre-state (BOR_PENDING identity)            */
    bit<16> ready_stored;  /* reg_ready pre-state (residency-confirmed epoch)       */
    bit<8>  op_matched;    /* 1 = reg_epoch == epoch_in (BOR_PENDING match, OPERATE) */
    bit<8>  op_ready;      /* 1 = reg_ready == epoch_in (residency, OPERATE)         */
    bit<8>  hold_ok;       /* 1 = op_matched AND op_ready (single-bit release gate)  */
    bit<8>  blk_live;      /* 1 = token epoch == reg_epoch (a live current-epoch token) */

    bit<8>  gen_in;        /* DNP3 generation carried by the crossed OPERATE        */
    bit<8>  gen_stored;    /* reg_gen pre-state                                     */
    bit<8>  verdict;       /* V_OP_* from reg_gen decode                            */
    bit<8>  budget_zero;   /* 1 if a ROLE_BLOCK token's ib.seq == 0 (watchdog)      */

    bit<32> j_ticks;       /* selected hold J (leak-safe codebook)                  */
    bit<32> budget_init;   /* K reservoir pass budget                               */
    bit<32> topj_cand;     /* t0_word + j_ticks = the armed T0+J word               */
    bit<32> dl_val_topj;   /* reg_topj write operand (DL_NO_WRITE = read)           */
    bit<32> age_topj;      /* now_word - reg_topj                                   */
    bit<16> expired_topj;  /* 1 = T0+J armed AND due                                */

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
        meta.port_ok = 8w0; meta.pclass = PC_OTHER;
        meta.ts_m = 32w0; meta.t0_m = 32w0; meta.now_word = 32w0; meta.t0_word = 32w0;
        meta.epoch_in = EPOCH_NONE; meta.epoch_stored = EPOCH_NONE; meta.ready_stored = EPOCH_NONE;
        meta.op_matched = 8w0; meta.op_ready = 8w0; meta.hold_ok = 8w0; meta.blk_live = 8w0;
        meta.gen_in = 8w0; meta.gen_stored = 8w0; meta.verdict = V_NONE; meta.budget_zero = 8w0;
        meta.j_ticks = 32w0; meta.budget_init = 32w0; meta.topj_cand = 32w0;
        meta.dl_val_topj = DL_NO_WRITE; meta.age_topj = 32w0; meta.expired_topj = 16w0;
        meta.ev_block_term = 8w0; meta.clone_tag = 32w0; meta.clone_ses = 10w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_X1    : from_xpipe;     /* SELECT-prepare or OPERATE from pipe 0 */
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
            ETYPE_XPIPE : parse_xpipe;   /* crossed SELECT-prepare or OPERATE */
            ETYPE_IPV4  : parse_ipv4;    /* the byte-identical held OPERATE on the L1 loop */
            default     : accept;
        }
    }
    state parse_token {
        pkt.extract(hdr.ib);
        meta.role = ROLE_BLOCK; meta.epoch_in = hdr.ib.epoch;
        transition accept;
    }
    state parse_xpipe {
        pkt.extract(hdr.xpipe);
        meta.is_xpipe = 8w1; meta.epoch_in = hdr.xpipe.epoch;
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
        /* only a CROSSED frame (is_xpipe) is a prepare/hold; a dequeued IPv4 (the held
         * OPERATE looping) keeps ROLE_BYPASS here and is handled by the dequeued path. */
        transition select(hdr.dnp3_app.func_code) {
            DNP3_FC_SELECT  : set_role_prepare;
            DNP3_FC_OPERATE : set_role_operate;
            default         : accept;
        }
    }
    state set_role_prepare { meta.role = ROLE_PREPARE; transition accept; }
    state set_role_operate { meta.role = ROLE_ARM;     transition accept; }
}

/* ================================ ingress ============================== */
control Ingress(inout headers_t hdr, inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS) ctr_fresh;
    Counter<bit<64>, bit<8>>(8,  CounterType_t.PACKETS) ctr_deq;

    /* ---- reg_epoch: BOR_PENDING(epoch). The SELECT prepares it; the OPERATE matches it;
     * a token peeks it; the watchdog / retire clear it. NOT a DNP3 generation. ---- */
    Register<bit<16>, bit<1>>(1, 0) reg_epoch;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_epoch) epoch_prepare = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; v = meta.epoch_in; }
    };
    /* read on the OPERATE / pktgen paths; on a token pass whose budget is exhausted AND that
     * carries the current epoch, RETIRE the epoch (the missing-OPERATE watchdog). budget_zero
     * is set ONLY for ROLE_BLOCK tokens, so the OPERATE/pktgen reads never trip the retire. */
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_epoch) epoch_read = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v;
            if (meta.budget_zero == 8w1 && v == meta.epoch_in) { v = EPOCH_NONE; }
        }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_epoch) epoch_retire = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; v = EPOCH_NONE; }
    };

    /* ---- reg_ready: the epoch for which qid3 residency is confirmed. A live token stamps it;
     * the SELECT and the retire clear it. ---- */
    Register<bit<16>, bit<1>>(1, 0) reg_ready;
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_ready) ready_confirm = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; v = meta.epoch_in; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_ready) ready_read = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<16>, bit<1>, bit<16>>(reg_ready) ready_clear = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; v = EPOCH_NONE; }
    };

    /* ---- reg_gen: the DNP3 generation of the HELD/handled OPERATE (retransmit dedup). ---- */
    Register<bit<8>, bit<1>>(1, 0) reg_gen;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_arm = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;                                   /* pre-state: 0 fresh, ==gen dup, else busy */
            if (v == GEN_INACTIVE) { v = meta.gen_in; }
        }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_clear = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; v = GEN_INACTIVE; }
    };

    /* ---- reg_topj: the OPERATE request-hold deadline T0+J ---- */
    Register<bit<32>, bit<1>>(1, 0) reg_topj;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_topj) topj_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;                   /* age for the qid3 expiry test */
            if (meta.dl_val_topj != DL_NO_WRITE) { v = meta.dl_val_topj; }
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
    #define OP_TO_RELAY() { ig_tm_md.ucast_egress_port = PORT_RELAY; \
                            ig_tm_md.qid               = QID_FWD;    \
                            ig_tm_md.bypass_egress     = 1w0; }
    #define OP_DROP()      { ig_dprsr_md.drop_ctl = 3w1; }
    #define STRIP_XPIPE()  { hdr.eth.etype = hdr.xpipe.orig_etype; hdr.xpipe.setInvalid(); }

    action arm_clone() {                      /* seed the qid3 reservoir via one mirror burst */
        ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE;
        meta.clone_ses          = CLONE_SESSION_ID;
        meta.clone_tag          = CLONE_TAG_MARKER | (bit<32>)meta.epoch_in;
    }

    /* ---- level 0: the packet classifier. ONE exact table folds (role, is_xpipe, dequeued,
     * is_pktgen) into a compact pclass, so every downstream register access gates on a single
     * pclass byte instead of a 3-field compound gateway (which over-populated the register
     * stages and failed placement). ---- */
    action set_pc(bit<8> c) { meta.pclass = c; }
    table tbl_classify {
        key = { meta.role : exact; meta.is_xpipe : exact; meta.dequeued : exact; meta.is_pktgen : exact; }
        actions = { set_pc; }
        const entries = {
            (ROLE_PREPARE, 8w1, 8w0, 8w0) : set_pc(PC_PREPARE);   /* crossed SELECT   */
            (ROLE_ARM,     8w1, 8w0, 8w0) : set_pc(PC_OPERATE);   /* crossed OPERATE  */
            (ROLE_BLOCK,   8w0, 8w1, 8w0) : set_pc(PC_TOKEN);     /* looped token     */
            (ROLE_BLOCK,   8w0, 8w0, 8w1) : set_pc(PC_PKTGEN);    /* pktgen admission */
            (ROLE_ARM,     8w0, 8w1, 8w0) : set_pc(PC_RELEASE);   /* held OPERATE loop */
        }
        const default_action = set_pc(PC_OTHER);
        size = 8;
    }

    /* ---- level 0: runtime params (keyless) + leak-safe J codebook (keyed) ---- */
    action set_params(bit<32> budget) { meta.budget_init = budget; }
    table tbl_params {
        actions = { set_params; }
        const default_action = set_params(BUDGET_DEFAULT);
        size = 1;
    }
    /* the bounded delay codebook: a per-flow J profile, keyed on the relay-facing dst_port,
     * NEVER on any public DNP3 application value and NEVER on the BOR epoch (anti-subtraction).
     * The production build swaps this for a leak-safe Random<>/salt source. */
    action set_j(bit<32> j_ticks) { meta.j_ticks = j_ticks; }
    table tbl_bor_codebook {
        key = { hdr.tcp.dst_port : exact; }
        actions = { set_j; }
        const default_action = set_j(J_DEFAULT_TICKS);
        size = 64;
    }

    /* ---- level 1: build the deadline-aligned "now" and T0 words ---- */
    action build_words() {
        meta.now_word = meta.ts_m | ARMED_MARK;
        meta.t0_word  = meta.t0_m | ARMED_MARK;
    }
    table tbl_build_words {
        actions = { build_words; }
        const default_action = build_words();
        size = 1;
    }

    /* ---- level ~5: single-bit release gate hold_ok = op_matched AND op_ready, AND — folded in
     * the same action (the RRC do_shape idiom, one stage instead of two) — the reg_topj arm for a
     * FRESH matched+ready OPERATE (dl_val_topj := topj_cand). verdict is a key so only the fresh
     * hold arms T0+J; a matched+ready DUP/BUSY is handled by the ACT before hold_ok is consulted. ---- */
    action hold_and_arm() { meta.hold_ok = 8w1; meta.dl_val_topj = meta.topj_cand; }
    action clr_hold_ok()  { meta.hold_ok = 8w0; }
    table tbl_hold_ok {
        key = { meta.op_matched : exact; meta.op_ready : exact; meta.verdict : exact; }
        actions = { hold_and_arm; clr_hold_ok; }
        const entries = { (8w1, 8w1, V_OP_FRESH) : hold_and_arm(); }
        const default_action = clr_hold_ok();
        size = 8;
    }

    /* ---- level 5: T0+J expiry (armed AND due), whole-container mask (as in RRC) ---- */
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
            meta.t0_m = hdr.xpipe.t0 & TICK_MASK;      /* T0 travels in the packet header */
            /* budget_zero is meaningful ONLY for a DEQUEUED (looped) token: it drives both the
             * loop-termination watchdog and the epoch_read watchdog-retire. Gating on dequeued
             * keeps a fresh pktgen admission (whose template ib.seq is arbitrary) from ever
             * tripping the retire. */
            tbl_classify.apply();                       /* -> meta.pclass (single-field gate) */
            if (meta.pclass == PC_TOKEN) {
                if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }   /* split: 32b compare alone */
            }
            tbl_params.apply();
            tbl_bor_codebook.apply();

            /* ---------- level 1: now_word / t0_word ---------- */
            tbl_build_words.apply();

            /* ---------- level 2: the epoch / generation registers (one access each) ------
             * gated on the single pclass byte:
             *   PREPARE -> epoch_prepare (write epoch)          RELEASE -> epoch_retire (clear)
             *   all else -> epoch_read (BOR_PENDING pre-state; a TOKEN with budget_zero also
             *               RETIRES the epoch inside epoch_read = the missing-OPERATE watchdog) */
            if (meta.pclass == PC_PREPARE) {
                meta.epoch_stored = epoch_prepare.execute(0);
            } else if (meta.pclass == PC_RELEASE) {
                meta.epoch_stored = epoch_retire.execute(0);
            } else {
                meta.epoch_stored = epoch_read.execute(0);
            }

            /* reg_gen: the OPERATE arms-if-inactive (dedup); PREPARE/RELEASE reset it. */
            if (meta.pclass == PC_OPERATE) {
                meta.gen_stored = gen_arm.execute(0);
            } else if (meta.pclass == PC_PREPARE || meta.pclass == PC_RELEASE) {
                meta.gen_stored = gen_clear.execute(0);
            } else {
                meta.gen_stored = gen_read.execute(0);
            }

            /* ---------- level 2: T0+J candidate (one add) ---------- */
            meta.topj_cand = meta.t0_word + meta.j_ticks;

            /* ---------- level 3: reg_ready — a live token confirms; the OPERATE reads;
             * the SELECT-prepare clears. reg_ready depends on reg_epoch (blk_live), so it
             * sits a level after reg_epoch. ---- */
            meta.blk_live = 8w0;
            /* a token (PC_TOKEN) is LIVE iff it carries the CURRENT epoch (both non-zero by
             * construction — tokens are stamped only while reg_epoch != 0, a retired reg_epoch
             * is 0). Nested so no gateway mixes the 16b equality with the pclass byte. */
            if (meta.pclass == PC_TOKEN) {
                if (meta.epoch_in == meta.epoch_stored) {
                    meta.blk_live = 8w1;
                    meta.verdict  = V_BLK_LIVE;
                }
            }
            /* ALL reg_ready accesses live here at level 3 (a register occupies ONE stage): a live
             * token confirms; the OPERATE reads; PREPARE and RELEASE clear. */
            if (meta.pclass == PC_TOKEN && meta.blk_live == 8w1) {
                ready_confirm.execute(0);                       /* residency: reg_ready := epoch */
            } else if (meta.pclass == PC_OPERATE) {
                meta.ready_stored = ready_read.execute(0);      /* residency pre-state for OPERATE */
            } else if (meta.pclass == PC_PREPARE || meta.pclass == PC_RELEASE) {
                ready_clear.execute(0);                         /* clean epoch / retire on release */
            }

            /* ---------- level 3: OPERATE match + generation verdict ----------
             * epoch_in of a crossed OPERATE is the (non-zero) epoch pipe 0 stamped, so a retired
             * reg_epoch/reg_ready (== 0) never matches — the != 0 guards are redundant and are
             * dropped so each gateway is a SINGLE 16b equality (no compound-input overflow). */
            if (meta.pclass == PC_OPERATE) {
                if (meta.epoch_stored == meta.epoch_in) { meta.op_matched = 8w1; }
                if (meta.ready_stored == meta.epoch_in) { meta.op_ready = 8w1; }
                if (meta.gen_stored == GEN_INACTIVE) {
                    meta.verdict = V_OP_FRESH;
                } else if (meta.gen_stored == meta.gen_in) {
                    meta.verdict = V_OP_DUP;
                } else {
                    meta.verdict = V_OP_BUSY;
                }
            }

            /* ---------- level ~5: hold_ok = op_matched AND op_ready, AND (folded) the reg_topj
             * arm (dl_val_topj := topj_cand) for a FRESH matched+ready OPERATE — see tbl_hold_ok. */
            tbl_hold_ok.apply();

            /* ---------- level ~6: reg_topj (arm on the committed hold, else age) ------ */
            meta.age_topj = topj_rmw.execute(0);

            /* ---------- level 6: expiry ---------- */
            tbl_topj_expiry.apply();

            /* ================= ACT (TM decisions only; every register access already ran) =====
             * The whole transaction retire on release is already committed: gen_clear (level 2),
             * epoch_retire (level 2, PC_RELEASE), ready_clear (level 3, PC_RELEASE). The ACT only
             * chooses the TM destination + counters. */
            if (meta.pclass == PC_PREPARE) {
                /* ---- the crossed SELECT: seed qid3, forward the byte-identical SELECT to relay ---- */
                arm_clone();                                /* seed the qid3 reservoir (this epoch) */
                STRIP_XPIPE()
                OP_TO_RELAY()
                ctr_fresh.count(CF_SEL_PREPARE);
            } else if (meta.pclass == PC_OPERATE) {
                /* ---- the crossed OPERATE ---- */
                if (meta.verdict == V_OP_DUP) {
                    OP_DROP()                               /* retransmit while held: exactly-once */
                    ctr_fresh.count(CF_OP_RETRANS);
                } else if (meta.verdict == V_OP_FRESH && meta.hold_ok == 8w1) {
                    /* matched BOR_PENDING(epoch) AND confirmed residency -> HOLD, first try */
                    STRIP_XPIPE()                           /* byte-identical original into qid2 */
                    to_op_hold();
                    ctr_fresh.count(CF_OP_HOLD);
                } else if (meta.verdict == V_OP_BUSY) {
                    STRIP_XPIPE()                           /* concurrent gen: forward unprotected */
                    OP_TO_RELAY()
                    ctr_fresh.count(CF_OP_BUSY);
                } else {
                    /* FRESH but NOT (matched AND resident) -> FAIL OPEN WITHOUT HOLDING: forward
                     * once + count; never enqueue on a stale/absent flag. reg_gen was armed by
                     * gen_arm so a retransmit still drops (exactly-once). */
                    STRIP_XPIPE()
                    OP_TO_RELAY()
                    ctr_fresh.count(CF_OP_FAILOPEN);
                }
            } else if (meta.pclass == PC_PKTGEN) {
                /* ---- pktgen admission: seed qid3 while an epoch is prepared ---- */
                if (meta.epoch_stored != EPOCH_NONE) {
                    hdr.ib.role  = ROLE_BLOCK;
                    hdr.ib.slot  = SLOT_OP;
                    hdr.ib.epoch = meta.epoch_stored;       /* stamp the current BOR epoch */
                    hdr.ib.seq   = meta.budget_init;        /* K pass budget      */
                    to_op_block();
                    ctr_fresh.count(CF_PKTGEN_ADMIT);
                } else {
                    OP_DROP()
                    ctr_fresh.count(CF_PKTGEN_DROP);
                }
            } else if (meta.pclass == PC_TOKEN) {
                /* the qid3 OPERATE blocker reservoir. Termination priority stale > deadline > budget. */
                if (meta.blk_live != 8w1) {
                    OP_DROP()                               /* stale epoch: terminate */
                    ctr_deq.count(CD_OP_TERM_STALE);
                    meta.ev_block_term = 8w1;
                } else if (meta.expired_topj == 16w1) {
                    OP_DROP()                               /* T0+J reached: drain -> release */
                    ctr_deq.count(CD_OP_TERM_DL);
                    meta.ev_block_term = 8w1;
                } else if (meta.budget_zero == 8w1) {
                    /* budget exhausted with no deadline -> MISSING-OPERATE WATCHDOG. epoch_read
                     * already RETIRED reg_epoch (v := 0) for this live-epoch token, so a late
                     * OPERATE now fails open. */
                    OP_DROP()
                    ctr_deq.count(CD_OP_TERM_TMO);
                    meta.ev_block_term = 8w1;
                } else {
                    hdr.ib.seq = hdr.ib.seq - 32w1;
                    to_op_block();                          /* re-enqueue qid3 */
                    ctr_deq.count(CD_OP_LOOP);
                }
            } else if (meta.pclass == PC_RELEASE) {
                /* ►► THE OP_RELEASE PASS. qid3 drained at T0+J, so the qid2-held original OPERATE
                 * is back on the hold ring — byte-identical (xpipe stripped at enqueue). Forward
                 * to the relay EXACTLY ONCE; the transaction was already retired at levels 2-3. */
                OP_TO_RELAY()
                ctr_deq.count(CD_OP_RELEASE);
            } else {
                OP_DROP()                                   /* nothing else is admitted */
                ctr_fresh.count(CF_CLONE_SEEN);
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
 * released / failed-open / forwarded SELECT+OPERATE frames to the relay, byte-identical. */
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

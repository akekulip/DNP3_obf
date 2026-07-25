/* ============================================================================
 * p11_classify_fold.p4 — variant P11: P10 + SINGLE-LOOKUP CLASSIFICATION
 *
 * (P11 note: P10 reached a critical path of 7 but still ALLOCATED 8 stages, because
 * the nested if/else that computes pkt_class and tag_val split across two MAU levels
 * — the outer `dequeued` gateway at stage 0 and the inner role/budget tests at stage
 * 1 — which pushed the tag access to stage 2. P11 replaces that nested chain with ONE
 * ternary lookup whose keys are all level-0 values, so classification finishes in a
 * single level and the whole chain compacts. Nothing about the state machine changes.)
 *
 * P9 measured 8 ingress stages with a critical path of 8, and the binding chain was no
 * longer the state machine — it was the ARITHMETIC PREP feeding it:
 *     ts_m = ts & TICK_MASK        (level 0)
 *  -> now_word = ts_m | ARMED_MARK (level 1, tbl_build_now)
 *  -> dl_cand  = now_word + seq_m  (level 2, tbl_build_cand)
 *  -> decode (3) -> deadline SALU (4) -> expiry (5) -> ACT (6) -> timestamps (7).
 *
 * P10 removes two of those three prep levels by moving the packing OUT of the data
 * plane and into the value the host already sends. G is carried pre-encoded:
 *     hdr.ib.seq (ROLE_ACK) = (G / 256 ns) << 8 | 1
 * i.e. G in 256 ns ticks, already in the stored word's alignment, with the ARMED
 * MARKER already set. Then:
 *   - `now_word` is just ts_m, so tbl_build_now disappears entirely;
 *   - `dl_cand = ts_m + hdr.ib.seq` is ONE op on two level-0 values, so it no longer
 *     waits for now_word.
 * The header comment of P0 already notes that carrying G in the packet is TEST_ONLY
 * and that a deployment holds G as policy in a register or table — in which case G
 * arrives pre-encoded as action data and this fold costs nothing at all.
 *
 * TWO PROPERTIES IMPROVE, neither weakens:
 *  1. NEVER EARLY. With now_word = ts_m (marker 0x00) against a stored marker 0x01,
 *     the low-byte subtraction always borrows, so the age is one tick more negative:
 *     release happens when trunc(now) > trunc(deadline), i.e. the observed interval
 *     lands in [G, G+256) ns. P1/P0 could fire up to 255 ns EARLY; P10 cannot fire
 *     early at all, which is the right direction for a guard interval.
 *  2. NO ZERO-VALUE HAZARD. hdr.ib.seq carries the marker bit, so dl_cand always has
 *     bit 0 set and can never collide with the "do not write" sentinel 0.
 * The expiry entry changes accordingly: an armed age has low byte 0xFF (0x00 - 0x01),
 * so the match is 0x000000FF &&& 0x800000FF. Unarmed (0x02 -> 0xFE) and power-on
 * (0x00 -> 0x00) still cannot match, so nothing else moves.
 *
 * Functionally equivalent to Part 12 `ibspg_hold_response.p4` (P0). The ONLY
 * architectural variable changed is how transaction state is stored and accessed.
 *
 *   P0:  reg_gen (8b) -> reg_active (8b) -> reg_deadline (32b)
 *        THREE RegisterActions in three SERIAL MAU stages, with a compare level
 *        and a write-driver level between each pair (P0 stages 2..8 — the
 *        dependency-bound core that WS1 forensics show sets the 12-stage budget).
 *
 *   P1:  reg_tag (8b)  +  reg_deadline (32b)   — TWO accesses, and three levels
 *        of compare/driver logic collapse into ONE ternary decode table.
 *
 *        reg_tag       0x00 = power-on, no transaction
 *                      g    = generation g active          (g in [1,254])
 *                      0xFF = INACTIVE, fail-open cleared
 *        reg_deadline  0x00000000 / 0x00000002 = NOT armed
 *                      ((t_ack+G) & 0xFFFFFF00) | 0x01 = armed
 *                      i.e. 24 bits of 256 ns ticks, and bit 0 is the ARMED MARKER.
 *
 * WHAT THE PACKING BUYS, concretely:
 *   1. generation + active pack into ONE byte, so P0's `gen_mismatch` compare
 *      level and its `active` register level and that register's write-driver
 *      level all disappear. The SALU returns `exp_tag - stored_tag`, so the
 *      comparison itself happens inside the stateful ALU: a difference of zero
 *      means "active, and this is my generation" — P0's `!stale` in one field.
 *   2. the ARMED FLAG packs into the deadline word as bit 0, so P0's separate
 *      `dl_armed = (dl_now != 0)` test disappears AND the deadline-zero sentinel
 *      ambiguity disappears with it (see below).
 *   3. the age subtraction moves INTO the SALU (`rv = now_word - v`), so P0's
 *      `meta.age = ts32 - dl_now` level disappears.
 *
 * THE ONE SUBTRACTION THAT DECIDES RELEASE.  The packet side builds
 *   now_word = (ts & 0xFFFFFF00) | 0x01
 * in the SAME alignment as a stored armed deadline, so
 *   age = now_word - stored
 * has low byte 0x00 exactly when a deadline is armed (0x01 - 0x01, no borrow), and
 * in that case, and only that case, bit 31 is the true sign of the 24-bit tick
 * difference. ONE ternary entry `0x00000000 &&& 0x800000FF` therefore tests
 * "armed AND due" together. Unarmed words (0x00000002, or the power-on 0x00000000)
 * give low byte 0xFF / 0x01, which no mask value can match: they can NEVER read as
 * expired, whatever the deadline bits hold.
 *
 * THREE MEASURED CONSTRAINTS SHAPED THIS (probes kept in salu_probes/):
 *   A. a TF1 SALU accepts at most 2 PHV inputs — the "one register does
 *      everything" form needs 5 and is rejected outright:
 *        "Ingress.reg_state requires more than 2 PHV inputs"        (probeB)
 *      Both RegisterActions below therefore use EXACTLY two PHV fields.
 *   B. an SALU compare immediate must be small: `!= 32w0xFFFFFFFF` dies in the
 *      assembler ("constant value -4294967295 too large for stateful alu",
 *      probeC); `!= 32w0` compiles clean (probeD). Hence ZERO is the "do not
 *      write" sentinel — collision-free, because every value this program stores
 *      is non-zero by construction (ARM stores g>=1, the ACK stores a word whose
 *      bit 0 is set, the fail-open clear stores 0xFF).
 *   C. the runtime generation MUST NOT be packed into the 32-bit deadline word.
 *      Doing so requires depositing an 8-bit header field into bits [7:0] of a
 *      32-bit arithmetic field, which forces a [7:0]/[31:8] split on the whole
 *      timestamp cluster and PHV allocation then fails:
 *        "Unable to slice the following group of fields due to unsatisfiable
 *         constraints: meta.ts32, meta.ts_m, ig_intr_md.ingress_mac_tstamp, ...
 *         PHV allocation was not successful, 33 field slices remain unallocated"
 *      (probeE_packed_word_REJECTED.p4 — the single-32-bit-word design, kept as
 *      evidence). This is the same invalid-SuperCluster trap P0's header warns
 *      about, reached from a new direction. The generation therefore stays in its
 *      own 8-bit register, where the comparison is an 8-bit subtraction, and only
 *      CONSTANTS (0x01, 0x02) are ever packed into the 32-bit word.
 *
 * NO BIT SLICING ANYWHERE. Words are BUILT with whole-container AND/OR against
 * constants; every sub-field TEST is a ternary match under a TCAM mask. The only
 * slice in the program is ig_intr_md.ingress_mac_tstamp[31:0], which P0 has too.
 *
 * ONE DELIBERATE SEMANTIC CHANGE vs P0, and it is a tightening. P0 clears the
 * transaction when a blocker is stale OR out of budget. "Stale" is register-derived
 * and cannot gate the same access that discovers it, so P1 clears on the pass-budget
 * timeout only. Fail-open is preserved exactly (the timeout clear is packet-derived,
 * writes INACTIVE, and every other token then reads a stale tag and terminates).
 * Every clear P1 performs, P0 also performed: the set of state-clearing events
 * strictly SHRINKS, so no new interference path can appear, and one is removed —
 * in P0 a leftover token from generation g-1 could clear `active` for a live
 * generation g and release its response early; in P1 a stale token cannot write
 * state at all.
 *
 * Unchanged from P0: wire format, queues, TM actions, forwarding, byte
 * preservation, the fail-open pass budget, blocker isolation, ACK re-arm
 * semantics, all 11 counters, all 4 timestamps, egress as a pure pass-through.
 * Full derivation: ../../PACKED_STATE_DESIGN.md
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_REAL  = 0x88C0;  /* ACK(7) + RESP(2) + ARM(6) roles */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK(1) private marker         */

/* ---- roles (numbering kept compatible with Parts 9/11/12) ---- */
const bit<8> ROLE_BLOCK = 1;
const bit<8> ROLE_RESP  = 2;
const bit<8> ROLE_ARM   = 6;
const bit<8> ROLE_ACK   = 7;

/* ---- ports ---- */
const PortId_t PORT_L      = 9w8;
const PortId_t PORT_VISION = 9w9;
const PortId_t PORT_HULK   = 9w11;

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;
const bit<5> QID_RESP  = 5w1;

const bit<8> SLOT0 = 8w0;

/* ---- packed-state constants ---- */
const bit<32> TICK_MASK    = 32w0xFFFFFF00;  /* keep 24 tick bits, clear the marker byte */
const bit<32> ARMED_MARK   = 32w0x00000001;  /* bit 0 of the deadline word = armed       */
const bit<32> UNARMED_WORD = 32w0x00000002;  /* explicit "armed nothing" (marker clear)  */
const bit<32> DL_NO_WRITE  = 32w0;           /* SALU sentinel: leave the deadline be     */
const bit<8>  TAG_INACTIVE = 8w0xFF;         /* explicit "no transaction"                */
const bit<8>  TAG_NO_WRITE = 8w0;            /* SALU sentinel: leave the tag be          */

/* ---- packet classes (drive the decode table) ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;   /* fresh ARM                        */
const bit<8> CLASS_ACK       = 8w2;   /* fresh ACK on SLOT0               */
const bit<8> CLASS_BLOCK_DEQ = 8w3;   /* blocker token back from loopback */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }
/* ingress -> egress only; emitted by the ingress deparser, stripped by the egress
 * parser, NEVER emitted by the egress deparser. Valid only on to_host() packets. */
header bridge_h   { bit<8> ack_ok; bit<32> ts32; }

struct headers_t {
    bridge_h   br;
    ethernet_h eth;
    ibspg_h    ib;
}

struct ig_meta_t {
    bit<8>  dequeued;
    bit<32> ts32;          /* full-resolution ns, for the timestamp bank only */
    bit<8>  budget_zero;

    /* level 0 — packet-derived */
    bit<32> ts_m;          /* ts32 & TICK_MASK      */
    bit<8>  exp_tag;       /* hdr.ib.gen — the tag this packet expects to own */

    /* level 1 */
    bit<8>  pkt_class;
    bit<8>  tag_val;       /* PHV input 2 of reg_tag: 0 = do not write        */

    /* level 2 */
    bit<32> dl_cand;       /* now_word + seq_m = the armed word for this ACK  */
    bit<8>  tag_diff;      /* PHV-side result: exp_tag - stored_tag           */

    /* level 3 */
    bit<32> dl_val;        /* PHV input 2 of reg_deadline: 0 = do not write   */
    bit<8>  tag_ok;        /* 1 = state is live AND is this generation        */
    bit<8>  ack_ok;        /* 1 = this ACK qualified and armed the deadline   */

    /* level 4 */
    bit<32> age;           /* now_word - deadline_word, straight out of the SALU */
    bit<8>  expired;       /* 1 = armed AND due (set by tbl_deadline_expiry)  */

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;
    bit<8>  ev_block_term;
    /* ev_ack_arm / ev_resp_release are gone: those two events are evidenced in
     * egress now, where the packet itself identifies the event. */
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.ts32            = 32w0;
        meta.ts_m            = 32w0;
        meta.exp_tag         = 8w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.tag_val         = TAG_NO_WRITE;
        meta.dl_cand         = 32w0;
        meta.tag_diff        = 8w0;
        meta.dl_val          = DL_NO_WRITE;
        meta.tag_ok          = 8w0;
        meta.ack_ok          = 8w0;
        meta.age             = 32w0;
        meta.expired         = 8w0;
        meta.ev_first_block  = 8w0;
        meta.ev_block_term   = 8w0;
        transition select(ig_intr_md.ingress_port) {
            PORT_L  : set_dequeued;
            default : parse_eth;
        }
    }
    state set_dequeued {
        meta.dequeued = 8w1;
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IBSPG_REAL  : parse_ib;
            ETHERTYPE_IBSPG_TOKEN : parse_ib;
            default               : accept;
        }
    }
    state parse_ib {
        pkt.extract(hdr.ib);
        transition select(hdr.ib.seq) {
            32w0    : set_budget_zero;
            default : accept;
        }
    }
    state set_budget_zero {
        meta.budget_zero = 8w1;
        transition accept;
    }
}

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ================= state register 1 of 2: the TAG =====================
     * Packs P0's reg_gen and reg_active into one byte. The SALU returns the
     * DIFFERENCE against the packet's generation, so the comparison happens in the
     * stateful ALU and P0's separate `gen_mismatch` level is gone:
     *     tag_diff == 0  <=>  a transaction is active AND it is this generation.
     * PHV inputs: meta.exp_tag, meta.tag_val — exactly 2 (measured limit A). */
    Register<bit<8>, bit<1>>(1, 0) reg_tag;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.exp_tag - v;
            if (meta.tag_val != TAG_NO_WRITE) { v = meta.tag_val; }
        }
    };

    /* ================= state register 2 of 2: the DEADLINE ================
     * 24 bits of 256 ns ticks in [31:8]; bit 0 is the ARMED MARKER. The SALU
     * returns the age directly, so P0's `meta.age = ts32 - dl_now` level is gone,
     * and because the marker rides in the same word, P0's separate `dl_armed`
     * test is gone too.
     * PHV inputs: meta.ts_m, meta.dl_val — exactly 2 (measured limit A). */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.ts_m - v;
            if (meta.dl_val != DL_NO_WRITE) { v = meta.dl_val; }
        }
    };

    /* ================= fixed-slot timestamp registers (4) — unchanged ===== */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    /* MOVED TO EGRESS: reg_ts_ack_arm (t_ack) */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    /* MOVED TO EGRESS: reg_ts_first_resp_release (the release timestamp) */

    /* ================= counters (unchanged, 11) ========================== */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_deadline;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    /* MOVED TO EGRESS: ctr_ack_arm, ctr_ack_bypass, ctr_resp_release */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_nonibspg;

    /* ================= TM actions (unchanged) ============================ */
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
    /* The bridge header is made valid HERE and nowhere else, so it can only ride
     * packets that actually enter egress (bypass_egress = 0). */
    action to_host(bit<8> ack_flag) {
        ig_tm_md.ucast_egress_port = PORT_VISION;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
        hdr.br.setValid();
        hdr.br.ack_ok              = ack_flag;
        hdr.br.ts32                = meta.ts32;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* ---- level 0: ONE lookup does all packet classification ----
     * Replaces a nested if/else whose outer gateway (`dequeued`) and inner tests
     * (role / slot / budget_zero) landed in two different MAU levels. Every key here
     * is available at level 0 — `dequeued` and `budget_zero` come from the parser
     * (P7) and role/slot straight off the header — so the class and the tag write
     * driver are both settled before the first stage ends. */
    action cls_arm()         { meta.pkt_class = CLASS_ARM;
                               meta.tag_val   = hdr.ib.gen; }      /* ARM takes ownership */
    action cls_ack()         { meta.pkt_class = CLASS_ACK; }
    action cls_blk()         { meta.pkt_class = CLASS_BLOCK_DEQ; }
    action cls_blk_timeout() { meta.pkt_class = CLASS_BLOCK_DEQ;
                               meta.tag_val   = TAG_INACTIVE; }    /* fail-open clear     */
    action cls_none()        { }
    table tbl_classify {
        key = {
            meta.dequeued    : exact;
            hdr.ib.role      : exact;
            hdr.ib.slot      : ternary;
            meta.budget_zero : ternary;
        }
        actions = { cls_arm; cls_ack; cls_blk; cls_blk_timeout; cls_none; }
        const default_action = cls_none();
        const entries = {
            (8w0, ROLE_ARM,   8w0   &&& 8w0x00, 8w0   &&& 8w0x00) : cls_arm();
            (8w0, ROLE_ACK,   SLOT0 &&& 8w0xFF, 8w0   &&& 8w0x00) : cls_ack();
            (8w1, ROLE_BLOCK, 8w0   &&& 8w0x00, 8w1   &&& 8w0xFF) : cls_blk_timeout();
            (8w1, ROLE_BLOCK, 8w0   &&& 8w0x00, 8w0   &&& 8w0x00) : cls_blk();
        }
        size = 8;
    }

    /* ---- level 1 (was level 2): the candidate armed word for an ACK ----
     * G arrives pre-encoded as (ticks << 8 | ARMED_MARK), so this is ONE add on two
     * level-0 values and no longer waits for a packed "now" word. Bit 0 of the sum is
     * always 1, so dl_cand can never be the "do not write" sentinel. */
    action build_cand() { meta.dl_cand = meta.ts_m + hdr.ib.seq; }
    table tbl_build_cand {
        actions = { build_cand; }
        const default_action = build_cand();
        size = 1;
    }

    /* ================= the ONE decode table ==============================
     * Replaces P0's gen_mismatch compare level, its active-clear driver level and
     * its ACK-qualify/deadline-driver level with a single lookup on the packet
     * class and the tag difference. The match unit reads the whole container under
     * a TCAM mask, so nothing is sliced.
     *
     *   tag_diff == 0  <=>  active AND this generation.
     * A qualifying ACK is a fresh ACK on the slot that finds tag_diff == 0 — the
     * same qualification rule as P0 (same generation, same slot, transaction
     * active), evaluated one level earlier. A non-qualifying ACK falls to the
     * default and writes NOTHING, so it cannot move any release time. */
    action dec_arm()     { meta.dl_val = UNARMED_WORD; }                       /* ARM disarms  */
    action dec_ack_arm() { meta.dl_val = meta.dl_cand; meta.ack_ok = 8w1; }    /* ACK arms     */
    action dec_live()    { meta.dl_val = DL_NO_WRITE;  meta.tag_ok = 8w1; }    /* live blocker */
    action dec_none()    { meta.dl_val = DL_NO_WRITE; }
    table tbl_state_decode {
        key = {
            meta.pkt_class : exact;
            meta.tag_diff  : ternary;
        }
        actions = { dec_arm; dec_ack_arm; dec_live; dec_none; }
        const default_action = dec_none();
        const entries = {
            (CLASS_ARM,       8w0 &&& 8w0x00) : dec_arm();      /* any tag: ARM always takes over */
            (CLASS_ACK,       8w0 &&& 8w0xFF) : dec_ack_arm();  /* qualified ACK only             */
            (CLASS_BLOCK_DEQ, 8w0 &&& 8w0xFF) : dec_live();     /* my generation, still live      */
        }
        size = 8;
    }

    /* ================= deadline expiry =================================
     * expired <=> the deadline word is ARMED (low byte of the age is 0xFF: the now
     * word has marker 0x00 and an armed stored word has marker 0x01, so the low byte
     * always borrows) AND the tick difference is non-negative (bit 31 clear).
     * Unarmed (0x02 -> 0xFE) and power-on (0x00 -> 0x00) cannot match.
     * ONE ternary entry tests both. This is P0's construct, doing P0's `dl_armed`
     * test for free instead of in a separate level. */
    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = { meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = {
            (32w0x000000FF &&& 32w0x800000FF) : mark_expired();
        }
        size = 2;
    }

    apply {
        if (!hdr.ib.isValid()) {
            ctr_nonibspg.count(0);
            drop_pkt();
        } else {
            /* ---------- level 0: packet-derived only ---------- */
            /* dequeued / budget_zero arrive from the PARSER (P7) */
            meta.ts32    = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m    = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            meta.exp_tag = hdr.ib.gen;

            /* ---------- level 0: class + tag write driver, ONE lookup ---------- */
            tbl_classify.apply();

            /* ---------- level 2: tag access (ACK candidate built in parallel) -- */
            meta.tag_diff = tag_rmw.execute(0);
            tbl_build_cand.apply();

            /* ---------- level 3: one decode for stale / qualify / disarm ------- */
            tbl_state_decode.apply();

            /* ---------- level 4: deadline access, returning the age ------------ */
            meta.age = deadline_rmw.execute(0);

            /* ---------- level 5: expiry ---------- */
            tbl_deadline_expiry.apply();

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- FRESH from host ----- */
                if (hdr.ib.role == ROLE_BLOCK) {
                    to_block();
                    ctr_block_enq.count(0);
                    meta.ev_first_block = 8w1;
                } else if (hdr.ib.role == ROLE_RESP) {
                    to_resp();
                    ctr_resp_enq.count(0);
                } else if (hdr.ib.role == ROLE_ACK) {
                    /* HOLD_RESPONSE: the ACK is NEVER held — forward it now.
                     * The qualification bit rides the bridge; egress counts it. */
                    if (meta.ack_ok == 8w1) {
                        to_host(8w1);
                    } else {
                        to_host(8w0);
                    }
                } else if (hdr.ib.role == ROLE_ARM) {
                    ctr_arm.count(0);
                    drop_pkt();
                } else {
                    drop_pkt();
                }
            } else {
                /* ----- DEQUEUED (looped back from dp8) ----- */
                if (hdr.ib.role == ROLE_BLOCK) {
                    /* terminate causes, priority: stale > deadline > budget */
                    if (meta.tag_ok == 8w0) {
                        drop_pkt();
                        ctr_block_term_stale.count(0);
                        meta.ev_block_term = 8w1;
                    } else if (meta.expired == 8w1) {
                        drop_pkt();
                        ctr_block_term_deadline.count(0);
                        meta.ev_block_term = 8w1;
                    } else if (meta.budget_zero == 8w1) {
                        drop_pkt();
                        ctr_block_term_timeout.count(0);
                        meta.ev_block_term = 8w1;
                    } else {
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_block_loop.count(0);
                    }
                } else if (hdr.ib.role == ROLE_RESP) {
                    /* only a RELEASED response ever reaches egress */
                    to_host(8w0);
                } else {
                    drop_pkt();
                }
            }

            /* ================= SPARSE latency capture (unchanged) ============ */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
        }
    }
}

/* ============================ ingress deparser ========================== */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.br);      /* ingress -> egress only; stripped before the wire */
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
    }
}

/* ============================ egress: the moved evidence ================ */
struct eg_meta_t { }

parser EgParser(packet_in pkt,
                out headers_t hdr,
                out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        pkt.extract(hdr.br);      /* stripped here; the deparser never emits it */
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            ETHERTYPE_IBSPG_REAL  : parse_ib;
            ETHERTYPE_IBSPG_TOKEN : parse_ib;
            default               : accept;
        }
    }
    state parse_ib {
        pkt.extract(hdr.ib);
        transition accept;
    }
}
control Egress(inout headers_t hdr,
               inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    /* Same write-if-zero shape as P0, stamping the INGRESS timestamp carried on the
     * bridge, so the recorded evidence is bit-identical to what P0 recorded. */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_arm;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_arm) ts_ack_arm_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = hdr.br.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_resp_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_resp_release) ts_first_resp_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = hdr.br.ts32; } }
    };
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_release;

    apply {
        if (hdr.ib.isValid()) {
            if (hdr.ib.role == ROLE_ACK) {
                if (hdr.br.ack_ok == 8w1) {
                    ctr_ack_arm.count(0);
                    ts_ack_arm_w.execute(0);
                } else {
                    ctr_ack_bypass.count(0);
                }
            } else if (hdr.ib.role == ROLE_RESP) {
                ctr_resp_release.count(0);
                ts_first_resp_w.execute(0);
            }
        }
    }
}
control EgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    eg_meta_t meta,
                   in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
    }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

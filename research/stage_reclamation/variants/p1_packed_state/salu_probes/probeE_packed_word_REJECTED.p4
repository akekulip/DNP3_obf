/* ============================================================================
 * p1_packed_state.p4 — variant P1 (WS2): PACKED TRANSACTION STATE
 *
 * Functionally identical to Part 12 `ibspg_hold_response.p4` (P0). The ONLY
 * architectural variable changed is how transaction state is stored and accessed:
 *
 *   P0:  reg_gen (8b)  ->  reg_active (8b)  ->  reg_deadline (32b)
 *        three RegisterActions on three registers, in three SERIAL MAU stages,
 *        with a compare level and a write-driver level between each pair
 *        (P0 stages 2,3,4,5,6,7,8 — the dependency-bound core of the pipeline).
 *
 *   P1:  reg_state (32b) — ONE register, ONE stage:
 *          bits 31:8  deadline, 24 bits of 256 ns ticks
 *          bits  7:0  tag = armed(bit7) | generation(bits 6:0)
 *
 * Full derivation, the wrap case, the quantization budget and the invariant
 * argument are in ../../PACKED_STATE_DESIGN.md. The essentials:
 *
 * ONE SUBTRACTION DECIDES EVERYTHING.  age = now_word - stored_word, where the
 * packet side builds now_word = (ts & 0xFFFFFF00) | (gen|0x80) in the SAME
 * alignment as the stored word. The low byte of the result classifies the state
 * (0x00 = armed & my generation, 0x80 = active & my generation but not yet armed,
 * anything else = stale) and, in the 0x00 case only — which is exactly the case
 * where the low-byte subtraction did not borrow — bit 31 is the sign of the
 * 24-bit tick difference. One ternary table reads all of it off one field.
 *
 * TWO MEASURED HARDWARE LIMITS SHAPE THIS (see salu_probes/):
 *   A. a TF1 SALU accepts at most 2 PHV inputs. The naive "one RegisterAction
 *      does everything" form needs 5 and is rejected:
 *        "Ingress.reg_state requires more than 2 PHV inputs"   (probeB)
 *      Hence the two RegisterActions below share the SAME two PHV fields
 *      (meta.salu_ref, meta.salu_new), selected by packet class beforehand, so
 *      the register's input crossbar sees exactly two inputs in total.
 *   B. an SALU compare immediate must be small: `!= 32w0xFFFFFFFF` dies in the
 *      assembler ("constant value -4294967295 too large for stateful alu",
 *      probeC) while `!= 32w0` compiles clean (probeD). So zero is the
 *      "do not write" sentinel — collision-free, because every word this program
 *      stores is non-zero by construction.
 *
 * NO BIT SLICING. Sub-fields are never extracted in the MAU: words are BUILT with
 * whole-container AND/OR, and every sub-field TEST is a ternary match under a TCAM
 * mask. The only slice is ig_intr_md.ingress_mac_tstamp[31:0], which P0 also has.
 *
 * TWO DELIBERATE SEMANTIC TIGHTENINGS vs P0 (both strictly safe, see §7 of the
 * design note):
 *   1. first ACK arms, later ACKs do not re-arm (P0 re-armed on every qualifying
 *      ACK, which would move the release without moving the write-once t_ack
 *      timestamp and corrupt G_observed);
 *   2. state is cleared on the pass-budget timeout only. P0 cleared on
 *      stale-OR-timeout; stale is register-derived and cannot gate the same access
 *      that reads it. Every clear P1 performs, P0 also performed — the set of
 *      state-clearing events strictly shrinks, so no new interference path exists.
 *
 * Unchanged from P0: queues, TM actions, forwarding, byte preservation, the
 * fail-open pass budget, blocker isolation, all 11 counters, all 4 timestamps.
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
const bit<32> TICK_MASK    = 32w0xFFFFFF00;  /* keep 24 tick bits, clear the tag byte */
const bit<32> ARMED_BIT    = 32w0x00000080;  /* tag bit 7 = a deadline is armed       */
const bit<32> TAG_INACTIVE = 32w0x000000FF;  /* explicit "no transaction" word        */
const bit<32> NO_WRITE     = 32w0;           /* SALU sentinel: leave the register be  */

/* ---- packet classes (drive the SALU operand mux and the decode table) ---- */
const bit<8> CLASS_OTHER     = 8w0;
const bit<8> CLASS_ARM       = 8w1;   /* fresh ARM                        */
const bit<8> CLASS_ACK       = 8w2;   /* fresh ACK on SLOT0               */
const bit<8> CLASS_BLOCK_DEQ = 8w3;   /* blocker token back from loopback */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
}

struct ig_meta_t {
    bit<8>  dequeued;
    bit<32> ts32;          /* full-resolution ns, for the timestamp bank only */
    bit<8>  budget_zero;

    /* level-0 packet-derived words */
    bit<32> ts_m;          /* ts32 & TICK_MASK                    */
    bit<32> sum;           /* ts32 + G                            */
    bit<32> tag_armed;     /* (bit<32>)gen | ARMED_BIT            */
    bit<32> exp_word;      /* (bit<32>)gen — the word ARM writes  */

    /* level-1 */
    bit<32> now_word;      /* ts_m | tag_armed                    */
    bit<32> sum_m;         /* sum & TICK_MASK                     */
    bit<8>  pkt_class;

    /* the TWO PHV inputs the register is allowed (limit A) */
    bit<32> salu_ref;
    bit<32> salu_new;

    /* the single state-access result */
    bit<32> salu_out;      /* age for every class except CLASS_ACK, which gets the pre-value */

    /* decoded */
    bit<8>  tag_ok;        /* 1 if the state is live and belongs to this generation */
    bit<8>  expired;       /* 1 if armed, same generation, and now >= deadline      */
    bit<8>  ack_qual;      /* 1 if the pre-value equalled exp_word (the ACK armed)  */

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;
    bit<8>  ev_ack_arm;
    bit<8>  ev_block_term;
    bit<8>  ev_resp_release;
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.dequeued        = 8w0;
        meta.ts32            = 32w0;
        meta.budget_zero     = 8w0;
        meta.ts_m            = 32w0;
        meta.sum             = 32w0;
        meta.tag_armed       = 32w0;
        meta.exp_word        = 32w0;
        meta.now_word        = 32w0;
        meta.sum_m           = 32w0;
        meta.pkt_class       = CLASS_OTHER;
        meta.salu_ref        = 32w0;
        meta.salu_new        = NO_WRITE;
        meta.salu_out        = 32w0;
        meta.tag_ok          = 8w0;
        meta.expired         = 8w0;
        meta.ack_qual        = 8w0;
        meta.ev_first_block  = 8w0;
        meta.ev_ack_arm      = 8w0;
        meta.ev_block_term   = 8w0;
        meta.ev_resp_release = 8w0;
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

/* ============================ ingress control =========================== */
control Ingress(inout headers_t hdr,
                inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ================= THE transaction register =========================
     * ONE 32-bit word: [deadline:24 ticks][armed:1][generation:7].
     * Two RegisterActions, both using the SAME two PHV fields, so the register's
     * input crossbar sees exactly two inputs (measured limit A). They are called
     * from mutually exclusive branches. */
    Register<bit<32>, bit<1>>(1, 0) reg_state;

    /* Everything except a fresh ACK: read out the age, write only when the packet
     * itself decided to (ARM, or the fail-open timeout). salu_new == 0 means
     * "leave it alone" — collision-free, since no storable word is zero. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_state) state_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.salu_ref - v;                        /* age = now_word - state */
            if (meta.salu_new != NO_WRITE) { v = meta.salu_new; }
        }
    };

    /* A fresh ACK: arm the deadline ONLY if the state is exactly "this generation,
     * active, not yet armed" — i.e. exactly the word ARM wrote. This full-word
     * equality is the write-side generation qualification, and doing it inside the
     * SALU is what removes P0's separate read -> compare -> drive -> write chain.
     * The output is the pre-value, which the telemetry compare reads to learn
     * whether this ACK was the one that armed. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_state) state_ack = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v == meta.salu_ref) { v = meta.salu_new; }
        }
    };

    /* ================= fixed-slot timestamp registers (4) — unchanged ===== */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_arm;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_arm) ts_ack_arm_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_resp_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_resp_release) ts_first_resp_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* ================= counters (unchanged, 11) ========================== */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_deadline;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_bypass;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_release;
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
    action to_host() {
        ig_tm_md.ucast_egress_port = PORT_VISION;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* ================= the ONE decode table =============================
     * Replaces P0's gen_mismatch compare, active read, ACK-qualify level, the
     * armed test and the separate expiry table. Key is the packet class plus the
     * single subtraction result; the match unit reads the whole container under a
     * TCAM mask, so nothing is ever sliced.
     *
     *   low byte 0x00 -> tag was gen|0x80 : armed, this generation. No borrow
     *                    occurred, so bit 31 is the true sign of the 24-bit tick
     *                    difference: 0 = due, 1 = not yet.
     *   low byte 0x80 -> tag was gen      : this generation, not yet armed -> live.
     *   otherwise     -> stale / inactive / another generation -> terminate. */
    /* Level-1 word building, in an explicit table.
     * Both operands are level-0 values, so this is a single-stage action; it must
     * NOT be written as a plain statement next to the level-0 assignments, because
     * bf-p4c merges consecutive unconditional statements into ONE action and then
     * rejects the intra-action dependency:
     *   "or: action spanning multiple stages ... We currently support only single
     *    stage actions."  (measured on 9.13.1) */
    action build_words() {
        meta.now_word = meta.ts_m | meta.tag_armed;
        meta.sum_m    = meta.sum  & TICK_MASK;
    }
    table tbl_build_words {
        actions = { build_words; }
        const default_action = build_words();
        size = 1;
    }

    action dec_expired() { meta.tag_ok = 8w1; meta.expired = 8w1; }
    action dec_live()    { meta.tag_ok = 8w1; meta.expired = 8w0; }
    action dec_stale()   { meta.tag_ok = 8w0; meta.expired = 8w0; }
    table tbl_state_decode {
        key = {
            meta.pkt_class : exact;
            meta.salu_out  : ternary;
        }
        actions = { dec_expired; dec_live; dec_stale; }
        const default_action = dec_stale();
        const entries = {
            (CLASS_BLOCK_DEQ, 32w0x00000000 &&& 32w0x800000FF) : dec_expired();
            (CLASS_BLOCK_DEQ, 32w0x80000000 &&& 32w0x800000FF) : dec_live();
            (CLASS_BLOCK_DEQ, 32w0x00000080 &&& 32w0x000000FF) : dec_live();
        }
        size = 8;
    }

    apply {
        if (!hdr.ib.isValid()) {
            ctr_nonibspg.count(0);
            drop_pkt();
        } else {
            /* ---------- level 0: packet-derived only ---------- */
            if (ig_intr_md.ingress_port == PORT_L) { meta.dequeued = 8w1; }
            meta.ts32      = ig_intr_md.ingress_mac_tstamp[31:0];
            meta.ts_m      = ig_intr_md.ingress_mac_tstamp[31:0] & TICK_MASK;
            meta.sum       = ig_intr_md.ingress_mac_tstamp[31:0] + hdr.ib.seq;
            meta.tag_armed = (bit<32>)hdr.ib.gen | ARMED_BIT;
            meta.exp_word  = (bit<32>)hdr.ib.gen;
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }   /* isolated 32b compare */

            /* ---------- level 1: build the words, classify ---------- */
            tbl_build_words.apply();
            if (meta.dequeued == 8w0) {
                if (hdr.ib.role == ROLE_ARM) {
                    meta.pkt_class = CLASS_ARM;
                } else if (hdr.ib.role == ROLE_ACK && hdr.ib.slot == SLOT0) {
                    meta.pkt_class = CLASS_ACK;
                }
            } else if (hdr.ib.role == ROLE_BLOCK) {
                meta.pkt_class = CLASS_BLOCK_DEQ;
            }

            /* ---------- level 2: choose the two SALU operands ----------
             * CLASS_ACK    : ref = the word ARM wrote (the qualification target)
             *                new = the armed word  ((t_ack+G) ticks | gen|0x80)
             * everything else: ref = now_word (so the SALU returns the age)
             *                new = ARM's word / INACTIVE / NO_WRITE */
            if (meta.pkt_class == CLASS_ACK) {
                meta.salu_ref = meta.exp_word;
                meta.salu_new = meta.sum_m | meta.tag_armed;
            } else {
                meta.salu_ref = meta.now_word;
                if (meta.pkt_class == CLASS_ARM) {
                    meta.salu_new = meta.exp_word;
                } else if (meta.pkt_class == CLASS_BLOCK_DEQ && meta.budget_zero == 8w1) {
                    meta.salu_new = TAG_INACTIVE;     /* fail-open: retire the transaction */
                }
            }

            /* ---------- level 3: THE single state access ---------- */
            if (meta.pkt_class == CLASS_ACK) {
                meta.salu_out = state_ack.execute(0);
            } else {
                meta.salu_out = state_rmw.execute(0);
            }

            /* ---------- level 4: decode (parallel, both read salu_out) ---------- */
            tbl_state_decode.apply();
            if (meta.salu_out == meta.exp_word) { meta.ack_qual = 8w1; } /* isolated 32b compare */

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
                    /* HOLD_RESPONSE: the ACK is NEVER held — forward it now. */
                    to_host();
                    if (meta.pkt_class == CLASS_ACK && meta.ack_qual == 8w1) {
                        ctr_ack_arm.count(0);
                        meta.ev_ack_arm = 8w1;
                    } else {
                        ctr_ack_bypass.count(0);
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
                    to_host();
                    ctr_resp_release.count(0);
                    meta.ev_resp_release = 8w1;
                } else {
                    drop_pkt();
                }
            }

            /* ================= SPARSE latency capture (unchanged) ============ */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm      == 8w1) { ts_ack_arm_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.ev_resp_release == 8w1) { ts_first_resp_w.execute(0); }
        }
    }
}

/* ============================ ingress deparser ========================== */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
    }
}

/* ============================ egress (unchanged pass-through) =========== */
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
    apply { }
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

/* ============================================================================
 * ibspg_ring_oracle.p4 — on-chip TM dequeue-ORDER oracle with a self-replenishing
 *                         RING mode (Tofino-1, TNA)
 *
 * PURPOSE (compile-only instrumentation): identical trace core to
 * ibspg_dequeue_oracle.p4 — record, on-chip and at sub-microsecond resolution,
 * the ORDER in which packets dequeue from two TM queues on an internal loopback
 * port L, plus a per-event timestamp — but add a control-plane-selectable RING
 * mode so BLOCK tokens self-replenish and EVERY loop pass is timestamped. The
 * inter-pass timestamp deltas then reveal loop RTT and, crucially, EMPTY-GAPS:
 * a large gap after a BLOCK dequeue means Q_BLOCK momentarily ran dry while
 * waiting for a token to loop back.
 *
 * MODE (Register<bit<8>> reg_mode, written by the control plane; default 0):
 *   0 = FINITE  : byte-identical to ibspg_dequeue_oracle.p4 — a dequeued packet
 *                 is recorded, then DROPPED (single pass, no re-enqueue).
 *   1 = RING    : a dequeued BLOCK token is recorded, then (if budget remains)
 *                 re-enqueued to Q_BLOCK to loop again; a dequeued HOLD token is
 *                 recorded and dropped in BOTH modes.
 *
 * HARD SAFETY BOUND: hdr.ib.seq is the pass BUDGET. A fresh BLOCK token is
 * injected with seq = budget; each RING pass consumes one unit (seq -= 1) and
 * the token expires (drops) when seq reaches 0. A runaway ring is therefore
 * IMPOSSIBLE — a token loops at most `budget` times regardless of mode bit state.
 *
 * MECHANISM (mirrors ibspg_dequeue_oracle.p4):
 *   Two queues on loopback port L:  Q_BLOCK = qid7,  Q_HOLD = qid1.
 *     - fresh packet (ingress_port != PORT_L)  -> ENQUEUE to its queue.
 *     - looped-back packet (ingress_port == PORT_L) -> it JUST DEQUEUED:
 *         record (role, seq, ts) into the trace at a monotonic event index,
 *         then act by role/mode (loop a RING BLOCK, else drop).
 *   The recorded role sequence IS the dequeue order; the ts deltas are the
 *   inter-dequeue gaps.
 *
 * Conventions mirror ibspg_dequeue_oracle.p4 (frozen trace core, untouched):
 * TNA skeleton, ig_tm_md ucast_egress_port/qid/bypass_egress, indexed Counters,
 * one-RegisterAction-per-register discipline, ethernet_h+ibspg_h, ethertypes
 * 0x88C0 REAL / 0x88C1 TOKEN.
 *
 * Timestamp source: ig_intr_md.ingress_mac_tstamp[31:0] — captured at the ingress
 * MAC, i.e. the instant the looped-back packet re-enters after dequeue; the best
 * on-chip proxy for dequeue time. Nanosecond units on Tofino-1.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_REAL  = 0x88C0;  /* HOLD (role 2) + reserved roles */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK (role 1) private marker   */

/* ---- roles ---- */
const bit<8> ROLE_BLOCK   = 1;   /* 0x88C1 : enqueued to Q_BLOCK (qid7)            */
const bit<8> ROLE_HOLD    = 2;   /* 0x88C0 : enqueued to Q_HOLD  (qid1)            */
const bit<8> ROLE_DRAIN_M = 3;   /* reserved for a later extension — drops for now */
const bit<8> ROLE_DRAIN_U = 4;   /* reserved                                       */
const bit<8> ROLE_ARM     = 6;   /* reserved                                       */

/* ---- ports (compile constants; the run pins the measured dev_ports) ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)     */
const PortId_t PORT_VISION = 9w9;   /* master-facing (unused here; reserved)        */
const PortId_t PORT_HULK   = 9w11;  /* outstation-facing (unused here; reserved)    */

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH strict priority (set in control plane)      */
const bit<5> QID_HOLD  = 5w1;   /* LOW  strict priority                             */

/* ---- trace geometry ---- */
const int     TRACE_LEN   = 512;      /* register-array depth (indices 0..511)      */
const bit<32> TRACE_LEN_V = 32w512;   /* same value, for the in-range guard compare */

/* ---- mode values ---- */
const bit<8> MODE_FINITE = 8w0;   /* record + drop, single pass (baseline oracle)   */
const bit<8> MODE_RING   = 8w1;   /* self-replenishing BLOCK loop                   */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
}

/* Flags widened to bit<8> (constraint-class 3: sub-byte fields next to 32-bit
 * register outputs invite SuperCluster failures). evt_idx is the trace write
 * index derived from the event counter in an earlier stage. mode/budget_zero are
 * 8-bit so every downstream gate is a cheap 8-bit equality. */
struct ig_meta_t {
    bit<9>  evt_idx;      /* trace array write index = value read from reg_event_ctr */
    bit<8>  in_range;     /* 1 if evt_idx < TRACE_LEN (else overflow)                */
    bit<32> ts32;         /* low 32 bits of ingress_mac_tstamp                       */
    bit<8>  mode;         /* control-plane mode read from reg_mode (0/1)             */
    bit<8>  budget_zero;  /* 1 if hdr.ib.seq == 0 as dequeued (budget exhausted)     */
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.evt_idx     = 9w0;
        meta.in_range    = 8w0;
        meta.ts32        = 32w0;
        meta.mode        = 8w0;
        meta.budget_zero = 8w0;
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

    /* --- event index counter: one RMW, executed at most once per packet.
     * Returns the current value (the event index for THIS dequeue) and
     * saturating-increments. Caps at TRACE_LEN so overflow events all read
     * back TRACE_LEN and are steered to the overflow path. --- */
    Register<bit<32>, bit<1>>(1, 0) reg_event_ctr;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_event_ctr) evt_ctr_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (v < TRACE_LEN_V) { v = v + 32w1; }
        }
    };

    /* --- mode selector: one read-only RegisterAction, executed at most once per
     * dequeued packet. Returns the control-plane-written mode byte (0=FINITE,
     * 1=RING) into metadata. Control plane writes it via pipe.Ingress.reg_mode. */
    Register<bit<8>, bit<1>>(1, 0) reg_mode;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_mode) mode_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };

    /* --- overflow tally: one RMW, write-only increment --- */
    Register<bit<32>, bit<1>>(1, 0) reg_overflow;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_overflow) ovf_rmw = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };

    /* --- three trace arrays, each written at the dynamic event index.
     * Each is exactly ONE write-only RegisterAction, executed at most once per
     * packet (per the one-RegisterAction-per-register placement discipline).
     * BYTE-IDENTICAL to ibspg_dequeue_oracle.p4. --- */
    Register<bit<8>,  bit<9>>(TRACE_LEN, 0) trace_role;
    RegisterAction<bit<8>, bit<9>, bit<8>>(trace_role) trace_role_w = {
        void apply(inout bit<8> v) { v = hdr.ib.role; }
    };

    Register<bit<32>, bit<9>>(TRACE_LEN, 0) trace_seq;
    RegisterAction<bit<32>, bit<9>, bit<32>>(trace_seq) trace_seq_w = {
        void apply(inout bit<32> v) { v = hdr.ib.seq; }
    };

    Register<bit<32>, bit<9>>(TRACE_LEN, 0) trace_ts;
    RegisterAction<bit<32>, bit<9>, bit<32>>(trace_ts) trace_ts_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };

    /* --- event counters (single-entry PACKETS counters) --- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_hold_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_deq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_hold_deq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;    /* RING re-enqueue */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_expiry;  /* RING budget hit 0 */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_trace_overflow;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_nonibspg;

    action to_block() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid = QID_BLOCK;
        ig_tm_md.bypass_egress = 1w1;
    }
    action to_hold() {
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid = QID_HOLD;
        ig_tm_md.bypass_egress = 1w1;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    apply {
        if (!hdr.ib.isValid()) {
            /* isolate the microbench: drop any non-IBSPG background traffic */
            ctr_nonibspg.count(0);
            drop_pkt();
        } else {
            /* ingress_port == PORT_L  <=>  packet just dequeued and looped back */
            bool dequeued = (ig_intr_md.ingress_port == PORT_L);

            if (!dequeued) {
                /* ---- FRESH from host: ENQUEUE to the role's queue ---- */
                if (hdr.ib.role == ROLE_BLOCK) {
                    to_block();
                    ctr_block_enq.count(0);
                } else if (hdr.ib.role == ROLE_HOLD) {
                    to_hold();
                    ctr_hold_enq.count(0);
                } else {
                    /* reserved roles (DRAIN_M/DRAIN_U/ARM): drop for now */
                    drop_pkt();
                }
            } else {
                /* ---- DEQUEUED: RECORD to the trace, then act by role/mode ---- */
                meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];

                /* Stage: read+increment the event counter (one SALU). */
                bit<32> ev = evt_ctr_rmw.execute(1w0);
                meta.evt_idx = ev[8:0];

                /* Read the control-plane mode once for this dequeued packet
                 * (one SALU). 0 = FINITE (record+drop); 1 = RING (self-replenish). */
                meta.mode = mode_rmw.execute(1w0);

                /* One isolated 32-bit magnitude compare (Class-1 safe: standalone
                 * gateway, no second predicate). Store an 8-bit in-range flag so
                 * every downstream gate is a cheap 8-bit equality. */
                if (ev < TRACE_LEN_V) { meta.in_range = 8w1; }

                /* One isolated 32-bit equality compare -> 8-bit budget flag. Reads
                 * hdr.ib.seq BEFORE any decrement, so it reflects the value as
                 * dequeued. Serves both the RING loop guard (budget remaining =
                 * seq != 0) and the expiry-vs-deq counter split below. */
                if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }

                /* Later stages: write each trace array at the dynamic index.
                 * Each execute is its own guarded block so the three SALUs place
                 * independently (one RegisterAction per register). BYTE-IDENTICAL
                 * to the FINITE oracle — records seq BEFORE the RING decrement. */
                if (meta.in_range == 8w1) { trace_role_w.execute(meta.evt_idx); }
                if (meta.in_range == 8w1) { trace_seq_w.execute(meta.evt_idx); }
                if (meta.in_range == 8w1) { trace_ts_w.execute(meta.evt_idx); }

                /* Overflow bookkeeping (trace full). NOTE: no drop here — the
                 * role/mode block below is the SOLE drop-vs-loop authority, so a
                 * RING keeps looping (still bounded by seq) even after the
                 * 512-deep trace is full and we stop being able to record it. */
                if (meta.in_range != 8w1) {
                    ovf_rmw.execute(1w0);
                    ctr_trace_overflow.count(0);
                }

                /* ---- act by role/mode: the sole drop-vs-loop authority ---- */
                if (hdr.ib.role == ROLE_BLOCK) {
                    if (meta.mode == MODE_RING && meta.budget_zero == 8w0) {
                        /* RING: consume one budget unit and re-enqueue to Q_BLOCK
                         * (the loop). Do NOT drop. trace_seq already recorded the
                         * PRE-decrement value above. */
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_block_loop.count(0);
                    } else {
                        /* FINITE mode, or RING budget exhausted: terminate token. */
                        drop_pkt();
                        if (meta.budget_zero == 8w1) { ctr_block_expiry.count(0); }
                        else                         { ctr_block_deq.count(0); }
                    }
                } else if (hdr.ib.role == ROLE_HOLD) {
                    /* HOLD is recorded then dropped in BOTH modes. */
                    drop_pkt();
                    ctr_hold_deq.count(0);
                } else {
                    /* reserved roles should not appear on a looped-back packet. */
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
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ib);
    }
}

/* ============================ egress (pass-through) =====================
 * Enqueued/looped packets carry bypass_egress=1 (egress skipped); dequeued
 * packets that terminate are dropped in ingress. So egress never processes a
 * real packet — keep it empty. */
struct eg_meta_t { }

parser EgParser(packet_in pkt,
                out headers_t hdr,
                out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
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
    apply { pkt.emit(hdr); }
}

/* ============================ pipeline ================================== */
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

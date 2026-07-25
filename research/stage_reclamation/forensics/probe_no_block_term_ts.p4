/* ============================================================================
 * ibspg_hold_response.p4 — Part 12: HOLD_RESPONSE timing branch over the frozen
 *                          IBSPG blocker-gate state machine.
 *                          (Tofino-1, TNA, bf-p4c 9.13.x)
 *
 * WHAT THIS IS. Part 11 (ibspg_paired.p4) proved ORDERING: a held ACK is released
 * before its held response, structurally, via three strict-priority levels. Part 12
 * is the other branch of the same unified state machine
 * (research/unified_queue_release/UNIFIED_TRANSACTION_STATE_MACHINE.md, HOLD_RESPONSE):
 *
 *   - the ACK is FORWARDED IMMEDIATELY (never held); its arrival stamps t_ack;
 *   - ONLY the RESPONSE is held, queue-resident, in the low-priority Q_RESP;
 *   - the release trigger is a DATA-PLANE DEADLINE  deadline = t_ack + G  — NOT an
 *     external DRAIN packet (Part 9) and not a paired-response event (Part 11).
 *
 * The observable consequence is the point of the whole line: the emitted
 * ACK->response interval becomes G, a fixed constant chosen by policy, regardless
 * of what the device's native interval was. That is CLRT normalization; Part 11's
 * ordering result is its substrate.
 *
 * MECHANISM (what changed vs ibspg_paired.p4)
 *   The blocker becomes DEADLINE-CHECKING. Each blocker token, on each loopback
 *   pass, compares now against the armed deadline and self-terminates once the
 *   deadline has passed. When every token has terminated Q_BLOCK empties, strict
 *   priority stops starving Q_RESP, and the held response dequeues — byte-identical,
 *   with no controller in the fast path.
 *
 *   REMOVED vs Part 11 (this is what buys back the stage budget — Part 11 fits at a
 *   tight 12/12): the whole controlled-drain path (ROLE_DRAIN_M/ROLE_DRAIN_U,
 *   reg_drain_req and its serial stage, 3 drain counters) and the entire ACK HOLD
 *   path (Q_ACK, ctr_ack_enq/ctr_ack_release, and the first/last-ACK ordering
 *   timestamp pair). Release here cannot be caused by any injected packet, which is
 *   a strictly stronger claim than Part 9's: the only release causes are the
 *   deadline and the fail-open budget.
 *   ADDED: reg_deadline (armed by a qualifying ACK) + the per-pass expiry test.
 *
 * DEADLINE TEST — why a subtraction and a sign bit, not a compare.
 *   meta.age = now - deadline (32-bit wrapping ns), expired iff age[31:31]==0 and a
 *   deadline is armed. A 1-bit gateway test costs nothing, whereas a 32-bit-vs-32-bit
 *   magnitude compare does not fit the 44-bit gateway predicate budget and a
 *   runtime-operand SALU predicate is the least portable construct in this toolchain.
 *   Valid while |now - deadline| < 2^31 ns (2.1 s); G here is milliseconds. The ns
 *   timestamp itself wraps every ~4.29 s (bit<32>), so a trial must not straddle a
 *   wrap — the harness re-reads and the budget bounds it either way.
 *
 * G IS CARRIED IN THE ACK (hdr.ib.seq), TEST_ONLY.
 *   hdr.ib.seq is the blocker's pass budget for ROLE_BLOCK and the guard interval
 *   G (ns) for ROLE_ACK — disjoint roles, one field. This makes a G sweep a pure
 *   host-side parameter with no control-plane write per trial. In a deployment G is
 *   policy and belongs in a register/table; that substitution does not change the
 *   mechanism under test.
 *
 * STATE-MACHINE DISCIPLINE (carried verbatim from Parts 9/11 — do not relax):
 *   - state registers (reg_gen -> reg_active -> reg_deadline) in that serial stage
 *     order, each ONE RegisterAction with ONE unconditional execute() call site,
 *     driven by upstream metadata write-enable/value fields.
 *   - timestamp registers are ONE RA / ONE guarded call site each.
 *   - all flags are bit<8>; every compare is isolated on its own line into its own
 *     metadata flag (no gateway exceeds the 44-bit predicate budget).
 *   - timestamp source ig_intr_md.ingress_mac_tstamp[31:0] (ns on TF1).
 *   - non-IBSPG background traffic is dropped to isolate the microbench.
 *
 * QUEUES. Only TWO priority levels are required here (the ACK is never queued):
 *   Q_BLOCK qid7 (max_priority HIGH=7) > Q_RESP qid1 (max_priority LOW=0).
 *   Leaving the Part-11 three-level configuration installed is harmless: qid5 is
 *   simply never used by this program.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_REAL  = 0x88C0;  /* ACK(7) + RESP(2) + ARM(6) roles */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK(1) private marker         */

/* ---- roles (numbering kept compatible with Parts 9/11) ---- */
const bit<8> ROLE_BLOCK = 1;   /* 0x88C1 : enqueue Q_BLOCK (qid7); deadline-checking */
const bit<8> ROLE_RESP  = 2;   /* 0x88C0 : enqueue Q_RESP (qid1); released to dp9    */
const bit<8> ROLE_ARM   = 6;   /* 0x88C0 : arm the synthetic slot, clear deadline    */
const bit<8> ROLE_ACK   = 7;   /* 0x88C0 : forwarded IMMEDIATELY; arms the deadline  */

/* ---- ports (compile constants; the run pins the measured dev_ports) ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)        */
const PortId_t PORT_VISION = 9w9;   /* host-facing port (dp9) — ACK + released RESP out */
const PortId_t PORT_HULK   = 9w11;  /* injection side (dp11)                            */

/* ---- queues on PORT_L (control plane sets the strict-priority levels) ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH (max_priority=7) : blocker reservoir */
const bit<5> QID_RESP  = 5w1;   /* LOW  (max_priority=0) : response held queue */

/* ---- one synthetic slot ---- */
const bit<8> SLOT0 = 8w0;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
/* seq = pass budget (ROLE_BLOCK) | guard interval G in ns (ROLE_ACK) */
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
}

struct ig_meta_t {
    bit<8>  dequeued;      /* 1 if ingress_port == PORT_L (packet just dequeued)  */
    bit<32> ts32;          /* low 32 bits of ingress_mac_tstamp                   */
    bit<8>  budget_zero;   /* 1 if hdr.ib.seq == 0 as dequeued (fail-open watchdog)*/

    /* state-register write drivers (set upstream of each single execute) */
    bit<8>  gen_we;    bit<8>  gen_val;
    bit<8>  active_we; bit<8>  active_val;
    bit<8>  dl_we;     bit<32> dl_val;

    /* state-register read results */
    bit<8>  gen_now;
    bit<8>  active_now;
    bit<32> dl_now;

    /* derived */
    bit<8>  gen_mismatch;  /* 1 if gen_now != hdr.ib.gen        */
    bit<8>  ack_ok;        /* 1 if this fresh ACK qualifies to arm the deadline */
    bit<8>  dl_armed;      /* 1 if dl_now != 0                  */
    bit<32> age;           /* now - deadline (wrapping)         */
    bit<8>  expired;       /* 1 if armed and age >= 0 (set by tbl_deadline_expiry) */

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;  /* fresh BLOCK admitted (timeline start)             */
    bit<8>  ev_ack_arm;      /* qualifying ACK forwarded + deadline armed (t_ack) */
    bit<8>  ev_block_term;   /* a BLOCK terminated (any cause)                    */
    bit<8>  ev_resp_release; /* looped RESP released to dp9                       */
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
        meta.gen_we          = 8w0; meta.gen_val    = 8w0;
        meta.active_we       = 8w0; meta.active_val = 8w0;
        meta.dl_we           = 8w0; meta.dl_val     = 32w0;
        meta.gen_now         = 8w0;
        meta.active_now      = 8w0;
        meta.dl_now          = 32w0;
        meta.gen_mismatch    = 8w0;
        meta.ack_ok          = 8w0;
        meta.dl_armed        = 8w0;
        meta.age             = 32w0;
        meta.expired         = 8w0;
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

    /* ================= state registers (3) — one RA, one call site each ====
     * Metadata-write-enable pattern: the RA ALWAYS returns the old value and
     * conditionally overwrites v with a metadata value when the write-enable is 1.
     * The SALU predicate is on a METADATA field (not on v), within the TF1
     * stateful-ALU operand budget. */

    Register<bit<8>, bit<1>>(1, 0) reg_gen;        /* current generation */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.gen_we == 8w1) { v = meta.gen_val; }
        }
    };

    Register<bit<8>, bit<1>>(1, 0) reg_active;     /* txn armed */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.active_we == 8w1) { v = meta.active_val; }
        }
    };

    /* THE Part-12 register: armed by a qualifying ACK (t_ack + G), read by every
     * blocker pass. Same single-call-site RMW shape as the two above, 32-bit. */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            if (meta.dl_we == 8w1) { v = meta.dl_val; }
        }
    };

    /* ================= fixed-slot timestamp registers (4) =================
     * SPARSE latency capture, write-if-zero = first occurrence. Each is ONE RA with
     * ONE guarded call site (this exact form validated on silicon in Parts 9/11).
     *   G_observed      = reg_ts_first_resp_release - reg_ts_ack_arm   <-- the result
     *   deadline error  = G_observed - G
     *   release tail    = reg_ts_first_resp_release - reg_ts_block_term */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* t_ack — the deadline base, and the left edge of the observed interval */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_ack_arm;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_ack_arm) ts_ack_arm_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* first blocker termination = the instant the reservoir starts draining */
    /* first response released = the right edge of the observed interval */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_resp_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_resp_release) ts_first_resp_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* ================= counters (Stats ALU — multi-site OK) ================ */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_deadline;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_arm;      /* qualifying ACK */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_bypass;   /* non-qualifying ACK */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_release;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_nonibspg;

    /* ================= TM actions ================= */
    action to_block() {                       /* enqueue Q_BLOCK on loopback dp8 */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {                        /* enqueue Q_RESP on loopback dp8  */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_host() {                        /* immediate ACK, or released RESP -> dp9 */
        ig_tm_md.ucast_egress_port = PORT_VISION;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;     /* run egress -> emit byte-identical frame */
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* ================= deadline expiry decision =================
     * expired  <=>  a deadline is armed AND (now - deadline) >= 0, i.e. the sign bit
     * of the wrapping difference is 0.
     *
     * Why a ternary match and not a gateway test on meta.age[31:31]: a bit-slice of a
     * 32-bit arithmetic field — in a gateway condition OR in an assignment — imposes a
     * [31:31]/[30:0] split on every field that shares its cluster (ts32, dl_val,
     * dl_now, hdr.ib.seq, ingress_mac_tstamp) and PHV allocation then fails outright
     * (measured on 9.13.1: "12 field slices remain unallocated"). The ternary match
     * unit reads the whole container under a TCAM mask, so it tests the same bit
     * while creating no slicing constraint. One TCAM entry; Part 11 used 0 TCAMs. */
    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = {
            meta.dl_armed : exact;
            meta.age      : ternary;
        }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = {
            (8w1, 32w0 &&& 32w0x80000000) : mark_expired();
        }
        size = 2;
    }

    apply {
        if (!hdr.ib.isValid()) {
            /* isolate the microbench: drop any non-IBSPG background traffic */
            ctr_nonibspg.count(0);
            drop_pkt();
        } else {
            /* ---------- classify (early) ---------- */
            if (ig_intr_md.ingress_port == PORT_L) { meta.dequeued = 8w1; }
            meta.ts32 = ig_intr_md.ingress_mac_tstamp[31:0];
            if (hdr.ib.seq == 32w0) { meta.budget_zero = 8w1; }  /* isolated 32b compare */

            /* ---------- ARM sets gen + active, and CLEARS any stale deadline ------ */
            if (meta.dequeued == 8w0 && hdr.ib.role == ROLE_ARM) {
                meta.gen_we    = 8w1; meta.gen_val    = hdr.ib.gen;
                meta.active_we = 8w1; meta.active_val = 8w1;
                meta.dl_we     = 8w1; meta.dl_val     = 32w0;
            }

            /* ---------- STAGE g: reg_gen read / conditional write ---------- */
            meta.gen_now = gen_rmw.execute(0);
            if (meta.gen_now != hdr.ib.gen) { meta.gen_mismatch = 8w1; }  /* isolated 8b */

            /* ---------- active clear driver: BLOCK terminates on stale/timeout ----
             * (deadline expiry does NOT clear active: the response is still queue-
             * resident and its own release path must stay reachable.) */
            if (meta.dequeued == 8w1 && hdr.ib.role == ROLE_BLOCK) {
                if (meta.gen_mismatch == 8w1 || meta.budget_zero == 8w1) {
                    meta.active_we = 8w1; meta.active_val = 8w0;
                }
            }

            /* ---------- STAGE a: reg_active read / conditional write ---------- */
            meta.active_now = active_rmw.execute(0);

            /* ---------- deadline write driver: a QUALIFYING fresh ACK only --------
             * qualification = same slot, same generation, transaction armed. A
             * non-qualifying ACK is still forwarded (invariant 7) but must not move
             * the release time of anything. */
            if (meta.dequeued == 8w0 && hdr.ib.role == ROLE_ACK
                && hdr.ib.slot == SLOT0 && meta.gen_mismatch == 8w0
                && meta.active_now == 8w1) {
                meta.ack_ok = 8w1;
                meta.dl_we  = 8w1;
                meta.dl_val = meta.ts32 + hdr.ib.seq;   /* deadline = t_ack + G */
            }

            /* ---------- STAGE d: reg_deadline read / conditional write ---------- */
            meta.dl_now = deadline_rmw.execute(0);

            /* ---------- deadline expiry test (subtract + sign bit) ---------- */
            if (meta.dl_now != 32w0) { meta.dl_armed = 8w1; }   /* isolated 32b compare */
            meta.age = meta.ts32 - meta.dl_now;
            tbl_deadline_expiry.apply();                        /* sets meta.expired */

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- FRESH from host ----- */
                if (hdr.ib.role == ROLE_BLOCK) {
                    to_block();
                    ctr_block_enq.count(0);
                    meta.ev_first_block = 8w1;
                } else if (hdr.ib.role == ROLE_RESP) {
                    to_resp();                        /* held on Q_RESP (qid1, LOW) */
                    ctr_resp_enq.count(0);
                } else if (hdr.ib.role == ROLE_ACK) {
                    /* HOLD_RESPONSE: the ACK is NEVER held — forward it now. */
                    to_host();
                    if (meta.ack_ok == 8w1) {
                        ctr_ack_arm.count(0);
                        meta.ev_ack_arm = 8w1;
                    } else {
                        ctr_ack_bypass.count(0);
                    }
                } else if (hdr.ib.role == ROLE_ARM) {
                    ctr_arm.count(0);
                    drop_pkt();                       /* consumed */
                } else {
                    drop_pkt();
                }
            } else {
                /* ----- DEQUEUED (looped back from dp8) ----- */
                if (hdr.ib.role == ROLE_BLOCK) {
                    /* terminate causes, priority: stale > deadline > budget */
                    if (meta.active_now == 8w0 || meta.gen_mismatch == 8w1) {
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
                        /* LOOP: consume one budget unit, re-enqueue Q_BLOCK */
                        hdr.ib.seq = hdr.ib.seq - 32w1;
                        to_block();
                        ctr_block_loop.count(0);
                    }
                } else if (hdr.ib.role == ROLE_RESP) {
                    /* RELEASED RESPONSE: forward to dp9, byte-identical, do NOT drop */
                    to_host();
                    ctr_resp_release.count(0);
                    meta.ev_resp_release = 8w1;
                } else {
                    drop_pkt();   /* ARM/ACK must never loop back */
                }
            }

            /* ================= SPARSE latency capture (single call site each) ==== */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_ack_arm      == 8w1) { ts_ack_arm_w.execute(0); }
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

/* ============================ egress ====================================
 * The immediately-forwarded ACK and the released RESPONSE traverse egress
 * (bypass_egress=0). The egress parser MUST extract eth+ib and the deparser MUST
 * re-emit them, or the frame egresses with no headers. Egress is a pure
 * pass-through: no field is modified, so the frame is byte-identical to what was
 * enqueued. */
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

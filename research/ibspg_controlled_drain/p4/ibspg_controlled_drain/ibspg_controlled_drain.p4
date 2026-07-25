/* ============================================================================
 * ibspg_controlled_drain_DESIGN.p4 — Part 9: a controlled data-plane DRAIN state
 *                                     machine over the frozen IBSPG ring oracle
 *                                     (Tofino-1, TNA, bf-p4c 9.13.x)
 *
 * WHAT THIS ADDS over ibspg_ring_oracle.p4 (the FROZEN, on-switch-proven baseline):
 *   The oracle terminates a looping BLOCK token ONLY when its pass budget (seq)
 *   expires. Part 9 lets a matching DRAIN packet deliberately terminate the
 *   blocker at a chosen time, with slot + generation matching, negative controls,
 *   external forwarding of the released HELD frame, and an independent fail-open
 *   watchdog (the seq budget is retained unchanged as that watchdog).
 *
 * ONE synthetic slot (index 0). Per-slot state in three single-entry registers:
 *   reg_active     : 1 while a transaction is armed.
 *   reg_gen        : current generation (bit<8>, mirrors hdr.ib.gen).
 *   reg_drain_req  : set when a matching drain has arrived (a pending kill).
 *
 * PACKET BEHAVIORS (all IBSPG; non-IBSPG dropped as in the oracle):
 *   ARM      (role 6, fresh from dp9): active=1, gen=hdr.gen, drain_req=0; DROP.
 *   DRAIN_M  (role 3, fresh from dp9): valid iff active==1 && slot==0 && gen match;
 *            if valid set drain_req=1 (ctr_drain_match) else reject; DROP.
 *   DRAIN_U  (role 4, fresh from dp9): non-matching slot -> reject, no state; DROP.
 *   BLOCK    (role 1, fresh from dp9): enqueue Q_BLOCK (loopback dp8).
 *   HOLD     (role 2, fresh from dp9): enqueue Q_HOLD  (loopback dp8).
 *   BLOCK looped (ingress==dp8): TERMINATE (drop + clear active) iff
 *            (active==0 || gen_mismatch || drain_req==1 || seq==0); else LOOP
 *            (seq-=1, re-enqueue Q_BLOCK). Split counters by cause.
 *   HOLD  looped (ingress==dp8) = RELEASED: forward to dp9, physically egress
 *            (bypass_egress=0), byte-identical. Do NOT drop, do NOT re-enqueue.
 *
 * DESIGN NOTE — the ordering resolution (see WORKSTREAM-A report, hard Q2):
 *   Registers are single-stage. The DRAIN path wants  active-read -> drain-write,
 *   the BLOCK path wants  drain-read -> active-write. Those orderings conflict.
 *   RESOLUTION: the DRAIN drain_req WRITE is gated on (slot==0 && gen-match) only,
 *   NOT on active. Reading active before the drain write is therefore unnecessary,
 *   which fixes the stage order to a clean chain:  reg_gen -> reg_drain_req ->
 *   reg_active. Gating drain_req on active is REDUNDANT for correctness because the
 *   BLOCK-return path independently terminates on active==0, and reg_drain_req is
 *   reset to 0 by the next ARM. The active==1 condition is retained ONLY for the
 *   drain COUNTER classification (a late, side-effect-free read at the active
 *   stage). The single observable consequence — reg_drain_req may be written 1 for
 *   a gen-matching drain that arrives while active==0 — is INERT (any looping
 *   block already terminates via active==0, and ARM clears it) and is documented.
 *
 * ONE-RA-PER-REGISTER / SINGLE-CALL-SITE discipline (from the placement notes):
 *   Each of the 3 state registers has exactly ONE RegisterAction with exactly ONE
 *   unconditional execute() call site. Per-packet-type behavior is driven by
 *   metadata write-enable/value fields set UPSTREAM of the execute. Each of the 7
 *   timestamp registers likewise has ONE RA and ONE call site, guarded by an
 *   8-bit event flag. Counters (Stats ALU) may sit at multiple sites; stateful
 *   registers may NOT.
 *
 * TIMESTAMP source: ig_intr_md.ingress_mac_tstamp[31:0] (ns on TF1), as the oracle.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes (unchanged from the oracle) ---- */
const bit<16> ETHERTYPE_IBSPG_REAL  = 0x88C0;  /* HOLD (role 2) + ARM/DRAIN roles */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK (role 1) private marker    */

/* ---- roles ---- */
const bit<8> ROLE_BLOCK   = 1;   /* 0x88C1 : enqueue Q_BLOCK (qid7)                 */
const bit<8> ROLE_HOLD    = 2;   /* 0x88C0 : enqueue Q_HOLD  (qid1); released to dp9*/
const bit<8> ROLE_DRAIN_M = 3;   /* 0x88C0 : matching drain (carries slot==0)       */
const bit<8> ROLE_DRAIN_U = 4;   /* 0x88C0 : unrelated drain (non-matching slot)    */
const bit<8> ROLE_ARM     = 6;   /* 0x88C0 : arm the synthetic slot                 */

/* ---- ports (compile constants; the run pins the measured dev_ports) ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)     */
const PortId_t PORT_VISION = 9w9;   /* host-facing port (dp9) — ARM/DRAIN in, HELD out */
const PortId_t PORT_HULK   = 9w11;  /* reserved                                     */

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH strict priority (set in control plane)      */
const bit<5> QID_HOLD  = 5w1;   /* LOW  strict priority                             */

/* ---- one synthetic slot ---- */
const bit<8> SLOT0 = 8w0;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
}

/* Every flag is bit<8> (constraint-class 3: sub-byte fields next to register
 * outputs invite SuperCluster failures). *_we / *_val drive the single-call-site
 * state RegisterActions; *_now hold their read results; ev_* are the timestamp
 * event flags so each ts register has ONE guarded call site. */
struct ig_meta_t {
    bit<8>  dequeued;      /* 1 if ingress_port == PORT_L (packet just dequeued)     */
    bit<32> ts32;          /* low 32 bits of ingress_mac_tstamp                      */
    bit<8>  budget_zero;   /* 1 if hdr.ib.seq == 0 as dequeued (fail-open watchdog)  */

    /* state-register write drivers (set upstream of each single execute) */
    bit<8>  gen_we;    bit<8>  gen_val;
    bit<8>  drain_we;  bit<8>  drain_val;
    bit<8>  active_we; bit<8>  active_val;

    /* state-register read results */
    bit<8>  gen_now;
    bit<8>  drain_now;
    bit<8>  active_now;

    /* derived */
    bit<8>  gen_mismatch;  /* 1 if gen_now != hdr.ib.gen                             */

    /* timestamp event flags (each guards ONE ts-register call site) */
    bit<8>  ev_first_block;  /* fresh BLOCK admitted                                 */
    bit<8>  ev_hold_admit;   /* fresh HOLD admitted                                  */
    bit<8>  ev_drain_match;  /* DRAIN validated                                      */
    bit<8>  ev_block_term;   /* BLOCK terminated (any cause)                         */
    bit<8>  ev_release;      /* HOLD released to dp9                                 */
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.dequeued       = 8w0;
        meta.ts32           = 32w0;
        meta.budget_zero    = 8w0;
        meta.gen_we         = 8w0; meta.gen_val    = 8w0;
        meta.drain_we       = 8w0; meta.drain_val  = 8w0;
        meta.active_we      = 8w0; meta.active_val = 8w0;
        meta.gen_now        = 8w0;
        meta.drain_now      = 8w0;
        meta.active_now     = 8w0;
        meta.gen_mismatch   = 8w0;
        meta.ev_first_block = 8w0;
        meta.ev_hold_admit  = 8w0;
        meta.ev_drain_match = 8w0;
        meta.ev_block_term  = 8w0;
        meta.ev_release     = 8w0;
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

    /* ================= state registers (3) — one RA, one call site each ===
     * All three use the metadata-write-enable pattern: the RA ALWAYS returns
     * the old value (rv=v) and conditionally overwrites v with a metadata value
     * when the metadata write-enable is 1. The SALU predicate is on a METADATA
     * field (not on v) — CONFIRMED-compiling on TF1 (2 PHV inputs + 1 output,
     * within the stateful-ALU operand budget). See report hard-Q1. */

    Register<bit<8>, bit<1>>(1, 0) reg_gen;        /* current generation           */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_gen) gen_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.gen_we == 8w1) { v = meta.gen_val; }
        }
    };

    Register<bit<8>, bit<1>>(1, 0) reg_drain_req;  /* pending controlled kill      */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_drain_req) drain_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.drain_we == 8w1) { v = meta.drain_val; }
        }
    };

    Register<bit<8>, bit<1>>(1, 0) reg_active;     /* txn armed                    */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_active) active_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.active_we == 8w1) { v = meta.active_val; }
        }
    };

    /* ================= fixed-slot timestamp registers (7) ==================
     * SPARSE latency capture (NOT a per-loop trace: ms holds are millions of
     * loops). write-if-zero = first occurrence; always-overwrite = last. Each is
     * ONE RA with ONE guarded call site (a stateful register at multiple sites
     * does NOT place — placement note fix). */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_hold_admit;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_hold_admit) ts_first_hold_admit_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_last_hold_admit;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_last_hold_admit) ts_last_hold_admit_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_drain_match;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_drain_match) ts_drain_match_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_release) ts_first_release_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    Register<bit<32>, bit<1>>(1, 0) reg_ts_last_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_last_release) ts_last_release_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };

    /* ================= counters (Stats ALU — multi-site OK) ================ */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_hold_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drain_match;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drain_reject_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drain_reject_unrelated;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_controlled;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_hold_release;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_nonibspg;

    /* ================= TM actions ================= */
    action to_block() {                       /* enqueue Q_BLOCK on loopback dp8   */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_hold() {                        /* enqueue Q_HOLD on loopback dp8    */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_HOLD;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action forward_release() {                /* released HELD -> physically egress dp9 */
        ig_tm_md.ucast_egress_port = PORT_VISION;
        ig_tm_md.qid               = 5w0;
        ig_tm_md.bypass_egress     = 1w0;     /* run egress -> emit byte-identical frame */
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

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

            /* ---------- ARM sets ALL three state drivers (fresh, role 6) ---------- */
            if (meta.dequeued == 8w0 && hdr.ib.role == ROLE_ARM) {
                meta.gen_we    = 8w1; meta.gen_val    = hdr.ib.gen;
                meta.drain_we  = 8w1; meta.drain_val  = 8w0;
                meta.active_we = 8w1; meta.active_val = 8w1;
            }

            /* ---------- STAGE g: reg_gen read / conditional write ---------- */
            meta.gen_now = gen_rmw.execute(0);
            if (meta.gen_now != hdr.ib.gen) { meta.gen_mismatch = 8w1; }  /* isolated 8b */

            /* ---------- drain_req write driver: DRAIN_M valid (slot==0, gen match) ----
             * NOT gated on active (see ordering note). Inert when active==0. */
            if (meta.dequeued == 8w0 && hdr.ib.role == ROLE_DRAIN_M
                && hdr.ib.slot == SLOT0 && meta.gen_mismatch == 8w0) {
                meta.drain_we = 8w1; meta.drain_val = 8w1;
            }

            /* ---------- STAGE d: reg_drain_req read / conditional write ---------- */
            meta.drain_now = drain_rmw.execute(0);

            /* ---------- active clear driver: BLOCK terminates on controlled/stale/timeout ----
             * active_now (needed for the active==0 stale cause) is the read result of
             * the SAME RA and is unavailable to gate it — but active==0 means active is
             * ALREADY 0, so not writing it is correct. This driver covers the causes
             * known before the active stage. */
            if (meta.dequeued == 8w1 && hdr.ib.role == ROLE_BLOCK) {
                if (meta.gen_mismatch == 8w1 || meta.drain_now == 8w1 || meta.budget_zero == 8w1) {
                    meta.active_we = 8w1; meta.active_val = 8w0;
                }
            }

            /* ---------- STAGE a: reg_active read / conditional write ---------- */
            meta.active_now = active_rmw.execute(0);

            /* ================= ACT (flat, no early returns) ================= */
            if (meta.dequeued == 8w0) {
                /* ----- FRESH from host (dp9) ----- */
                if (hdr.ib.role == ROLE_BLOCK) {
                    to_block();
                    ctr_block_enq.count(0);
                    meta.ev_first_block = 8w1;
                } else if (hdr.ib.role == ROLE_HOLD) {
                    to_hold();
                    ctr_hold_enq.count(0);
                    meta.ev_hold_admit = 8w1;
                } else if (hdr.ib.role == ROLE_ARM) {
                    ctr_arm.count(0);
                    drop_pkt();                       /* consumed */
                } else if (hdr.ib.role == ROLE_DRAIN_M) {
                    /* classify the drain (faithful to spec: valid = active==1 &&
                     * slot==0 && gen match). Priority: unrelated(slot) > stale(gen)
                     * > match(active) > unrelated(no active txn). */
                    if (hdr.ib.slot != SLOT0) {
                        ctr_drain_reject_unrelated.count(0);
                    } else if (meta.gen_mismatch == 8w1) {
                        ctr_drain_reject_stale.count(0);
                    } else if (meta.active_now == 8w1) {
                        ctr_drain_match.count(0);
                        meta.ev_drain_match = 8w1;
                    } else {
                        /* gen matched a stale (ended) txn, active==0: drain_req was
                         * written 1 above but is INERT (documented). */
                        ctr_drain_reject_unrelated.count(0);
                    }
                    drop_pkt();                       /* consumed */
                } else if (hdr.ib.role == ROLE_DRAIN_U) {
                    ctr_drain_reject_unrelated.count(0);
                    drop_pkt();                       /* consumed, no state change */
                } else {
                    drop_pkt();
                }
            } else {
                /* ----- DEQUEUED (looped back from dp8) ----- */
                if (hdr.ib.role == ROLE_BLOCK) {
                    /* terminate causes, priority: stale > controlled > timeout */
                    if (meta.active_now == 8w0 || meta.gen_mismatch == 8w1) {
                        drop_pkt();
                        ctr_block_term_stale.count(0);
                        meta.ev_block_term = 8w1;
                    } else if (meta.drain_now == 8w1) {
                        drop_pkt();
                        ctr_block_term_controlled.count(0);
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
                } else if (hdr.ib.role == ROLE_HOLD) {
                    /* RELEASED: forward to dp9, byte-identical, do NOT drop */
                    forward_release();
                    ctr_hold_release.count(0);
                    meta.ev_release = 8w1;
                } else {
                    drop_pkt();   /* ARM/DRAIN should never loop back */
                }
            }

            /* ================= SPARSE latency capture (single call site each) =====
             * Each ts register executed exactly once here, guarded by its 8-bit
             * event flag. Separate if-blocks so no two register executes bundle
             * into one compiler action (placement note fix #3). */
            if (meta.ev_first_block == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_hold_admit  == 8w1) { ts_first_hold_admit_w.execute(0); }
            if (meta.ev_hold_admit  == 8w1) { ts_last_hold_admit_w.execute(0); }
            if (meta.ev_drain_match == 8w1) { ts_drain_match_w.execute(0); }
            if (meta.ev_block_term  == 8w1) { ts_block_term_w.execute(0); }
            if (meta.ev_release     == 8w1) { ts_first_release_w.execute(0); }
            if (meta.ev_release     == 8w1) { ts_last_release_w.execute(0); }
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
 * CRITICAL DIFFERENCE FROM THE ORACLE: the released HELD frame traverses egress
 * (bypass_egress=0). The egress parser MUST extract eth+ib and the deparser MUST
 * re-emit them, or the released frame egresses with no headers. (The oracle's
 * egress never saw a real packet, so it could skip parsing — Part 9 cannot.)
 * Egress stays a pure pass-through: no field is modified, so the frame is
 * byte-identical to what was enqueued. */
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

/* ============================================================================
 * ibspg_paired_DESIGN.p4 — Part 11: PAIRED ACK-before-RESPONSE ordering over the
 *                          frozen IBSPG controlled-drain state machine.
 *                          (Tofino-1, TNA, bf-p4c 9.13.x)
 *
 * WHAT THIS ADDS over ibspg_controlled_drain.p4 (the on-silicon-validated Part-9
 * baseline that COMPILES 0-errors, 11/12 ingress stages):
 *   Part 9 held every held packet in ONE role (ROLE_HOLD, role 2) on ONE queue
 *   Q_HOLD (qid1). Part 11 splits held traffic into TWO ordered held roles that
 *   are held together during blocking and RELEASED in a GUARANTEED order — every
 *   ACK before any RESPONSE — using a THIRD strict-priority level on the dp8
 *   loopback port. The ordering is a pure control-plane TM property (three
 *   distinct max_priority levels); nothing in this P4 blocks or enforces it, and
 *   this program's job is to (a) steer each held role to its queue on enqueue and
 *   (b) instrument the release order so the invariant is provable on-chip.
 *
 *   ROLE_ACK  = 7  (NEW, etype 0x88C0): fresh (ingress != dp8) -> enqueue Q_ACK
 *                  (qid5); looped-back (ingress == dp8, i.e. RELEASED) -> forward
 *                  to host dp9 byte-identical, count ctr_ack_release.
 *   ROLE_RESP = 2  (the former ROLE_HOLD, renamed): fresh -> enqueue Q_RESP (qid1);
 *                  looped-back -> forward to dp9 byte-identical, count ctr_resp_release.
 *   BLOCK/ARM/DRAIN_M/DRAIN_U and the entire controlled-drain state machine are
 *   UNCHANGED. QID_BLOCK=qid7 UNCHANGED.
 *
 * THREE STRICT-PRIORITY LEVELS ON dp8 (set by the CONTROL PLANE, documented here,
 * NOT set in P4):
 *   Q_BLOCK qid7 (max_priority HIGH=7) > Q_ACK qid5 (max_priority MID=3)
 *                                      > Q_RESP qid1 (max_priority LOW=0).
 *   During blocking the Q_BLOCK reservoir starves both held queues. On the matching
 *   drain, Q_BLOCK empties, then strict priority drains ALL of Q_ACK before ANY of
 *   Q_RESP -> ACK-before-response is structural. (This is the Part-3 max_priority
 *   result extended to three levels; confirmed on silicon that a higher max_priority
 *   queue drains to empty before a lower one competes for the remaining bandwidth.)
 *
 * ORDERING PROOF (the crux of Part 11) — on-chip, register-free of the wire:
 *   reg_ts_last_ack_release  (always-overwrite) : ns of the LAST ACK released.
 *   reg_ts_first_resp_release(write-if-zero)     : ns of the FIRST RESPONSE released.
 *   INVARIANT:  reg_ts_last_ack_release  <  reg_ts_first_resp_release
 *   i.e. every ACK left the box before the first response did. Read both from the
 *   control plane after a run and compare.
 *
 * STATE-MACHINE DISCIPLINE (carried verbatim from Part 9 — do not relax):
 *   - 3 state registers reg_gen -> reg_drain_req -> reg_active in that serial
 *     stage order, each ONE RegisterAction with ONE unconditional execute() call
 *     site, driven by upstream metadata write-enable/value fields.
 *   - Timestamp registers are ONE RA / ONE guarded call site each (a stateful
 *     register at multiple sites does NOT place).
 *   - All flags are bit<8> (sub-byte fields next to 32-bit register outputs invite
 *     invalid-SuperCluster PHV failures).
 *   - Compares are isolated (each magnitude/equality compare on its own line into
 *     its own metadata flag) so no gateway exceeds the 44-bit predicate budget.
 *   - Timestamp source ig_intr_md.ingress_mac_tstamp[31:0] (ns on TF1).
 *   - Non-IBSPG background traffic is dropped to isolate the microbench.
 *
 * STAGE BUDGET (hard constraint: <= 12 ingress stages; Part 9 is 11/12):
 *   The ACK path adds only ACT-block gateways + two simple actions (to_ack,
 *   forward-of-a-looped-ACK), which do NOT lengthen the serial state chain. The
 *   register count DROPS from 10 (3 state + 7 ts) to 9 (3 state + 6 ts): the two
 *   Part-9 hold-admit timestamp registers are removed, and the single release ts
 *   pair is re-split into an ACK pair + a RESP first. Net PHV is neutral (one ev_*
 *   flag dropped, one added). Estimated ~11 ingress stages, within 12. If the ts
 *   bank spills to a 13th stage, the documented CUT is to drop reg_ts_first_block
 *   (+ ev_first_block), taking the ts bank to 5.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_REAL  = 0x88C0;  /* ACK(7) + RESP(2) + ARM/DRAIN roles */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCK(1) private marker            */

/* ---- roles ---- */
const bit<8> ROLE_BLOCK   = 1;   /* 0x88C1 : enqueue Q_BLOCK (qid7)                  */
const bit<8> ROLE_RESP    = 2;   /* 0x88C0 : enqueue Q_RESP (qid1); released to dp9  */
const bit<8> ROLE_DRAIN_M = 3;   /* 0x88C0 : matching drain (carries slot==0)        */
const bit<8> ROLE_DRAIN_U = 4;   /* 0x88C0 : unrelated drain (non-matching slot)     */
const bit<8> ROLE_ARM     = 6;   /* 0x88C0 : arm the synthetic slot                  */
const bit<8> ROLE_ACK     = 7;   /* 0x88C0 : enqueue Q_ACK (qid5); released to dp9   */

/* ---- ports (compile constants; the run pins the measured dev_ports) ---- */
const PortId_t PORT_L      = 9w8;   /* internal loopback L (dev_port 8, pipe 0)      */
const PortId_t PORT_VISION = 9w9;   /* host-facing port (dp9) — ARM/DRAIN in, held out */
const PortId_t PORT_HULK   = 9w11;  /* reserved                                      */

/* ---- queues on PORT_L (control plane sets the three strict-priority levels) ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH (max_priority=7) : blocker reservoir         */
const bit<5> QID_ACK   = 5w5;   /* MID  (max_priority=3) : ACK held queue            */
const bit<5> QID_RESP  = 5w1;   /* LOW  (max_priority=0) : RESPONSE held queue       */

/* ---- one synthetic slot ---- */
const bit<8> SLOT0 = 8w0;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
}

/* Every flag is bit<8> (constraint-class 3). *_we / *_val drive the single-call-
 * site state RegisterActions; *_now hold read results; ev_* are the timestamp
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
    bit<8>  ev_first_block;  /* fresh BLOCK admitted (timeline start; CUT-lever)     */
    bit<8>  ev_drain_match;  /* DRAIN validated                                      */
    bit<8>  ev_block_term;   /* BLOCK terminated (any cause)                         */
    bit<8>  ev_ack_release;  /* looped ACK  released to dp9 (guards first+last ACK)  */
    bit<8>  ev_resp_release; /* looped RESP released to dp9 (guards first RESP)      */
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
        meta.drain_we        = 8w0; meta.drain_val  = 8w0;
        meta.active_we       = 8w0; meta.active_val = 8w0;
        meta.gen_now         = 8w0;
        meta.drain_now       = 8w0;
        meta.active_now      = 8w0;
        meta.gen_mismatch    = 8w0;
        meta.ev_first_block  = 8w0;
        meta.ev_drain_match  = 8w0;
        meta.ev_block_term   = 8w0;
        meta.ev_ack_release  = 8w0;
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

    /* ================= state registers (3) — one RA, one call site each ===
     * Metadata-write-enable pattern: the RA ALWAYS returns the old value and
     * conditionally overwrites v with a metadata value when the write-enable is 1.
     * The SALU predicate is on a METADATA field (not on v) — within the TF1
     * stateful-ALU operand budget (2 PHV inputs + 1 output). */

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

    /* ================= fixed-slot timestamp registers (6) ==================
     * SPARSE latency capture. write-if-zero = first occurrence; always-overwrite =
     * last. Each is ONE RA with ONE guarded call site. write-if-zero (v==0
     * sentinel) is a known-good pattern here: the slot is seeded 0 by the Register
     * constructor and the semantics are exactly "record the first event"; this
     * exact form validated on silicon in Part 9. */

    /* timeline start — CUT-lever if the ts bank forces a 13th stage */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_block;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_block) ts_first_block_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* drain validated */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_drain_match;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_drain_match) ts_drain_match_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* blocker terminated (drain-match window closes as the reservoir empties) */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_block_term;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_block_term) ts_block_term_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* --- ORDERING PROOF BANK --- */
    /* first ACK released */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_ack_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_ack_release) ts_first_ack_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };
    /* last ACK released (always-overwrite) — LHS of the invariant */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_last_ack_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_last_ack_release) ts_last_ack_w = {
        void apply(inout bit<32> v) { v = meta.ts32; }
    };
    /* first RESPONSE released (write-if-zero) — RHS of the invariant */
    Register<bit<32>, bit<1>>(1, 0) reg_ts_first_resp_release;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_ts_first_resp_release) ts_first_resp_w = {
        void apply(inout bit<32> v) { if (v == 32w0) { v = meta.ts32; } }
    };

    /* ================= counters (Stats ALU — multi-site OK) ================ */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_enq;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_enq;                  /* NEW */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_enq;                 /* was hold_enq */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drain_match;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drain_reject_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_drain_reject_unrelated;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_loop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_controlled;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_timeout;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_block_term_stale;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_ack_release;              /* NEW */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_resp_release;             /* was hold_release */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_nonibspg;

    /* ================= TM actions ================= */
    action to_block() {                       /* enqueue Q_BLOCK on loopback dp8   */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_BLOCK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_ack() {                         /* enqueue Q_ACK on loopback dp8     */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_ACK;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action to_resp() {                        /* enqueue Q_RESP on loopback dp8    */
        ig_tm_md.ucast_egress_port = PORT_L;
        ig_tm_md.qid               = QID_RESP;
        ig_tm_md.bypass_egress     = 1w1;
    }
    action forward_release() {                /* released held frame -> egress dp9 */
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
             * NOT gated on active (Part-9 ordering resolution). Inert when active==0. */
            if (meta.dequeued == 8w0 && hdr.ib.role == ROLE_DRAIN_M
                && hdr.ib.slot == SLOT0 && meta.gen_mismatch == 8w0) {
                meta.drain_we = 8w1; meta.drain_val = 8w1;
            }

            /* ---------- STAGE d: reg_drain_req read / conditional write ---------- */
            meta.drain_now = drain_rmw.execute(0);

            /* ---------- active clear driver: BLOCK terminates on controlled/stale/timeout ---- */
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
                } else if (hdr.ib.role == ROLE_ACK) {
                    to_ack();                         /* held on Q_ACK (qid5, MID) */
                    ctr_ack_enq.count(0);
                } else if (hdr.ib.role == ROLE_RESP) {
                    to_resp();                        /* held on Q_RESP (qid1, LOW) */
                    ctr_resp_enq.count(0);
                } else if (hdr.ib.role == ROLE_ARM) {
                    ctr_arm.count(0);
                    drop_pkt();                       /* consumed */
                } else if (hdr.ib.role == ROLE_DRAIN_M) {
                    /* classify the drain: valid = active==1 && slot==0 && gen match.
                     * Priority: unrelated(slot) > stale(gen) > match(active) >
                     * unrelated(no active txn). */
                    if (hdr.ib.slot != SLOT0) {
                        ctr_drain_reject_unrelated.count(0);
                    } else if (meta.gen_mismatch == 8w1) {
                        ctr_drain_reject_stale.count(0);
                    } else if (meta.active_now == 8w1) {
                        ctr_drain_match.count(0);
                        meta.ev_drain_match = 8w1;
                    } else {
                        /* gen matched a stale (ended) txn, active==0: drain_req was
                         * written 1 above but is INERT (documented in Part 9). */
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
                } else if (hdr.ib.role == ROLE_ACK) {
                    /* RELEASED ACK: forward to dp9, byte-identical, do NOT drop */
                    forward_release();
                    ctr_ack_release.count(0);
                    meta.ev_ack_release = 8w1;
                } else if (hdr.ib.role == ROLE_RESP) {
                    /* RELEASED RESPONSE: forward to dp9, byte-identical, do NOT drop */
                    forward_release();
                    ctr_resp_release.count(0);
                    meta.ev_resp_release = 8w1;
                } else {
                    drop_pkt();   /* ARM/DRAIN should never loop back */
                }
            }

            /* ================= SPARSE latency capture (single call site each) =====
             * Each ts register executed exactly once, guarded by its 8-bit event
             * flag. Separate if-blocks so no two register executes bundle into one
             * compiler action (placement note fix). */
            if (meta.ev_first_block  == 8w1) { ts_first_block_w.execute(0); }
            if (meta.ev_drain_match  == 8w1) { ts_drain_match_w.execute(0); }
            if (meta.ev_block_term   == 8w1) { ts_block_term_w.execute(0); }
            if (meta.ev_ack_release  == 8w1) { ts_first_ack_w.execute(0); }
            if (meta.ev_ack_release  == 8w1) { ts_last_ack_w.execute(0); }
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
 * Released ACK and RESPONSE frames traverse egress (bypass_egress=0). The egress
 * parser MUST extract eth+ib and the deparser MUST re-emit them, or the released
 * frame egresses with no headers. Egress is a pure pass-through: no field is
 * modified, so the frame is byte-identical to what was enqueued. */
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

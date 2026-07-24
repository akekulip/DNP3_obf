/* ============================================================================
 * ibspg_mb.p4 — Internal-Blocker Strict-Priority Gate microbenchmark (Tofino-1)
 *
 * Smallest pipeline that tests whether a REAL packet can be held queue-resident
 * in a low strict-priority queue (Q_HOLD) on an internal loopback port L, kept
 * un-serviced by a continuously-occupied high strict-priority queue (Q_BLOCK)
 * carrying an internal blocker token, and released ONLY when a data-plane
 * DRAIN_MATCH event drains the blocker. No original-packet continuous
 * recirculation; blocker never egresses a protected port.
 *
 * This is a COMPILE-ONLY prototype for local bf-p4c 9.13.1 (fixed single slot
 * usable; NUM_SLOTS small). It does NOT parse DNP3 — synthetic marked frames
 * only. Conventions follow queue_microbench.p4 (ig_tm_md.qid assignment,
 * indexed Counters, RegisterActions). Frozen sources are untouched.
 *
 * Roles (hdr.ib.role):
 *   1 BLOCKER  — internal token; loops in Q_BLOCK; dropped when reg_drain[slot]=1
 *   2 HELD     — the real packet; parked in Q_HOLD; released after drain
 *   3 DRAIN_M  — matched drain (checks generation) -> sets reg_drain[slot]=1
 *   4 DRAIN_U  — unrelated drain -> never sets reg_drain
 *   6 ARM      — arms slot: sets reg_gen[slot], clears reg_drain[slot]
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* ---- ethertypes ---- */
const bit<16> ETHERTYPE_IBSPG_REAL  = 0x88C0;  /* HELD_REAL, DRAIN_*, ARM        */
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;  /* BLOCKER_TOKEN private marker    */

/* ---- roles ---- */
const bit<8> ROLE_BLOCKER = 1;
const bit<8> ROLE_HELD    = 2;
const bit<8> ROLE_DRAIN_M = 3;
const bit<8> ROLE_DRAIN_U = 4;
const bit<8> ROLE_ARM     = 6;

/* ---- ports (finalized at config time; MEASURED before any silicon run) ----
 * PORT_L is the internal loopback (MAC-near loopback on a spare physical port,
 * or the pipe recirc port). PORT_VISION/PORT_HULK are the protected host ports.
 * Values here are compile placeholders; the control plane and run harness pin
 * the measured dev_ports. */
const bit<9> PORT_L      = 9w8;   /* PHYSICAL MAC-near loopback variant (dp8).
                                   * Tests whether a real egress port's strict
                                   * priority absolutely starves Q_HOLD, unlike the
                                   * recirc port (result #1). Config puts dp8 in
                                   * BF_LPBK_MAC_NEAR; pg_id=2, pg_port_nr=0.       */
const bit<9> PORT_VISION = 9w9;   /* master-facing, direction dp9 (MEASURE first) */
const bit<9> PORT_HULK   = 9w11;  /* outstation-facing, direction dp11 (MEASURE)  */

/* ---- queues on PORT_L ---- */
const bit<5> QID_BLOCK = 5w7;   /* HIGH strict priority (set in control plane)  */
const bit<5> QID_HOLD  = 5w1;   /* LOW  strict priority                          */

const int NUM_SLOTS = 4;        /* first prototype uses fixed slot 0             */

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
}

struct ig_meta_t {
    bit<2> slot;        /* index into the NUM_SLOTS=4 state arrays (simple index) */
    bit<1> is_arm;      /* drives the predicated write inside gen_access          */
    bit<1> drain_write; /* drives the predicated write inside drain_access        */
    bit<8> drain_val;   /* value to write when drain_write==1                     */
}

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.slot = 0;
        meta.is_arm = 0;
        meta.drain_write = 0;
        meta.drain_val = 0;
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

    /* per-slot state (index type bit<2> matches NUM_SLOTS=4).
     * Each register is touched by exactly ONE RegisterAction, executed at most
     * once per packet, with a predicated write — so all state accesses collapse
     * to one stateful table per register (Tofino placement requirement). */
    Register<bit<8>, bit<2>>(NUM_SLOTS, 0) reg_drain;
    Register<bit<8>, bit<2>>(NUM_SLOTS, 0) reg_gen;

    /* reg_gen: returns the stored generation; ARM writes the new generation. */
    RegisterAction<bit<8>, bit<2>, bit<8>>(reg_gen) gen_access = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.is_arm == 1w1) { v = hdr.ib.gen; }
        }
    };
    /* reg_drain: returns the pre-value; DRAIN_M(gen ok) writes 1, ARM writes 0. */
    RegisterAction<bit<8>, bit<2>, bit<8>>(reg_drain) drain_access = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.drain_write == 1w1) { v = meta.drain_val; }
        }
    };

    /* per-slot event counters (packets) */
    Counter<bit<64>, bit<2>>(NUM_SLOTS, CounterType_t.PACKETS) ctr_blk_loop;
    Counter<bit<64>, bit<2>>(NUM_SLOTS, CounterType_t.PACKETS) ctr_blk_drop;
    Counter<bit<64>, bit<2>>(NUM_SLOTS, CounterType_t.PACKETS) ctr_held_enq;   /* all hold-routings; value - injections = empty-gap events */
    Counter<bit<64>, bit<2>>(NUM_SLOTS, CounterType_t.PACKETS) ctr_held_release;
    Counter<bit<64>, bit<2>>(NUM_SLOTS, CounterType_t.PACKETS) ctr_drain_match;
    Counter<bit<64>, bit<2>>(NUM_SLOTS, CounterType_t.PACKETS) ctr_drain_badgen;
    Counter<bit<64>, bit<2>>(NUM_SLOTS, CounterType_t.PACKETS) ctr_drain_unrel;
    Counter<bit<64>, bit<2>>(NUM_SLOTS, CounterType_t.PACKETS) ctr_arm;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS)         ctr_nonibspg;

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
    action release_to(bit<9> p) {
        ig_tm_md.ucast_egress_port = p;
        ig_tm_md.bypass_egress = 1w1;
    }
    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    apply {
        if (!hdr.ib.isValid()) {
            /* non-IBSPG background traffic: isolate the microbench, drop it */
            ctr_nonibspg.count(0);
            drop_pkt();
            return;
        }

        /* slot index: low 2 bits of the slot field (simple slice; NUM_SLOTS=4).
         * The first prototype drives fixed slot 0. */
        meta.slot = hdr.ib.slot[1:0];
        bit<2> s = meta.slot;

        /* role predicates */
        bool is_blocker    = (hdr.eth.etype == ETHERTYPE_IBSPG_TOKEN) && (hdr.ib.role == ROLE_BLOCKER);
        bool is_held       = (hdr.eth.etype == ETHERTYPE_IBSPG_REAL)  && (hdr.ib.role == ROLE_HELD);
        bool is_drain_m    = (hdr.eth.etype == ETHERTYPE_IBSPG_REAL)  && (hdr.ib.role == ROLE_DRAIN_M);
        bool is_drain_u    = (hdr.eth.etype == ETHERTYPE_IBSPG_REAL)  && (hdr.ib.role == ROLE_DRAIN_U);
        bool is_arm        = (hdr.eth.etype == ETHERTYPE_IBSPG_REAL)  && (hdr.ib.role == ROLE_ARM);

        /* Stage 1: read/arm generation (one stateful table). */
        meta.is_arm = 1w0;
        if (is_arm) { meta.is_arm = 1w1; }
        bit<8> cur_gen = gen_access.execute(s);
        bool gen_ok = (cur_gen == hdr.ib.gen);

        /* Stage 2: decide the drain write, then read-modify-write drain (one table). */
        meta.drain_write = 1w0;
        meta.drain_val   = 8w0;
        if (is_drain_m && gen_ok) { meta.drain_write = 1w1; meta.drain_val = 8w1; }
        else if (is_arm)          { meta.drain_write = 1w1; meta.drain_val = 8w0; }
        bit<8> d = drain_access.execute(s);   /* pre-drain value */

        /* Stage 3: route + count (mutually exclusive by role). */
        if (is_blocker) {
            if (d == 8w1) { drop_pkt(); ctr_blk_drop.count(s); }   /* ring dies after drain */
            else          { to_block(); ctr_blk_loop.count(s); }   /* keep ring alive       */
        }
        else if (is_held) {
            /* Route purely by the drain bit: drain=0 -> hold (fresh OR looped re-hold);
             * drain=1 -> release. Premature escape is impossible (release is drain-gated).
             * ctr_held_enq counts EVERY hold-routing, so (ctr_held_enq - injected) = the
             * number of empty-gap loop events; == injected means true zero-pass residency. */
            if (d == 8w1) { release_to(PORT_VISION); ctr_held_release.count(s); }
            else          { to_hold();               ctr_held_enq.count(s); }
        }
        else if (is_drain_m) {
            if (gen_ok) { ctr_drain_match.count(s); } else { ctr_drain_badgen.count(s); }
            drop_pkt();
        }
        else if (is_drain_u) {
            ctr_drain_unrel.count(s);                              /* never sets reg_drain  */
            drop_pkt();
        }
        else if (is_arm) {
            ctr_arm.count(s);
            drop_pkt();
        }
        else { drop_pkt(); }
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

/* ============================ egress (pass-through) ===================== */
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

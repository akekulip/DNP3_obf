/*******************************************************************************
 * queue_microbench.p4  —  Phase-4 joint size-and-time TM microbenchmark
 *
 * PURPOSE (review artifact only — NOT the DNP3 defense program):
 *   A minimal, SELF-CONTAINED Tofino-1 (TNA) program to measure whether a
 *   size-labelled Traffic-Manager queue + scheduler can, for a LOW-RATE (~5 Hz)
 *   sparse flow, (a) release packets on a required TIMING (interval tau / rate R)
 *   and (b) preserve a required SIZE-STATE ORDER  P = [S0, S1, ... , S(L-1)].
 *   It is SEPARATE from and does NOT modify the frozen dcrn_defense1/2.p4.
 *
 * SEMANTIC LOCK (Dr. Lin 2026-07-21):
 *   - The obfuscation "pattern" is an ORDERED SIZE-STATE LIST  P = [S0..S(L-1)];
 *     each state is a TARGET PACKET SIZE. This is realized by the `size_pattern`
 *     table (index i -> target state S_i).
 *   - The TM does NOT set sizes. It enforces the ORDER of states (queue
 *     assignment + priority + round-robin) and the TRANSMISSION TIMING, where
 *     TIMING is a single scheduler INTERVAL tau (pktgen period) OR RATE R
 *     (TM shaper) -- NOT a per-slot timing-valued pattern.
 *   - Mechanism under test = ( P = [S0..S(L-1)] , tau or R ).
 *
 * PER-PACKET ALGORITHM (Dr. Lin steps 1-8), realized here:
 *   (1) select next eligible size state    -> `size_pattern` advanced per tau tick
 *   (2) preserve if it already fits         -> classify action pad = PAD_NONE
 *   (3) pad if smaller                      -> classify action pad = PAD_Sx (deparser
 *                                              emits a COMPILE-TIME-CONSTANT filler)
 *   (4) split across states                 -> Tofino-1 has NO verified transparent
 *                                              splitting => NOT implemented on-switch.
 *                                              Host pre-splits; each component enters
 *                                              as an ordinary per-state packet.
 *   (5) else wait for a large-enough state OR fail open -> global oversize guard =>
 *                                              fail open (forward unchanged).
 *   (6) place into the REAL (high-priority) queue for that state.
 *   (7) a per-state CHAFF (low-priority) queue preserves empty pattern states so
 *       round-robin never skips a state (metronome mode: the tick IS the chaff).
 *   (8) the TM scheduler determines the state's output time.
 *
 * TWO RELEASE MECHANISMS compared (GridCloak lesson: the TM PPS shaper STARVES
 * below ~1200 pps, so it may not pace a ~5 Hz flow):
 *   - MECH_PKTGEN : a pktgen PERIODIC app on dp68 is the metronome (period = tau).
 *                   Reals are recirc-HELD on dp68 and released one per tau tick in
 *                   size-pattern order (reuses GridCloak Mechanism-C machinery).
 *   - MECH_SHAPER : reals go straight to a per-state TM queue paced by a rate R
 *                   (`tf1.tm.queue.sched_shaping`); chaff fills the low-pri queue.
 *
 * TWO CONFIG MODES (selected purely by the control plane, no recompile):
 *   - v1  (PRIMARY): EQUAL-sized packets, |P| = 1 (pat_mask = 0), padding OFF.
 *                    Isolates TM timing: does tau/R pace a sparse equal-sized flow?
 *   - final:        multiple size-labelled states (|P| >= 2), padding ON, real+chaff
 *                    queue pair per state -> verify size ORDER *and* timing together.
 *
 * Target: Tofino 1 (TNA), bf-p4c (local 9.13.1 fit-check; switch 9.13.2 authoritative).
 * All constraint-class workarounds (tofino-p4 skill) applied preemptively; see notes
 * at each site. Ports/qids chosen to NOT collide with GridCloak (belt-and-suspenders;
 * this program REPLACES gridcloak via a gated bf_switchd swap, never co-resides).
 ******************************************************************************/

#include <core.p4>
#include <tna.p4>

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_MB    = 0x88B6;   // internal encap (GridCloak uses 0x88B5)

const bit<8>  IP_PROTO_UDP    = 17;

// Test classification field = UDP destination port (plan: "UDP dport / DSCP / ethertype").
const bit<16> DPORT_ACK_S1     = 20001;   // small "ACK"      -> state S1, pad up
const bit<16> DPORT_RESP_S2    = 20002;   // small "response" -> state S2, pad up
const bit<16> DPORT_SPLIT_S1   = 20003;   // host-pre-split component -> state S1
const bit<16> DPORT_SPLIT_S2   = 20004;   // host-pre-split component -> state S2
const bit<16> DPORT_PRE_S1     = 20005;   // already S1-sized -> preserve (no pad)
const bit<16> DPORT_PRE_S2     = 20006;   // already S2-sized -> preserve (no pad)
// any other dport / non-UDP -> fail open (transparent forward)

// Ports (authoritative testbed map): dp9 = Hulk (generator), dp8 = Vision (OBSERVE
// tap / egress-measure), dp68 = pipe-0 internal recirculation (no cable).
const PortId_t PORT_HULK    = 9w9;
const PortId_t PORT_OBSERVE = 9w8;    // Vision: capture shaped output here
const PortId_t PORT_RECIRC  = 9w68;   // metronome hold-loop + pktgen source

// Size states (bit<8>, Class-3: no sub-byte flags).
const bit<8> S_NONE = 8w0;
const bit<8> S1     = 8w1;
const bit<8> S2     = 8w2;

// Roles (for ACK-before-response ordering + observability).
const bit<8> ROLE_NONE     = 8w0;
const bit<8> ROLE_ACK      = 8w1;
const bit<8> ROLE_RESP     = 8w2;
const bit<8> ROLE_SPLIT    = 8w3;
const bit<8> ROLE_PRESERVE = 8w4;

// Padding selector (Class-3: bit<8>).
const bit<8> PAD_NONE = 8w0;
const bit<8> PAD_S1   = 8w1;
const bit<8> PAD_S2   = 8w2;

// Release mechanism (controller-seeded register; Class-8: seed from controller).
const bit<8> MECH_PKTGEN = 8w0;   // metronome (recirc-hold + pktgen tick)
const bit<8> MECH_SHAPER = 8w1;   // TM per-state rate shaper

// recirc-hold seq machine (metronome mode).
const bit<8> SEQ_ENTER = 8w0;   // just encap'd from host  -> register pending, hold
const bit<8> SEQ_HELD  = 8w1;   // held & looping          -> release on its pattern slot

// mb.is_tick frame subtype (set by the pktgen template / by encap).
const bit<8> MB_REAL  = 8w0;    // a real host frame held on the recirc loop
const bit<8> MB_METRO = 8w1;    // metronome slot-clock tick (metronome mode only)
const bit<8> MB_CHAFF = 8w2;    // per-state chaff frame (shaper mode only)

// TM queues. Real = HIGH priority, chaff = LOW priority, per state (step 6/7).
// Real+chaff queues live on the OBSERVE egress port (dp8) where scheduling +
// measurement happen. QID_HOLD is the recirc hold-loop cap queue on dp68.
// (GridCloak uses qid 0/3/5 on dp68; we use disjoint numbers.)
const bit<5> QID_REAL_S1  = 5w1;
const bit<5> QID_CHAFF_S1 = 5w2;
const bit<5> QID_REAL_S2  = 5w3;
const bit<5> QID_CHAFF_S2 = 5w4;
const bit<5> QID_HOLD     = 5w6;   // dp68 recirc hold-loop (metronome mode)

// Compile-time-constant filler sizes (Tofino-feasible size knob).
// v1/final generator sends a fixed BASE frame of 64 B on the wire
// (14 eth + 20 ipv4 + 8 udp + 22 payload). Targets: S1 = 128 B, S2 = 256 B.
//   pad_s1 = 128 - 64 =  64 B = 512 bits
//   pad_s2 = 256 - 64 = 192 B = 1536 bits
// The filler is emitted AFTER the UDP header and BEFORE the residual body, so the
// delivered frame stays a well-formed Eth/IPv4/UDP frame with trailing filler
// bytes reaching the target wire size. NO ipv4/udp length or checksum edit is
// needed (Class-6 end-around-carry avoided entirely) -- the microbench measures
// wire size + timing, not payload semantics. The real DNP3 size-normalizer's
// seq/checksum translation is a SEPARATE, out-of-scope concern.
const MirrorId_t MIRROR_SID = 10w2;   // optional measurement tap (GridCloak uses 1)

/*==============================================================================
 * HEADERS
 *============================================================================*/

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

// Internal encap carried while a real frame recirc-holds (metronome mode). Sits
// between Ethernet and IPv4; stripped on release so the delivered frame is clean.
header mb_h {
    bit<8>  is_tick;          // TICK_YES (pktgen chaff/metronome) | TICK_NO (real)
    bit<8>  state;            // S1 | S2
    bit<8>  role;             // ROLE_*
    bit<8>  seq;              // SEQ_ENTER | SEQ_HELD
    bit<16> orig_ethertype;   // restored on release
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

// Compile-time-constant fillers (at most one valid per packet).
header pad_s1_h { bit<512>  f; }   // 64 B  -> base 64 -> 128
header pad_s2_h { bit<1536> f; }   // 192 B -> base 64 -> 256

/*==============================================================================
 * STRUCTS
 *============================================================================*/

struct metadata_t {
    bit<8>     is_mb;        // 1 = a classified microbench packet, 0 = fail-open
    bit<8>     state;        // assigned size state
    bit<8>     role;         // ROLE_*
    bit<8>     pad_sel;      // PAD_*
    bit<8>     oversize;     // 1 = larger than the biggest state -> fail open
    bit<8>     slot;         // free-running pattern-slot counter (tick path)
    bit<8>     pat_lo;       // slot mod |P| = pattern index into pat_state
    bit<8>     slot_state;   // target size state for this slot (from pat_state = P)
    bit<8>     slot_pad;     // chaff pad selector for this slot (PAD_NONE in v1)
    MirrorId_t mir;          // optional tap session (0 = off)
}

struct egress_metadata_t { bit<8> _unused; }

struct headers_t {
    ethernet_h ethernet;
    mb_h       mb;
    ipv4_h     ipv4;
    udp_h      udp;
    pad_s2_h   pad_s2;   // emitted after UDP, before residual body
    pad_s1_h   pad_s1;
}

struct egress_headers_t { ethernet_h ethernet; }

/*==============================================================================
 * INGRESS PARSER
 *============================================================================*/

parser IngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.is_mb      = 0;
        meta.state      = S_NONE;
        meta.role       = ROLE_NONE;
        meta.pad_sel    = PAD_NONE;
        meta.oversize   = 0;
        meta.slot       = 0;
        meta.pat_lo     = 0;
        meta.slot_state = S1;
        meta.slot_pad   = PAD_NONE;
        meta.mir        = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_MB   : parse_mb;      // recirc frame: tick or held real
            ETHERTYPE_IPV4 : parse_ipv4;    // host frame
            default        : accept;        // fail open
        }
    }

    // On a recirc pass we parse ONLY eth+mb; ipv4/udp/pad ride in the body.
    state parse_mb {
        pkt.extract(hdr.mb);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            4w5    : parse_l4;
            default: accept;
        }
    }
    state parse_l4 {
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP : parse_udp;
            default      : accept;         // non-UDP -> fail open
        }
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

/*==============================================================================
 * INGRESS CONTROL
 *============================================================================*/

control Ingress(
        inout headers_t hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action drop() { ig_dprsr_md.drop_ctl = 1; }

    /* ---- observability counters (count at a SINGLE site each; GridCloak B4) ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_encap;      // host -> recirc hold
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_grad;       // real released
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_tick;       // metronome cover emitted
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_shaper;     // shaper-path real emitted
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_chaff;      // shaper-path chaff emitted
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_failopen;   // unrecognized class -> forward
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_oversize;   // too big for any state -> forward

    /* ---- controller-seeded config registers (Class-8: seed from controller) ----
     * mech_reg is read ONLY on the host path (metronome-encap vs shaper-queue).
     * Reals recirc-hold only in metronome mode; tick subtype (MB_METRO/MB_CHAFF)
     * already encodes the mechanism for pktgen frames, so mech is NOT read on the
     * recirc/tick critical paths (keeps the arm/release registers shallow enough
     * to co-locate -- the register/table placement lesson). */
    Register<bit<8>, bit<1>>(1) mech_reg;      // MECH_PKTGEN | MECH_SHAPER
    RegisterAction<bit<8>, bit<1>, bit<8>>(mech_reg) mech_read = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; } };

    /* ---- size-pattern P = [S0..S(L-1)] realized as a control-plane TABLE (pat_state,
     * below) keyed on a free-running slot counter. This table literally IS the ordered
     * size-state list (the locked Dr. Lin semantics), so the mode is chosen purely by
     * what the control plane installs, with no recompile:
     *    v1    : every slot -> S1                (equal-sized: isolate TM timing)
     *    final : S1,S2,S1,S2,... (or any P)      (verify size ORDER + timing)
     * `advance_pat` free-runs once per pktgen tick; meta.pat_lo = slot mod |P| indexes
     * pat_state. The tick gateway then tests ONE field (meta.slot_state == S1). An
     * earlier `sb = t[0] & altbit` form put a runtime AND-of-two-PHV-bits inside the
     * gateway -> bf-p4c "condition too complex" (Class-1 gateway restriction); the
     * table removes both the extra register and the illegal gateway. Timing is tau
     * (pktgen period) or R (shaper rate); this table is only the size ORDER. */
    Register<bit<8>, bit<1>>(1) pat_idx_reg;
    RegisterAction<bit<8>, bit<1>, bit<8>>(pat_idx_reg) advance_pat = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 1; rv = v; } };

    /* ---- per-state balanced arm/release counters (GridCloak G6) ----
     * RegisterAction needs a CONSTANT index -> one 1-entry register per state,
     * not one register indexed by state at runtime. pend++ on ENTER; the tau
     * tick pend-- (peeks a pending real) and rel++ ; the held real rel-- to
     * graduate. Balanced counters, NOT saturating flags (the flag bug that
     * stranded a held frame during a 3-in-flight burst). */
    Register<bit<8>, bit<1>>(1) pendS1_reg;
    Register<bit<8>, bit<1>>(1) pendS2_reg;
    Register<bit<8>, bit<1>>(1) relS1_reg;
    Register<bit<8>, bit<1>>(1) relS2_reg;
    RegisterAction<bit<8>, bit<1>, bit<8>>(pendS1_reg) pendS1_add = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 1; rv = 0; } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(pendS2_reg) pendS2_add = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 1; rv = 0; } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(pendS1_reg) pendS1_take = {
        void apply(inout bit<8> v, out bit<8> rv) { if (v > 0) { rv = 1; v = v - 1; } else { rv = 0; } } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(pendS2_reg) pendS2_take = {
        void apply(inout bit<8> v, out bit<8> rv) { if (v > 0) { rv = 1; v = v - 1; } else { rv = 0; } } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(relS1_reg) relS1_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 1; rv = 0; } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(relS2_reg) relS2_set = {
        void apply(inout bit<8> v, out bit<8> rv) { v = v + 1; rv = 0; } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(relS1_reg) relS1_take = {
        void apply(inout bit<8> v, out bit<8> rv) { if (v > 0) { rv = 1; v = v - 1; } else { rv = 0; } } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(relS2_reg) relS2_take = {
        void apply(inout bit<8> v, out bit<8> rv) { if (v > 0) { rv = 1; v = v - 1; } else { rv = 0; } } };

    /* ACK-before-response ordering is a MEASURED property of the microbench, not
     * an enforced token here: the size-pattern places the ACK's state slot before
     * the response's, and the analyzer verifies the emitted order. (The hard
     * zero-inversion token from dcrn_defense1 is deliberately omitted so the queue
     * behavior is isolated; adding it back is a known, separate stage cost.) */

    /* ---- classification: UDP dport -> (state, role, pad) mark ----
     * Exact match (cheap; no gateway magnitude compare -> Class-1 safe). */
    action mb_mark(bit<8> st, bit<8> role, bit<8> pad) {
        meta.is_mb = 1; meta.state = st; meta.role = role; meta.pad_sel = pad;
    }
    action mb_none() { meta.is_mb = 0; }
    table mb_classify {
        key     = { hdr.udp.dst_port : exact; }
        actions = { mb_mark; mb_none; }
        const entries = {
            DPORT_ACK_S1   : mb_mark(S1, ROLE_ACK,      PAD_S1);
            DPORT_RESP_S2  : mb_mark(S2, ROLE_RESP,     PAD_S2);
            DPORT_SPLIT_S1 : mb_mark(S1, ROLE_SPLIT,    PAD_S1);
            DPORT_SPLIT_S2 : mb_mark(S2, ROLE_SPLIT,    PAD_S2);
            DPORT_PRE_S1   : mb_mark(S1, ROLE_PRESERVE, PAD_NONE);
            DPORT_PRE_S2   : mb_mark(S2, ROLE_PRESERVE, PAD_NONE);
        }
        const default_action = mb_none();
        size = 8;
    }

    /* ---- step (5) global oversize guard: larger than the biggest state (S2) can
     * never be padded to fit and Tofino has no verified split -> fail open.
     * Range-match on the 16-bit total_len (<= 20-bit key -> Class-2 safe; no
     * gateway magnitude compare -> Class-1 safe). Threshold = S2 payload budget. */
    action set_oversize() { meta.oversize = 1; }
    action set_fits()     { meta.oversize = 0; }
    table oversize_guard {
        key     = { hdr.ipv4.total_len : range; }
        actions = { set_oversize; set_fits; }
        const entries = {
            (16w0 .. 16w242) : set_fits();      // <= 256 B wire (14+ ... ) fits S2
        }
        const default_action = set_oversize();   // > S2 budget: fail open
        size = 2;
    }

    /* ---- pattern lookup P = [S0..S(L-1)]: slot index -> target size state.
     * Keyed on meta.pat_lo = slot mod |P| (masked to the low 3 bits => |P| up to 8).
     * The control plane installs the ordered list (v1: all S1; final: S1,S2,...),
     * so switching mode is a table-entry change, not a recompile. */
    action set_slot_state(bit<8> st, bit<8> chaff_pad) {
        meta.slot_state = st; meta.slot_pad = chaff_pad;
    }
    table pat_state {
        key     = { meta.pat_lo : exact; }
        actions = { set_slot_state; }
        // safe default: single state, no chaff pad (v1 equal-sized behaviour)
        const default_action = set_slot_state(S1, PAD_NONE);
        size = 8;
    }

    /* ---------------------------------------------------------------- helpers
     * P4 actions must be straight-line (no `if`), so queue selection by state is
     * done with an if in `apply` around a parameterless assignment. recirc_hold
     * has no branch so it stays an action. */
    action recirc_hold() {
        ig_tm_md.ucast_egress_port = PORT_RECIRC;
        ig_tm_md.qid = QID_HOLD;
    }

    /* PLACEMENT NOTE (why one if/else tree, no early `return`):
     * an earlier version used nested `if { ... return; }` per frame type. Each
     * `return` forces a `hasReturned` predicate that SERIALIZES the (runtime
     * mutually-exclusive) frame-type branches into one long dependency chain, so
     * pendS1_add landed ~12 stages away from pendS1_take and a single-stage
     * register could not span both -> "Table placement was not able to allocate
     * ... along with Register pendS1_reg" and an 18-stage blow-up. The fix is
     * exactly dcrn.p4's (17-deep chain > 12 stages): flatten to a single
     * if / else-if / else tree with NO early returns, so bf-p4c knows the branches
     * are exclusive and OVERLAPS them (each register then places in one stage with
     * its shallow access delayed to meet its deep access). See memory: register/
     * table placement fit, fixes #5 (equalize access depth) + #6 (flatten). */
    apply {
        if (!hdr.ethernet.isValid()) {
            drop();
        }
        /* ============================================================
         * A) RECIRC / PKTGEN frames (mb encap present)
         * ============================================================ */
        else if (hdr.mb.isValid()) {

            if (hdr.mb.is_tick == MB_CHAFF) {
                /* shaper-mode per-state chaff: fill the low-priority queue so an
                 * empty pattern state is never skipped (step 7). No recirc. */
                ig_tm_md.ucast_egress_port = PORT_OBSERVE;
                if (hdr.mb.state == S1) { ig_tm_md.qid = QID_CHAFF_S1; }
                else                    { ig_tm_md.qid = QID_CHAFF_S2; }
                ctr_chaff.count(0);
            }
            else if (hdr.mb.is_tick == MB_METRO) {
                /* --- tau tick: advance P, arm the slot's state or emit cover ---
                 * If a real of this slot's state is pending, arm its release and
                 * DROP this tick (the real graduates into the slot); else the tick
                 * BECOMES the slot's chaff cover, so the size state stays visible
                 * and cadence tau shows even on an empty state (step 7). Shape
                 * follows gridcloak_c.p4:404-413. */
                meta.slot   = advance_pat.execute(0);      // free-running slot counter
                meta.pat_lo = meta.slot & 8w0x07;          // slot mod |P|  (|P| up to 8)
                pat_state.apply();                         // meta.pat_lo -> meta.slot_state
                bit<8> tok = 0;
                if (meta.slot_state == S1) { tok = pendS1_take.execute(0); }
                else                       { tok = pendS2_take.execute(0); }
                if (tok == 1) {
                    // real waiting for this state -> arm its release, drop the tick
                    if (meta.slot_state == S1) { relS1_set.execute(0); }
                    else                       { relS2_set.execute(0); }
                    drop();
                } else {
                    // empty slot -> tick becomes the slot's chaff cover, padded to
                    // the slot's TARGET size so the size pattern is visible on cover
                    // frames too (PAD_NONE in v1 = equal-sized: pure timing test).
                    if (meta.slot_pad == PAD_S1)      { hdr.pad_s1.setValid(); hdr.pad_s1.f = 0; }
                    else if (meta.slot_pad == PAD_S2) { hdr.pad_s2.setValid(); hdr.pad_s2.f = 0; }
                    ig_tm_md.ucast_egress_port = PORT_OBSERVE;
                    if (meta.slot_state == S1) { hdr.mb.state = S1; ig_tm_md.qid = QID_CHAFF_S1; }
                    else                       { hdr.mb.state = S2; ig_tm_md.qid = QID_CHAFF_S2; }
                    ctr_tick.count(0);
                }
            }
            else if (hdr.mb.seq == SEQ_ENTER) {
                /* MB_REAL just encap'd, first recirc pass: register pending, hold.
                 * (No ctr here -- encap is counted once at its host-path site to
                 * avoid the GridCloak B4 double-count.) */
                if (hdr.mb.state == S1) { pendS1_add.execute(0); }
                else                    { pendS2_add.execute(0); }
                hdr.mb.seq = SEQ_HELD;
                recirc_hold();
            }
            else {
                /* MB_REAL SEQ_HELD: release when this state's slot has been armed.
                 * Read mb fields into locals BEFORE setInvalid. */
                bit<8>  st  = hdr.mb.state;
                bit<16> oet = hdr.mb.orig_ethertype;
                bit<8>  rel = 0;
                if (st == S1) { rel = relS1_take.execute(0); }
                else          { rel = relS2_take.execute(0); }
                if (rel == 1) {
                    // graduate: strip encap, restore ethertype, deliver to the
                    // state's REAL (high-priority) queue on OBSERVE (step 6).
                    hdr.ethernet.ether_type = oet;
                    hdr.mb.setInvalid();
                    ig_tm_md.ucast_egress_port = PORT_OBSERVE;
                    if (st == S1) { ig_tm_md.qid = QID_REAL_S1; }
                    else          { ig_tm_md.qid = QID_REAL_S2; }
                    ctr_grad.count(0);
                } else {
                    recirc_hold();    // keep looping
                }
            }
        }
        /* ============================================================
         * B) HOST frames (dp9 / dp8): classify -> transform -> queue
         * ============================================================ */
        else {
            bit<8> mech = mech_read.execute(0);   // MECH_PKTGEN | MECH_SHAPER
            mb_classify.apply();                  // meta.is_mb/state/role/pad_sel

            if (meta.is_mb == 0) {
                // fail open: transparent forward to the peer host, unchanged.
                if (ig_intr_md.ingress_port == PORT_HULK) { ig_tm_md.ucast_egress_port = PORT_OBSERVE; }
                else                                      { ig_tm_md.ucast_egress_port = PORT_HULK; }
                ig_tm_md.qid = QID_HOLD;
                ctr_failopen.count(0);
            }
            else {
                // step (5): oversize (bigger than the largest state) -> fail open.
                if (hdr.ipv4.isValid()) { oversize_guard.apply(); }
                if (meta.oversize == 1) {
                    if (ig_intr_md.ingress_port == PORT_HULK) { ig_tm_md.ucast_egress_port = PORT_OBSERVE; }
                    else                                      { ig_tm_md.ucast_egress_port = PORT_HULK; }
                    ig_tm_md.qid = QID_HOLD;
                    ctr_oversize.count(0);
                }
                else {
                    // steps (2)/(3): preserve (PAD_NONE) or pad (const filler).
                    if (meta.pad_sel == PAD_S1)      { hdr.pad_s1.setValid(); hdr.pad_s1.f = 0; }
                    else if (meta.pad_sel == PAD_S2) { hdr.pad_s2.setValid(); hdr.pad_s2.f = 0; }

                    if (mech == MECH_PKTGEN) {
                        // metronome: encap + recirc-hold; released on its pattern slot.
                        hdr.mb.setValid();
                        hdr.mb.is_tick        = MB_REAL;
                        hdr.mb.state          = meta.state;
                        hdr.mb.role           = meta.role;
                        hdr.mb.seq            = SEQ_ENTER;
                        hdr.mb.orig_ethertype = hdr.ethernet.ether_type;
                        hdr.ethernet.ether_type = ETHERTYPE_MB;
                        recirc_hold();
                        ctr_encap.count(0);          // single encap-count site (B4)
                    } else {
                        // shaper: straight to the per-state REAL (high-prio) queue
                        // (step 6); TM rate R paces it (step 8). Ordering across
                        // states is scheduler-determined -> a MEASURED finding.
                        ig_tm_md.ucast_egress_port = PORT_OBSERVE;
                        if (meta.state == S1) { ig_tm_md.qid = QID_REAL_S1; }
                        else                  { ig_tm_md.qid = QID_REAL_S2; }
                        ctr_shaper.count(0);
                    }
                }
            }
        }
    }
}

/*==============================================================================
 * INGRESS DEPARSER
 *============================================================================*/

control IngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Mirror() ig_mirror;

    apply {
        // Optional measurement tap (default OFF). The deparser mirror gate MUST be
        // `mirror_type == constant` (TNA restriction). Ingress never sets
        // ig_dprsr_md.mirror_type here, so this is off by default; set
        // ig_dprsr_md.mirror_type = 3w1 (and meta.mir = MIRROR_SID) in a release
        // branch to clone that frame to the tap session.
        if (ig_dprsr_md.mirror_type == 3w1) { ig_mirror.emit(meta.mir); }

        // Emit order: eth, mb, ipv4, udp, pad(after UDP, before body), then the
        // implicit residual body. Invalid headers emit nothing, so:
        //  - host encap pass: eth+mb+ipv4+udp+pad+body
        //  - recirc pass    : eth+mb+body (ipv4/udp/pad ride in body)
        //  - released real  : eth+ipv4+udp+pad+body (mb stripped)
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.mb);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.pad_s2);
        pkt.emit(hdr.pad_s1);
    }
}

/*==============================================================================
 * EGRESS — pure pass-through (all size/timing logic is ingress + TM).
 *============================================================================*/

parser EgressParser(
        packet_in pkt,
        out egress_headers_t hdr,
        out egress_metadata_t meta,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        meta._unused = 0;
        transition accept;
    }
}

control Egress(
        inout egress_headers_t hdr,
        inout egress_metadata_t meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}

control EgressDeparser(
        packet_out pkt,
        inout egress_headers_t hdr,
        in egress_metadata_t meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { }
}

/*==============================================================================
 * PIPELINE
 *============================================================================*/

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

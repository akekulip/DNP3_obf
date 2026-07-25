/* AUTO-DERIVED from queue_microbench_trace_v1.p4 by size_audit/make_telemoff.py:
 * the SAME size primitive with ALL telemetry removed at compile time
 * (Digest<>, telemetry_enable + run_id registers, digest scratch metadata,
 * ctr_digest_emit).  Answers 'exact resource cost with telemetry OFF'.
 * The classify -> pad -> strip -> queue datapath is untouched. */
/*******************************************************************************
 * queue_microbench_trace_v1.p4  —  Level-1 trace-driven SIZE-normalization
 *
 * PURPOSE (review / microbench artifact — NOT a live defense program):
 *   Map a FINITE set of 13 DNP3-derived input frame sizes to ONE 128 B output
 *   state, on Tofino-1 (TNA), in a single ingress pass. Selected pattern from the
 *   Phase-2 base-corpus study (autonomous_run_20260722/CANDIDATE_SELECTION.md):
 *   pad every frame to 128 B; the 13 observed input sizes and their pad deltas are
 *
 *     input B :  60  62  66  74  76  88  89  91  101 103 108 115 120
 *     delta B :  68  66  62  54  52  40  39  37   27  25  20  13   8   (= 128 - input)
 *
 *   LEVEL 1 (explicit scope): this program accepts SYNTHETIC trace-replay frames
 *   whose size/role/direction/timing are DERIVED FROM REAL CAPTURES and carried as
 *   MEASUREMENT-ONLY labels in a replay/encap header. It does NOT parse or produce
 *   valid live TCP/DNP3. The declared `input_size_class` label is TRUSTED (Level-1);
 *   a Level-2 program would cross-check it against the actual frame length.
 *
 *   It is SEPARATE from, and does NOT modify, the loaded queue_microbench.p4 or the
 *   frozen dcrn_defense1/2.p4. It implements ONLY the SIZE component: no metronome,
 *   no external cover/chaff, no recirculation hold. The normalized frame is released
 *   DIRECTLY through one real high-priority queue. It makes NO timing claim and does
 *   NOT implement Defense 1/2.
 *
 * PER-FRAME ALGORITHM:
 *   (1) classify: replay ethertype present?  no  -> fail open (forward unchanged, ctr)
 *   (2) look up declared input_size_class -> pad delta (13 exact entries).
 *       size not in the 13-set -> fail open (forward unchanged, ctr). Never truncated.
 *   (3) strip the replay header, restore the original ethertype.
 *   (4) pad by `delta` using a FINITE POWER-OF-2 pad-header set {1,2,4,8,16,32,64 B}
 *       selected by the bits of delta -> output = input + delta = 128 B EXACTLY.
 *   (5) release into ONE real high-priority queue (QID_REAL_S1) on the observe port.
 *   (6) emit ONE measurement-only learning digest per released frame, A/B-gated by
 *       telemetry_enable (default 0). The digest CANNOT affect (1)-(5).
 *
 * BYTE ACCOUNTING (stated explicitly; R = replay-header width = 19 B):
 *   Generator sends on the wire:  ethernet(14) | trace_replay(19) | body(input-14).
 *     physical wire size = 14 + 19 + (input - 14) = input + 19.
 *   This program removes exactly the 19 B replay header and adds exactly `delta` B:
 *     output = (input + 19) - 19 + delta = input + (128 - input) = 128 B.  ∀ 13 classes.
 *   Delivered frame on the wire:  ethernet(14) | pad(delta) | body(input-14) = 128 B.
 *   (pad precedes the body: the body is the implicit deparser residual, always last.)
 *
 * Target: Tofino 1 (TNA), bf-p4c (local 9.13.1 fit-check). Constraint-class
 * workarounds (tofino-p4 skill) applied preemptively:
 *   - Class 1 (44-bit gateway): classification is EXACT match on a declared label;
 *     no magnitude compare in any gateway. Pad selection tests single delta BITS.
 *   - Class 3 (byte-align PHV): every flag/label field is bit<8> (or wider), never
 *     a sub-byte field adjacent to a wide register.
 *   - Class 4 (48 B learn quantum): the digest is 26 B < 48 B.
 *   Reuses the validated idioms of queue_microbench.p4: pad-header setValid+zero in
 *   the deparser emit chain, the telemetry_enable A/B gate + run_id_reg + a CONSTANT
 *   digest_type + Digest<> in the IngressDeparser, and the QID_REAL_S1 real queue.
 ******************************************************************************/

#include <core.p4>
#include <tna.p4>

/*==============================================================================
 * CONSTANTS
 *============================================================================*/

// Distinct internal encap ethertype for the trace-replay frame. Chosen to NOT
// collide with GridCloak (0x88B5) or the loaded queue_microbench (0x88B6).
const bit<16> ETHERTYPE_TRACE = 0x88B7;

// Testbed ports (authoritative map; identical convention to queue_microbench.p4):
// dp9 = Hulk (trace generator). dp8 = Vision (observe) is a HAIRPIN to dp9 while
// Vision is down, so Hulk both generates and captures. Off-switch compile only ->
// exact port numbers are not load-bearing here; kept for consistency.
const PortId_t PORT_HULK    = 9w9;
const PortId_t PORT_OBSERVE = 9w9;

// ONE real high-priority queue for the normalized frame (reuse queue_microbench's).
const bit<5> QID_REAL_S1 = 5w1;
const bit<5> QID_FWD     = 5w0;   // default queue for fail-open forwarding

// Single output size state (Class-3: bit<8>). |P| = 1 (one state = 128 B).
const bit<8>  STATE_128   = 8w1;
const bit<16> TARGET_SIZE = 16w128;

// Release reason (single reason in this size microbench).
const bit<8> REL_SIZE_NORM = 8w1;

// AUDIT: per-release learning digest (measurement-only; frames stay byte-clean).

/*==============================================================================
 * HEADERS
 *============================================================================*/

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

// Trace-replay / encap header (R = 19 B). Carries MEASUREMENT-ONLY labels derived
// from real captures. `input_size_class` is the ONLY field that steers the datapath
// (it keys the pad table); the rest are telemetry. Stripped before egress so the
// delivered 128 B frame is clean.
//
// SECURITY NOTE: this cleartext label header is a MICROBENCH-ONLY construct. A real
// deployment must NOT expose device/operation/size labels on the wire — they exist
// here solely so an offline analyzer can correlate the emitted 128 B frame back to
// its source class. No security property is claimed for these labels.
header trace_replay_h {
    bit<16> run_id;             // control-plane run epoch (telemetry)
    bit<32> seq;                // per-frame sequence number (telemetry / correlation)
    bit<8>  device_label;       // source device id           (telemetry)
    bit<8>  operation_label;    // DNP3 operation class        (telemetry)
    bit<8>  direction;          // master->outstation / rev    (telemetry)
    bit<8>  input_size_class;   // DECLARED input size (one of the 13) — DATAPATH KEY
    bit<16> transaction_id;     // DNP3 transaction id         (telemetry)
    bit<8>  ack_mode;           // separate / combined ACK     (telemetry)
    bit<16> orig_ethertype;     // restored on strip -> clean delivered frame
    bit<32> tx_tstamp;          // host tx timestamp (low 32b) (telemetry)
}

// Finite POWER-OF-2 pad-header set. Bit i of `delta` selects the 2^i-byte header,
// so a valid subset sums to any delta in {8..68}. At most 7 valid at once.
header pad1_h  { bit<8>    f; }   //  1 B  (delta bit 0)
header pad2_h  { bit<16>   f; }   //  2 B  (delta bit 1)
header pad4_h  { bit<32>   f; }   //  4 B  (delta bit 2)
header pad8_h  { bit<64>   f; }   //  8 B  (delta bit 3)
header pad16_h { bit<128>  f; }   // 16 B  (delta bit 4)
header pad32_h { bit<256>  f; }   // 32 B  (delta bit 5)
header pad64_h { bit<512>  f; }   // 64 B  (delta bit 6)

/*==============================================================================
 * STRUCTS
 *============================================================================*/

struct metadata_t {
    bit<8>  is_trace;    // 1 = recognized replay frame (parser-set)
    bit<8>  supported;   // 1 = input_size_class is one of the 13 (table-set)
}

struct egress_metadata_t { bit<8> _unused; }

struct headers_t {
    ethernet_h     ethernet;
    trace_replay_h trace_replay;
    // pad headers emitted after ethernet, before the residual body:
    pad64_h        pad64;
    pad32_h        pad32;
    pad16_h        pad16;
    pad8_h         pad8;
    pad4_h         pad4;
    pad2_h         pad2;
    pad1_h         pad1;
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
        meta.is_trace  = 0;
        meta.supported = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_TRACE : parse_replay;   // synthetic trace-replay frame
            default         : accept;         // anything else -> fail open
        }
    }

    // Extract ONLY eth + replay header; the DNP3-derived body rides as opaque residual.
    state parse_replay {
        pkt.extract(hdr.trace_replay);
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

    /* ---- observability counters (single count site each; GridCloak B4) ---- */
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_released;     // normalized 128 B frame released
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_failopen;     // not a trace frame -> forwarded unchanged
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_unsupported;  // trace frame, size not in the 13-set -> forwarded



    /* ---- pad table P: declared input_size_class -> pad delta (= 128 - input),
     * realized as the POWER-OF-2 header subset whose widths sum to delta.
     * EXACT match on a declared label (Class-1 safe: no gateway magnitude compare).
     * 13 const entries; default -> unsupported (fail open, never truncate). This table
     * IS the finite input-size -> single-128-state map (the locked Dr. Lin semantics
     * for the SIZE component).
     *
     * WHY COMPILE-TIME DECODE: each of the 13 deltas is decomposed at compile time into
     * its power-of-2 pad headers (delta bit i set  <=>  pad(2^i B) valid), and the WHOLE
     * subset is set valid inside ONE action -> all pads for a class land in the table's
     * single stage. The equivalent RUNTIME form (store delta, then 7 `if (delta[i]) pad`
     * bit-tests) is correct too but serializes into 7 stages (the compiler cannot overlap
     * the 7 independent validity writes); a Level-2 DYNAMIC-delta variant (delta computed
     * from a measured length, not a fixed 13-set) would use that runtime form and pay the
     * stages for genericity. Each action name encodes its delta; the comment shows the
     * exact bit decomposition ("iff bit set in delta"). ---- */
    action pad_none() { meta.supported = 0; }                                     // unsupported size
    action pad_d8()  { meta.supported = 1; hdr.pad8.setValid();  hdr.pad8.f  = 0; }                                                                                       // 8  = 8            (input 120)
    action pad_d13() { meta.supported = 1; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad1.setValid();  hdr.pad1.f  = 0; }         // 13 = 8+4+1        (input 115)
    action pad_d20() { meta.supported = 1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; }                                                // 20 = 16+4         (input 108)
    action pad_d25() { meta.supported = 1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad1.setValid();  hdr.pad1.f  = 0; }         // 25 = 16+8+1       (input 103)
    action pad_d27() { meta.supported = 1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad2.setValid();  hdr.pad2.f  = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; } // 27 = 16+8+2+1 (input 101)
    action pad_d37() { meta.supported = 1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad1.setValid();  hdr.pad1.f  = 0; }         // 37 = 32+4+1       (input 91)
    action pad_d39() { meta.supported = 1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad2.setValid();  hdr.pad2.f  = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; } // 39 = 32+4+2+1 (input 89)
    action pad_d40() { meta.supported = 1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; }                                                // 40 = 32+8         (input 88)
    action pad_d52() { meta.supported = 1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; }         // 52 = 32+16+4      (input 76)
    action pad_d54() { meta.supported = 1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; } // 54 = 32+16+4+2 (input 74)
    action pad_d62() { meta.supported = 1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; } // 62 = 32+16+8+4+2 (input 66)
    action pad_d66() { meta.supported = 1; hdr.pad64.setValid(); hdr.pad64.f = 0; hdr.pad2.setValid();  hdr.pad2.f  = 0; }                                                // 66 = 64+2         (input 62)
    action pad_d68() { meta.supported = 1; hdr.pad64.setValid(); hdr.pad64.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; }                                                // 68 = 64+4         (input 60)
    table size_class_pad {
        key     = { hdr.trace_replay.input_size_class : exact; }
        actions = {
            pad_none; pad_d8; pad_d13; pad_d20; pad_d25; pad_d27; pad_d37;
            pad_d39; pad_d40; pad_d52; pad_d54; pad_d62; pad_d66; pad_d68;
        }
        const entries = {
            8w60  : pad_d68();   // 128 - 60  = 68
            8w62  : pad_d66();   // 128 - 62  = 66
            8w66  : pad_d62();   // 128 - 66  = 62
            8w74  : pad_d54();   // 128 - 74  = 54
            8w76  : pad_d52();   // 128 - 76  = 52
            8w88  : pad_d40();   // 128 - 88  = 40
            8w89  : pad_d39();   // 128 - 89  = 39
            8w91  : pad_d37();   // 128 - 91  = 37
            8w101 : pad_d27();   // 128 - 101 = 27
            8w103 : pad_d25();   // 128 - 103 = 25
            8w108 : pad_d20();   // 128 - 108 = 20
            8w115 : pad_d13();   // 128 - 115 = 13
            8w120 : pad_d8();    // 128 - 120 =  8
        }
        const default_action = pad_none();
        size = 16;
    }

    /* fail-open forward: send the frame to the peer host unchanged (no strip, no pad).
     * PORT_HULK == PORT_OBSERVE (dp9 hairpin) today, so this reduces to a hairpin; the
     * ingress-port test keeps it correct for when Vision (dp8) returns. */
    action forward_unchanged() {
        ig_tm_md.qid = QID_FWD;
    }

    apply {
        if (!hdr.ethernet.isValid()) {
            drop();
        }
        /* ============================================================
         * TRACE-REPLAY frame: classify -> normalize to 128 B -> queue
         * ============================================================ */
        else if (hdr.trace_replay.isValid()) {
            // classify + set the correct power-of-2 pad subset in ONE action:
            size_class_pad.apply();          // meta.supported (+ pad headers on match)

            if (meta.supported == 1) {
                /* ---- RELEASE (transform) — NO telemetry symbols in this block ----
                 * pads are already set by the matched table action; restore the original
                 * ethertype and queue the (now 128 B) frame to the real queue. */
                hdr.ethernet.ether_type = hdr.trace_replay.orig_ethertype;

                ig_tm_md.ucast_egress_port = PORT_OBSERVE;
                ig_tm_md.qid = QID_REAL_S1;
                ctr_released.count(0);


                // strip the replay header LAST (after capture); deparser then omits it.
                hdr.trace_replay.setInvalid();
            }
            else {
                // declared size not one of the 13 -> fail open, forward unchanged.
                if (ig_intr_md.ingress_port == PORT_HULK) { ig_tm_md.ucast_egress_port = PORT_OBSERVE; }
                else                                      { ig_tm_md.ucast_egress_port = PORT_HULK; }
                forward_unchanged();
                ctr_unsupported.count(0);
            }
        }
        /* ============================================================
         * NON-trace frame: fail open, forward unchanged.
         * ============================================================ */
        else {
            if (ig_intr_md.ingress_port == PORT_HULK) { ig_tm_md.ucast_egress_port = PORT_OBSERVE; }
            else                                      { ig_tm_md.ucast_egress_port = PORT_HULK; }
            forward_unchanged();
            ctr_failopen.count(0);
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


    apply {
        // Emit order: ethernet, pad headers (largest->smallest), replay, then the
        // implicit residual body. Invalid headers emit nothing, so:
        //  - released frame : ethernet | valid pads | body           (replay stripped) = 128 B
        //  - fail-open frame: ethernet | trace_replay | body         (no pads valid)    = unchanged
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.pad64);
        pkt.emit(hdr.pad32);
        pkt.emit(hdr.pad16);
        pkt.emit(hdr.pad8);
        pkt.emit(hdr.pad4);
        pkt.emit(hdr.pad2);
        pkt.emit(hdr.pad1);
        pkt.emit(hdr.trace_replay);
    }
}

/*==============================================================================
 * EGRESS — pure pass-through (all size logic is ingress + deparser).
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

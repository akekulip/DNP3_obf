/* ============================================================================
 * p4_size_only.p4 — VARIANT P4 of the stage-reclamation study.
 *
 * ONE ARCHITECTURAL VARIABLE: the validated Level-1 SIZE primitive, ALONE,
 * with NO timing mechanism, expressed in THIS codebase's frame format
 * (ethernet + ibspg_h, exactly the headers ibspg_hold_response.p4 parses).
 *
 * PURPOSE. Establish the standalone ingress cost of "one fixed output size
 * state" in the same compiler run as the P0 timing baseline, so the P4/P5/P6
 * comparison is not a quote from an older report.
 *
 * WHAT IT REPRODUCES from queue_microbench_trace_v1.p4 (the hardware-validated
 * Level-1 program, tag queue-trace-level1-hw-pass):
 *   - ONE target size state (128 B).
 *   - A DECLARED input-size class (here: hdr.ib.slot, a trusted label) that
 *     exact-matches a 13-entry const table.
 *   - COMPILE-TIME power-of-2 pad decode: each matched action sets the whole
 *     pad-header subset valid inside ONE action, so all pads for a class land
 *     in that table's single stage.  (The runtime `if (delta[i])` bit-test form
 *     serializes into 7 stages — see SIZE_PRIMITIVE_REUSE_AUDIT.md §6.)
 *   - Fail open: an unrecognised class is forwarded unchanged, never truncated.
 *
 * WHAT IT DELIBERATELY OMITS vs trace_v1 (this is the telemetry-OFF shape):
 *   no Digest<>, no telemetry_enable / run_id registers, no digest scratch
 *   metadata, no ctr_digest_emit.  Those are measurement scaffolding, not the
 *   primitive.
 *
 * SCOPE HONESTY.  Like trace_v1 this pads BETWEEN the last parsed header and
 * the unparsed residual.  For the synthetic ibspg/trace frame that is harmless;
 * for a live IPv4/TCP/DNP3 frame it is NOT a valid construction (it lands
 * inside the IP datagram).  See SIZE_PRIMITIVE_REUSE_AUDIT.md §4.
 *
 * Target: Tofino 1 (TNA), bf-p4c 9.13.1.  Compile-only; never loaded.
 * ==========================================================================*/
#include <core.p4>
#include <tna.p4>

/* Same ethertypes / ports / roles as the P0 timing baseline so the frame
 * format is identical across P0/P4/P5/P6. */
const bit<16> ETHERTYPE_IBSPG_REAL  = 0x88C0;
const bit<16> ETHERTYPE_IBSPG_TOKEN = 0x88C1;

const PortId_t PORT_VISION = 9w9;
const PortId_t PORT_HULK   = 9w11;

const bit<5> QID_OUT = 5w0;

/* ONE size state. */
const bit<16> TARGET_SIZE = 16w128;

/* ============================ headers ==================================== */
header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
/* `slot` carries the DECLARED input-size class (Level-1 trusted label). */
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }

/* Finite POWER-OF-2 pad-header set: bit i of delta selects the 2^i-byte header.
 * A valid subset sums to any delta in {8..68}.  At most 7 valid at once. */
header pad1_h  { bit<8>   f; }
header pad2_h  { bit<16>  f; }
header pad4_h  { bit<32>  f; }
header pad8_h  { bit<64>  f; }
header pad16_h { bit<128> f; }
header pad32_h { bit<256> f; }
header pad64_h { bit<512> f; }

struct headers_t {
    ethernet_h eth;
    ibspg_h    ib;
    pad64_h    pad64;
    pad32_h    pad32;
    pad16_h    pad16;
    pad8_h     pad8;
    pad4_h     pad4;
    pad2_h     pad2;
    pad1_h     pad1;
}

struct ig_meta_t {
    bit<8> supported;   /* 1 = declared class is one of the 13 */
}

struct eg_meta_t { }

/* ============================ ingress parser ============================= */
parser IgParser(packet_in pkt,
                out headers_t hdr,
                out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.supported = 8w0;
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

    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_normalized;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_unsupported;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) ctr_failopen;

    action drop_pkt() { ig_dprsr_md.drop_ctl = 3w1; }

    /* --- pad table P: declared class -> compile-time power-of-2 pad subset --- */
    action pad_none() { meta.supported = 8w0; }
    action pad_d8()  { meta.supported = 8w1; hdr.pad8.setValid();  hdr.pad8.f  = 0; }
    action pad_d13() { meta.supported = 8w1; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d20() { meta.supported = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; }
    action pad_d25() { meta.supported = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d27() { meta.supported = 8w1; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d37() { meta.supported = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d39() { meta.supported = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; hdr.pad1.setValid(); hdr.pad1.f = 0; }
    action pad_d40() { meta.supported = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad8.setValid();  hdr.pad8.f  = 0; }
    action pad_d52() { meta.supported = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; }
    action pad_d54() { meta.supported = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d62() { meta.supported = 8w1; hdr.pad32.setValid(); hdr.pad32.f = 0; hdr.pad16.setValid(); hdr.pad16.f = 0; hdr.pad8.setValid(); hdr.pad8.f = 0; hdr.pad4.setValid(); hdr.pad4.f = 0; hdr.pad2.setValid(); hdr.pad2.f = 0; }
    action pad_d66() { meta.supported = 8w1; hdr.pad64.setValid(); hdr.pad64.f = 0; hdr.pad2.setValid();  hdr.pad2.f  = 0; }
    action pad_d68() { meta.supported = 8w1; hdr.pad64.setValid(); hdr.pad64.f = 0; hdr.pad4.setValid();  hdr.pad4.f  = 0; }

    table size_class_pad {
        key     = { hdr.ib.slot : exact; }
        actions = { pad_none; pad_d8; pad_d13; pad_d20; pad_d25; pad_d27; pad_d37;
                    pad_d39; pad_d40; pad_d52; pad_d54; pad_d62; pad_d66; pad_d68; }
        const entries = {
            8w60  : pad_d68();   8w62  : pad_d66();   8w66  : pad_d62();
            8w74  : pad_d54();   8w76  : pad_d52();   8w88  : pad_d40();
            8w89  : pad_d39();   8w91  : pad_d37();   8w101 : pad_d27();
            8w103 : pad_d25();   8w108 : pad_d20();   8w115 : pad_d13();
            8w120 : pad_d8();
        }
        const default_action = pad_none();
        size = 16;
    }

    action to_host() {
        ig_tm_md.ucast_egress_port = PORT_VISION;
        ig_tm_md.qid               = QID_OUT;
        ig_tm_md.bypass_egress     = 1w0;
    }
    action to_peer() {
        ig_tm_md.ucast_egress_port = PORT_HULK;
        ig_tm_md.qid               = QID_OUT;
        ig_tm_md.bypass_egress     = 1w0;
    }

    apply {
        if (!hdr.ib.isValid()) {
            /* not an instrumented frame -> fail open, forward unchanged */
            to_peer();
            ctr_failopen.count(0);
        } else {
            size_class_pad.apply();
            if (meta.supported == 8w1) {
                to_host();
                ctr_normalized.count(0);
            } else {
                to_host();
                ctr_unsupported.count(0);
            }
        }
    }
}

/* ============================ ingress deparser ==========================
 * Emit order: eth, pads (largest -> smallest), ib, then the implicit residual.
 * Invalid pad headers emit nothing. */
control IgDeparser(packet_out pkt,
                   inout headers_t hdr,
                   in    ig_meta_t meta,
                   in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.pad64);
        pkt.emit(hdr.pad32);
        pkt.emit(hdr.pad16);
        pkt.emit(hdr.pad8);
        pkt.emit(hdr.pad4);
        pkt.emit(hdr.pad2);
        pkt.emit(hdr.pad1);
        pkt.emit(hdr.ib);
    }
}

/* ============================ egress (pass-through) ===================== */
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
    apply { }
}

Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;

Switch(pipe) main;

/* =============================================================================
 *  probe_retire_dependency.p4 — COMPILE-ONLY PROBE, never loaded on a switch.
 *
 *  PURPOSE (meeting_direction.md 2026-07-29, FALLBACK clause). The preferred
 *  conditional-retirement-on-ACK-release construction does not compile:
 *
 *      error: Table placement cannot make any more progress.  Though some tables
 *      have not yet been placed, dependency analysis has found that no more
 *      tables are placeable.
 *
 *  This probe reduces that to the smallest reproduction and then tests the two
 *  candidate encodings, so the failure is attributed to a STRUCTURE rather than to
 *  something incidental about the Defense 3 program.
 *
 *  THE STRUCTURE. Two registers, accessed in OPPOSITE order on two packet paths:
 *
 *      path RESP     : regTAG (read the generation)  ->  regPEND (write it)
 *      path ACK_REL  : regPEND (read the pending gen) -> regTAG (conditional retire)
 *
 *  Register placement is STATIC — each register lives in exactly one stage — so a
 *  pair with opposite orders on two paths is a genuine cycle no matter that the two
 *  paths are mutually exclusive at run time. The predicates are invisible to
 *  placement.
 *
 *  Build all three:
 *      -DPROBE_CYCLE     the cycle           -> EXPECTED TO FAIL
 *      -DPROBE_ONE_REG   encoding E1: the pending marker lives INSIDE regTAG
 *      -DPROBE_ACK_ONLY  encoding E2: retire on ACK release, RESPONSE writes nothing
 * ============================================================================= */
#include <core.p4>
#include <tna.p4>

header eth_h { bit<48> dst; bit<48> src; bit<16> etype; }
struct hdrs_t { eth_h eth; }
struct meta_t { bit<8> gen; bit<8> pend; bit<8> cls; }

parser IgParser(packet_in pkt, out hdrs_t hdr, out meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.gen = 8w0; meta.pend = 8w0; meta.cls = 8w0;
        pkt.extract(hdr.eth);
        transition accept;
    }
}

control Ingress(inout hdrs_t hdr, inout meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    Register<bit<8>, bit<1>>(1, 0) regTAG;
    RegisterAction<bit<8>, bit<1>, bit<8>>(regTAG) tag_rd = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(regTAG) tag_retire_if = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.pend != 8w0) { v = 8w0; }
        }
    };
#ifdef PROBE_ONE_REG
    /* E1: the pending state lives INSIDE regTAG. The marker is the SIGN BIT, so the
     * predicate is a compare against ZERO and needs no large immediate:
     *     live, no RESPONSE pending : 0xC0..0xCF   (MSB set)
     *     live, RESPONSE pending    : 0x10..0x1F   (MSB clear, never 0x00)
     *     idle                      : 0x00
     * The RESPONSE rewrites the tag in place, so no second register and no cycle. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(regTAG) tag_mark_pending = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            v = v - 8w0xB0;
        }
    };
    RegisterAction<bit<8>, bit<1>, bit<8>>(regTAG) tag_retire_if_unmarked = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (v < 8w0) { v = 8w0; }        /* MSB set => nothing pending => retire */
        }
    };
#endif
#if defined(PROBE_CYCLE) || defined(PROBE_ACK_ONLY)
    Register<bit<8>, bit<1>>(1, 0) regPEND;
    RegisterAction<bit<8>, bit<1>, bit<8>>(regPEND) pend_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen - v;
            if (meta.cls != 8w0) { v = meta.gen; }
        }
    };
#endif

    action set_cls(bit<8> c) { meta.cls = c; }
    table tbl_cls {
        key = { hdr.eth.etype : exact; }
        actions = { set_cls; }
        default_action = set_cls(0);
        size = 8;
    }

    apply {
        tbl_cls.apply();
#ifdef PROBE_CYCLE
        /* path RESP: read the generation, then record it as pending */
        if (meta.cls == 8w1) {
            meta.gen  = tag_rd.execute(0);
            meta.pend = pend_rmw.execute(0);
        }
        /* path ACK_REL: read the pending generation, then retire the tag */
        if (meta.cls == 8w2) {
            meta.gen  = tag_rd.execute(0);
            meta.pend = pend_rmw.execute(0);
            tag_retire_if.execute(0);          /* <-- closes the cycle */
        }
#endif
#ifdef PROBE_ONE_REG
        if (meta.cls == 8w1) { meta.gen = tag_mark_pending.execute(0); }
        if (meta.cls == 8w2) { meta.gen = tag_retire_if_unmarked.execute(0); }
#endif
#ifdef PROBE_ACK_ONLY
        if (meta.cls == 8w1) {
            meta.gen  = tag_rd.execute(0);
            meta.pend = pend_rmw.execute(0);
        }
        if (meta.cls == 8w2) { meta.gen = tag_retire_if.execute(0); }
#endif
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        ig_tm_md.bypass_egress     = 1w1;
    }
}

control IgDeparser(packet_out pkt, inout hdrs_t hdr, in meta_t meta,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr); }
}
parser EgParser(packet_in pkt, out hdrs_t hdr, out meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start { pkt.extract(eg_intr_md); meta.gen = 0; meta.pend = 0; meta.cls = 0;
                  transition accept; }
}
control Egress(inout hdrs_t hdr, inout meta_t meta,
               in    egress_intrinsic_metadata_t eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}
control EgDeparser(packet_out pkt, inout hdrs_t hdr, in meta_t meta,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { pkt.emit(hdr); }
}
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

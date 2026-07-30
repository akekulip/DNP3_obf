/* =============================================================================
 *  probe_salu_immediate.p4 — COMPILE-ONLY PROBE, never loaded on a switch.
 *
 *  PURPOSE (meeting_direction.md 2026-07-29, CHECK 1): F02 was caused by a stateful
 *  ALU predicate comparing against the constant 0xFF, which bf-p4c lowered to
 *  `equ lo, lo, -255` — an immediate that does not fit the field — and the
 *  conditional state write then silently never committed while the SALU's RETURN
 *  value kept working. The direction requires auditing every comparison against a
 *  constant in 0x80..0xFF. Two data points existed (2 works, 255 does not); this
 *  probe finds WHERE the boundary is, so the audit has a rule instead of anecdotes.
 *
 *  Each register carries one predicate `v == K` for a different K. Read the emitted
 *  immediate for each out of pipe/*.bfa:
 *
 *      equ lo, lo          <=>  v == 0                 (no immediate)
 *      equ lo, lo, -K      <=>  v == K                 (immediate holds MINUS K)
 *
 *  A K whose -K is NOT representable is the bug class. Also note whether the
 *  compiler ERRORS, WARNS, or silently emits — silence is what made F02 expensive.
 * ============================================================================= */
#include <core.p4>
#include <tna.p4>

header eth_h { bit<48> dst; bit<48> src; bit<16> etype; }
struct hdrs_t { eth_h eth; }
struct meta_t { bit<8> w8; bit<32> w32; }

parser IgParser(packet_in pkt, out hdrs_t hdr, out meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.w8  = 8w0;
        meta.w32 = 32w0;
        pkt.extract(hdr.eth);
        transition accept;
    }
}

control Ingress(inout hdrs_t hdr, inout meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

/* one 8-bit register + one compare-and-write action per probed constant */
#define PROBE8(NAME, K)                                                        \
    Register<bit<8>, bit<1>>(1, 0) reg_##NAME;                                 \
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_##NAME) act_##NAME = {           \
        void apply(inout bit<8> v, out bit<8> rv) {                            \
            rv = v;                                                            \
            if (v == K) { v = meta.w8; }                                       \
        }                                                                      \
    };

    PROBE8(k001, 8w0x01)
    PROBE8(k002, 8w0x02)
    PROBE8(k007, 8w0x07)
    PROBE8(k008, 8w0x08)
    PROBE8(k00f, 8w0x0F)
    PROBE8(k010, 8w0x10)
    PROBE8(k03f, 8w0x3F)
    PROBE8(k040, 8w0x40)
    PROBE8(k07f, 8w0x7F)
    PROBE8(k080, 8w0x80)
    PROBE8(k0c0, 8w0xC0)
    PROBE8(k0fe, 8w0xFE)
    PROBE8(k0ff, 8w0xFF)

    apply {
        meta.w8 = hdr.eth.etype[7:0];
        /* every probe on its own packet path, so each gets its own SALU instruction */
        if (hdr.eth.etype == 16w0x0001) { meta.w8 = act_k001.execute(0); }
        else if (hdr.eth.etype == 16w0x0002) { meta.w8 = act_k002.execute(0); }
        else if (hdr.eth.etype == 16w0x0007) { meta.w8 = act_k007.execute(0); }
        else if (hdr.eth.etype == 16w0x0008) { meta.w8 = act_k008.execute(0); }
        else if (hdr.eth.etype == 16w0x000F) { meta.w8 = act_k00f.execute(0); }
        else if (hdr.eth.etype == 16w0x0010) { meta.w8 = act_k010.execute(0); }
        else if (hdr.eth.etype == 16w0x003F) { meta.w8 = act_k03f.execute(0); }
        else if (hdr.eth.etype == 16w0x0040) { meta.w8 = act_k040.execute(0); }
        else if (hdr.eth.etype == 16w0x007F) { meta.w8 = act_k07f.execute(0); }
        else if (hdr.eth.etype == 16w0x0080) { meta.w8 = act_k080.execute(0); }
        else if (hdr.eth.etype == 16w0x00C0) { meta.w8 = act_k0c0.execute(0); }
        else if (hdr.eth.etype == 16w0x00FE) { meta.w8 = act_k0fe.execute(0); }
        else if (hdr.eth.etype == 16w0x00FF) { meta.w8 = act_k0ff.execute(0); }
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
    state start { pkt.extract(eg_intr_md); transition accept; }
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

Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;

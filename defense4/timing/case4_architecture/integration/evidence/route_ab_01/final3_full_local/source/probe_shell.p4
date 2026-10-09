#ifndef CASE4_PROBE_SHELL_P4
#define CASE4_PROBE_SHELL_P4
// No target side effects: the shell forwards diagnostic events to ingress port.
parser EmptyEgressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                        out egress_intrinsic_metadata_t eg_intr_md) {
    state start { pkt.extract(eg_intr_md); transition accept; }
}
control EmptyEgress(inout header_t hdr, inout metadata_t md,
                   in egress_intrinsic_metadata_t eg_intr_md,
                   in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
                   inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
                   inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}
control EmptyEgressDeparser(packet_out pkt, inout header_t hdr,
                          in metadata_t md,
                          in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { }
}
#endif

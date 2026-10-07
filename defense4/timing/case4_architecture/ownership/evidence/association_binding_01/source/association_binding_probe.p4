#include <core.p4>
#include <tna.p4>
#include "association_binding.p4"
// Diagnostic offline key-cell probe. INSTALL commands are test setup only;
// final native network admission must satisfy the helper's pin/quiescence API.
header ethernet_t { bit<48> dst; bit<48> src; bit<16> ether_type; }
header command_t { bit<32> epoch; bit<32> cookie; bit<8> operation; bit<8> function; bit<16> reserved; }
header report_t { bit<32> value; bit<8> authorized; bit<8> kind; bit<16> reserved; }
struct header_t { ethernet_t ethernet; command_t command; report_t report; }
struct metadata_t { binding_result_t binding; bit<8> kind; }
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start { pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE); transition ethernet; }
    state ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) { 0x88d4 : command; default : reject; }
    }
    state command { pkt.extract(hdr.command); transition accept; }
}
control Ingress(inout header_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    AssociationBinding() binding;
    AssociationKind() kind;
    apply {
        binding.apply(hdr.command.operation, hdr.command.epoch, hdr.command.cookie, md.binding);
        kind.apply(hdr.command.function, md.kind);
        hdr.report.setValid();
        hdr.report.value = md.binding.value;
        hdr.report.authorized = md.binding.authorized;
        hdr.report.kind = md.kind; hdr.report.reserved = 0;
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port; ig_tm_md.bypass_egress = 1;
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) { apply { pkt.emit(hdr); } }
#include "probe_shell.p4"
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;

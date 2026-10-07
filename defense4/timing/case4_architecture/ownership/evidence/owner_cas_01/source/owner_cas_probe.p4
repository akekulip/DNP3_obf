#include <core.p4>
#include <tna.p4>
#include "owner_cell.p4"
header ethernet_t { bit<48> dst; bit<48> src; bit<16> ether_type; }
header report_t { bit<32> observed; bit<8> accepted; bit<24> reserved; }
struct header_t { ethernet_t ethernet; owner_command_t command; report_t report; }
struct metadata_t { owner_result_t owner; }
parser IngressParser(packet_in pkt, out header_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition ethernet;
    }
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
    OwnerCell() owner;
    apply {
        owner.apply(hdr.command, md.owner);
        hdr.report.setValid();
        hdr.report.observed = md.owner.observed;
        hdr.report.accepted = md.owner.accepted;
        hdr.report.reserved = 0;
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        ig_tm_md.bypass_egress = 1;
    }
}
control IngressDeparser(packet_out pkt, inout header_t hdr, in metadata_t md,
                       in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr); }
}
#include "probe_shell.p4"
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(),
         EmptyEgress(), EmptyEgressDeparser()) pipe;
Switch(pipe) main;

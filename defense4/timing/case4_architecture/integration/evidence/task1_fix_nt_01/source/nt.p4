// Local functional-model fixture ONLY: exact N pipe0 and T pipe2 snapshots.
// Private device ports remain 68 and325/326/327. No M, production or physical qualification.
#include <core.p4>
#include <tna.p4>
#define NATIVE_BINDING_NO_MAIN
#define Ingress NIngress
#include "n/native_binding.p4"
#undef Ingress
#define READ_TIMING_NO_MAIN
#define Ingress TIngress
#include "t/read_timing.p4"
#undef Ingress
struct stub_h{}
struct stub_m{}
parser StubParser(packet_in pkt,out stub_h hdr,out stub_m md,out ingress_intrinsic_metadata_t ig){state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);transition accept;}}
control StubDrop(inout stub_h hdr,inout stub_m md,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t d,inout ingress_intrinsic_metadata_for_tm_t tm){apply{d.drop_ctl=1;}}
control StubDeparser(packet_out pkt,inout stub_h hdr,in stub_m md,in ingress_intrinsic_metadata_for_deparser_t d){apply{}}
Pipeline(IgParser(),NIngress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) p0;
Pipeline(StubParser(),StubDrop(),StubDeparser(),EmptyEgressParser(),EmptyEgress(),EmptyEgressDeparser()) p1;
Pipeline(IngressParser(),TIngress(),IngressDeparser(),EmptyEgressParser(),EmptyEgress(),EmptyEgressDeparser()) p2;
Pipeline(StubParser(),StubDrop(),StubDeparser(),EmptyEgressParser(),EmptyEgress(),EmptyEgressDeparser()) p3;
Switch(p0,p1,p2,p3) main;

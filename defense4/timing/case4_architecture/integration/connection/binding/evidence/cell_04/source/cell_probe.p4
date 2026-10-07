/* Diagnostic input fields, NOT a SYN/SELECT validation or live producer.
 * Determines whether two-PHV full epoch + packed phase transition fits Tofino.
 * No deployment, reset/drain/reuse, timing admission or complete target claim.
 */
#include <core.p4>
#include <tna.p4>
#include "epoch_types.p4"
header diagnostic_h{bit<32> epoch;bit<32> expected;bit<8> operation;bit<32> result;}
struct headers_t{diagnostic_h diagnostic;}
struct meta_t{bit<32> epoch;bit<32> expected;bit<8> operation;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);pkt.extract(hdr.diagnostic);
 m.epoch=hdr.diagnostic.epoch;m.expected=hdr.diagnostic.expected;m.operation=hdr.diagnostic.operation;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 #include "epoch_cell.p4"
 action read(){hdr.diagnostic.result=read_cell.execute(1w0);}
 action claim(){hdr.diagnostic.result=claim_cell.execute(1w0);}
 action advance(){hdr.diagnostic.result=transition_cell.execute(1w0);}
 action close(){hdr.diagnostic.result=close_cell.execute(1w0);}
 table dispatch{key={m.operation:exact;m.expected:range;}actions={read;claim;advance;close;NoAction;}size=4;
 const entries={(8w0,32w0..32w0xffffffff):read();(8w1,32w0..32w0xffffffff):claim();(8w2,32w1..32w10):advance();(8w3,32w0..32w0xffffffff):close();}const default_action=NoAction();}
 apply{tm.ucast_egress_port=9w8;tm.bypass_egress=1w1;dispatch.apply();}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

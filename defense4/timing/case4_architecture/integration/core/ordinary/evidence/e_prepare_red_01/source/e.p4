/* Partial protected E prepare. Typed40B interface; no endpoint release authority. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header reference_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;}
header captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header cache_reference_h{bit<32> generation;bit<32> wire_start;bit<32> expected_owner;}
header image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
struct producer_cell_t{bit<32> generation;bit<32> phase;}
struct cache_tag_t{bit<32> epoch;bit<32> generation;}
struct headers_t{reference_h reference;captured_decoy_h captured;cache_reference_h cache;eth_h eth;ip_h ip;tcp_h tcp;image_h image;}
struct meta_t{bit<1> parsed;bit<1> enabled;bool ip_error;bit<16> tcp_sum;bit<32> grant;}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){Checksum() ic;Checksum() tc;
 state start{pkt.extract(eg);m.parsed=1w0;m.enabled=1w0;transition select(eg.egress_port){9w68:reference;default:reject;}}
 state reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:reject;default:generation;}}
 state generation{transition select(hdr.reference.generation){32w0:reject;default:owner;}}
 state owner{transition select(hdr.reference.expected_owner[31:16]){16w9:cookie;default:reject;}}
 state cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:reject;default:event;}}
 state event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0405,16w1):captured;default:reject;}}
 state captured{pkt.extract(hdr.captured);pkt.extract(hdr.cache);transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:reject;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w95,8w6):ip_flags;default:reject;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:reject;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):image;(4w5,4w0,8w0x18,16w0):image;default:reject;}}
 state image{pkt.extract(hdr.image);tc.subtract(hdr.image);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 action deny(){md.drop_ctl=3w1;}
 action allow_connection(){m.enabled=1w1;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={allow_connection;NoAction;}size=1;default_action=NoAction();}
 apply{deny();}
}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);transition accept;}}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){apply{md.drop_ctl=3w1;}}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{}}
#ifndef ORDINARY_E_NO_MAIN
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
#endif

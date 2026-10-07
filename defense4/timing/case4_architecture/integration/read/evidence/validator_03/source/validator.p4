/* Native READ20/response49 full-profile observer. Default admission denies.
 * Exact frozen g10v2 range0..22 query. No timing owner/epoch association yet.
 * No holding/padding/carving; forwards original bytes and counts full validation.
 */
#include <core.p4>
#include <tna.p4>
header eth_h{bit<48> dst;bit<48> src;bit<16> type;}
header ip_h{bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h{bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header request_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}
header first_h{bit<8> tp;bit<8> app;bit<8> func;bit<16> iin;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<48> values;bit<16> crc;}
header second_h{bit<128> values;bit<16> crc;}
header tail_h{bit<8> value;bit<16> crc;}
struct headers_t{eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;request_h request;first_h first;second_h second;tail_h tail;}
struct meta_t{bit<8> parsed;bit<8> kind;bit<8> direction;bit<1> admitted;bit<1> profile;bit<1> slot;bit<1> badh;bit<1> bad0;bit<1> bad1;bit<1> badt;bool ip_error;bit<16> tcp_sum;bit<16> hcrc;bit<16> crc0;bit<16> crc1;bit<16> crct;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=8w0;m.kind=8w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w60):request_ip_flags;(4w4,4w5,8w6,16w89):response_ip_flags;default:accept;}}
 state request_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):request_tcp;(13w0,3w2):request_tcp;default:accept;}}
 state response_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):response_tcp;(13w0,3w2):response_tcp;default:accept;}}
 state request_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w16,16w0):request_dl;(4w5,4w0,8w24,16w0):request_dl;default:accept;}}
 state response_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w16,16w0):response_dl;(4w5,4w0,8w24,16w0):response_dl;default:accept;}}
 state request_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition request;}
 state response_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition first;}
 state request{pkt.extract(hdr.request);tc.subtract(hdr.request);m.kind=8w1;transition finish;}
 state first{pkt.extract(hdr.first);tc.subtract(hdr.first);transition second;}
 state second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.kind=8w2;transition finish;}
 state finish{m.tcp_sum=tc.get();m.parsed=8w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.admitted=1w1;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action forward(PortId_t port){m.direction=8w1;tm.ucast_egress_port=port;}
 action reverse(PortId_t port){m.direction=8w2;tm.ucast_egress_port=port;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={forward;reverse;NoAction;}size=2;default_action=NoAction();}
 action request_ok(){m.profile=1w1;m.slot=1w0;}
 action response_ok(){m.profile=1w1;m.slot=1w1;}
 table request_profile{key={m.direction:exact;hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.request.tp:ternary;hdr.request.app:ternary;hdr.request.func:exact;hdr.request.group:exact;hdr.request.variation:exact;hdr.request.qualifier:exact;hdr.request.first:exact;hdr.request.last:exact;}
 actions={request_ok;NoAction;}size=1;const default_action=NoAction();const entries={(8w1,16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):request_ok();}}
 table response_profile{key={m.direction:exact;hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.tp:ternary;hdr.first.app:ternary;hdr.first.func:exact;hdr.first.group:exact;hdr.first.variation:exact;hdr.first.qualifier:exact;hdr.first.first:exact;hdr.first.last:exact;}
 actions={response_ok;NoAction;}size=1;const default_action=NoAction();const entries={(8w2,16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):response_ok();}}
 CRCPolynomial<bit<16>>(16w0x3d65,true,false,false,16w0,16w0xffff) poly;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_header;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_request;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_first;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_second;
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;
 action head_crc(){m.hcrc=hash_header.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
 table head_t{actions={head_crc;}size=1;const default_action=head_crc();}
 action request_crc(){m.crc0=hash_request.get({hdr.request.tp,hdr.request.app,hdr.request.func,hdr.request.group,hdr.request.variation,hdr.request.qualifier,hdr.request.first,hdr.request.last});}
 table request_t{actions={request_crc;}size=1;const default_action=request_crc();}
 action first_crc(){m.crc0=hash_first.get({hdr.first.tp,hdr.first.app,hdr.first.func,hdr.first.iin,hdr.first.group,hdr.first.variation,hdr.first.qualifier,hdr.first.first,hdr.first.last,hdr.first.values});}
 table first_t{actions={first_crc;}size=1;const default_action=first_crc();}
 action second_crc(){m.crc1=hash_second.get({hdr.second.values});}
 table second_t{actions={second_crc;}size=1;const default_action=second_crc();}
 action tail_crc(){m.crct=hash_tail.get({hdr.tail.value});}
 table tail_t{actions={tail_crc;}size=1;const default_action=tail_crc();}
 Register<bit<32>,bit<1>>(2,0) qualified;
 RegisterAction<bit<32>,bit<1>,bit<32>>(qualified) count={void apply(inout bit<32> v,out bit<32> rv){v=v+32w1;rv=v;}};
 action observe(){count.execute(m.slot);}
 table observe_t{actions={observe;}size=1;const default_action=observe();}
 apply{m.admitted=1w0;m.profile=1w0;m.direction=8w0;m.badh=1w0;m.bad0=1w0;m.bad1=1w0;m.badt=1w0;
 forwarding.apply();
 if(m.admitted==1w1&&m.parsed==8w1&&!m.ip_error&&m.tcp_sum==16w0xffeb&&hdr.ip.ttl!=8w0){
  connection.apply();head_t.apply();
  if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}
  if(m.kind==8w1){request_profile.apply();request_t.apply();
   if(hdr.request.crc!=(m.crc0[7:0]++m.crc0[15:8])){m.bad0=1w1;}
  }else if(m.kind==8w2){response_profile.apply();first_t.apply();second_t.apply();tail_t.apply();
   if(hdr.first.crc!=(m.crc0[7:0]++m.crc0[15:8])){m.bad0=1w1;}
   if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=1w1;}
   if(hdr.tail.crc!=(m.crct[7:0]++m.crct[15:8])){m.badt=1w1;}
  }
  if(m.profile==1w1&&m.badh==1w0&&m.bad0==1w0&&m.bad1==1w0&&m.badt==1w0){observe_t.apply();}
 }
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

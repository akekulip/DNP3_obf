/* Partial ordinary SELECT M prepare: actual N28 handoff, full native35 validation,
 * captured decoy construction and persistent producer reservation. No release
 * authority: E must finish all image stores before ready; N commits afterward. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header native_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<16> crc;}
header tail_h{bit<32> off;bit<8> status;bit<16> crc;}
header appended_h{bit<32> off;bit<8> status;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<16> on_first;bit<16> crc;}
header final_h{bit<16> on_last;bit<32> off;bit<8> status;bit<16> crc;}
header reference_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;}
header captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header cache_reference_h{bit<32> generation;bit<32> wire_start;}
struct producer_cell_t{bit<32> generation;bit<32> phase;}
struct headers_t{reference_h reference;captured_decoy_h captured;cache_reference_h cache;eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;native_h native;tail_h tail;appended_h appended;final_h last;}
struct meta_t{bit<32> reservation_grant;bit<1> parsed;bit<1> enabled;bit<1> profile;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=1w0;m.enabled=1w0;m.profile=1w0;m.changed=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;transition select(ig.ingress_port){9w196:reference;default:accept;}}
 state reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:accept;default:reference_generation;}}
 state reference_generation{transition select(hdr.reference.generation){32w0:accept;default:reference_owner;}}
 state reference_owner{transition select(hdr.reference.expected_owner[31:16]){16w9:reference_cookie;default:accept;}}
 state reference_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:accept;default:reference_event;}}
 state reference_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0305,16w1):captured;default:accept;}}
 state captured{pkt.extract(hdr.captured);transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w75,8w6):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):dl;(4w5,4w0,8w0x18,16w0):dl;default:accept;}}
 state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native;}
 state native{pkt.extract(hdr.native);tc.subtract(hdr.native);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w0;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action allow_connection(){m.enabled=1w1;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={allow_connection;NoAction;}size=1;default_action=NoAction();}
 Register<producer_cell_t,bit<1>>(1,{0,4}) reservation;
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) reserve={
  void apply(inout producer_cell_t value,out bit<32> granted){
   granted=32w0;
   if(value.phase==32w4&&value.generation<hdr.reference.generation){
    value.generation=hdr.reference.generation;value.phase=32w1;granted=32w1;
   }
  }
 };
 action reserve_producer(){m.reservation_grant=reserve.execute(1w0);}
 table reserve_t{actions={reserve_producer;}size=1;const default_action=reserve_producer();}
 action eligible(){m.profile=1w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.native.tp:ternary;hdr.native.app:ternary;hdr.native.func:exact;hdr.native.group:exact;hdr.native.variation:exact;hdr.native.qualifier:exact;hdr.native.count:exact;hdr.tail.status:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w3,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();}}
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_head;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_body;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_newhead;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_newbody;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_newtail;
action input_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table input_head_t{actions={input_head;}size=1;const default_action=input_head();}
action input_body(){m.bcrc=hash_body.get({hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on});}
table input_body_t{actions={input_body;}size=1;const default_action=input_body();}
action input_tail(){m.tcrc=hash_tail.get({hdr.tail.off,hdr.tail.status});}
table input_tail_t{actions={input_tail;}size=1;const default_action=input_tail();}
action construct(){hdr.appended.setValid();hdr.last.setValid();hdr.appended.off=hdr.tail.off;hdr.appended.status=hdr.tail.status;hdr.appended.group=8w12;hdr.appended.variation=8w1;hdr.appended.qualifier=8w0x28;hdr.appended.count=16w0x0100;hdr.appended.index=hdr.captured.index;hdr.appended.code=hdr.captured.code;hdr.appended.repeat=hdr.captured.repeat;hdr.appended.on_first=hdr.captured.on[31:16];hdr.last.on_last=hdr.captured.on[15:0];hdr.last.off=hdr.captured.off;hdr.last.status=8w0;hdr.tail.setInvalid();hdr.dl.len=8w44;hdr.ip.len=16w95;m.tcp_length=16w75;m.changed=1w1;hdr.cache.setValid();hdr.cache.generation=hdr.reference.generation;hdr.cache.wire_start=hdr.tcp.seq;hdr.reference.event=16w0x0405;}
 table construct_t{actions={construct;}size=1;const default_action=construct();}
action output_newhead(){m.hcrc=hash_newhead.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table output_newhead_t{actions={output_newhead;}size=1;const default_action=output_newhead();}
action output_newbody(){m.bcrc=hash_newbody.get({hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first});}
table output_newbody_t{actions={output_newbody;}size=1;const default_action=output_newbody();}
action output_newtail(){m.tcrc=hash_newtail.get({hdr.last.on_last,hdr.last.off,hdr.last.status});}
table output_newtail_t{actions={output_newtail;}size=1;const default_action=output_newtail();}
action crc_render(){hdr.dl.crc=m.hcrc[7:0]++m.hcrc[15:8];hdr.appended.crc=m.bcrc[7:0]++m.bcrc[15:8];hdr.last.crc=m.tcrc[7:0]++m.tcrc[15:8];}
 table crc_render_t{actions={crc_render;}size=1;const default_action=crc_render();}
 table crc_gate{key={m.badh:exact;m.badb:exact;m.badt:exact;}actions={NoAction;}size=1;const default_action=NoAction();}
 apply{
 forwarding.apply();
 if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
  connection.apply();profile.apply();
  if(m.enabled==1w1&&m.profile==1w1){
   input_head_t.apply();input_body_t.apply();input_tail_t.apply();
   if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}
   if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}
   if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
   if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0&&hdr.native.index!=hdr.captured.index){
    reserve_t.apply();
    if(m.reservation_grant==32w1){
     construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();
    }else{deny();}
   }else{deny();}
  }else{deny();}
 }else{deny();}
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on,hdr.native.crc,hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first,hdr.appended.crc,hdr.last.on_last,hdr.last.off,hdr.last.status,hdr.last.crc});}pkt.emit(hdr.reference);pkt.emit(hdr.captured);pkt.emit(hdr.cache);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.native);pkt.emit(hdr.tail);pkt.emit(hdr.appended);pkt.emit(hdr.last);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
#ifndef ORDINARY_M_NO_MAIN
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

#endif

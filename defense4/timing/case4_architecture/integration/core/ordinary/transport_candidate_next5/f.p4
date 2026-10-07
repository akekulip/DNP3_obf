/* Partial protected E prepare. Typed24B interface; no endpoint release authority. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header reference_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;}
header captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header cache_reference_h{bit<32> generation;bit<32> expected_owner;}
header completion_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;bit<32> cached_generation;bit<32> cached_owner;}
header completion_stamp_h{bit<32> epoch;}
header image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
struct producer_cell_t{bit<32> generation;bit<32> phase;}
struct cache_tag_t{bit<32> epoch;bit<32> generation;}
struct headers_t{reference_h reference;cache_reference_h cache;completion_stamp_h completion;eth_h eth;ip_h ip;tcp_h tcp;image_h image;}
struct meta_t{bit<32> pin_generation;bit<16> tcp_length;bit<32> completion_epoch;bit<32> completion_generation;bit<32> completion_owner;bit<32> completion_cache_generation;bit<32> completion_cache_owner;bit<16> completion_event;bit<16> completion_format;bit<32> expected_phase;bit<32> completion_diff;bit<10> mirror_sid;bit<1> emit_ready;bit<8> role;bit<32> tag_match;bit<32> stored_owner_diff;bit<32> stored_position_diff;bit<1> parsed;bit<1> enabled;bool ip_error;bit<16> tcp_sum;bit<32> grant;bit<32> gen_diff;bit<32> owner_diff;bit<1> done0;bit<1> done1;bit<1> done2;bit<1> done3;bit<1> done4;bit<1> done5;bit<1> done6;bit<1> done7;bit<1> done8;bit<1> done9;bit<1> done10;bit<1> done11;bit<1> done12;bit<1> done13;bit<1> position_done;bit<1> tag_done;bit<1> owner_done;bit<1> identity_grant;}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){Checksum() ic;Checksum() tc;
 state start{pkt.extract(eg);m.grant=32w0;m.emit_ready=1w0;m.role=8w0;m.parsed=1w0;m.enabled=1w0;m.identity_grant=1w0;m.position_done=1w0;m.tag_done=1w0;m.owner_done=1w0;m.done0=1w0;m.done1=1w0;m.done2=1w0;m.done3=1w0;m.done4=1w0;m.done5=1w0;m.done6=1w0;m.done7=1w0;m.done8=1w0;m.done9=1w0;m.done10=1w0;m.done11=1w0;m.done12=1w0;m.done13=1w0;transition select(eg.egress_port){9w2:emit_reference;default:reject;}}
 state emit_reference{m.role=8w2;pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:reject;default:emit_generation;}}
 state emit_generation{transition select(hdr.reference.generation){32w0:reject;default:emit_owner;}}
 state emit_owner{transition select(hdr.reference.expected_owner[31:16]){16w17:emit_cookie;default:reject;}}
 state emit_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:reject;default:emit_event;}}
 state emit_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0d14,16w2):emit_cache;default:reject;}}
 state reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:reject;default:generation;}}
 state generation{transition select(hdr.reference.generation){32w0:reject;default:owner;}}
 state owner{transition select(hdr.reference.expected_owner[31:16]){16w9:cookie;16w17:query_cookie;default:reject;}}
 state query_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:reject;default:query_event;}}
 state query_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0914,16w2):query_cache;(16w0x0e14,16w2):completion_cache;(16w0x1214,16w3):terminal_cache;default:reject;}}
 state terminal_cache{m.role=8w4;pkt.extract(hdr.cache);pkt.extract(hdr.completion);m.parsed=1w1;transition accept;}
 state emit_cache{pkt.extract(hdr.cache);transition eth;}
 state completion_cache{m.role=8w3;m.expected_phase=32w2;pkt.extract(hdr.cache);transition eth;}
 state query_cache{m.role=8w1;m.expected_phase=32w1;pkt.extract(hdr.cache);transition eth;}
 state cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:reject;default:event;}}
 state event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0405,16w2):cache;default:reject;}}
 state cache{pkt.extract(hdr.cache);transition eth;}
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
 Register<bit<32>,bit<1>>(1,0) emitted_generation;
 RegisterAction<bit<32>,bit<1>,bit<32>>(emitted_generation) claim_emit={void apply(inout bit<32> value,out bit<32> result){result=32w0;if(value<hdr.reference.generation){value=hdr.reference.generation;result=32w1;}}};
 action claim(){m.grant=claim_emit.execute(1w0);}
 table claim_t{key={m.enabled:exact;m.gen_diff:exact;m.owner_diff:exact;}actions={claim;deny;}size=1;const default_action=deny();const entries={(1w1,32w0,32w0x80000):claim();}}
 action endpoint_ready(){m.emit_ready=1w1;m.tcp_length=16w75;m.mirror_sid=10w1;md.mirror_type=3w2;m.completion_epoch=hdr.reference.epoch;m.completion_generation=hdr.reference.generation;m.completion_owner=hdr.reference.expected_owner;m.completion_cache_generation=hdr.cache.generation;m.completion_cache_owner=hdr.cache.expected_owner;m.completion_event=16w0x0e14;m.completion_format=16w2;hdr.reference.setInvalid();hdr.cache.setInvalid();}
 apply{
  if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
   connection.apply();
   m.gen_diff=hdr.reference.generation-hdr.cache.generation;
   m.owner_diff=hdr.reference.expected_owner-hdr.cache.expected_owner;
   claim_t.apply();if(m.grant==32w1){endpoint_ready();}else{deny();}
  }else{deny();}
 }
}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){
 Checksum() tc;
 Mirror() mirror;
 apply{
  if(m.emit_ready==1w1){
   hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.image.w0,hdr.image.w1,hdr.image.w2,hdr.image.w3,hdr.image.w4,hdr.image.w5,hdr.image.w6,hdr.image.w7,hdr.image.w8,hdr.image.w9,hdr.image.w10,hdr.image.w11,hdr.image.w12,hdr.image.w13});
   mirror.emit<completion_h>(m.mirror_sid,{m.completion_epoch,m.completion_generation,m.completion_owner,m.completion_event,m.completion_format,m.completion_cache_generation,m.completion_cache_owner});
  }
  pkt.emit(hdr);
 }
}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);transition accept;}}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){apply{md.drop_ctl=3w1;}}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{}}
#ifndef ORDINARY_E_NO_MAIN
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
#endif

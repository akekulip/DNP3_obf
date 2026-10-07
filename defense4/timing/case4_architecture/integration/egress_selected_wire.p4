/* Role-specific wire composition experiment. NEVER DEPLOY. No complete lifecycle. */
#include <core.p4>
#include <tna.p4>
/* Actual native35 validation/padding wire primitive. Default profile disabled. No lifecycle or assembly. */
header cache_eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header cache_ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header cache_tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header cache_dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header cache_native_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<16> crc;}
header cache_tail_h{bit<32> off;bit<8> status;bit<16> crc;}
header cache_appended_h{bit<32> off;bit<8> status;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<16> on_first;bit<16> crc;}
header cache_final_h{bit<16> on_last;bit<32> off;bit<8> status;bit<16> crc;}
header cache_descriptor_h{bit<32> generation;bit<32> wire_start;bit<8> operation;bit<8> slot;bit<16> reserved;}
header cache_image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
header cache_byte_h{bit<8> data;}
struct cache_headers_t{cache_descriptor_h descriptor;cache_image_h image;cache_byte_h replay;cache_eth_h eth;cache_ip_h ip;cache_tcp_h tcp;cache_dl_h dl;cache_native_h native;cache_tail_h tail;cache_appended_h appended;cache_final_h last;}
struct cache_meta_t{bit<1> descriptor_valid;bit<1> replay_parsed;bit<1> replay_allowed;bit<32> generation;bit<32> wire_start;bit<8> native_last;bit<8> slot;bit<32> last_word;bit<1> parsed;bit<1> enabled;bit<1> profile;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;}
parser cache_IgParser(packet_in pkt,out cache_headers_t hdr,out cache_meta_t m){Checksum() ic;Checksum() tc;
 state start{m.descriptor_valid=1w0;m.replay_parsed=1w0;m.replay_allowed=1w0;m.parsed=1w0;m.enabled=1w0;m.profile=1w0;m.changed=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w75,8w6):ip_flags_full;(4w4,4w5,16w41,8w6):ip_flags_replay;default:accept;}}
 state ip_flags_full{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp_full;(13w0,3w2):tcp_full;default:accept;}}
 state ip_flags_replay{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp_replay;(13w0,3w2):tcp_replay;default:accept;}}
 state tcp_full{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):dl;(4w5,4w0,8w0x18,16w0):dl;default:accept;}}
 state tcp_replay{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):replay;(4w5,4w0,8w0x18,16w0):replay;default:accept;}}
 state replay{pkt.extract(hdr.replay);tc.subtract(hdr.replay);m.tcp_sum=tc.get();m.replay_parsed=1w1;transition accept;}
 state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native;}
 state native{pkt.extract(hdr.native);tc.subtract(hdr.native);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control cache_Ingress(inout cache_headers_t hdr,inout cache_meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w0;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action configure(bit<16> index,bit<8> code,bit<8> repeat,bit<32> on,bit<32> off,bit<32> generation){m.generation=generation;m.enabled=1w1;m.decoy_index=index;m.decoy_code=code;m.decoy_repeat=repeat;m.decoy_on=on;m.decoy_off=off;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=1;default_action=NoAction();}
 action eligible(){m.profile=1w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.native.tp:ternary;hdr.native.app:ternary;hdr.native.func:exact;hdr.native.group:exact;hdr.native.variation:exact;hdr.native.qualifier:exact;hdr.native.count:exact;hdr.tail.status:exact;}
 actions={eligible;NoAction;}size=2;const default_action=NoAction();const entries={(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w3,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w4,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();}}
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
action construct(){hdr.appended.setValid();hdr.last.setValid();hdr.appended.off=hdr.tail.off;hdr.appended.status=hdr.tail.status;hdr.appended.group=8w12;hdr.appended.variation=8w1;hdr.appended.qualifier=8w0x28;hdr.appended.count=16w0x0100;hdr.appended.index=m.decoy_index;hdr.appended.code=m.decoy_code;hdr.appended.repeat=m.decoy_repeat;hdr.appended.on_first=m.decoy_on[31:16];hdr.last.on_last=m.decoy_on[15:0];hdr.last.off=m.decoy_off;hdr.last.status=8w0;hdr.tail.setInvalid();hdr.dl.len=8w44;hdr.ip.len=16w95;m.tcp_length=16w75;m.changed=1w1;}
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
 action cached(bit<32> generation,bit<32> wire_start,bit<8> native_last,bit<8> slot){m.replay_allowed=1w1;m.generation=generation;m.wire_start=wire_start;m.native_last=native_last;m.slot=slot;}
 table replay_context{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;hdr.tcp.seq:exact;}actions={cached;NoAction;}size=2;const default_action=NoAction();}
 action write_descriptor(){m.descriptor_valid=1w1;hdr.descriptor.setValid();hdr.descriptor.generation=m.generation;hdr.descriptor.wire_start=hdr.tcp.seq;hdr.descriptor.operation=8w2;hdr.descriptor.slot=m.slot;hdr.descriptor.reserved=16w0;}
 table write_descriptor_t{actions={write_descriptor;}size=1;const default_action=write_descriptor();}
 action read_descriptor(){m.descriptor_valid=1w1;hdr.descriptor.setValid();hdr.descriptor.generation=m.generation;hdr.descriptor.wire_start=m.wire_start;hdr.descriptor.operation=8w1;hdr.descriptor.slot=m.slot;hdr.descriptor.reserved=16w0;}
 table read_descriptor_t{actions={read_descriptor;}size=1;const default_action=read_descriptor();}
 apply{forwarding.apply();if(md.drop_ctl==3w0){if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB){connection.apply();profile.apply();if(m.enabled==1w1&&m.profile==1w1){input_head_t.apply();input_body_t.apply();input_tail_t.apply();if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
 if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0&&hdr.native.index!=m.decoy_index){construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();m.slot=hdr.native.func-8w3;if(m.generation!=32w0){write_descriptor_t.apply();}}}}
 if(m.replay_parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB){replay_context.apply();if(m.replay_allowed==1w1&&m.generation!=32w0&&hdr.replay.data==m.native_last){read_descriptor_t.apply();}}
 }if(m.descriptor_valid==1w0){deny();}}
}
control cache_IgDeparser(packet_out pkt,inout cache_headers_t hdr,in cache_meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on,hdr.native.crc,hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first,hdr.appended.crc,hdr.last.on_last,hdr.last.off,hdr.last.status,hdr.last.crc});}pkt.emit(hdr.descriptor);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.replay);pkt.emit(hdr.dl);pkt.emit(hdr.native);pkt.emit(hdr.tail);pkt.emit(hdr.appended);pkt.emit(hdr.last);}}
parser cache_EgParser(packet_in pkt,out cache_headers_t hdr,out cache_meta_t m){
 state start{pkt.extract(hdr.descriptor);pkt.extract(hdr.eth);pkt.extract(hdr.ip);pkt.extract(hdr.tcp);transition select(hdr.descriptor.operation,hdr.descriptor.slot){(8w2,8w0):image;(8w2,8w1):image;(8w1,8w0):replay;(8w1,8w1):replay;default:reject;}}
 state image{pkt.extract(hdr.image);transition accept;}
 state replay{pkt.extract(hdr.replay);transition accept;}
}
control cache_Egress(inout cache_headers_t hdr,inout cache_meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
Register<bit<32>,bit<1>>(2,32w0) image_0;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_0) write_0={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w0;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_0) read_0={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_0(){write_0.execute(hdr.descriptor.slot[0:0]);}

 action load_0(){hdr.image.w0=read_0.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_1;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_1) write_1={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w1;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_1) read_1={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_1(){write_1.execute(hdr.descriptor.slot[0:0]);}

 action load_1(){hdr.image.w1=read_1.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_2;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_2) write_2={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w2;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_2) read_2={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_2(){write_2.execute(hdr.descriptor.slot[0:0]);}

 action load_2(){hdr.image.w2=read_2.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_3;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_3) write_3={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w3;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_3) read_3={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_3(){write_3.execute(hdr.descriptor.slot[0:0]);}

 action load_3(){hdr.image.w3=read_3.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_4;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_4) write_4={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w4;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_4) read_4={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_4(){write_4.execute(hdr.descriptor.slot[0:0]);}

 action load_4(){hdr.image.w4=read_4.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_5;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_5) write_5={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w5;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_5) read_5={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_5(){write_5.execute(hdr.descriptor.slot[0:0]);}

 action load_5(){hdr.image.w5=read_5.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_6;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_6) write_6={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w6;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_6) read_6={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_6(){write_6.execute(hdr.descriptor.slot[0:0]);}

 action load_6(){hdr.image.w6=read_6.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_7;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_7) write_7={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w7;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_7) read_7={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_7(){write_7.execute(hdr.descriptor.slot[0:0]);}

 action load_7(){hdr.image.w7=read_7.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_8;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_8) write_8={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w8;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_8) read_8={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_8(){write_8.execute(hdr.descriptor.slot[0:0]);}

 action load_8(){hdr.image.w8=read_8.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_9;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_9) write_9={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w9;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_9) read_9={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_9(){write_9.execute(hdr.descriptor.slot[0:0]);}

 action load_9(){hdr.image.w9=read_9.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_10;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_10) write_10={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w10;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_10) read_10={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_10(){write_10.execute(hdr.descriptor.slot[0:0]);}

 action load_10(){hdr.image.w10=read_10.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_11;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_11) write_11={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w11;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_11) read_11={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_11(){write_11.execute(hdr.descriptor.slot[0:0]);}

 action load_11(){hdr.image.w11=read_11.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_12;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_12) write_12={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w12;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_12) read_12={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_12(){write_12.execute(hdr.descriptor.slot[0:0]);}

 action load_12(){hdr.image.w12=read_12.execute(hdr.descriptor.slot[0:0]);}

Register<bit<32>,bit<1>>(2,32w0) image_13;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_13) write_13={void apply(inout bit<32> v,out bit<32> rv){v=m.last_word;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_13) read_13={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_13(){write_13.execute(hdr.descriptor.slot[0:0]);}

 action load_13(){m.last_word=read_13.execute(hdr.descriptor.slot[0:0]);}

action deny(){md.drop_ctl=3w1;}
 action form_last(){m.last_word=hdr.image.w13++8w0;}
 table form_last_t{actions={form_last;}size=1;const default_action=form_last();}
 action render(){hdr.image.w13=m.last_word[31:8];hdr.image.setValid();hdr.replay.setInvalid();hdr.ip.len=16w95;hdr.tcp.seq=hdr.descriptor.wire_start;}
 table render_t{actions={render;}size=1;const default_action=render();}
table image_0_t{key={hdr.descriptor.operation:exact;}actions={store_0;load_0;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_0();8w1:load_0();}}
table image_1_t{key={hdr.descriptor.operation:exact;}actions={store_1;load_1;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_1();8w1:load_1();}}
table image_2_t{key={hdr.descriptor.operation:exact;}actions={store_2;load_2;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_2();8w1:load_2();}}
table image_3_t{key={hdr.descriptor.operation:exact;}actions={store_3;load_3;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_3();8w1:load_3();}}
table image_4_t{key={hdr.descriptor.operation:exact;}actions={store_4;load_4;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_4();8w1:load_4();}}
table image_5_t{key={hdr.descriptor.operation:exact;}actions={store_5;load_5;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_5();8w1:load_5();}}
table image_6_t{key={hdr.descriptor.operation:exact;}actions={store_6;load_6;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_6();8w1:load_6();}}
table image_7_t{key={hdr.descriptor.operation:exact;}actions={store_7;load_7;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_7();8w1:load_7();}}
table image_8_t{key={hdr.descriptor.operation:exact;}actions={store_8;load_8;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_8();8w1:load_8();}}
table image_9_t{key={hdr.descriptor.operation:exact;}actions={store_9;load_9;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_9();8w1:load_9();}}
table image_10_t{key={hdr.descriptor.operation:exact;}actions={store_10;load_10;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_10();8w1:load_10();}}
table image_11_t{key={hdr.descriptor.operation:exact;}actions={store_11;load_11;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_11();8w1:load_11();}}
table image_12_t{key={hdr.descriptor.operation:exact;}actions={store_12;load_12;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_12();8w1:load_12();}}
table image_13_t{key={hdr.descriptor.operation:exact;}actions={store_13;load_13;NoAction;}size=2;const default_action=NoAction();const entries={8w2:store_13();8w1:load_13();}}
 apply{if(hdr.descriptor.generation==32w0){deny();}else{
if(hdr.descriptor.operation==8w2){form_last_t.apply();}
image_0_t.apply();image_1_t.apply();image_2_t.apply();image_3_t.apply();image_4_t.apply();image_5_t.apply();image_6_t.apply();image_7_t.apply();image_8_t.apply();image_9_t.apply();image_10_t.apply();image_11_t.apply();image_12_t.apply();image_13_t.apply();
if(hdr.descriptor.operation==8w1){render_t.apply();}
}m.tcp_length=16w75;}
}
control cache_EgDeparser(packet_out pkt,inout cache_headers_t hdr,in cache_meta_t m,in egress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;
 apply{hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.image.w0,hdr.image.w1,hdr.image.w2,hdr.image.w3,hdr.image.w4,hdr.image.w5,hdr.image.w6,hdr.image.w7,hdr.image.w8,hdr.image.w9,hdr.image.w10,hdr.image.w11,hdr.image.w12,hdr.image.w13});pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.image);}
}

/* Direction 1 grouped TCP mapping primitive. CP-seeded two-boundary state only; no handshake/producer.
 * One ingress pass completes a real pure-ACK packet; no internal placeholder completion.
 * Default forwarding/profile tables deny. No hardware qualification. */
header forward_eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header forward_ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header forward_tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
struct forward_headers_t {forward_eth_h eth;forward_ip_h ip;forward_tcp_h tcp;}
struct forward_meta_t {bit<32> first;bit<32> second;bit<8> valid;bit<8> direction;PortId_t output_port;
 bit<32> right;bit<32> left;bit<32> native_right;bit<32> so1;bit<32> so2;bit<32> ao1;bit<32> ao2;bit<32> ro1;bit<32> ro2;
 bit<32> seq_result;bit<16> output_window;bit<32> full_window;bit<32> window_after;bit<32> original_seq;bit<32> original_ack;bit<32> growth;bit<16> original_window;bit<16> tcp_len;bit<16> tcp_sum;bool ip_error;bit<8> parsed;bit<1> changed;}
parser forward_IgParser(packet_in pkt,out forward_headers_t hdr,out forward_meta_t m){
 Checksum() ipcheck;Checksum() tcpcheck;
 state start{m.parsed=8w0;m.changed=1w0;m.direction=8w0;m.valid=8w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ipcheck.add(hdr.ip);m.ip_error=ipcheck.verify();tcpcheck.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});
 transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w40):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tcpcheck.subtract(hdr.tcp);m.tcp_sum=tcpcheck.get();transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):eligible;default:accept;} }
 state eligible{m.parsed=8w1;transition accept;}
}
@pa_container_size("ingress", "hdr.forward.tcp.seq", 32)
@pa_container_size("ingress", "hdr.forward.tcp.ack", 32)
@pa_container_size("ingress", "m.forward.first", 32)
@pa_container_size("ingress", "m.forward.second", 32)
@pa_container_size("ingress", "m.forward.right", 32)
@pa_container_size("ingress", "m.forward.left", 32)
@pa_container_size("ingress", "m.forward.native_right", 32)
@pa_container_size("ingress", "m.forward.so1", 32)
@pa_container_size("ingress", "m.forward.so2", 32)
@pa_container_size("ingress", "m.forward.ao1", 32)
@pa_container_size("ingress", "m.forward.ao2", 32)
@pa_container_size("ingress", "m.forward.ro1", 32)
@pa_container_size("ingress", "m.forward.ro2", 32)
@pa_container_size("ingress", "m.forward.original_seq", 32)
@pa_container_size("ingress", "m.forward.original_ack", 32)
@pa_container_size("ingress", "m.forward.growth", 32)
@pa_container_size("ingress", "m.forward.full_window", 32)
@pa_container_size("ingress", "m.forward.window_after", 32)
@pa_container_size("ingress", "m.forward.seq_result", 32)
control forward_Ingress(inout forward_headers_t hdr,inout forward_meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.output_port=port;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action configure(bit<32> first,bit<32> second,bit<8> valid,bit<8> direction){m.first=first;m.second=second;m.valid=valid;m.direction=direction;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=2;default_action=NoAction();}
 action prepare_window(){m.full_window=16w0++hdr.tcp.window;}
 table prepare_window_t{actions={prepare_window;}size=1;const default_action=prepare_window();}
 action edges(){m.right=hdr.tcp.ack+m.full_window;m.left=hdr.tcp.ack;m.original_ack=hdr.tcp.ack;m.original_seq=hdr.tcp.seq;m.seq_result=hdr.tcp.seq;m.original_window=hdr.tcp.window;m.tcp_len=16w20;}
 table edges_t{actions={edges;}size=1;const default_action=edges();}
 action offsets(){m.so1=m.original_seq-m.first;m.so2=m.original_seq-m.second;m.ao1=m.original_ack-m.first;m.ao2=m.original_ack-m.second;m.ro1=m.right-m.first;m.ro2=m.right-m.second;m.native_right=m.right;}
 table offsets_t{actions={offsets;}size=1;const default_action=offsets();}
action seq1_shift(){m.seq_result=m.original_seq+32w20;}
table seq1{key={m.direction:exact;m.valid:ternary;m.so1:ternary;}actions={seq1_shift;NoAction;}size=128;const default_action=NoAction();const entries={
(8w1,8w1&&&8w1,32w0x23&&&32w0xffffffff):seq1_shift();
(8w1,8w1&&&8w1,32w0x24&&&32w0xfffffffc):seq1_shift();
(8w1,8w1&&&8w1,32w0x28&&&32w0xfffffff8):seq1_shift();
(8w1,8w1&&&8w1,32w0x30&&&32w0xfffffff0):seq1_shift();
(8w1,8w1&&&8w1,32w0x40&&&32w0xffffffc0):seq1_shift();
(8w1,8w1&&&8w1,32w0x80&&&32w0xffffff80):seq1_shift();
(8w1,8w1&&&8w1,32w0x100&&&32w0xffffff00):seq1_shift();
(8w1,8w1&&&8w1,32w0x200&&&32w0xfffffe00):seq1_shift();
(8w1,8w1&&&8w1,32w0x400&&&32w0xfffffc00):seq1_shift();
(8w1,8w1&&&8w1,32w0x800&&&32w0xfffff800):seq1_shift();
(8w1,8w1&&&8w1,32w0x1000&&&32w0xfffff000):seq1_shift();
(8w1,8w1&&&8w1,32w0x2000&&&32w0xffffe000):seq1_shift();
(8w1,8w1&&&8w1,32w0x4000&&&32w0xffffc000):seq1_shift();
(8w1,8w1&&&8w1,32w0x8000&&&32w0xffff8000):seq1_shift();
(8w1,8w1&&&8w1,32w0x10000&&&32w0xffff0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x80000&&&32w0xfff80000):seq1_shift();
(8w1,8w1&&&8w1,32w0x100000&&&32w0xfff00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x200000&&&32w0xffe00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x400000&&&32w0xffc00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x800000&&&32w0xff800000):seq1_shift();
(8w1,8w1&&&8w1,32w0x1000000&&&32w0xff000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):seq1_shift();
}}
action seq2_shift(){m.seq_result=m.original_seq+32w40;}
table seq2{key={m.direction:exact;m.valid:ternary;m.so2:ternary;}actions={seq2_shift;NoAction;}size=128;const default_action=NoAction();const entries={
(8w1,8w2&&&8w2,32w0x23&&&32w0xffffffff):seq2_shift();
(8w1,8w2&&&8w2,32w0x24&&&32w0xfffffffc):seq2_shift();
(8w1,8w2&&&8w2,32w0x28&&&32w0xfffffff8):seq2_shift();
(8w1,8w2&&&8w2,32w0x30&&&32w0xfffffff0):seq2_shift();
(8w1,8w2&&&8w2,32w0x40&&&32w0xffffffc0):seq2_shift();
(8w1,8w2&&&8w2,32w0x80&&&32w0xffffff80):seq2_shift();
(8w1,8w2&&&8w2,32w0x100&&&32w0xffffff00):seq2_shift();
(8w1,8w2&&&8w2,32w0x200&&&32w0xfffffe00):seq2_shift();
(8w1,8w2&&&8w2,32w0x400&&&32w0xfffffc00):seq2_shift();
(8w1,8w2&&&8w2,32w0x800&&&32w0xfffff800):seq2_shift();
(8w1,8w2&&&8w2,32w0x1000&&&32w0xfffff000):seq2_shift();
(8w1,8w2&&&8w2,32w0x2000&&&32w0xffffe000):seq2_shift();
(8w1,8w2&&&8w2,32w0x4000&&&32w0xffffc000):seq2_shift();
(8w1,8w2&&&8w2,32w0x8000&&&32w0xffff8000):seq2_shift();
(8w1,8w2&&&8w2,32w0x10000&&&32w0xffff0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x80000&&&32w0xfff80000):seq2_shift();
(8w1,8w2&&&8w2,32w0x100000&&&32w0xfff00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x200000&&&32w0xffe00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x400000&&&32w0xffc00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x800000&&&32w0xff800000):seq2_shift();
(8w1,8w2&&&8w2,32w0x1000000&&&32w0xff000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):seq2_shift();
}}
action left1_shift(){m.left=m.original_ack-32w20;}
action left1_clamp(){m.left=m.first+32w34;}
table left1{key={m.direction:exact;m.valid:ternary;m.ao1:ternary;}actions={left1_shift;NoAction;left1_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w1&&&8w1,32w0x23&&&32w0xffffffff):left1_clamp();
(8w2,8w1&&&8w1,32w0x24&&&32w0xfffffffc):left1_clamp();
(8w2,8w1&&&8w1,32w0x28&&&32w0xfffffff8):left1_clamp();
(8w2,8w1&&&8w1,32w0x30&&&32w0xfffffffc):left1_clamp();
(8w2,8w1&&&8w1,32w0x34&&&32w0xfffffffe):left1_clamp();
(8w2,8w1&&&8w1,32w0x36&&&32w0xffffffff):left1_clamp();
(8w2,8w1&&&8w1,32w0x37&&&32w0xffffffff):left1_shift();
(8w2,8w1&&&8w1,32w0x38&&&32w0xfffffff8):left1_shift();
(8w2,8w1&&&8w1,32w0x40&&&32w0xffffffc0):left1_shift();
(8w2,8w1&&&8w1,32w0x80&&&32w0xffffff80):left1_shift();
(8w2,8w1&&&8w1,32w0x100&&&32w0xffffff00):left1_shift();
(8w2,8w1&&&8w1,32w0x200&&&32w0xfffffe00):left1_shift();
(8w2,8w1&&&8w1,32w0x400&&&32w0xfffffc00):left1_shift();
(8w2,8w1&&&8w1,32w0x800&&&32w0xfffff800):left1_shift();
(8w2,8w1&&&8w1,32w0x1000&&&32w0xfffff000):left1_shift();
(8w2,8w1&&&8w1,32w0x2000&&&32w0xffffe000):left1_shift();
(8w2,8w1&&&8w1,32w0x4000&&&32w0xffffc000):left1_shift();
(8w2,8w1&&&8w1,32w0x8000&&&32w0xffff8000):left1_shift();
(8w2,8w1&&&8w1,32w0x10000&&&32w0xffff0000):left1_shift();
(8w2,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):left1_shift();
(8w2,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):left1_shift();
(8w2,8w1&&&8w1,32w0x80000&&&32w0xfff80000):left1_shift();
(8w2,8w1&&&8w1,32w0x100000&&&32w0xfff00000):left1_shift();
(8w2,8w1&&&8w1,32w0x200000&&&32w0xffe00000):left1_shift();
(8w2,8w1&&&8w1,32w0x400000&&&32w0xffc00000):left1_shift();
(8w2,8w1&&&8w1,32w0x800000&&&32w0xff800000):left1_shift();
(8w2,8w1&&&8w1,32w0x1000000&&&32w0xff000000):left1_shift();
(8w2,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):left1_shift();
(8w2,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):left1_shift();
(8w2,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):left1_shift();
(8w2,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):left1_shift();
(8w2,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):left1_shift();
(8w2,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):left1_shift();
}}
action left2_shift(){m.left=m.original_ack-32w40;}
action left2_clamp(){m.left=m.second+32w34;}
table left2{key={m.direction:exact;m.valid:ternary;m.ao2:ternary;}actions={left2_shift;NoAction;left2_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w2&&&8w2,32w0x37&&&32w0xffffffff):left2_clamp();
(8w2,8w2&&&8w2,32w0x38&&&32w0xfffffff8):left2_clamp();
(8w2,8w2&&&8w2,32w0x40&&&32w0xfffffff8):left2_clamp();
(8w2,8w2&&&8w2,32w0x48&&&32w0xfffffffe):left2_clamp();
(8w2,8w2&&&8w2,32w0x4a&&&32w0xffffffff):left2_clamp();
(8w2,8w2&&&8w2,32w0x4b&&&32w0xffffffff):left2_shift();
(8w2,8w2&&&8w2,32w0x4c&&&32w0xfffffffc):left2_shift();
(8w2,8w2&&&8w2,32w0x50&&&32w0xfffffff0):left2_shift();
(8w2,8w2&&&8w2,32w0x60&&&32w0xffffffe0):left2_shift();
(8w2,8w2&&&8w2,32w0x80&&&32w0xffffff80):left2_shift();
(8w2,8w2&&&8w2,32w0x100&&&32w0xffffff00):left2_shift();
(8w2,8w2&&&8w2,32w0x200&&&32w0xfffffe00):left2_shift();
(8w2,8w2&&&8w2,32w0x400&&&32w0xfffffc00):left2_shift();
(8w2,8w2&&&8w2,32w0x800&&&32w0xfffff800):left2_shift();
(8w2,8w2&&&8w2,32w0x1000&&&32w0xfffff000):left2_shift();
(8w2,8w2&&&8w2,32w0x2000&&&32w0xffffe000):left2_shift();
(8w2,8w2&&&8w2,32w0x4000&&&32w0xffffc000):left2_shift();
(8w2,8w2&&&8w2,32w0x8000&&&32w0xffff8000):left2_shift();
(8w2,8w2&&&8w2,32w0x10000&&&32w0xffff0000):left2_shift();
(8w2,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):left2_shift();
(8w2,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):left2_shift();
(8w2,8w2&&&8w2,32w0x80000&&&32w0xfff80000):left2_shift();
(8w2,8w2&&&8w2,32w0x100000&&&32w0xfff00000):left2_shift();
(8w2,8w2&&&8w2,32w0x200000&&&32w0xffe00000):left2_shift();
(8w2,8w2&&&8w2,32w0x400000&&&32w0xffc00000):left2_shift();
(8w2,8w2&&&8w2,32w0x800000&&&32w0xff800000):left2_shift();
(8w2,8w2&&&8w2,32w0x1000000&&&32w0xff000000):left2_shift();
(8w2,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):left2_shift();
(8w2,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):left2_shift();
(8w2,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):left2_shift();
(8w2,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):left2_shift();
(8w2,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):left2_shift();
(8w2,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):left2_shift();
}}
action right1_shift(){m.native_right=m.right-32w20;}
action right1_clamp(){m.native_right=m.first+32w34;}
table right1{key={m.direction:exact;m.valid:ternary;m.ro1:ternary;}actions={right1_shift;NoAction;right1_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w1&&&8w1,32w0x23&&&32w0xffffffff):right1_clamp();
(8w2,8w1&&&8w1,32w0x24&&&32w0xfffffffc):right1_clamp();
(8w2,8w1&&&8w1,32w0x28&&&32w0xfffffff8):right1_clamp();
(8w2,8w1&&&8w1,32w0x30&&&32w0xfffffffc):right1_clamp();
(8w2,8w1&&&8w1,32w0x34&&&32w0xfffffffe):right1_clamp();
(8w2,8w1&&&8w1,32w0x36&&&32w0xffffffff):right1_clamp();
(8w2,8w1&&&8w1,32w0x37&&&32w0xffffffff):right1_shift();
(8w2,8w1&&&8w1,32w0x38&&&32w0xfffffff8):right1_shift();
(8w2,8w1&&&8w1,32w0x40&&&32w0xffffffc0):right1_shift();
(8w2,8w1&&&8w1,32w0x80&&&32w0xffffff80):right1_shift();
(8w2,8w1&&&8w1,32w0x100&&&32w0xffffff00):right1_shift();
(8w2,8w1&&&8w1,32w0x200&&&32w0xfffffe00):right1_shift();
(8w2,8w1&&&8w1,32w0x400&&&32w0xfffffc00):right1_shift();
(8w2,8w1&&&8w1,32w0x800&&&32w0xfffff800):right1_shift();
(8w2,8w1&&&8w1,32w0x1000&&&32w0xfffff000):right1_shift();
(8w2,8w1&&&8w1,32w0x2000&&&32w0xffffe000):right1_shift();
(8w2,8w1&&&8w1,32w0x4000&&&32w0xffffc000):right1_shift();
(8w2,8w1&&&8w1,32w0x8000&&&32w0xffff8000):right1_shift();
(8w2,8w1&&&8w1,32w0x10000&&&32w0xffff0000):right1_shift();
(8w2,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):right1_shift();
(8w2,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):right1_shift();
(8w2,8w1&&&8w1,32w0x80000&&&32w0xfff80000):right1_shift();
(8w2,8w1&&&8w1,32w0x100000&&&32w0xfff00000):right1_shift();
(8w2,8w1&&&8w1,32w0x200000&&&32w0xffe00000):right1_shift();
(8w2,8w1&&&8w1,32w0x400000&&&32w0xffc00000):right1_shift();
(8w2,8w1&&&8w1,32w0x800000&&&32w0xff800000):right1_shift();
(8w2,8w1&&&8w1,32w0x1000000&&&32w0xff000000):right1_shift();
(8w2,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):right1_shift();
(8w2,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):right1_shift();
(8w2,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):right1_shift();
(8w2,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):right1_shift();
(8w2,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):right1_shift();
(8w2,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):right1_shift();
}}
action right2_shift(){m.native_right=m.right-32w40;}
action right2_clamp(){m.native_right=m.second+32w34;}
table right2{key={m.direction:exact;m.valid:ternary;m.ro2:ternary;}actions={right2_shift;NoAction;right2_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w2&&&8w2,32w0x37&&&32w0xffffffff):right2_clamp();
(8w2,8w2&&&8w2,32w0x38&&&32w0xfffffff8):right2_clamp();
(8w2,8w2&&&8w2,32w0x40&&&32w0xfffffff8):right2_clamp();
(8w2,8w2&&&8w2,32w0x48&&&32w0xfffffffe):right2_clamp();
(8w2,8w2&&&8w2,32w0x4a&&&32w0xffffffff):right2_clamp();
(8w2,8w2&&&8w2,32w0x4b&&&32w0xffffffff):right2_shift();
(8w2,8w2&&&8w2,32w0x4c&&&32w0xfffffffc):right2_shift();
(8w2,8w2&&&8w2,32w0x50&&&32w0xfffffff0):right2_shift();
(8w2,8w2&&&8w2,32w0x60&&&32w0xffffffe0):right2_shift();
(8w2,8w2&&&8w2,32w0x80&&&32w0xffffff80):right2_shift();
(8w2,8w2&&&8w2,32w0x100&&&32w0xffffff00):right2_shift();
(8w2,8w2&&&8w2,32w0x200&&&32w0xfffffe00):right2_shift();
(8w2,8w2&&&8w2,32w0x400&&&32w0xfffffc00):right2_shift();
(8w2,8w2&&&8w2,32w0x800&&&32w0xfffff800):right2_shift();
(8w2,8w2&&&8w2,32w0x1000&&&32w0xfffff000):right2_shift();
(8w2,8w2&&&8w2,32w0x2000&&&32w0xffffe000):right2_shift();
(8w2,8w2&&&8w2,32w0x4000&&&32w0xffffc000):right2_shift();
(8w2,8w2&&&8w2,32w0x8000&&&32w0xffff8000):right2_shift();
(8w2,8w2&&&8w2,32w0x10000&&&32w0xffff0000):right2_shift();
(8w2,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):right2_shift();
(8w2,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):right2_shift();
(8w2,8w2&&&8w2,32w0x80000&&&32w0xfff80000):right2_shift();
(8w2,8w2&&&8w2,32w0x100000&&&32w0xfff00000):right2_shift();
(8w2,8w2&&&8w2,32w0x200000&&&32w0xffe00000):right2_shift();
(8w2,8w2&&&8w2,32w0x400000&&&32w0xffc00000):right2_shift();
(8w2,8w2&&&8w2,32w0x800000&&&32w0xff800000):right2_shift();
(8w2,8w2&&&8w2,32w0x1000000&&&32w0xff000000):right2_shift();
(8w2,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):right2_shift();
(8w2,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):right2_shift();
(8w2,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):right2_shift();
(8w2,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):right2_shift();
(8w2,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):right2_shift();
(8w2,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):right2_shift();
}}
action difference(){m.growth=m.native_right-m.left;m.window_after=m.native_right-m.left;}
 table difference_t{actions={difference;}size=1;const default_action=difference();}
 action growth(){m.growth=m.growth-m.full_window;}
 table growth_t{actions={growth;}size=1;const default_action=growth();}
 table window_guard{key={m.growth:ternary;}actions={deny;NoAction;}size=32;const default_action=NoAction();const entries={
(32w0x1&&&32w0xffffffff):deny();
(32w0x2&&&32w0xfffffffe):deny();
(32w0x4&&&32w0xfffffffc):deny();
(32w0x8&&&32w0xfffffff8):deny();
(32w0x10&&&32w0xfffffff0):deny();
(32w0x20&&&32w0xffffffe0):deny();
(32w0x40&&&32w0xffffffc0):deny();
(32w0x80&&&32w0xffffff80):deny();
(32w0x100&&&32w0xffffff00):deny();
(32w0x200&&&32w0xfffffe00):deny();
(32w0x400&&&32w0xfffffc00):deny();
(32w0x800&&&32w0xfffff800):deny();
(32w0x1000&&&32w0xfffff000):deny();
(32w0x2000&&&32w0xffffe000):deny();
(32w0x4000&&&32w0xffffc000):deny();
(32w0x8000&&&32w0xffff8000):deny();
(32w0x10000&&&32w0xffff0000):deny();
(32w0x20000&&&32w0xfffe0000):deny();
(32w0x40000&&&32w0xfffc0000):deny();
(32w0x80000&&&32w0xfff80000):deny();
(32w0x100000&&&32w0xfff00000):deny();
(32w0x200000&&&32w0xffe00000):deny();
(32w0x400000&&&32w0xffc00000):deny();
(32w0x800000&&&32w0xff800000):deny();
(32w0x1000000&&&32w0xff000000):deny();
(32w0x2000000&&&32w0xfe000000):deny();
(32w0x4000000&&&32w0xfc000000):deny();
(32w0x8000000&&&32w0xf8000000):deny();
(32w0x10000000&&&32w0xf0000000):deny();
(32w0x20000000&&&32w0xe0000000):deny();
(32w0x40000000&&&32w0xc0000000):deny();
}}
 action window_narrow(){m.output_window=(bit<16>)m.window_after;}
 table window_narrow_t{actions={window_narrow;}size=1;const default_action=window_narrow();}
 action complete(){hdr.tcp.seq=m.seq_result;hdr.tcp.ack=m.left;hdr.tcp.window=m.output_window;m.changed=1w1;tm.ucast_egress_port=m.output_port;}
 table complete_t{actions={complete;}size=1;const default_action=complete();}
 apply{forwarding.apply();if(m.parsed==8w1 && !m.ip_error && m.tcp_sum==16w0xFFEB){
 connection.apply();if(m.direction!=8w0){prepare_window_t.apply();edges_t.apply();offsets_t.apply();seq1.apply();seq2.apply();
 hdr.tcp.seq=m.seq_result;m.changed=1w1;}}}
}
control forward_IgDeparser(packet_out pkt,inout forward_headers_t hdr,in forward_meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() tcpcheck;apply{if(m.changed==1w1){hdr.tcp.checksum=tcpcheck.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_len,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}
parser forward_EgParser(packet_in pkt,out forward_headers_t hdr,out forward_meta_t m){state start{transition eth;}state eth{pkt.extract(hdr.eth);transition ip;}state ip{pkt.extract(hdr.ip);transition tcp;}state tcp{pkt.extract(hdr.tcp);transition accept;}}
control forward_Egress(inout forward_headers_t hdr,inout forward_meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control forward_EgDeparser(packet_out pkt,inout forward_headers_t hdr,in forward_meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}

/* Direction 2 grouped TCP mapping primitive. CP-seeded two-boundary state only; no handshake/producer.
 * One ingress pass completes a real pure-ACK packet; no internal placeholder completion.
 * Default forwarding/profile tables deny. No hardware qualification. */
header reverse_eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header reverse_ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header reverse_tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
struct reverse_headers_t {reverse_eth_h eth;reverse_ip_h ip;reverse_tcp_h tcp;}
struct reverse_meta_t {bit<32> first;bit<32> second;bit<8> valid;bit<8> direction;PortId_t output_port;
 bit<32> right;bit<32> left;bit<32> native_right;bit<32> so1;bit<32> so2;bit<32> ao1;bit<32> ao2;bit<32> ro1;bit<32> ro2;
 bit<32> seq_result;bit<16> output_window;bit<32> full_window;bit<32> window_after;bit<32> original_seq;bit<32> original_ack;bit<32> growth;bit<16> original_window;bit<16> tcp_len;bit<16> tcp_sum;bool ip_error;bit<8> parsed;bit<1> changed;}
parser reverse_IgParser(packet_in pkt,out reverse_headers_t hdr,out reverse_meta_t m){
 Checksum() ipcheck;Checksum() tcpcheck;
 state start{m.parsed=8w0;m.changed=1w0;m.direction=8w0;m.valid=8w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ipcheck.add(hdr.ip);m.ip_error=ipcheck.verify();tcpcheck.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});
 transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w40):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tcpcheck.subtract(hdr.tcp);m.tcp_sum=tcpcheck.get();transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):eligible;default:accept;} }
 state eligible{m.parsed=8w1;transition accept;}
}
@pa_container_size("ingress", "hdr.reverse.tcp.seq", 32)
@pa_container_size("ingress", "hdr.reverse.tcp.ack", 32)
@pa_container_size("ingress", "m.reverse.first", 32)
@pa_container_size("ingress", "m.reverse.second", 32)
@pa_container_size("ingress", "m.reverse.right", 32)
@pa_container_size("ingress", "m.reverse.left", 32)
@pa_container_size("ingress", "m.reverse.native_right", 32)
@pa_container_size("ingress", "m.reverse.so1", 32)
@pa_container_size("ingress", "m.reverse.so2", 32)
@pa_container_size("ingress", "m.reverse.ao1", 32)
@pa_container_size("ingress", "m.reverse.ao2", 32)
@pa_container_size("ingress", "m.reverse.ro1", 32)
@pa_container_size("ingress", "m.reverse.ro2", 32)
@pa_container_size("ingress", "m.reverse.original_seq", 32)
@pa_container_size("ingress", "m.reverse.original_ack", 32)
@pa_container_size("ingress", "m.reverse.growth", 32)
@pa_container_size("ingress", "m.reverse.full_window", 32)
@pa_container_size("ingress", "m.reverse.window_after", 32)
@pa_container_size("ingress", "m.reverse.seq_result", 32)
control reverse_Ingress(inout reverse_headers_t hdr,inout reverse_meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.output_port=port;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action configure(bit<32> first,bit<32> second,bit<8> valid,bit<8> direction){m.first=first;m.second=second;m.valid=valid;m.direction=direction;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=2;default_action=NoAction();}
 action prepare_window(){m.full_window=16w0++hdr.tcp.window;}
 table prepare_window_t{actions={prepare_window;}size=1;const default_action=prepare_window();}
 action edges(){m.right=hdr.tcp.ack+m.full_window;m.left=hdr.tcp.ack;m.original_ack=hdr.tcp.ack;m.original_seq=hdr.tcp.seq;m.seq_result=hdr.tcp.seq;m.original_window=hdr.tcp.window;m.tcp_len=16w20;}
 table edges_t{actions={edges;}size=1;const default_action=edges();}
 action offsets(){m.so1=m.original_seq-m.first;m.so2=m.original_seq-m.second;m.ao1=m.original_ack-m.first;m.ao2=m.original_ack-m.second;m.ro1=m.right-m.first;m.ro2=m.right-m.second;m.native_right=m.right;}
 table offsets_t{actions={offsets;}size=1;const default_action=offsets();}
action seq1_shift(){m.seq_result=m.original_seq+32w20;}
table seq1{key={m.direction:exact;m.valid:ternary;m.so1:ternary;}actions={seq1_shift;NoAction;}size=128;const default_action=NoAction();const entries={
(8w1,8w1&&&8w1,32w0x23&&&32w0xffffffff):seq1_shift();
(8w1,8w1&&&8w1,32w0x24&&&32w0xfffffffc):seq1_shift();
(8w1,8w1&&&8w1,32w0x28&&&32w0xfffffff8):seq1_shift();
(8w1,8w1&&&8w1,32w0x30&&&32w0xfffffff0):seq1_shift();
(8w1,8w1&&&8w1,32w0x40&&&32w0xffffffc0):seq1_shift();
(8w1,8w1&&&8w1,32w0x80&&&32w0xffffff80):seq1_shift();
(8w1,8w1&&&8w1,32w0x100&&&32w0xffffff00):seq1_shift();
(8w1,8w1&&&8w1,32w0x200&&&32w0xfffffe00):seq1_shift();
(8w1,8w1&&&8w1,32w0x400&&&32w0xfffffc00):seq1_shift();
(8w1,8w1&&&8w1,32w0x800&&&32w0xfffff800):seq1_shift();
(8w1,8w1&&&8w1,32w0x1000&&&32w0xfffff000):seq1_shift();
(8w1,8w1&&&8w1,32w0x2000&&&32w0xffffe000):seq1_shift();
(8w1,8w1&&&8w1,32w0x4000&&&32w0xffffc000):seq1_shift();
(8w1,8w1&&&8w1,32w0x8000&&&32w0xffff8000):seq1_shift();
(8w1,8w1&&&8w1,32w0x10000&&&32w0xffff0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):seq1_shift();
(8w1,8w1&&&8w1,32w0x80000&&&32w0xfff80000):seq1_shift();
(8w1,8w1&&&8w1,32w0x100000&&&32w0xfff00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x200000&&&32w0xffe00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x400000&&&32w0xffc00000):seq1_shift();
(8w1,8w1&&&8w1,32w0x800000&&&32w0xff800000):seq1_shift();
(8w1,8w1&&&8w1,32w0x1000000&&&32w0xff000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):seq1_shift();
(8w1,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):seq1_shift();
}}
action seq2_shift(){m.seq_result=m.original_seq+32w40;}
table seq2{key={m.direction:exact;m.valid:ternary;m.so2:ternary;}actions={seq2_shift;NoAction;}size=128;const default_action=NoAction();const entries={
(8w1,8w2&&&8w2,32w0x23&&&32w0xffffffff):seq2_shift();
(8w1,8w2&&&8w2,32w0x24&&&32w0xfffffffc):seq2_shift();
(8w1,8w2&&&8w2,32w0x28&&&32w0xfffffff8):seq2_shift();
(8w1,8w2&&&8w2,32w0x30&&&32w0xfffffff0):seq2_shift();
(8w1,8w2&&&8w2,32w0x40&&&32w0xffffffc0):seq2_shift();
(8w1,8w2&&&8w2,32w0x80&&&32w0xffffff80):seq2_shift();
(8w1,8w2&&&8w2,32w0x100&&&32w0xffffff00):seq2_shift();
(8w1,8w2&&&8w2,32w0x200&&&32w0xfffffe00):seq2_shift();
(8w1,8w2&&&8w2,32w0x400&&&32w0xfffffc00):seq2_shift();
(8w1,8w2&&&8w2,32w0x800&&&32w0xfffff800):seq2_shift();
(8w1,8w2&&&8w2,32w0x1000&&&32w0xfffff000):seq2_shift();
(8w1,8w2&&&8w2,32w0x2000&&&32w0xffffe000):seq2_shift();
(8w1,8w2&&&8w2,32w0x4000&&&32w0xffffc000):seq2_shift();
(8w1,8w2&&&8w2,32w0x8000&&&32w0xffff8000):seq2_shift();
(8w1,8w2&&&8w2,32w0x10000&&&32w0xffff0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):seq2_shift();
(8w1,8w2&&&8w2,32w0x80000&&&32w0xfff80000):seq2_shift();
(8w1,8w2&&&8w2,32w0x100000&&&32w0xfff00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x200000&&&32w0xffe00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x400000&&&32w0xffc00000):seq2_shift();
(8w1,8w2&&&8w2,32w0x800000&&&32w0xff800000):seq2_shift();
(8w1,8w2&&&8w2,32w0x1000000&&&32w0xff000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):seq2_shift();
(8w1,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):seq2_shift();
}}
action left1_shift(){m.left=m.original_ack-32w20;}
action left1_clamp(){m.left=m.first+32w34;}
table left1{key={m.direction:exact;m.valid:ternary;m.ao1:ternary;}actions={left1_shift;NoAction;left1_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w1&&&8w1,32w0x23&&&32w0xffffffff):left1_clamp();
(8w2,8w1&&&8w1,32w0x24&&&32w0xfffffffc):left1_clamp();
(8w2,8w1&&&8w1,32w0x28&&&32w0xfffffff8):left1_clamp();
(8w2,8w1&&&8w1,32w0x30&&&32w0xfffffffc):left1_clamp();
(8w2,8w1&&&8w1,32w0x34&&&32w0xfffffffe):left1_clamp();
(8w2,8w1&&&8w1,32w0x36&&&32w0xffffffff):left1_clamp();
(8w2,8w1&&&8w1,32w0x37&&&32w0xffffffff):left1_shift();
(8w2,8w1&&&8w1,32w0x38&&&32w0xfffffff8):left1_shift();
(8w2,8w1&&&8w1,32w0x40&&&32w0xffffffc0):left1_shift();
(8w2,8w1&&&8w1,32w0x80&&&32w0xffffff80):left1_shift();
(8w2,8w1&&&8w1,32w0x100&&&32w0xffffff00):left1_shift();
(8w2,8w1&&&8w1,32w0x200&&&32w0xfffffe00):left1_shift();
(8w2,8w1&&&8w1,32w0x400&&&32w0xfffffc00):left1_shift();
(8w2,8w1&&&8w1,32w0x800&&&32w0xfffff800):left1_shift();
(8w2,8w1&&&8w1,32w0x1000&&&32w0xfffff000):left1_shift();
(8w2,8w1&&&8w1,32w0x2000&&&32w0xffffe000):left1_shift();
(8w2,8w1&&&8w1,32w0x4000&&&32w0xffffc000):left1_shift();
(8w2,8w1&&&8w1,32w0x8000&&&32w0xffff8000):left1_shift();
(8w2,8w1&&&8w1,32w0x10000&&&32w0xffff0000):left1_shift();
(8w2,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):left1_shift();
(8w2,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):left1_shift();
(8w2,8w1&&&8w1,32w0x80000&&&32w0xfff80000):left1_shift();
(8w2,8w1&&&8w1,32w0x100000&&&32w0xfff00000):left1_shift();
(8w2,8w1&&&8w1,32w0x200000&&&32w0xffe00000):left1_shift();
(8w2,8w1&&&8w1,32w0x400000&&&32w0xffc00000):left1_shift();
(8w2,8w1&&&8w1,32w0x800000&&&32w0xff800000):left1_shift();
(8w2,8w1&&&8w1,32w0x1000000&&&32w0xff000000):left1_shift();
(8w2,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):left1_shift();
(8w2,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):left1_shift();
(8w2,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):left1_shift();
(8w2,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):left1_shift();
(8w2,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):left1_shift();
(8w2,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):left1_shift();
}}
action left2_shift(){m.left=m.original_ack-32w40;}
action left2_clamp(){m.left=m.second+32w34;}
table left2{key={m.direction:exact;m.valid:ternary;m.ao2:ternary;}actions={left2_shift;NoAction;left2_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w2&&&8w2,32w0x37&&&32w0xffffffff):left2_clamp();
(8w2,8w2&&&8w2,32w0x38&&&32w0xfffffff8):left2_clamp();
(8w2,8w2&&&8w2,32w0x40&&&32w0xfffffff8):left2_clamp();
(8w2,8w2&&&8w2,32w0x48&&&32w0xfffffffe):left2_clamp();
(8w2,8w2&&&8w2,32w0x4a&&&32w0xffffffff):left2_clamp();
(8w2,8w2&&&8w2,32w0x4b&&&32w0xffffffff):left2_shift();
(8w2,8w2&&&8w2,32w0x4c&&&32w0xfffffffc):left2_shift();
(8w2,8w2&&&8w2,32w0x50&&&32w0xfffffff0):left2_shift();
(8w2,8w2&&&8w2,32w0x60&&&32w0xffffffe0):left2_shift();
(8w2,8w2&&&8w2,32w0x80&&&32w0xffffff80):left2_shift();
(8w2,8w2&&&8w2,32w0x100&&&32w0xffffff00):left2_shift();
(8w2,8w2&&&8w2,32w0x200&&&32w0xfffffe00):left2_shift();
(8w2,8w2&&&8w2,32w0x400&&&32w0xfffffc00):left2_shift();
(8w2,8w2&&&8w2,32w0x800&&&32w0xfffff800):left2_shift();
(8w2,8w2&&&8w2,32w0x1000&&&32w0xfffff000):left2_shift();
(8w2,8w2&&&8w2,32w0x2000&&&32w0xffffe000):left2_shift();
(8w2,8w2&&&8w2,32w0x4000&&&32w0xffffc000):left2_shift();
(8w2,8w2&&&8w2,32w0x8000&&&32w0xffff8000):left2_shift();
(8w2,8w2&&&8w2,32w0x10000&&&32w0xffff0000):left2_shift();
(8w2,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):left2_shift();
(8w2,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):left2_shift();
(8w2,8w2&&&8w2,32w0x80000&&&32w0xfff80000):left2_shift();
(8w2,8w2&&&8w2,32w0x100000&&&32w0xfff00000):left2_shift();
(8w2,8w2&&&8w2,32w0x200000&&&32w0xffe00000):left2_shift();
(8w2,8w2&&&8w2,32w0x400000&&&32w0xffc00000):left2_shift();
(8w2,8w2&&&8w2,32w0x800000&&&32w0xff800000):left2_shift();
(8w2,8w2&&&8w2,32w0x1000000&&&32w0xff000000):left2_shift();
(8w2,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):left2_shift();
(8w2,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):left2_shift();
(8w2,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):left2_shift();
(8w2,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):left2_shift();
(8w2,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):left2_shift();
(8w2,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):left2_shift();
}}
action right1_shift(){m.native_right=m.right-32w20;}
action right1_clamp(){m.native_right=m.first+32w34;}
table right1{key={m.direction:exact;m.valid:ternary;m.ro1:ternary;}actions={right1_shift;NoAction;right1_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w1&&&8w1,32w0x23&&&32w0xffffffff):right1_clamp();
(8w2,8w1&&&8w1,32w0x24&&&32w0xfffffffc):right1_clamp();
(8w2,8w1&&&8w1,32w0x28&&&32w0xfffffff8):right1_clamp();
(8w2,8w1&&&8w1,32w0x30&&&32w0xfffffffc):right1_clamp();
(8w2,8w1&&&8w1,32w0x34&&&32w0xfffffffe):right1_clamp();
(8w2,8w1&&&8w1,32w0x36&&&32w0xffffffff):right1_clamp();
(8w2,8w1&&&8w1,32w0x37&&&32w0xffffffff):right1_shift();
(8w2,8w1&&&8w1,32w0x38&&&32w0xfffffff8):right1_shift();
(8w2,8w1&&&8w1,32w0x40&&&32w0xffffffc0):right1_shift();
(8w2,8w1&&&8w1,32w0x80&&&32w0xffffff80):right1_shift();
(8w2,8w1&&&8w1,32w0x100&&&32w0xffffff00):right1_shift();
(8w2,8w1&&&8w1,32w0x200&&&32w0xfffffe00):right1_shift();
(8w2,8w1&&&8w1,32w0x400&&&32w0xfffffc00):right1_shift();
(8w2,8w1&&&8w1,32w0x800&&&32w0xfffff800):right1_shift();
(8w2,8w1&&&8w1,32w0x1000&&&32w0xfffff000):right1_shift();
(8w2,8w1&&&8w1,32w0x2000&&&32w0xffffe000):right1_shift();
(8w2,8w1&&&8w1,32w0x4000&&&32w0xffffc000):right1_shift();
(8w2,8w1&&&8w1,32w0x8000&&&32w0xffff8000):right1_shift();
(8w2,8w1&&&8w1,32w0x10000&&&32w0xffff0000):right1_shift();
(8w2,8w1&&&8w1,32w0x20000&&&32w0xfffe0000):right1_shift();
(8w2,8w1&&&8w1,32w0x40000&&&32w0xfffc0000):right1_shift();
(8w2,8w1&&&8w1,32w0x80000&&&32w0xfff80000):right1_shift();
(8w2,8w1&&&8w1,32w0x100000&&&32w0xfff00000):right1_shift();
(8w2,8w1&&&8w1,32w0x200000&&&32w0xffe00000):right1_shift();
(8w2,8w1&&&8w1,32w0x400000&&&32w0xffc00000):right1_shift();
(8w2,8w1&&&8w1,32w0x800000&&&32w0xff800000):right1_shift();
(8w2,8w1&&&8w1,32w0x1000000&&&32w0xff000000):right1_shift();
(8w2,8w1&&&8w1,32w0x2000000&&&32w0xfe000000):right1_shift();
(8w2,8w1&&&8w1,32w0x4000000&&&32w0xfc000000):right1_shift();
(8w2,8w1&&&8w1,32w0x8000000&&&32w0xf8000000):right1_shift();
(8w2,8w1&&&8w1,32w0x10000000&&&32w0xf0000000):right1_shift();
(8w2,8w1&&&8w1,32w0x20000000&&&32w0xe0000000):right1_shift();
(8w2,8w1&&&8w1,32w0x40000000&&&32w0xc0000000):right1_shift();
}}
action right2_shift(){m.native_right=m.right-32w40;}
action right2_clamp(){m.native_right=m.second+32w34;}
table right2{key={m.direction:exact;m.valid:ternary;m.ro2:ternary;}actions={right2_shift;NoAction;right2_clamp;}size=128;const default_action=NoAction();const entries={
(8w2,8w2&&&8w2,32w0x37&&&32w0xffffffff):right2_clamp();
(8w2,8w2&&&8w2,32w0x38&&&32w0xfffffff8):right2_clamp();
(8w2,8w2&&&8w2,32w0x40&&&32w0xfffffff8):right2_clamp();
(8w2,8w2&&&8w2,32w0x48&&&32w0xfffffffe):right2_clamp();
(8w2,8w2&&&8w2,32w0x4a&&&32w0xffffffff):right2_clamp();
(8w2,8w2&&&8w2,32w0x4b&&&32w0xffffffff):right2_shift();
(8w2,8w2&&&8w2,32w0x4c&&&32w0xfffffffc):right2_shift();
(8w2,8w2&&&8w2,32w0x50&&&32w0xfffffff0):right2_shift();
(8w2,8w2&&&8w2,32w0x60&&&32w0xffffffe0):right2_shift();
(8w2,8w2&&&8w2,32w0x80&&&32w0xffffff80):right2_shift();
(8w2,8w2&&&8w2,32w0x100&&&32w0xffffff00):right2_shift();
(8w2,8w2&&&8w2,32w0x200&&&32w0xfffffe00):right2_shift();
(8w2,8w2&&&8w2,32w0x400&&&32w0xfffffc00):right2_shift();
(8w2,8w2&&&8w2,32w0x800&&&32w0xfffff800):right2_shift();
(8w2,8w2&&&8w2,32w0x1000&&&32w0xfffff000):right2_shift();
(8w2,8w2&&&8w2,32w0x2000&&&32w0xffffe000):right2_shift();
(8w2,8w2&&&8w2,32w0x4000&&&32w0xffffc000):right2_shift();
(8w2,8w2&&&8w2,32w0x8000&&&32w0xffff8000):right2_shift();
(8w2,8w2&&&8w2,32w0x10000&&&32w0xffff0000):right2_shift();
(8w2,8w2&&&8w2,32w0x20000&&&32w0xfffe0000):right2_shift();
(8w2,8w2&&&8w2,32w0x40000&&&32w0xfffc0000):right2_shift();
(8w2,8w2&&&8w2,32w0x80000&&&32w0xfff80000):right2_shift();
(8w2,8w2&&&8w2,32w0x100000&&&32w0xfff00000):right2_shift();
(8w2,8w2&&&8w2,32w0x200000&&&32w0xffe00000):right2_shift();
(8w2,8w2&&&8w2,32w0x400000&&&32w0xffc00000):right2_shift();
(8w2,8w2&&&8w2,32w0x800000&&&32w0xff800000):right2_shift();
(8w2,8w2&&&8w2,32w0x1000000&&&32w0xff000000):right2_shift();
(8w2,8w2&&&8w2,32w0x2000000&&&32w0xfe000000):right2_shift();
(8w2,8w2&&&8w2,32w0x4000000&&&32w0xfc000000):right2_shift();
(8w2,8w2&&&8w2,32w0x8000000&&&32w0xf8000000):right2_shift();
(8w2,8w2&&&8w2,32w0x10000000&&&32w0xf0000000):right2_shift();
(8w2,8w2&&&8w2,32w0x20000000&&&32w0xe0000000):right2_shift();
(8w2,8w2&&&8w2,32w0x40000000&&&32w0xc0000000):right2_shift();
}}
action difference(){m.growth=m.native_right-m.left;m.window_after=m.native_right-m.left;}
 table difference_t{actions={difference;}size=1;const default_action=difference();}
 action growth(){m.growth=m.growth-m.full_window;}
 table growth_t{actions={growth;}size=1;const default_action=growth();}
 table window_guard{key={m.growth:ternary;}actions={deny;NoAction;}size=32;const default_action=NoAction();const entries={
(32w0x1&&&32w0xffffffff):deny();
(32w0x2&&&32w0xfffffffe):deny();
(32w0x4&&&32w0xfffffffc):deny();
(32w0x8&&&32w0xfffffff8):deny();
(32w0x10&&&32w0xfffffff0):deny();
(32w0x20&&&32w0xffffffe0):deny();
(32w0x40&&&32w0xffffffc0):deny();
(32w0x80&&&32w0xffffff80):deny();
(32w0x100&&&32w0xffffff00):deny();
(32w0x200&&&32w0xfffffe00):deny();
(32w0x400&&&32w0xfffffc00):deny();
(32w0x800&&&32w0xfffff800):deny();
(32w0x1000&&&32w0xfffff000):deny();
(32w0x2000&&&32w0xffffe000):deny();
(32w0x4000&&&32w0xffffc000):deny();
(32w0x8000&&&32w0xffff8000):deny();
(32w0x10000&&&32w0xffff0000):deny();
(32w0x20000&&&32w0xfffe0000):deny();
(32w0x40000&&&32w0xfffc0000):deny();
(32w0x80000&&&32w0xfff80000):deny();
(32w0x100000&&&32w0xfff00000):deny();
(32w0x200000&&&32w0xffe00000):deny();
(32w0x400000&&&32w0xffc00000):deny();
(32w0x800000&&&32w0xff800000):deny();
(32w0x1000000&&&32w0xff000000):deny();
(32w0x2000000&&&32w0xfe000000):deny();
(32w0x4000000&&&32w0xfc000000):deny();
(32w0x8000000&&&32w0xf8000000):deny();
(32w0x10000000&&&32w0xf0000000):deny();
(32w0x20000000&&&32w0xe0000000):deny();
(32w0x40000000&&&32w0xc0000000):deny();
}}
 action window_narrow(){m.output_window=(bit<16>)m.window_after;}
 table window_narrow_t{actions={window_narrow;}size=1;const default_action=window_narrow();}
 action complete(){hdr.tcp.ack=m.left;hdr.tcp.window=m.output_window;m.changed=1w1;tm.ucast_egress_port=m.output_port;}
 table complete_t{actions={complete;}size=1;const default_action=complete();}
 apply{forwarding.apply();if(m.parsed==8w1 && !m.ip_error && m.tcp_sum==16w0xFFEB){
 connection.apply();if(m.direction!=8w0){prepare_window_t.apply();edges_t.apply();offsets_t.apply();left1.apply();left2.apply();right1.apply();right2.apply();
 {difference_t.apply();growth_t.apply();window_guard.apply();window_narrow_t.apply();complete_t.apply();}}}}
}
control reverse_IgDeparser(packet_out pkt,inout reverse_headers_t hdr,in reverse_meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() tcpcheck;apply{if(m.changed==1w1){hdr.tcp.checksum=tcpcheck.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_len,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}
parser reverse_EgParser(packet_in pkt,out reverse_headers_t hdr,out reverse_meta_t m){state start{transition eth;}state eth{pkt.extract(hdr.eth);transition ip;}state ip{pkt.extract(hdr.ip);transition tcp;}state tcp{pkt.extract(hdr.tcp);transition accept;}}
control reverse_Egress(inout reverse_headers_t hdr,inout reverse_meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control reverse_EgDeparser(packet_out pkt,inout reverse_headers_t hdr,in reverse_meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}

/* Response57 CRC/profile validator + ordered TCP carve primitive; no transaction association/queue order proof. */
header carving_eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header carving_ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header carving_tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header carving_dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header carving_block_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<16> crc;}
header carving_tail_h{bit<32> w0;bit<32> w1;bit<8> w2;bit<16> crc;}
struct carving_headers_t{carving_eth_h eth;carving_ip_h ip;carving_tcp_h tcp;carving_dl_h dl;carving_block_h first;carving_block_h second;carving_tail_h tail;}
struct carving_meta_t{bit<1> selected_match;bit<1> parsed;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> hcrc;bit<16> crc0;bit<16> crc1;bit<16> crct;bit<1> badh;bit<1> bad0;bit<1> bad1;bit<1> badt;bit<1> profile;}
parser carving_IgParser(packet_in pkt,out carving_headers_t hdr,out carving_meta_t m){Checksum() ic;Checksum() tc;
 state start{m.parsed=1w0;m.selected_match=1w0;m.changed=1w0;m.badh=1w0;m.bad0=1w0;m.bad1=1w0;m.badt=1w0;m.profile=1w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w97):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):dl;(4w5,4w0,8w0x18,16w0):dl;default:accept;}}
 state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition first;}
 state first{pkt.extract(hdr.first);tc.subtract(hdr.first);transition second;}
 state second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control carving_Ingress(inout carving_headers_t hdr,inout carving_meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action split(bit<16> mgid){tm.mcast_grp_a=mgid;tm.bypass_egress=1w0;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={split;NoAction;}size=1;default_action=NoAction();}
action selected(){m.selected_match=1w1;}
table selected_objects{key={hdr.dl.dst:exact;hdr.dl.src:exact;hdr.first.w0[31:24]:exact;hdr.first.w0[23:16]:exact;hdr.first.w2[15:0]:exact;hdr.first.w3:exact;hdr.second.w0:exact;hdr.second.w1[31:16]:exact;hdr.second.w3:exact;hdr.tail.w0:exact;hdr.tail.w1:exact;}actions={selected;NoAction;}size=2;default_action=NoAction();}
 action eligible(){m.profile=1w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:8]:exact;hdr.first.w1[23:0]:exact;hdr.first.w2[31:16]:exact;hdr.second.w1[7:0]:exact;hdr.second.w2:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w46,8w0x44,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,24w0x0C0128,16w0x0100,8w12,32w0x01280100):eligible();}}
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_head;
action crc_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table crc_head_t{actions={crc_head;}size=1;const default_action=crc_head();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_first;
action crc_first(){m.crc0=hash_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}
table crc_first_t{actions={crc_first;}size=1;const default_action=crc_first();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_second;
action crc_second(){m.crc1=hash_second.get({hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3});}
table crc_second_t{actions={crc_second;}size=1;const default_action=crc_second();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;
action crc_tail(){m.crct=hash_tail.get({hdr.tail.w0,hdr.tail.w1,hdr.tail.w2});}
table crc_tail_t{actions={crc_tail;}size=1;const default_action=crc_tail();}
apply{forwarding.apply();if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB){profile.apply();if(m.profile==1w1){crc_head_t.apply();crc_first_t.apply();crc_second_t.apply();crc_tail_t.apply();if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}if(hdr.first.crc!=(m.crc0[7:0]++m.crc0[15:8])){m.bad0=1w1;}if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=1w1;}if(hdr.tail.crc!=(m.crct[7:0]++m.crct[15:8])){m.badt=1w1;}if(md.drop_ctl==3w0&&m.badh==1w0&&m.bad0==1w0&&m.bad1==1w0&&m.badt==1w0){selected_objects.apply();if(m.selected_match==1w1){connection.apply();}}}}}
}
control carving_IgDeparser(packet_out pkt,inout carving_headers_t hdr,in carving_meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.first);pkt.emit(hdr.second);pkt.emit(hdr.tail);}}
parser carving_EgParser(packet_in pkt,out carving_headers_t hdr,out carving_meta_t m){state start{m.changed=1w0;transition eth;}state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}state ip{pkt.extract(hdr.ip);transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w97):tcp;default:accept;}}state tcp{pkt.extract(hdr.tcp);transition dl;}state dl{pkt.extract(hdr.dl);transition first;}state first{pkt.extract(hdr.first);transition second;}state second{pkt.extract(hdr.second);transition tail;}state tail{pkt.extract(hdr.tail);transition accept;}}
control carving_Egress(inout carving_headers_t hdr,inout carving_meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 action render_first(){hdr.second.setInvalid();hdr.tail.setInvalid();hdr.ip.len=16w68;hdr.tcp.flags=hdr.tcp.flags&8w0xF7;m.changed=1w1;}
 action render_second(){hdr.dl.setInvalid();hdr.first.setInvalid();hdr.ip.len=16w69;hdr.tcp.seq=hdr.tcp.seq+32w28;m.changed=1w1;}
 table rendering{key={eg.egress_rid:exact;}actions={render_first;render_second;NoAction;}size=2;const default_action=NoAction();const entries={16w1:render_first();16w2:render_second();}}
 apply{if(hdr.tail.isValid()){rendering.apply();}m.tcp_length=hdr.ip.len-16w20;}
}
control carving_EgDeparser(packet_out pkt,inout carving_headers_t hdr,in carving_meta_t m,in egress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3,hdr.first.crc,hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3,hdr.second.crc,hdr.tail.w0,hdr.tail.w1,hdr.tail.w2,hdr.tail.crc});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.first);pkt.emit(hdr.second);pkt.emit(hdr.tail);}}

/* Native READ20/response49 full-profile observer. Default admission denies.
 * Exact frozen g10v2 range0..22 query. No timing owner/epoch association yet.
 * No holding/padding/carving; forwards original bytes and counts full validation.
 */
header read_eth_h{bit<48> dst;bit<48> src;bit<16> type;}
header read_ip_h{bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header read_tcp_h{bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header read_dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header read_request_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}
header read_first_h{bit<8> tp;bit<8> app;bit<8> func;bit<16> iin;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<48> values;bit<16> crc;}
header read_second_h{bit<128> values;bit<16> crc;}
header read_tail_h{bit<8> value;bit<16> crc;}
struct read_headers_t{read_eth_h eth;read_ip_h ip;read_tcp_h tcp;read_dl_h dl;read_request_h request;read_first_h first;read_second_h second;read_tail_h tail;}
struct read_meta_t{bit<8> parsed;bit<8> kind;bit<8> direction;bit<1> admitted;bit<1> profile;bit<1> slot;bit<1> badh;bit<1> bad0;bit<1> bad1;bit<1> badt;bit<1> badlink;bit<16> link_dst;bit<16> link_src;bool ip_error;bit<16> tcp_sum;bit<16> hcrc;bit<16> crc0;bit<16> crc1;bit<16> crct;}
parser read_IgParser(packet_in pkt,out read_headers_t hdr,out read_meta_t m){
 Checksum() ic;Checksum() tc;
 state start{m.parsed=8w0;m.kind=8w0;transition eth;}
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
control read_Ingress(inout read_headers_t hdr,inout read_meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.admitted=1w1;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action forward(PortId_t port,bit<16> dst,bit<16> src){m.direction=8w1;m.link_dst=dst;m.link_src=src;tm.ucast_egress_port=port;}
 action reverse(PortId_t port,bit<16> dst,bit<16> src){m.direction=8w2;m.link_dst=dst;m.link_src=src;tm.ucast_egress_port=port;}
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
 apply{m.admitted=1w0;m.profile=1w0;m.direction=8w0;m.badh=1w0;m.bad0=1w0;m.bad1=1w0;m.badt=1w0;m.badlink=1w0;
 forwarding.apply();
 if(p.parser_err==16w0){
 if(m.admitted==1w1&&m.parsed==8w1&&!m.ip_error&&m.tcp_sum==16w0xffeb&&hdr.ip.ttl!=8w0){
  connection.apply();head_t.apply();
  if(hdr.dl.dst!=m.link_dst){m.badlink=1w1;}
  if(hdr.dl.src!=m.link_src){m.badlink=1w1;}
  if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}
  if(m.kind==8w1){request_profile.apply();request_t.apply();
   if(hdr.request.crc!=(m.crc0[7:0]++m.crc0[15:8])){m.bad0=1w1;}
  }else if(m.kind==8w2){response_profile.apply();first_t.apply();second_t.apply();tail_t.apply();
   if(hdr.first.crc!=(m.crc0[7:0]++m.crc0[15:8])){m.bad0=1w1;}
   if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=1w1;}
   if(hdr.tail.crc!=(m.crct[7:0]++m.crct[15:8])){m.badt=1w1;}
  }
  if(m.profile==1w1&&m.badlink==1w0&&m.badh==1w0&&m.bad0==1w0&&m.bad1==1w0&&m.badt==1w0){observe_t.apply();}
 }
 }
 }
}
control read_IgDeparser(packet_out pkt,inout read_headers_t hdr,in read_meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser read_EgParser(packet_in pkt,out read_headers_t hdr,out read_meta_t m){state start{transition accept;}}
control read_Egress(inout read_headers_t hdr,inout read_meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control read_EgDeparser(packet_out pkt,inout read_headers_t hdr,in read_meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
header dispatch_h {bit<112> eth;bit<16> first;bit<16> len;}
struct headers_t {cache_headers_t cache;forward_headers_t forward;reverse_headers_t reverse;carving_headers_t carving;read_headers_t read;}
struct meta_t {bit<8> role;cache_meta_t cache;forward_meta_t forward;reverse_meta_t reverse;carving_meta_t carving;read_meta_t read;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
cache_IgParser() cache;
forward_IgParser() forward;
reverse_IgParser() reverse;
carving_IgParser() carving;
read_IgParser() read;
state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.role=8w0;m.cache.changed=1w0;m.forward.changed=1w0;m.reverse.changed=1w0;m.carving.changed=1w0;transition dispatch;}
state dispatch{transition select(ig.ingress_port,pkt.lookahead<dispatch_h>().len){
(9w9,16w75):cache_state;
(9w9,16w41):cache_state;
(9w9,16w40):forward_state;
(9w64,16w40):reverse_state;
(9w64,16w97):carving_state;
(9w9,16w60):read_state;
(9w64,16w89):read_state;
default:accept;}}
state cache_state{m.role=8w1;cache.apply(pkt,hdr.cache,m.cache);transition accept;}
state forward_state{m.role=8w2;forward.apply(pkt,hdr.forward,m.forward);transition accept;}
state reverse_state{m.role=8w3;reverse.apply(pkt,hdr.reverse,m.reverse);transition accept;}
state carving_state{m.role=8w4;carving.apply(pkt,hdr.carving,m.carving);transition accept;}
state read_state{m.role=8w5;read.apply(pkt,hdr.read,m.read);transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
cache_Ingress() cache;
forward_Ingress() forward;
reverse_Ingress() reverse;
carving_Ingress() carving;
read_Ingress() read;
apply{m.cache.changed=1w0;m.forward.changed=1w0;m.reverse.changed=1w0;m.carving.changed=1w0;if(p.parser_err==16w0){
if(m.role==8w1){cache.apply(hdr.cache,m.cache,ig,p,md,tm);}
else if(m.role==8w2){forward.apply(hdr.forward,m.forward,ig,p,md,tm);}
else if(m.role==8w3){reverse.apply(hdr.reverse,m.reverse,ig,p,md,tm);}
else if(m.role==8w4){carving.apply(hdr.carving,m.carving,ig,p,md,tm);}
else if(m.role==8w5){read.apply(hdr.read,m.read,ig,p,md,tm);}
else{md.drop_ctl=3w1;}}else{md.drop_ctl=3w1;}}}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){
cache_IgDeparser() cache;
forward_IgDeparser() forward;
reverse_IgDeparser() reverse;
carving_IgDeparser() carving;
read_IgDeparser() read;
apply{
cache.apply(pkt,hdr.cache,m.cache,md);
forward.apply(pkt,hdr.forward,m.forward,md);
reverse.apply(pkt,hdr.reverse,m.reverse,md);
carving.apply(pkt,hdr.carving,m.carving,md);
read.apply(pkt,hdr.read,m.read,md);
}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){
 cache_EgParser() cache;carving_EgParser() carving;
 state start{pkt.extract(eg);transition select(eg.egress_rid){16w1:carving_state;16w2:carving_state;default:cache_state;}}
 state cache_state{m.role=8w1;cache.apply(pkt,hdr.cache,m.cache);transition accept;}
 state carving_state{m.role=8w2;carving.apply(pkt,hdr.carving,m.carving);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 cache_Egress() cache;carving_Egress() carving;
 apply{m.cache.changed=1w0;m.carving.changed=1w0;if(p.parser_err==16w0){if(m.role==8w1){cache.apply(hdr.cache,m.cache,eg,p,md,port);}else if(m.role==8w2){carving.apply(hdr.carving,m.carving,eg,p,md,port);}else{md.drop_ctl=3w1;}}else{md.drop_ctl=3w1;}}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){
 cache_EgDeparser() cache;carving_EgDeparser() carving;
 apply{cache.apply(pkt,hdr.cache,m.cache,md);carving.apply(pkt,hdr.carving,m.carving,md);}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

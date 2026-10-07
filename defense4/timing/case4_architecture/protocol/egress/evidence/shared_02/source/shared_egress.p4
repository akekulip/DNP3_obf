/* Actual native35 validation/padding wire primitive. Default profile disabled. No lifecycle or assembly. */
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
header descriptor_h{bit<32> generation;bit<32> wire_start;bit<8> operation;bit<8> slot;bit<16> reserved;}
header image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
header byte_h{bit<8> data;}
struct headers_t{descriptor_h descriptor;image_h image;byte_h replay;eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;native_h native;tail_h tail;appended_h appended;final_h last;}
struct meta_t{bit<1> descriptor_valid;bit<1> replay_parsed;bit<1> replay_allowed;bit<32> generation;bit<32> wire_start;bit<8> native_last;bit<8> slot;bit<32> last_word;bit<1> parsed;bit<1> enabled;bit<1> profile;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.descriptor_valid=1w0;m.replay_parsed=1w0;m.replay_allowed=1w0;m.parsed=1w0;m.enabled=1w0;m.profile=1w0;m.changed=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w75,8w6):ip_flags;(4w4,4w5,16w41,8w6):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):payload;(4w5,4w0,8w0x18,16w0):payload;default:accept;}}
 state payload{transition select(hdr.ip.len){16w75:dl;16w41:replay;default:accept;}}
 state replay{pkt.extract(hdr.replay);tc.subtract(hdr.replay);m.tcp_sum=tc.get();m.replay_parsed=1w1;transition accept;}
 state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native;}
 state native{pkt.extract(hdr.native);tc.subtract(hdr.native);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
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
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on,hdr.native.crc,hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first,hdr.appended.crc,hdr.last.on_last,hdr.last.off,hdr.last.status,hdr.last.crc});}pkt.emit(hdr.descriptor);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.replay);pkt.emit(hdr.dl);pkt.emit(hdr.native);pkt.emit(hdr.tail);pkt.emit(hdr.appended);pkt.emit(hdr.last);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){
 state start{pkt.extract(eg);pkt.extract(hdr.descriptor);pkt.extract(hdr.eth);pkt.extract(hdr.ip);pkt.extract(hdr.tcp);transition select(hdr.descriptor.operation,hdr.descriptor.slot){(8w2,8w0):image;(8w2,8w1):image;(8w1,8w0):replay;(8w1,8w1):replay;default:reject;}}
 state image{pkt.extract(hdr.image);transition accept;}
 state replay{pkt.extract(hdr.replay);transition accept;}
}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
Register<bit<32>,bit<1>>(2,32w0) image_0;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_0) write_0={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w0;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_0) read_0={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_0(){write_0.execute(hdr.descriptor.slot[0:0]);}
 table store_0_t{actions={store_0;}size=1;const default_action=store_0();}
 action load_0(){hdr.image.w0=read_0.execute(hdr.descriptor.slot[0:0]);}
 table load_0_t{actions={load_0;}size=1;const default_action=load_0();}
Register<bit<32>,bit<1>>(2,32w0) image_1;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_1) write_1={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w1;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_1) read_1={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_1(){write_1.execute(hdr.descriptor.slot[0:0]);}
 table store_1_t{actions={store_1;}size=1;const default_action=store_1();}
 action load_1(){hdr.image.w1=read_1.execute(hdr.descriptor.slot[0:0]);}
 table load_1_t{actions={load_1;}size=1;const default_action=load_1();}
Register<bit<32>,bit<1>>(2,32w0) image_2;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_2) write_2={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w2;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_2) read_2={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_2(){write_2.execute(hdr.descriptor.slot[0:0]);}
 table store_2_t{actions={store_2;}size=1;const default_action=store_2();}
 action load_2(){hdr.image.w2=read_2.execute(hdr.descriptor.slot[0:0]);}
 table load_2_t{actions={load_2;}size=1;const default_action=load_2();}
Register<bit<32>,bit<1>>(2,32w0) image_3;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_3) write_3={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w3;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_3) read_3={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_3(){write_3.execute(hdr.descriptor.slot[0:0]);}
 table store_3_t{actions={store_3;}size=1;const default_action=store_3();}
 action load_3(){hdr.image.w3=read_3.execute(hdr.descriptor.slot[0:0]);}
 table load_3_t{actions={load_3;}size=1;const default_action=load_3();}
Register<bit<32>,bit<1>>(2,32w0) image_4;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_4) write_4={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w4;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_4) read_4={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_4(){write_4.execute(hdr.descriptor.slot[0:0]);}
 table store_4_t{actions={store_4;}size=1;const default_action=store_4();}
 action load_4(){hdr.image.w4=read_4.execute(hdr.descriptor.slot[0:0]);}
 table load_4_t{actions={load_4;}size=1;const default_action=load_4();}
Register<bit<32>,bit<1>>(2,32w0) image_5;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_5) write_5={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w5;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_5) read_5={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_5(){write_5.execute(hdr.descriptor.slot[0:0]);}
 table store_5_t{actions={store_5;}size=1;const default_action=store_5();}
 action load_5(){hdr.image.w5=read_5.execute(hdr.descriptor.slot[0:0]);}
 table load_5_t{actions={load_5;}size=1;const default_action=load_5();}
Register<bit<32>,bit<1>>(2,32w0) image_6;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_6) write_6={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w6;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_6) read_6={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_6(){write_6.execute(hdr.descriptor.slot[0:0]);}
 table store_6_t{actions={store_6;}size=1;const default_action=store_6();}
 action load_6(){hdr.image.w6=read_6.execute(hdr.descriptor.slot[0:0]);}
 table load_6_t{actions={load_6;}size=1;const default_action=load_6();}
Register<bit<32>,bit<1>>(2,32w0) image_7;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_7) write_7={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w7;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_7) read_7={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_7(){write_7.execute(hdr.descriptor.slot[0:0]);}
 table store_7_t{actions={store_7;}size=1;const default_action=store_7();}
 action load_7(){hdr.image.w7=read_7.execute(hdr.descriptor.slot[0:0]);}
 table load_7_t{actions={load_7;}size=1;const default_action=load_7();}
Register<bit<32>,bit<1>>(2,32w0) image_8;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_8) write_8={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w8;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_8) read_8={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_8(){write_8.execute(hdr.descriptor.slot[0:0]);}
 table store_8_t{actions={store_8;}size=1;const default_action=store_8();}
 action load_8(){hdr.image.w8=read_8.execute(hdr.descriptor.slot[0:0]);}
 table load_8_t{actions={load_8;}size=1;const default_action=load_8();}
Register<bit<32>,bit<1>>(2,32w0) image_9;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_9) write_9={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w9;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_9) read_9={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_9(){write_9.execute(hdr.descriptor.slot[0:0]);}
 table store_9_t{actions={store_9;}size=1;const default_action=store_9();}
 action load_9(){hdr.image.w9=read_9.execute(hdr.descriptor.slot[0:0]);}
 table load_9_t{actions={load_9;}size=1;const default_action=load_9();}
Register<bit<32>,bit<1>>(2,32w0) image_10;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_10) write_10={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w10;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_10) read_10={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_10(){write_10.execute(hdr.descriptor.slot[0:0]);}
 table store_10_t{actions={store_10;}size=1;const default_action=store_10();}
 action load_10(){hdr.image.w10=read_10.execute(hdr.descriptor.slot[0:0]);}
 table load_10_t{actions={load_10;}size=1;const default_action=load_10();}
Register<bit<32>,bit<1>>(2,32w0) image_11;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_11) write_11={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w11;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_11) read_11={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_11(){write_11.execute(hdr.descriptor.slot[0:0]);}
 table store_11_t{actions={store_11;}size=1;const default_action=store_11();}
 action load_11(){hdr.image.w11=read_11.execute(hdr.descriptor.slot[0:0]);}
 table load_11_t{actions={load_11;}size=1;const default_action=load_11();}
Register<bit<32>,bit<1>>(2,32w0) image_12;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_12) write_12={void apply(inout bit<32> v,out bit<32> rv){v=hdr.image.w12;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_12) read_12={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_12(){write_12.execute(hdr.descriptor.slot[0:0]);}
 table store_12_t{actions={store_12;}size=1;const default_action=store_12();}
 action load_12(){hdr.image.w12=read_12.execute(hdr.descriptor.slot[0:0]);}
 table load_12_t{actions={load_12;}size=1;const default_action=load_12();}
Register<bit<32>,bit<1>>(2,32w0) image_13;
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_13) write_13={void apply(inout bit<32> v,out bit<32> rv){v=m.last_word;rv=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_13) read_13={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
 action store_13(){write_13.execute(hdr.descriptor.slot[0:0]);}
 table store_13_t{actions={store_13;}size=1;const default_action=store_13();}
 action load_13(){m.last_word=read_13.execute(hdr.descriptor.slot[0:0]);}
 table load_13_t{actions={load_13;}size=1;const default_action=load_13();}
action deny(){md.drop_ctl=3w1;}
 action form_last(){m.last_word=hdr.image.w13++8w0;}
 table form_last_t{actions={form_last;}size=1;const default_action=form_last();}
 action render(){hdr.image.w13=m.last_word[31:8];hdr.image.setValid();hdr.replay.setInvalid();hdr.ip.len=16w95;hdr.tcp.seq=hdr.descriptor.wire_start;}
 table render_t{actions={render;}size=1;const default_action=render();}
 apply{if(hdr.descriptor.generation==32w0){deny();}else{if(hdr.descriptor.operation==8w2){form_last_t.apply();store_0_t.apply();store_1_t.apply();store_2_t.apply();store_3_t.apply();store_4_t.apply();store_5_t.apply();store_6_t.apply();store_7_t.apply();store_8_t.apply();store_9_t.apply();store_10_t.apply();store_11_t.apply();store_12_t.apply();store_13_t.apply();}else{if(hdr.descriptor.operation==8w1){load_0_t.apply();load_1_t.apply();load_2_t.apply();load_3_t.apply();load_4_t.apply();load_5_t.apply();load_6_t.apply();load_7_t.apply();load_8_t.apply();load_9_t.apply();load_10_t.apply();load_11_t.apply();load_12_t.apply();load_13_t.apply();render_t.apply();}else{deny();}}}m.tcp_length=16w75;}
}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;
 apply{hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.image.w0,hdr.image.w1,hdr.image.w2,hdr.image.w3,hdr.image.w4,hdr.image.w5,hdr.image.w6,hdr.image.w7,hdr.image.w8,hdr.image.w9,hdr.image.w10,hdr.image.w11,hdr.image.w12,hdr.image.w13});pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.image);}
}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

/* Actual native35 validation/padding wire primitive. Default profile disabled. Actual image writes; NO connection/work-slot publication/lifecycle or assembly. */
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
struct headers_t{eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;native_h native;tail_h tail;appended_h appended;final_h last;}
struct cache_word_t{bit<32> generation;bit<32> data;}
struct meta_t{bit<32> work_generation;bit<32> status0;bit<32> status1;bit<32> status2;bit<32> status3;bit<32> status4;bit<32> status5;bit<32> status6;bit<32> status7;bit<32> status8;bit<32> status9;bit<32> status10;bit<32> status11;bit<32> status12;bit<32> status13;bit<1> image_slot;bit<32> image_word0;bit<32> image_word1;bit<32> image_word2;bit<32> image_word3;bit<32> image_word4;bit<32> image_word5;bit<32> image_word6;bit<32> image_word7;bit<32> image_word8;bit<32> image_word9;bit<32> image_word10;bit<32> image_word11;bit<32> image_word12;bit<32> image_word13;bit<1> parsed;bit<1> enabled;bit<1> profile;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);m.work_generation=32w0;pkt.advance(PORT_METADATA_SIZE);m.parsed=1w0;m.enabled=1w0;m.profile=1w0;m.changed=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w75,8w6):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):dl;(4w5,4w0,8w0x18,16w0):dl;default:accept;}}
 state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native;}
 state native{pkt.extract(hdr.native);tc.subtract(hdr.native);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_0;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_0) write_0={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word0;rv=32w0;}
 else if(v.data!=m.image_word0){rv=32w1;}
}};
action candidate_0(){m.image_word0=hdr.dl.magic++hdr.dl.len++hdr.dl.ctrl;}
table candidate_0_t{actions={candidate_0;}size=1;const default_action=candidate_0();}
action store_0(){m.status0=write_0.execute(m.image_slot);}
table store_0_t{actions={store_0;}size=1;const default_action=store_0();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_1;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_1) write_1={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word1;rv=32w0;}
 else if(v.data!=m.image_word1){rv=32w1;}
}};
action candidate_1(){m.image_word1=hdr.dl.dst++hdr.dl.src;}
table candidate_1_t{actions={candidate_1;}size=1;const default_action=candidate_1();}
action store_1(){m.status1=write_1.execute(m.image_slot);}
table store_1_t{actions={store_1;}size=1;const default_action=store_1();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_2;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_2) write_2={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word2;rv=32w0;}
 else if(v.data!=m.image_word2){rv=32w1;}
}};
action candidate_2(){m.image_word2=hdr.dl.crc++hdr.native.tp++hdr.native.app;}
table candidate_2_t{actions={candidate_2;}size=1;const default_action=candidate_2();}
action store_2(){m.status2=write_2.execute(m.image_slot);}
table store_2_t{actions={store_2;}size=1;const default_action=store_2();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_3;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_3) write_3={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word3;rv=32w0;}
 else if(v.data!=m.image_word3){rv=32w1;}
}};
action candidate_3(){m.image_word3=hdr.native.func++hdr.native.group++hdr.native.variation++hdr.native.qualifier;}
table candidate_3_t{actions={candidate_3;}size=1;const default_action=candidate_3();}
action store_3(){m.status3=write_3.execute(m.image_slot);}
table store_3_t{actions={store_3;}size=1;const default_action=store_3();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_4;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_4) write_4={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word4;rv=32w0;}
 else if(v.data!=m.image_word4){rv=32w1;}
}};
action candidate_4(){m.image_word4=hdr.native.count++hdr.native.index;}
table candidate_4_t{actions={candidate_4;}size=1;const default_action=candidate_4();}
action store_4(){m.status4=write_4.execute(m.image_slot);}
table store_4_t{actions={store_4;}size=1;const default_action=store_4();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_5;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_5) write_5={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word5;rv=32w0;}
 else if(v.data!=m.image_word5){rv=32w1;}
}};
action candidate_5(){m.image_word5=hdr.native.code++hdr.native.repeat++hdr.native.on[31:16];}
table candidate_5_t{actions={candidate_5;}size=1;const default_action=candidate_5();}
action store_5(){m.status5=write_5.execute(m.image_slot);}
table store_5_t{actions={store_5;}size=1;const default_action=store_5();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_6;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_6) write_6={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word6;rv=32w0;}
 else if(v.data!=m.image_word6){rv=32w1;}
}};
action candidate_6(){m.image_word6=hdr.native.on[15:0]++hdr.native.crc;}
table candidate_6_t{actions={candidate_6;}size=1;const default_action=candidate_6();}
action store_6(){m.status6=write_6.execute(m.image_slot);}
table store_6_t{actions={store_6;}size=1;const default_action=store_6();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_7;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_7) write_7={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word7;rv=32w0;}
 else if(v.data!=m.image_word7){rv=32w1;}
}};
action candidate_7(){m.image_word7=hdr.appended.off;}
table candidate_7_t{actions={candidate_7;}size=1;const default_action=candidate_7();}
action store_7(){m.status7=write_7.execute(m.image_slot);}
table store_7_t{actions={store_7;}size=1;const default_action=store_7();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_8;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_8) write_8={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word8;rv=32w0;}
 else if(v.data!=m.image_word8){rv=32w1;}
}};
action candidate_8(){m.image_word8=hdr.appended.status++hdr.appended.group++hdr.appended.variation++hdr.appended.qualifier;}
table candidate_8_t{actions={candidate_8;}size=1;const default_action=candidate_8();}
action store_8(){m.status8=write_8.execute(m.image_slot);}
table store_8_t{actions={store_8;}size=1;const default_action=store_8();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_9;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_9) write_9={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word9;rv=32w0;}
 else if(v.data!=m.image_word9){rv=32w1;}
}};
action candidate_9(){m.image_word9=hdr.appended.count++hdr.appended.index;}
table candidate_9_t{actions={candidate_9;}size=1;const default_action=candidate_9();}
action store_9(){m.status9=write_9.execute(m.image_slot);}
table store_9_t{actions={store_9;}size=1;const default_action=store_9();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_10;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_10) write_10={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word10;rv=32w0;}
 else if(v.data!=m.image_word10){rv=32w1;}
}};
action candidate_10(){m.image_word10=hdr.appended.code++hdr.appended.repeat++hdr.appended.on_first;}
table candidate_10_t{actions={candidate_10;}size=1;const default_action=candidate_10();}
action store_10(){m.status10=write_10.execute(m.image_slot);}
table store_10_t{actions={store_10;}size=1;const default_action=store_10();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_11;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_11) write_11={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word11;rv=32w0;}
 else if(v.data!=m.image_word11){rv=32w1;}
}};
action candidate_11(){m.image_word11=hdr.appended.crc++hdr.last.on_last;}
table candidate_11_t{actions={candidate_11;}size=1;const default_action=candidate_11();}
action store_11(){m.status11=write_11.execute(m.image_slot);}
table store_11_t{actions={store_11;}size=1;const default_action=store_11();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_12;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_12) write_12={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word12;rv=32w0;}
 else if(v.data!=m.image_word12){rv=32w1;}
}};
action candidate_12(){m.image_word12=hdr.last.off;}
table candidate_12_t{actions={candidate_12;}size=1;const default_action=candidate_12();}
action store_12(){m.status12=write_12.execute(m.image_slot);}
table store_12_t{actions={store_12;}size=1;const default_action=store_12();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_13;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_13) write_13={void apply(inout cache_word_t v,out bit<32> rv){
 rv=v.generation-m.work_generation;
 if(v.generation<m.work_generation){v.generation=m.work_generation;v.data=m.image_word13;rv=32w0;}
 else if(v.data!=m.image_word13){rv=32w1;}
}};
action candidate_13(){m.image_word13=hdr.last.status++hdr.last.crc++8w0;}
table candidate_13_t{actions={candidate_13;}size=1;const default_action=candidate_13();}
action store_13(){m.status13=write_13.execute(m.image_slot);}
table store_13_t{actions={store_13;}size=1;const default_action=store_13();}
 action deny(){md.drop_ctl=3w1;}
table cache_results{key={m.status0:exact;m.status1:exact;m.status2:exact;m.status3:exact;m.status4:exact;m.status5:exact;m.status6:exact;m.status7:exact;m.status8:exact;m.status9:exact;m.status10:exact;m.status11:exact;m.status12:exact;m.status13:exact;}actions={deny;NoAction;}size=1;const default_action=deny();const entries={(32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0):NoAction();}}

 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action configure(bit<16> index,bit<8> code,bit<8> repeat,bit<32> on,bit<32> off,bit<32> work_generation){m.work_generation=work_generation;m.enabled=1w1;m.decoy_index=index;m.decoy_code=code;m.decoy_repeat=repeat;m.decoy_on=on;m.decoy_off=off;}
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
 apply{forwarding.apply();if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB){connection.apply();profile.apply();if(m.enabled==1w1&&m.profile==1w1&&m.work_generation!=32w0){input_head_t.apply();input_body_t.apply();input_tail_t.apply();if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
 if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0&&hdr.native.index!=m.decoy_index){construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();if(hdr.native.func==8w3){m.image_slot=1w0;}else{m.image_slot=1w1;}candidate_0_t.apply();store_0_t.apply();candidate_1_t.apply();store_1_t.apply();candidate_2_t.apply();store_2_t.apply();candidate_3_t.apply();store_3_t.apply();candidate_4_t.apply();store_4_t.apply();candidate_5_t.apply();store_5_t.apply();candidate_6_t.apply();store_6_t.apply();candidate_7_t.apply();store_7_t.apply();candidate_8_t.apply();store_8_t.apply();candidate_9_t.apply();store_9_t.apply();candidate_10_t.apply();store_10_t.apply();candidate_11_t.apply();store_11_t.apply();candidate_12_t.apply();store_12_t.apply();candidate_13_t.apply();store_13_t.apply();cache_results.apply();}}}}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on,hdr.native.crc,hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first,hdr.appended.crc,hdr.last.on_last,hdr.last.off,hdr.last.status,hdr.last.crc});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.native);pkt.emit(hdr.tail);pkt.emit(hdr.appended);pkt.emit(hdr.last);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

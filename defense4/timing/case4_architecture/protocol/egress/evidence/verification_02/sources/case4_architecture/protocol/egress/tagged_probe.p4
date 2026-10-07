#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header descriptor_h{bit<32> generation;bit<32> wire_start;bit<8> operation;bit<1> slot;bit<7> pad;bit<16> reserved;}
header image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
header byte_h{bit<8> data;}
struct cache_word_t{bit<32> generation;bit<32> data;}
struct headers_t{descriptor_h descriptor;eth_h eth;ip_h ip;tcp_h tcp;image_h image;byte_h native;}
struct meta_t{bit<32> last_word;bit<16> tcp_length;bit<32> tag0;cache_word_t loaded0;bit<32> tag1;cache_word_t loaded1;bit<32> tag2;cache_word_t loaded2;bit<32> tag3;cache_word_t loaded3;bit<32> tag4;cache_word_t loaded4;bit<32> tag5;cache_word_t loaded5;bit<32> tag6;cache_word_t loaded6;bit<32> tag7;cache_word_t loaded7;bit<32> tag8;cache_word_t loaded8;bit<32> tag9;cache_word_t loaded9;bit<32> tag10;cache_word_t loaded10;bit<32> tag11;cache_word_t loaded11;bit<32> tag12;cache_word_t loaded12;bit<32> tag13;cache_word_t loaded13;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);pkt.extract(hdr.descriptor);pkt.extract(hdr.eth);pkt.extract(hdr.ip);pkt.extract(hdr.tcp);transition select(hdr.descriptor.operation){8w2:image;8w1:byte;default:reject;}}state image{pkt.extract(hdr.image);transition accept;}state byte{pkt.extract(hdr.native);transition accept;}}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){apply{tm.ucast_egress_port=ig.ingress_port;tm.bypass_egress=1w0;}}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.descriptor);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.image);pkt.emit(hdr.native);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);pkt.extract(hdr.descriptor);pkt.extract(hdr.eth);pkt.extract(hdr.ip);pkt.extract(hdr.tcp);transition select(hdr.descriptor.operation){8w2:image;8w1:byte;default:reject;}}state image{pkt.extract(hdr.image);transition accept;}state byte{pkt.extract(hdr.native);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_0;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_0) write_0={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w0;rv=v.generation;}
else{if(v.data!=hdr.image.w0){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_0) read_0={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_0(){m.tag0=write_0.execute(hdr.descriptor.slot);}
table store_0_t{actions={store_0;}size=1;const default_action=store_0();}
action load_0(){m.loaded0=read_0.execute(hdr.descriptor.slot);}
table load_0_t{actions={load_0;}size=1;const default_action=load_0();}
action unpack_0(){m.tag0=m.loaded0.generation;hdr.image.w0=m.loaded0.data;}
table unpack_0_t{actions={unpack_0;}size=1;const default_action=unpack_0();}
action difference_0(){m.tag0=m.tag0^hdr.descriptor.generation;}
table difference_0_t{actions={difference_0;}size=1;const default_action=difference_0();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_1;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_1) write_1={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w1;rv=v.generation;}
else{if(v.data!=hdr.image.w1){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_1) read_1={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_1(){m.tag1=write_1.execute(hdr.descriptor.slot);}
table store_1_t{actions={store_1;}size=1;const default_action=store_1();}
action load_1(){m.loaded1=read_1.execute(hdr.descriptor.slot);}
table load_1_t{actions={load_1;}size=1;const default_action=load_1();}
action unpack_1(){m.tag1=m.loaded1.generation;hdr.image.w1=m.loaded1.data;}
table unpack_1_t{actions={unpack_1;}size=1;const default_action=unpack_1();}
action difference_1(){m.tag1=m.tag1^hdr.descriptor.generation;}
table difference_1_t{actions={difference_1;}size=1;const default_action=difference_1();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_2;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_2) write_2={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w2;rv=v.generation;}
else{if(v.data!=hdr.image.w2){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_2) read_2={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_2(){m.tag2=write_2.execute(hdr.descriptor.slot);}
table store_2_t{actions={store_2;}size=1;const default_action=store_2();}
action load_2(){m.loaded2=read_2.execute(hdr.descriptor.slot);}
table load_2_t{actions={load_2;}size=1;const default_action=load_2();}
action unpack_2(){m.tag2=m.loaded2.generation;hdr.image.w2=m.loaded2.data;}
table unpack_2_t{actions={unpack_2;}size=1;const default_action=unpack_2();}
action difference_2(){m.tag2=m.tag2^hdr.descriptor.generation;}
table difference_2_t{actions={difference_2;}size=1;const default_action=difference_2();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_3;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_3) write_3={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w3;rv=v.generation;}
else{if(v.data!=hdr.image.w3){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_3) read_3={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_3(){m.tag3=write_3.execute(hdr.descriptor.slot);}
table store_3_t{actions={store_3;}size=1;const default_action=store_3();}
action load_3(){m.loaded3=read_3.execute(hdr.descriptor.slot);}
table load_3_t{actions={load_3;}size=1;const default_action=load_3();}
action unpack_3(){m.tag3=m.loaded3.generation;hdr.image.w3=m.loaded3.data;}
table unpack_3_t{actions={unpack_3;}size=1;const default_action=unpack_3();}
action difference_3(){m.tag3=m.tag3^hdr.descriptor.generation;}
table difference_3_t{actions={difference_3;}size=1;const default_action=difference_3();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_4;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_4) write_4={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w4;rv=v.generation;}
else{if(v.data!=hdr.image.w4){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_4) read_4={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_4(){m.tag4=write_4.execute(hdr.descriptor.slot);}
table store_4_t{actions={store_4;}size=1;const default_action=store_4();}
action load_4(){m.loaded4=read_4.execute(hdr.descriptor.slot);}
table load_4_t{actions={load_4;}size=1;const default_action=load_4();}
action unpack_4(){m.tag4=m.loaded4.generation;hdr.image.w4=m.loaded4.data;}
table unpack_4_t{actions={unpack_4;}size=1;const default_action=unpack_4();}
action difference_4(){m.tag4=m.tag4^hdr.descriptor.generation;}
table difference_4_t{actions={difference_4;}size=1;const default_action=difference_4();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_5;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_5) write_5={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w5;rv=v.generation;}
else{if(v.data!=hdr.image.w5){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_5) read_5={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_5(){m.tag5=write_5.execute(hdr.descriptor.slot);}
table store_5_t{actions={store_5;}size=1;const default_action=store_5();}
action load_5(){m.loaded5=read_5.execute(hdr.descriptor.slot);}
table load_5_t{actions={load_5;}size=1;const default_action=load_5();}
action unpack_5(){m.tag5=m.loaded5.generation;hdr.image.w5=m.loaded5.data;}
table unpack_5_t{actions={unpack_5;}size=1;const default_action=unpack_5();}
action difference_5(){m.tag5=m.tag5^hdr.descriptor.generation;}
table difference_5_t{actions={difference_5;}size=1;const default_action=difference_5();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_6;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_6) write_6={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w6;rv=v.generation;}
else{if(v.data!=hdr.image.w6){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_6) read_6={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_6(){m.tag6=write_6.execute(hdr.descriptor.slot);}
table store_6_t{actions={store_6;}size=1;const default_action=store_6();}
action load_6(){m.loaded6=read_6.execute(hdr.descriptor.slot);}
table load_6_t{actions={load_6;}size=1;const default_action=load_6();}
action unpack_6(){m.tag6=m.loaded6.generation;hdr.image.w6=m.loaded6.data;}
table unpack_6_t{actions={unpack_6;}size=1;const default_action=unpack_6();}
action difference_6(){m.tag6=m.tag6^hdr.descriptor.generation;}
table difference_6_t{actions={difference_6;}size=1;const default_action=difference_6();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_7;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_7) write_7={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w7;rv=v.generation;}
else{if(v.data!=hdr.image.w7){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_7) read_7={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_7(){m.tag7=write_7.execute(hdr.descriptor.slot);}
table store_7_t{actions={store_7;}size=1;const default_action=store_7();}
action load_7(){m.loaded7=read_7.execute(hdr.descriptor.slot);}
table load_7_t{actions={load_7;}size=1;const default_action=load_7();}
action unpack_7(){m.tag7=m.loaded7.generation;hdr.image.w7=m.loaded7.data;}
table unpack_7_t{actions={unpack_7;}size=1;const default_action=unpack_7();}
action difference_7(){m.tag7=m.tag7^hdr.descriptor.generation;}
table difference_7_t{actions={difference_7;}size=1;const default_action=difference_7();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_8;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_8) write_8={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w8;rv=v.generation;}
else{if(v.data!=hdr.image.w8){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_8) read_8={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_8(){m.tag8=write_8.execute(hdr.descriptor.slot);}
table store_8_t{actions={store_8;}size=1;const default_action=store_8();}
action load_8(){m.loaded8=read_8.execute(hdr.descriptor.slot);}
table load_8_t{actions={load_8;}size=1;const default_action=load_8();}
action unpack_8(){m.tag8=m.loaded8.generation;hdr.image.w8=m.loaded8.data;}
table unpack_8_t{actions={unpack_8;}size=1;const default_action=unpack_8();}
action difference_8(){m.tag8=m.tag8^hdr.descriptor.generation;}
table difference_8_t{actions={difference_8;}size=1;const default_action=difference_8();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_9;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_9) write_9={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w9;rv=v.generation;}
else{if(v.data!=hdr.image.w9){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_9) read_9={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_9(){m.tag9=write_9.execute(hdr.descriptor.slot);}
table store_9_t{actions={store_9;}size=1;const default_action=store_9();}
action load_9(){m.loaded9=read_9.execute(hdr.descriptor.slot);}
table load_9_t{actions={load_9;}size=1;const default_action=load_9();}
action unpack_9(){m.tag9=m.loaded9.generation;hdr.image.w9=m.loaded9.data;}
table unpack_9_t{actions={unpack_9;}size=1;const default_action=unpack_9();}
action difference_9(){m.tag9=m.tag9^hdr.descriptor.generation;}
table difference_9_t{actions={difference_9;}size=1;const default_action=difference_9();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_10;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_10) write_10={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w10;rv=v.generation;}
else{if(v.data!=hdr.image.w10){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_10) read_10={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_10(){m.tag10=write_10.execute(hdr.descriptor.slot);}
table store_10_t{actions={store_10;}size=1;const default_action=store_10();}
action load_10(){m.loaded10=read_10.execute(hdr.descriptor.slot);}
table load_10_t{actions={load_10;}size=1;const default_action=load_10();}
action unpack_10(){m.tag10=m.loaded10.generation;hdr.image.w10=m.loaded10.data;}
table unpack_10_t{actions={unpack_10;}size=1;const default_action=unpack_10();}
action difference_10(){m.tag10=m.tag10^hdr.descriptor.generation;}
table difference_10_t{actions={difference_10;}size=1;const default_action=difference_10();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_11;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_11) write_11={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w11;rv=v.generation;}
else{if(v.data!=hdr.image.w11){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_11) read_11={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_11(){m.tag11=write_11.execute(hdr.descriptor.slot);}
table store_11_t{actions={store_11;}size=1;const default_action=store_11();}
action load_11(){m.loaded11=read_11.execute(hdr.descriptor.slot);}
table load_11_t{actions={load_11;}size=1;const default_action=load_11();}
action unpack_11(){m.tag11=m.loaded11.generation;hdr.image.w11=m.loaded11.data;}
table unpack_11_t{actions={unpack_11;}size=1;const default_action=unpack_11();}
action difference_11(){m.tag11=m.tag11^hdr.descriptor.generation;}
table difference_11_t{actions={difference_11;}size=1;const default_action=difference_11();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_12;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_12) write_12={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=hdr.image.w12;rv=v.generation;}
else{if(v.data!=hdr.image.w12){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_12) read_12={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_12(){m.tag12=write_12.execute(hdr.descriptor.slot);}
table store_12_t{actions={store_12;}size=1;const default_action=store_12();}
action load_12(){m.loaded12=read_12.execute(hdr.descriptor.slot);}
table load_12_t{actions={load_12;}size=1;const default_action=load_12();}
action unpack_12(){m.tag12=m.loaded12.generation;hdr.image.w12=m.loaded12.data;}
table unpack_12_t{actions={unpack_12;}size=1;const default_action=unpack_12();}
action difference_12(){m.tag12=m.tag12^hdr.descriptor.generation;}
table difference_12_t{actions={difference_12;}size=1;const default_action=difference_12();}
Register<cache_word_t,bit<1>>(2,{32w0,32w0}) image_13;
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_13) write_13={void apply(inout cache_word_t v,out bit<32> rv){
if(v.generation<hdr.descriptor.generation){v.generation=hdr.descriptor.generation;v.data=m.last_word;rv=v.generation;}
else{if(v.data!=m.last_word){rv=32w0;}else{rv=v.generation;}}
}};
RegisterAction<cache_word_t,bit<1>,cache_word_t>(image_13) read_13={void apply(inout cache_word_t v,out cache_word_t rv){rv=v;}};
action store_13(){m.tag13=write_13.execute(hdr.descriptor.slot);}
table store_13_t{actions={store_13;}size=1;const default_action=store_13();}
action load_13(){m.loaded13=read_13.execute(hdr.descriptor.slot);}
table load_13_t{actions={load_13;}size=1;const default_action=load_13();}
action unpack_13(){m.tag13=m.loaded13.generation;hdr.image.w13=m.loaded13.data[31:8];}
table unpack_13_t{actions={unpack_13;}size=1;const default_action=unpack_13();}
action difference_13(){m.tag13=m.tag13^hdr.descriptor.generation;}
table difference_13_t{actions={difference_13;}size=1;const default_action=difference_13();}
action deny(){md.drop_ctl=3w1;}
action last_word(){m.last_word=hdr.image.w13++8w0;}
table last_word_t{actions={last_word;}size=1;const default_action=last_word();}
table valid_tags{key={m.tag0:exact;m.tag1:exact;m.tag2:exact;m.tag3:exact;m.tag4:exact;m.tag5:exact;m.tag6:exact;m.tag7:exact;m.tag8:exact;m.tag9:exact;m.tag10:exact;m.tag11:exact;m.tag12:exact;m.tag13:exact;}actions={NoAction;deny;}size=1;const default_action=deny();const entries={(32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0):NoAction();}}
apply{if(hdr.descriptor.generation==32w0){deny();}else{if(hdr.descriptor.operation==8w2){last_word_t.apply();store_0_t.apply();store_1_t.apply();store_2_t.apply();store_3_t.apply();store_4_t.apply();store_5_t.apply();store_6_t.apply();store_7_t.apply();store_8_t.apply();store_9_t.apply();store_10_t.apply();store_11_t.apply();store_12_t.apply();store_13_t.apply();}else{load_0_t.apply();unpack_0_t.apply();load_1_t.apply();unpack_1_t.apply();load_2_t.apply();unpack_2_t.apply();load_3_t.apply();unpack_3_t.apply();load_4_t.apply();unpack_4_t.apply();load_5_t.apply();unpack_5_t.apply();load_6_t.apply();unpack_6_t.apply();load_7_t.apply();unpack_7_t.apply();load_8_t.apply();unpack_8_t.apply();load_9_t.apply();unpack_9_t.apply();load_10_t.apply();unpack_10_t.apply();load_11_t.apply();unpack_11_t.apply();load_12_t.apply();unpack_12_t.apply();load_13_t.apply();unpack_13_t.apply();hdr.image.setValid();hdr.native.setInvalid();hdr.ip.len=16w95;hdr.tcp.seq=hdr.descriptor.wire_start;}difference_0_t.apply();difference_1_t.apply();difference_2_t.apply();difference_3_t.apply();difference_4_t.apply();difference_5_t.apply();difference_6_t.apply();difference_7_t.apply();difference_8_t.apply();difference_9_t.apply();difference_10_t.apply();difference_11_t.apply();difference_12_t.apply();difference_13_t.apply();valid_tags.apply();}m.tcp_length=16w75;}
}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.image.w0,hdr.image.w1,hdr.image.w2,hdr.image.w3,hdr.image.w4,hdr.image.w5,hdr.image.w6,hdr.image.w7,hdr.image.w8,hdr.image.w9,hdr.image.w10,hdr.image.w11,hdr.image.w12,hdr.image.w13});pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.image);}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

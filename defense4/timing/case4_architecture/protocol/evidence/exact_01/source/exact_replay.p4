/* Offline cache render experiment: CP-published record, no admission/lifecycle producer. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header image_h {bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
header byte_h{bit<8> data;}
struct headers_t{eth_h eth;ip_h ip;tcp_h tcp;byte_h native;image_h image;}
struct meta_t{bit<1> render;bit<16> ip_length;bit<16> tcp_length;bit<32> wire_start;bit<8> expected_byte;bit<16> tcp_sum;bool ip_error;bit<1> parsed;bit<16> hcrc;bit<16> crc0;bit<16> crc1;bit<16> crct;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.render=1w0;m.parsed=1w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto,hdr.ip.frag,hdr.ip.flags){(4w4,4w5,16w41,8w6,13w0,3w0):tcp;(4w4,4w5,16w41,8w6,13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):body;(4w5,4w0,8w0x18,16w0):body;default:accept;}}
 state body{pkt.extract(hdr.native);tc.subtract(hdr.native);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action cached(bit<32> wire_start,bit<8> native_last){m.render=1w1;m.wire_start=wire_start;m.expected_byte=native_last;}
 table replay{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;hdr.tcp.seq:exact;}actions={cached;NoAction;}size=2;default_action=NoAction();}
Register<bit<32>,bit<1>>(2,0) image_0;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_0) read_0={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_0(){hdr.image.w0=read_0.execute(1w0);}
table load_0_t{actions={load_0;}size=1;const default_action=load_0();}
Register<bit<32>,bit<1>>(2,0) image_1;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_1) read_1={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_1(){hdr.image.w1=read_1.execute(1w0);}
table load_1_t{actions={load_1;}size=1;const default_action=load_1();}
Register<bit<32>,bit<1>>(2,0) image_2;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_2) read_2={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_2(){hdr.image.w2=read_2.execute(1w0);}
table load_2_t{actions={load_2;}size=1;const default_action=load_2();}
Register<bit<32>,bit<1>>(2,0) image_3;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_3) read_3={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_3(){hdr.image.w3=read_3.execute(1w0);}
table load_3_t{actions={load_3;}size=1;const default_action=load_3();}
Register<bit<32>,bit<1>>(2,0) image_4;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_4) read_4={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_4(){hdr.image.w4=read_4.execute(1w0);}
table load_4_t{actions={load_4;}size=1;const default_action=load_4();}
Register<bit<32>,bit<1>>(2,0) image_5;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_5) read_5={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_5(){hdr.image.w5=read_5.execute(1w0);}
table load_5_t{actions={load_5;}size=1;const default_action=load_5();}
Register<bit<32>,bit<1>>(2,0) image_6;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_6) read_6={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_6(){hdr.image.w6=read_6.execute(1w0);}
table load_6_t{actions={load_6;}size=1;const default_action=load_6();}
Register<bit<32>,bit<1>>(2,0) image_7;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_7) read_7={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_7(){hdr.image.w7=read_7.execute(1w0);}
table load_7_t{actions={load_7;}size=1;const default_action=load_7();}
Register<bit<32>,bit<1>>(2,0) image_8;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_8) read_8={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_8(){hdr.image.w8=read_8.execute(1w0);}
table load_8_t{actions={load_8;}size=1;const default_action=load_8();}
Register<bit<32>,bit<1>>(2,0) image_9;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_9) read_9={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_9(){hdr.image.w9=read_9.execute(1w0);}
table load_9_t{actions={load_9;}size=1;const default_action=load_9();}
Register<bit<32>,bit<1>>(2,0) image_10;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_10) read_10={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_10(){hdr.image.w10=read_10.execute(1w0);}
table load_10_t{actions={load_10;}size=1;const default_action=load_10();}
Register<bit<32>,bit<1>>(2,0) image_11;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_11) read_11={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_11(){hdr.image.w11=read_11.execute(1w0);}
table load_11_t{actions={load_11;}size=1;const default_action=load_11();}
Register<bit<32>,bit<1>>(2,0) image_12;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_12) read_12={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_12(){hdr.image.w12=read_12.execute(1w0);}
table load_12_t{actions={load_12;}size=1;const default_action=load_12();}
Register<bit<32>,bit<1>>(2,0) image_13;
RegisterAction<bit<32>,bit<1>,bit<32>>(image_13) read_13={void apply(inout bit<32> v,out bit<32> rv){rv=v;}};
action load_13(){hdr.image.w13=(bit<24>)read_13.execute(1w0);}
table load_13_t{actions={load_13;}size=1;const default_action=load_13();}
action complete(){hdr.image.setValid();hdr.native.setInvalid();hdr.tcp.seq=m.wire_start;hdr.ip.len=16w95;m.ip_length=16w95;m.tcp_length=16w75;}
table complete_t{actions={complete;}size=1;const default_action=complete();}
apply{forwarding.apply();if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB){replay.apply();if(m.render==1w1){if(hdr.native.data!=m.expected_byte){deny();}else{load_0_t.apply();load_1_t.apply();load_2_t.apply();load_3_t.apply();load_4_t.apply();load_5_t.apply();load_6_t.apply();load_7_t.apply();load_8_t.apply();load_9_t.apply();load_10_t.apply();load_11_t.apply();load_12_t.apply();load_13_t.apply();complete_t.apply();}}}}}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.render==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.image.w0,hdr.image.w1,hdr.image.w2,hdr.image.w3,hdr.image.w4,hdr.image.w5,hdr.image.w6,hdr.image.w7,hdr.image.w8,hdr.image.w9,hdr.image.w10,hdr.image.w11,hdr.image.w12,hdr.image.w13});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.native);pkt.emit(hdr.image);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

#include <core.p4>
#include <tna.p4>
// Internal executable bank primitive, not raw network admission or protected publication.
header eth_h{bit<48> dst;bit<48> src;bit<16> type;}
header ref_h{bit<32> epoch;bit<32> generation;bit<32> expected_cell;bit<16> event;bit<16> reserved;}
header words_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;}
struct bucket_t{bit<32> generation;bit<32> encoded;}
struct headers_t{eth_h eth;ref_h ref;words_h expected;words_h candidate;}
struct meta_t{bit<32> generation;bit<32> status0;bit<32> status1;bit<32> status2;bit<32> status3;bit<32> status4;bit<32> status5;bit<32> status6;bit<32> status7;bit<32> status8;bit<32> status9;bit<32> status10;bit<32> status11;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x88D4:ref;default:reject;}}
 state ref{pkt.extract(hdr.ref);m.generation=hdr.ref.generation;transition expected;}
 state expected{pkt.extract(hdr.expected);transition candidate;}
 state candidate{pkt.extract(hdr.candidate);transition accept;}}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_0;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_0) snapshot_0={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_0) cas_0={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w0){v.encoded=hdr.candidate.w0;rv=32w0;}
}};
action read_0(){hdr.expected.w0=snapshot_0.execute(1w0);}
table read_0_t{actions={read_0;}size=1;const default_action=read_0();}
action write_0(){m.status0=cas_0.execute(1w0);}
table write_0_t{actions={write_0;}size=1;const default_action=write_0();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_1;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_1) snapshot_1={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_1) cas_1={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w1){v.encoded=hdr.candidate.w1;rv=32w0;}
}};
action read_1(){hdr.expected.w1=snapshot_1.execute(1w0);}
table read_1_t{actions={read_1;}size=1;const default_action=read_1();}
action write_1(){m.status1=cas_1.execute(1w0);}
table write_1_t{actions={write_1;}size=1;const default_action=write_1();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_2;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_2) snapshot_2={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_2) cas_2={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w2){v.encoded=hdr.candidate.w2;rv=32w0;}
}};
action read_2(){hdr.expected.w2=snapshot_2.execute(1w0);}
table read_2_t{actions={read_2;}size=1;const default_action=read_2();}
action write_2(){m.status2=cas_2.execute(1w0);}
table write_2_t{actions={write_2;}size=1;const default_action=write_2();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_3;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_3) snapshot_3={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_3) cas_3={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w3){v.encoded=hdr.candidate.w3;rv=32w0;}
}};
action read_3(){hdr.expected.w3=snapshot_3.execute(1w0);}
table read_3_t{actions={read_3;}size=1;const default_action=read_3();}
action write_3(){m.status3=cas_3.execute(1w0);}
table write_3_t{actions={write_3;}size=1;const default_action=write_3();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_4;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_4) snapshot_4={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_4) cas_4={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w4){v.encoded=hdr.candidate.w4;rv=32w0;}
}};
action read_4(){hdr.expected.w4=snapshot_4.execute(1w0);}
table read_4_t{actions={read_4;}size=1;const default_action=read_4();}
action write_4(){m.status4=cas_4.execute(1w0);}
table write_4_t{actions={write_4;}size=1;const default_action=write_4();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_5;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_5) snapshot_5={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_5) cas_5={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w5){v.encoded=hdr.candidate.w5;rv=32w0;}
}};
action read_5(){hdr.expected.w5=snapshot_5.execute(1w0);}
table read_5_t{actions={read_5;}size=1;const default_action=read_5();}
action write_5(){m.status5=cas_5.execute(1w0);}
table write_5_t{actions={write_5;}size=1;const default_action=write_5();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_6;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_6) snapshot_6={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_6) cas_6={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w6){v.encoded=hdr.candidate.w6;rv=32w0;}
}};
action read_6(){hdr.expected.w6=snapshot_6.execute(1w0);}
table read_6_t{actions={read_6;}size=1;const default_action=read_6();}
action write_6(){m.status6=cas_6.execute(1w0);}
table write_6_t{actions={write_6;}size=1;const default_action=write_6();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_7;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_7) snapshot_7={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_7) cas_7={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w7){v.encoded=hdr.candidate.w7;rv=32w0;}
}};
action read_7(){hdr.expected.w7=snapshot_7.execute(1w0);}
table read_7_t{actions={read_7;}size=1;const default_action=read_7();}
action write_7(){m.status7=cas_7.execute(1w0);}
table write_7_t{actions={write_7;}size=1;const default_action=write_7();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_8;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_8) snapshot_8={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_8) cas_8={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w8){v.encoded=hdr.candidate.w8;rv=32w0;}
}};
action read_8(){hdr.expected.w8=snapshot_8.execute(1w0);}
table read_8_t{actions={read_8;}size=1;const default_action=read_8();}
action write_8(){m.status8=cas_8.execute(1w0);}
table write_8_t{actions={write_8;}size=1;const default_action=write_8();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_9;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_9) snapshot_9={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_9) cas_9={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w9){v.encoded=hdr.candidate.w9;rv=32w0;}
}};
action read_9(){hdr.expected.w9=snapshot_9.execute(1w0);}
table read_9_t{actions={read_9;}size=1;const default_action=read_9();}
action write_9(){m.status9=cas_9.execute(1w0);}
table write_9_t{actions={write_9;}size=1;const default_action=write_9();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_10;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_10) snapshot_10={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_10) cas_10={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w10){v.encoded=hdr.candidate.w10;rv=32w0;}
}};
action read_10(){hdr.expected.w10=snapshot_10.execute(1w0);}
table read_10_t{actions={read_10;}size=1;const default_action=read_10();}
action write_10(){m.status10=cas_10.execute(1w0);}
table write_10_t{actions={write_10;}size=1;const default_action=write_10();}
Register<bucket_t,bit<1>>(1,{32w0,32w0}) bucket_11;
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_11) snapshot_11={void apply(inout bucket_t v,out bit<32> rv){
 if(v.generation<m.generation){v.generation=m.generation;v.encoded=32w0;}
 rv=v.encoded;
}};
RegisterAction<bucket_t,bit<1>,bit<32>>(bucket_11) cas_11={void apply(inout bucket_t v,out bit<32> rv){
 rv=32w1;if(v.generation==m.generation&&v.encoded==hdr.expected.w11){v.encoded=hdr.candidate.w11;rv=32w0;}
}};
action read_11(){hdr.expected.w11=snapshot_11.execute(1w0);}
table read_11_t{actions={read_11;}size=1;const default_action=read_11();}
action write_11(){m.status11=cas_11.execute(1w0);}
table write_11_t{actions={write_11;}size=1;const default_action=write_11();}
action deny(){md.drop_ctl=3w1;}
table result{key={m.status0:exact;m.status1:exact;m.status2:exact;m.status3:exact;m.status4:exact;m.status5:exact;m.status6:exact;m.status7:exact;m.status8:exact;m.status9:exact;m.status10:exact;m.status11:exact;}actions={deny;NoAction;}size=1;const default_action=deny();const entries={(32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0):NoAction();}}
apply{tm.ucast_egress_port=ig.ingress_port;tm.bypass_egress=1w1;if(m.generation!=32w0){if(hdr.ref.event==16w1){read_0_t.apply();read_1_t.apply();read_2_t.apply();read_3_t.apply();read_4_t.apply();read_5_t.apply();read_6_t.apply();read_7_t.apply();read_8_t.apply();read_9_t.apply();read_10_t.apply();read_11_t.apply();}else if(hdr.ref.event==16w2){write_0_t.apply();write_1_t.apply();write_2_t.apply();write_3_t.apply();write_4_t.apply();write_5_t.apply();write_6_t.apply();write_7_t.apply();write_8_t.apply();write_9_t.apply();write_10_t.apply();write_11_t.apply();result.apply();}else{deny();}}else{deny();}}}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);pkt.emit(hdr.ref);pkt.emit(hdr.expected);pkt.emit(hdr.candidate);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

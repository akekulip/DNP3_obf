/* Partial protected E prepare. Typed24B interface; no endpoint release authority. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header reference_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;}
header captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header cache_reference_h{bit<32> generation;bit<32> expected_owner;}
header image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
struct producer_cell_t{bit<32> generation;bit<32> phase;}
struct cache_tag_t{bit<32> epoch;bit<32> generation;}
struct headers_t{reference_h reference;cache_reference_h cache;eth_h eth;ip_h ip;tcp_h tcp;image_h image;}
struct meta_t{bit<1> parsed;bit<1> enabled;bool ip_error;bit<16> tcp_sum;bit<32> grant;bit<32> gen_diff;bit<32> owner_diff;bit<1> done0;bit<1> done1;bit<1> done2;bit<1> done3;bit<1> done4;bit<1> done5;bit<1> done6;bit<1> done7;bit<1> done8;bit<1> done9;bit<1> done10;bit<1> done11;bit<1> done12;bit<1> done13;bit<1> position_done;bit<1> tag_done;bit<1> owner_done;bit<1> identity_grant;}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){Checksum() ic;Checksum() tc;
 state start{pkt.extract(eg);m.parsed=1w0;m.enabled=1w0;m.identity_grant=1w0;m.position_done=1w0;m.tag_done=1w0;m.owner_done=1w0;m.done0=1w0;m.done1=1w0;m.done2=1w0;m.done3=1w0;m.done4=1w0;m.done5=1w0;m.done6=1w0;m.done7=1w0;m.done8=1w0;m.done9=1w0;m.done10=1w0;m.done11=1w0;m.done12=1w0;m.done13=1w0;transition select(eg.egress_port){9w68:reference;default:reject;}}
 state reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:reject;default:generation;}}
 state generation{transition select(hdr.reference.generation){32w0:reject;default:owner;}}
 state owner{transition select(hdr.reference.expected_owner[31:16]){16w9:cookie;default:reject;}}
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

 action compare_reference(){m.gen_diff=hdr.reference.generation-hdr.cache.generation;m.owner_diff=hdr.reference.expected_owner-hdr.cache.expected_owner;}
 table compare_reference_t{actions={compare_reference;}size=1;const default_action=compare_reference();}
 action identity_admitted(){m.identity_grant=1w1;}
 table identity_t{key={m.gen_diff:exact;m.owner_diff:exact;}actions={identity_admitted;NoAction;}size=1;const default_action=NoAction();const entries={(32w0,32w0):identity_admitted();}}
 Register<producer_cell_t,bit<1>>(1,{0,4}) reservation;
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) reserve={void apply(inout producer_cell_t value,out bit<32> granted){granted=32w0;if(value.phase==32w4&&value.generation<hdr.cache.generation){value.generation=hdr.cache.generation;value.phase=32w1;granted=32w1;}}};
 action reserve_image(){m.grant=reserve.execute(1w0);}
 table reserve_t{actions={reserve_image;}size=1;const default_action=reserve_image();}
 Register<bit<32>,bit<1>>(1,0) image_0;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_0) write_0={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w0;completed=1w1;}};
 action store_0(){m.done0=write_0.execute(1w0);}
 table store_0_t{actions={store_0;}size=1;const default_action=store_0();}
 Register<bit<32>,bit<1>>(1,0) image_1;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_1) write_1={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w1;completed=1w1;}};
 action store_1(){m.done1=write_1.execute(1w0);}
 table store_1_t{actions={store_1;}size=1;const default_action=store_1();}
 Register<bit<32>,bit<1>>(1,0) image_2;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_2) write_2={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w2;completed=1w1;}};
 action store_2(){m.done2=write_2.execute(1w0);}
 table store_2_t{actions={store_2;}size=1;const default_action=store_2();}
 Register<bit<32>,bit<1>>(1,0) image_3;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_3) write_3={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w3;completed=1w1;}};
 action store_3(){m.done3=write_3.execute(1w0);}
 table store_3_t{actions={store_3;}size=1;const default_action=store_3();}
 Register<bit<32>,bit<1>>(1,0) image_4;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_4) write_4={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w4;completed=1w1;}};
 action store_4(){m.done4=write_4.execute(1w0);}
 table store_4_t{actions={store_4;}size=1;const default_action=store_4();}
 Register<bit<32>,bit<1>>(1,0) image_5;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_5) write_5={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w5;completed=1w1;}};
 action store_5(){m.done5=write_5.execute(1w0);}
 table store_5_t{actions={store_5;}size=1;const default_action=store_5();}
 Register<bit<32>,bit<1>>(1,0) image_6;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_6) write_6={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w6;completed=1w1;}};
 action store_6(){m.done6=write_6.execute(1w0);}
 table store_6_t{actions={store_6;}size=1;const default_action=store_6();}
 Register<bit<32>,bit<1>>(1,0) image_7;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_7) write_7={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w7;completed=1w1;}};
 action store_7(){m.done7=write_7.execute(1w0);}
 table store_7_t{actions={store_7;}size=1;const default_action=store_7();}
 Register<bit<32>,bit<1>>(1,0) image_8;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_8) write_8={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w8;completed=1w1;}};
 action store_8(){m.done8=write_8.execute(1w0);}
 table store_8_t{actions={store_8;}size=1;const default_action=store_8();}
 Register<bit<32>,bit<1>>(1,0) image_9;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_9) write_9={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w9;completed=1w1;}};
 action store_9(){m.done9=write_9.execute(1w0);}
 table store_9_t{actions={store_9;}size=1;const default_action=store_9();}
 Register<bit<32>,bit<1>>(1,0) image_10;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_10) write_10={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w10;completed=1w1;}};
 action store_10(){m.done10=write_10.execute(1w0);}
 table store_10_t{actions={store_10;}size=1;const default_action=store_10();}
 Register<bit<32>,bit<1>>(1,0) image_11;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_11) write_11={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w11;completed=1w1;}};
 action store_11(){m.done11=write_11.execute(1w0);}
 table store_11_t{actions={store_11;}size=1;const default_action=store_11();}
 Register<bit<32>,bit<1>>(1,0) image_12;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_12) write_12={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w12;completed=1w1;}};
 action store_12(){m.done12=write_12.execute(1w0);}
 table store_12_t{actions={store_12;}size=1;const default_action=store_12();}
 Register<bit<32>,bit<1>>(1,0) image_13;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_13) write_13={void apply(inout bit<32> value,out bit<1> completed){value=8w0++hdr.image.w13;completed=1w1;}};
 action store_13(){m.done13=write_13.execute(1w0);}
 table store_13_t{actions={store_13;}size=1;const default_action=store_13();}
 Register<cache_tag_t,bit<1>>(1,{0,0}) cache_tag;
 RegisterAction<cache_tag_t,bit<1>,bit<1>>(cache_tag) tag_write={void apply(inout cache_tag_t value,out bit<1> completed){value.epoch=hdr.reference.epoch;value.generation=hdr.cache.generation;completed=1w1;}};
 Register<bit<32>,bit<1>>(1,0) cache_owner;
 RegisterAction<bit<32>,bit<1>,bit<1>>(cache_owner) owner_write={void apply(inout bit<32> value,out bit<1> completed){value=hdr.cache.expected_owner;completed=1w1;}};
 action publish_tag(){m.tag_done=tag_write.execute(1w0);}
 action publish_owner(){m.owner_done=owner_write.execute(1w0);}
 table publish_tag_t{key={m.done0:exact;m.done1:exact;m.done2:exact;m.done3:exact;m.done4:exact;m.done5:exact;m.done6:exact;m.done7:exact;m.done8:exact;m.done9:exact;m.done10:exact;m.done11:exact;m.done12:exact;m.done13:exact;}actions={publish_tag;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1):publish_tag();}}
 table publish_owner_t{key={m.done0:exact;m.done1:exact;m.done2:exact;m.done3:exact;m.done4:exact;m.done5:exact;m.done6:exact;m.done7:exact;m.done8:exact;m.done9:exact;m.done10:exact;m.done11:exact;m.done12:exact;m.done13:exact;}actions={publish_owner;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1):publish_owner();}}
 Register<bit<32>,bit<1>>(1,0) wire_position;
 RegisterAction<bit<32>,bit<1>,bit<1>>(wire_position) position_write={void apply(inout bit<32> value,out bit<1> completed){value=hdr.tcp.seq;completed=1w1;}};
 action publish_position(){m.position_done=position_write.execute(1w0);}
 table publish_position_t{key={m.done0:exact;m.done1:exact;m.done2:exact;m.done3:exact;m.done4:exact;m.done5:exact;m.done6:exact;m.done7:exact;m.done8:exact;m.done9:exact;m.done10:exact;m.done11:exact;m.done12:exact;m.done13:exact;}actions={publish_position;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1):publish_position();}}
 action ready(){hdr.reference.event=16w0x0514;}
 table ready_t{key={m.tag_done:exact;m.owner_done:exact;m.position_done:exact;}actions={ready;deny;}size=1;const default_action=deny();const entries={(1w1,1w1,1w1):ready();}}
 apply{
  if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
   connection.apply();compare_reference_t.apply();identity_t.apply();
   if(m.enabled==1w1&&m.identity_grant==1w1){
    reserve_t.apply();
    if(m.grant==32w1){
store_0_t.apply();store_1_t.apply();store_2_t.apply();store_3_t.apply();store_4_t.apply();store_5_t.apply();store_6_t.apply();store_7_t.apply();store_8_t.apply();store_9_t.apply();store_10_t.apply();store_11_t.apply();store_12_t.apply();store_13_t.apply();
     publish_tag_t.apply();publish_owner_t.apply();publish_position_t.apply();ready_t.apply();
    }else{deny();}
   }else{deny();}
  }else{deny();}
 }

}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);transition accept;}}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){apply{md.drop_ctl=3w1;}}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{}}
#ifndef ORDINARY_E_NO_MAIN
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
#endif

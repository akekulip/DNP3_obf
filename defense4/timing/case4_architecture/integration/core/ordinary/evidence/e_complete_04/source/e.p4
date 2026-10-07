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
struct meta_t{bit<16> tcp_length;bit<32> completion_epoch;bit<32> completion_generation;bit<32> completion_owner;bit<32> completion_cache_generation;bit<32> completion_cache_owner;bit<16> completion_event;bit<16> completion_format;bit<32> expected_phase;bit<32> completion_diff;bit<10> mirror_sid;bit<1> emit_ready;bit<8> role;bit<32> tag_match;bit<32> stored_owner_diff;bit<32> stored_position_diff;bit<1> parsed;bit<1> enabled;bool ip_error;bit<16> tcp_sum;bit<32> grant;bit<32> gen_diff;bit<32> owner_diff;bit<1> done0;bit<1> done1;bit<1> done2;bit<1> done3;bit<1> done4;bit<1> done5;bit<1> done6;bit<1> done7;bit<1> done8;bit<1> done9;bit<1> done10;bit<1> done11;bit<1> done12;bit<1> done13;bit<1> position_done;bit<1> tag_done;bit<1> owner_done;bit<1> identity_grant;}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){Checksum() ic;Checksum() tc;
 state start{pkt.extract(eg);m.grant=32w0;m.emit_ready=1w0;m.role=8w0;m.parsed=1w0;m.enabled=1w0;m.identity_grant=1w0;m.position_done=1w0;m.tag_done=1w0;m.owner_done=1w0;m.done0=1w0;m.done1=1w0;m.done2=1w0;m.done3=1w0;m.done4=1w0;m.done5=1w0;m.done6=1w0;m.done7=1w0;m.done8=1w0;m.done9=1w0;m.done10=1w0;m.done11=1w0;m.done12=1w0;m.done13=1w0;transition select(eg.egress_port){9w68:reference;9w2:emit_reference;default:reject;}}
 state emit_reference{m.role=8w2;pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:reject;default:emit_generation;}}
 state emit_generation{transition select(hdr.reference.generation){32w0:reject;default:emit_owner;}}
 state emit_owner{transition select(hdr.reference.expected_owner[31:16]){16w17:emit_cookie;default:reject;}}
 state emit_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:reject;default:emit_event;}}
 state emit_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0b14,16w2):emit_cache;default:reject;}}
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

 action compare_reference(){m.gen_diff=hdr.reference.generation-hdr.cache.generation;m.owner_diff=hdr.reference.expected_owner-hdr.cache.expected_owner;}
 table compare_reference_t{actions={compare_reference;}size=1;const default_action=compare_reference();}
 action identity_admitted(){m.identity_grant=1w1;}
 table identity_t{key={m.role:exact;m.gen_diff:ternary;m.owner_diff:exact;}actions={identity_admitted;NoAction;}size=5;const default_action=NoAction();const entries={(8w4,32w0,32w0x80000):identity_admitted();(8w0,32w0,32w0):identity_admitted();(8w1,_,32w0x80000):identity_admitted();(8w2,32w0,32w0x80000):identity_admitted();(8w3,32w0,32w0x80000):identity_admitted();}}
 Register<producer_cell_t,bit<1>>(1,{0,4}) reservation;
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) reserve={void apply(inout producer_cell_t value,out bit<32> granted){granted=32w0;if(value.phase==32w4&&value.generation<hdr.cache.generation){value.generation=hdr.cache.generation;value.phase=32w1;granted=32w1;}}};
 action reserve_image(){m.grant=reserve.execute(1w0);}
 table reserve_t{actions={reserve_image;}size=1;const default_action=reserve_image();}
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) claim_emit={void apply(inout producer_cell_t value,out bit<32> granted){granted=32w0;if(value.generation==hdr.cache.generation&&value.phase==32w1){value.generation=hdr.reference.generation;value.phase=32w2;granted=32w1;}}};
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) terminal={void apply(inout producer_cell_t value,out bit<32> granted){granted=32w0;if(value.generation==hdr.reference.generation&&value.phase==32w2){value.phase=32w4;granted=32w1;}}};
 action claim_endpoint(){m.grant=claim_emit.execute(1w0);}
 table claim_endpoint_t{actions={claim_endpoint;}size=1;const default_action=claim_endpoint();}
 action retire_emit(){m.grant=terminal.execute(1w0);}
 table retire_emit_t{actions={retire_emit;}size=1;const default_action=retire_emit();}
 Register<bit<32>,bit<1>>(1,0) image_0;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_0) write_0={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w0;completed=1w1;}};
 action store_0(){m.done0=write_0.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_0) read_0={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_0(){hdr.image.w0=read_0.execute(1w0);m.done0=1w1;}
 table load_0_t{actions={load_0;}size=1;const default_action=load_0();}
 table store_0_t{actions={store_0;}size=1;const default_action=store_0();}
 Register<bit<32>,bit<1>>(1,0) image_1;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_1) write_1={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w1;completed=1w1;}};
 action store_1(){m.done1=write_1.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_1) read_1={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_1(){hdr.image.w1=read_1.execute(1w0);m.done1=1w1;}
 table load_1_t{actions={load_1;}size=1;const default_action=load_1();}
 table store_1_t{actions={store_1;}size=1;const default_action=store_1();}
 Register<bit<32>,bit<1>>(1,0) image_2;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_2) write_2={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w2;completed=1w1;}};
 action store_2(){m.done2=write_2.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_2) read_2={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_2(){hdr.image.w2=read_2.execute(1w0);m.done2=1w1;}
 table load_2_t{actions={load_2;}size=1;const default_action=load_2();}
 table store_2_t{actions={store_2;}size=1;const default_action=store_2();}
 Register<bit<32>,bit<1>>(1,0) image_3;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_3) write_3={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w3;completed=1w1;}};
 action store_3(){m.done3=write_3.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_3) read_3={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_3(){hdr.image.w3=read_3.execute(1w0);m.done3=1w1;}
 table load_3_t{actions={load_3;}size=1;const default_action=load_3();}
 table store_3_t{actions={store_3;}size=1;const default_action=store_3();}
 Register<bit<32>,bit<1>>(1,0) image_4;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_4) write_4={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w4;completed=1w1;}};
 action store_4(){m.done4=write_4.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_4) read_4={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_4(){hdr.image.w4=read_4.execute(1w0);m.done4=1w1;}
 table load_4_t{actions={load_4;}size=1;const default_action=load_4();}
 table store_4_t{actions={store_4;}size=1;const default_action=store_4();}
 Register<bit<32>,bit<1>>(1,0) image_5;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_5) write_5={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w5;completed=1w1;}};
 action store_5(){m.done5=write_5.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_5) read_5={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_5(){hdr.image.w5=read_5.execute(1w0);m.done5=1w1;}
 table load_5_t{actions={load_5;}size=1;const default_action=load_5();}
 table store_5_t{actions={store_5;}size=1;const default_action=store_5();}
 Register<bit<32>,bit<1>>(1,0) image_6;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_6) write_6={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w6;completed=1w1;}};
 action store_6(){m.done6=write_6.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_6) read_6={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_6(){hdr.image.w6=read_6.execute(1w0);m.done6=1w1;}
 table load_6_t{actions={load_6;}size=1;const default_action=load_6();}
 table store_6_t{actions={store_6;}size=1;const default_action=store_6();}
 Register<bit<32>,bit<1>>(1,0) image_7;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_7) write_7={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w7;completed=1w1;}};
 action store_7(){m.done7=write_7.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_7) read_7={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_7(){hdr.image.w7=read_7.execute(1w0);m.done7=1w1;}
 table load_7_t{actions={load_7;}size=1;const default_action=load_7();}
 table store_7_t{actions={store_7;}size=1;const default_action=store_7();}
 Register<bit<32>,bit<1>>(1,0) image_8;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_8) write_8={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w8;completed=1w1;}};
 action store_8(){m.done8=write_8.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_8) read_8={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_8(){hdr.image.w8=read_8.execute(1w0);m.done8=1w1;}
 table load_8_t{actions={load_8;}size=1;const default_action=load_8();}
 table store_8_t{actions={store_8;}size=1;const default_action=store_8();}
 Register<bit<32>,bit<1>>(1,0) image_9;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_9) write_9={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w9;completed=1w1;}};
 action store_9(){m.done9=write_9.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_9) read_9={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_9(){hdr.image.w9=read_9.execute(1w0);m.done9=1w1;}
 table load_9_t{actions={load_9;}size=1;const default_action=load_9();}
 table store_9_t{actions={store_9;}size=1;const default_action=store_9();}
 Register<bit<32>,bit<1>>(1,0) image_10;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_10) write_10={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w10;completed=1w1;}};
 action store_10(){m.done10=write_10.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_10) read_10={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_10(){hdr.image.w10=read_10.execute(1w0);m.done10=1w1;}
 table load_10_t{actions={load_10;}size=1;const default_action=load_10();}
 table store_10_t{actions={store_10;}size=1;const default_action=store_10();}
 Register<bit<32>,bit<1>>(1,0) image_11;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_11) write_11={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w11;completed=1w1;}};
 action store_11(){m.done11=write_11.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_11) read_11={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_11(){hdr.image.w11=read_11.execute(1w0);m.done11=1w1;}
 table load_11_t{actions={load_11;}size=1;const default_action=load_11();}
 table store_11_t{actions={store_11;}size=1;const default_action=store_11();}
 Register<bit<32>,bit<1>>(1,0) image_12;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_12) write_12={void apply(inout bit<32> value,out bit<1> completed){value=hdr.image.w12;completed=1w1;}};
 action store_12(){m.done12=write_12.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_12) read_12={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_12(){hdr.image.w12=read_12.execute(1w0);m.done12=1w1;}
 table load_12_t{actions={load_12;}size=1;const default_action=load_12();}
 table store_12_t{actions={store_12;}size=1;const default_action=store_12();}
 Register<bit<32>,bit<1>>(1,0) image_13;
 RegisterAction<bit<32>,bit<1>,bit<1>>(image_13) write_13={void apply(inout bit<32> value,out bit<1> completed){value=8w0++hdr.image.w13;completed=1w1;}};
 action store_13(){m.done13=write_13.execute(1w0);}
 RegisterAction<bit<32>,bit<1>,bit<32>>(image_13) read_13={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action load_13(){hdr.image.w13=read_13.execute(1w0)[23:0];m.done13=1w1;}
 table load_13_t{actions={load_13;}size=1;const default_action=load_13();}
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
 action endpoint_ready(){m.emit_ready=1w1;m.tcp_length=16w75;m.mirror_sid=10w1;md.mirror_type=3w2;m.completion_epoch=hdr.reference.epoch;m.completion_generation=hdr.reference.generation;m.completion_owner=hdr.reference.expected_owner;m.completion_cache_generation=hdr.cache.generation;m.completion_cache_owner=hdr.cache.expected_owner;m.completion_event=16w0x0e14;m.completion_format=16w2;hdr.reference.setInvalid();hdr.cache.setInvalid();}
 table endpoint_ready_t{key={m.done0:exact;m.done1:exact;m.done2:exact;m.done3:exact;m.done4:exact;m.done5:exact;m.done6:exact;m.done7:exact;m.done8:exact;m.done9:exact;m.done10:exact;m.done11:exact;m.done12:exact;m.done13:exact;}actions={endpoint_ready;deny;}size=1;const default_action=deny();const entries={(1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1,1w1):endpoint_ready();}}
 action ready(){hdr.reference.event=16w0x0514;}
 table ready_t{key={m.tag_done:exact;m.owner_done:exact;m.position_done:exact;}actions={ready;deny;}size=1;const default_action=deny();const entries={(1w1,1w1,1w1):ready();}}

 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) inspect={void apply(inout producer_cell_t value,out bit<32> granted){granted=32w0;if(value.generation==hdr.cache.generation&&value.phase==m.expected_phase){granted=32w1;}}};
 action inspect_cache_pin(){m.grant=inspect.execute(1w0);}
 table inspect_cache_pin_t{actions={inspect_cache_pin;}size=1;const default_action=inspect_cache_pin();}
 RegisterAction<cache_tag_t,bit<1>,bit<32>>(cache_tag) tag_check={void apply(inout cache_tag_t value,out bit<32> result){result=32w0;if(value.epoch!=hdr.reference.epoch||value.generation!=hdr.cache.generation){result=32w1;}}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(cache_owner) owner_check={void apply(inout bit<32> value,out bit<32> result){result=value-hdr.cache.expected_owner;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(wire_position) position_check={void apply(inout bit<32> value,out bit<32> result){result=value-hdr.tcp.seq;}};
 action check_tag(){m.tag_match=tag_check.execute(1w0);}
 table check_tag_t{actions={check_tag;}size=1;const default_action=check_tag();}
 action check_owner(){m.stored_owner_diff=owner_check.execute(1w0);}
 table check_owner_t{actions={check_owner;}size=1;const default_action=check_owner();}
 action check_position(){m.stored_position_diff=position_check.execute(1w0);}
 table check_position_t{actions={check_position;}size=1;const default_action=check_position();}
 action query_qualified(){hdr.reference.event=16w0x0b14;}
 action completion_qualified(){hdr.completion.setValid();hdr.completion.epoch=hdr.reference.epoch;hdr.reference.event=16w0x1214;hdr.reference.format=16w3;}
 table query_result_t{key={m.role:exact;m.tag_match:exact;m.stored_owner_diff:exact;m.stored_position_diff:exact;}actions={query_qualified;completion_qualified;deny;}size=2;const default_action=deny();const entries={(8w1,32w0,32w0,32w0):query_qualified();(8w3,32w0,32w0,32w0):completion_qualified();}}
 table terminal_gate_t{key={m.identity_grant:exact;m.completion_diff:exact;}actions={retire_emit;deny;}size=1;const default_action=deny();const entries={(1w1,32w0):retire_emit();}}
 action strip_completion(){hdr.reference.event=16w0x0e14;hdr.reference.format=16w2;hdr.completion.setInvalid();}
 table completion_result_t{key={m.grant:exact;}actions={strip_completion;deny;}size=1;const default_action=deny();const entries={32w1:strip_completion();}}
 apply{
  compare_reference_t.apply();identity_t.apply();
  if(m.role==8w4&&m.parsed==1w1){
   m.completion_diff=hdr.reference.epoch-hdr.completion.epoch;
   terminal_gate_t.apply();completion_result_t.apply();
  }else if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
   connection.apply();
   if(m.enabled==1w1&&m.identity_grant==1w1){
    if(m.role==8w2){
     claim_endpoint_t.apply();
     if(m.grant==32w1){load_0_t.apply();load_1_t.apply();load_2_t.apply();load_3_t.apply();load_4_t.apply();load_5_t.apply();load_6_t.apply();load_7_t.apply();load_8_t.apply();load_9_t.apply();load_10_t.apply();load_11_t.apply();load_12_t.apply();load_13_t.apply();endpoint_ready_t.apply();}else{deny();}
    }else if(m.role==8w1||m.role==8w3){
     inspect_cache_pin_t.apply();
     if(m.grant==32w1){check_tag_t.apply();check_owner_t.apply();check_position_t.apply();query_result_t.apply();}else{deny();}
    }else{reserve_t.apply();
    if(m.grant==32w1){
store_0_t.apply();store_1_t.apply();store_2_t.apply();store_3_t.apply();store_4_t.apply();store_5_t.apply();store_6_t.apply();store_7_t.apply();store_8_t.apply();store_9_t.apply();store_10_t.apply();store_11_t.apply();store_12_t.apply();store_13_t.apply();
     publish_tag_t.apply();publish_owner_t.apply();publish_position_t.apply();ready_t.apply();
    }else{deny();}
    }
   }else{deny();}
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

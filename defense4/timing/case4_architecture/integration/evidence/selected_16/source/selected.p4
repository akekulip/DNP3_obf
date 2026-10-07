/* Autonomous actual native35 SELECT context publisher experiment.
 * Four processing passes; full network/profile/all3CRC validation precedes work.
 * Transaction epoch equals nonwrapping allocated work generation; it is NOT
 * yet the live connection epoch. Actual response57/allstatuses and OP comparisons; no verified reset/reuse
 * or live connection-epoch composition. Stored REAL object and frozen configured decoy are distinct.
 */
#include <core.p4>
#include <tna.p4>
#include "work_record.p4"
const PortId_t RETURN_PORT=9w68;
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header tail_h{bit<32> off;bit<8> status;bit<16> crc;}
header block_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<16> crc;}
header response_tail_h{bit<32> w0;bit<32> w1;bit<8> w2;bit<16> crc;}
struct object_pair_t{bit<32> first;bit<32> second;}
struct publication_cell_t{bit<32> generation;bit<32> phase;}
header epoch_h{bit<32> epoch;}
header generation_h{bit<32> generation;}
header expected_h{bit<32> expected;}
header event_h{bit<16> event;bit<16> reserved;}
struct headers_t{epoch_h epoch;generation_h generation;expected_h expected;event_h event;eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;block_h first;tail_h tail;block_h second;response_tail_h response_tail;}
struct meta_t{bit<8> cache_mode;bit<8> association_allowed;bit<8> response;bit<8> matched;bit<8> operate_qualified;bit<32> prefix_difference;bit<32> accepted_diff;bit<16> crc1;bit<8> bad1;bit<32> compare_real_links;bit<32> diff_real_links;bit<32> compare_real_tcp_src;bit<32> diff_real_tcp_src;bit<32> compare_real_tcp_dst;bit<32> diff_real_tcp_dst;bit<32> compare_real_tcp_ports;bit<32> diff_real_tcp_ports;bit<32> compare_real_object;bit<32> diff_real_object;bit<32> compare_real_on;bit<32> diff_real_on;bit<32> compare_real_off;bit<32> diff_real_off;bit<32> compare_native_start;bit<32> diff_native_start;bit<32> compare_native_end;bit<32> diff_native_end;bit<32> compare_server_start;bit<32> diff_server_start;bit<32> compare_application;bit<32> diff_application;bit<32> compare_frozen_decoy_object;bit<32> diff_frozen_decoy_object;bit<32> compare_frozen_decoy_on;bit<32> diff_frozen_decoy_on;bit<32> compare_frozen_decoy_off;bit<32> diff_frozen_decoy_off;bit<8> port_valid;bit<8> stage;bit<8> kind;bit<8> work_op;bit<32> generation;bit<32> work_phase;bit<32> context_generation;bit<32> native_end;bit<8> parsed;bit<8> enabled;bit<8> profile;bit<8> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<8> badh;bit<8> badb;bit<8> badt;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=8w0;m.cache_mode=8w0;m.association_allowed=8w0;m.response=8w0;m.matched=8w0;m.bad1=8w0;m.port_valid=8w0;m.stage=8w0;m.kind=8w0;m.enabled=8w0;m.profile=8w0;m.changed=8w0;m.badh=8w0;m.badb=8w0;m.badt=8w0;transition select(ig.ingress_port){RETURN_PORT:epoch;default:eth;}}
 state epoch{pkt.extract(hdr.epoch);transition select(hdr.epoch.epoch){32w0:accept;default:generation;}}
 state generation{pkt.extract(hdr.generation);transition select(hdr.generation.generation){32w0:accept;default:expected;}}
 state expected{pkt.extract(hdr.expected);pkt.extract(hdr.event);m.stage=hdr.event.event[15:8];m.kind=hdr.event.event[7:0];transition reserved;}
 state reserved{transition select(hdr.event.reserved){16w0:events;default:accept;}}
 state events{transition select(hdr.event.event){16w0x0101:eth;16w0x0201:eth;16w0x0301:eth;16w0x01ff:eth;16w0x02ff:eth;16w0x03ff:eth;default:accept;}}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w75,8w6):native_ip_flags;(4w4,4w5,16w97,8w6):response_ip_flags;default:accept;}}
 state native_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):native_tcp;(13w0,3w2):native_tcp;default:accept;}}
 state native_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):native_dl;(4w5,4w0,8w0x18,16w0):native_dl;default:accept;}}
 state native_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native;}
 state response_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):response_tcp;(13w0,3w2):response_tcp;default:accept;}}
 state response_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):response_dl;(4w5,4w0,8w0x18,16w0):response_dl;default:accept;}}
 state response_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition first;}
 state native{pkt.extract(hdr.first);tc.subtract(hdr.first);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=8w1;transition accept;} state first{pkt.extract(hdr.first);tc.subtract(hdr.first);transition second;}
 state second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition response_tail;}
 state response_tail{pkt.extract(hdr.response_tail);tc.subtract(hdr.response_tail);m.tcp_sum=tc.get();m.response=8w1;m.parsed=8w1;transition accept;}

}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.port_valid=8w1;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action configure(bit<16> index,bit<8> code,bit<8> repeat,bit<32> on,bit<32> off){m.enabled=8w1;m.decoy_index=index;m.decoy_code=code;m.decoy_repeat=repeat;m.decoy_on=on;m.decoy_off=off;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=2;default_action=NoAction();}
 action eligible(){m.profile=8w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:8]:exact;hdr.first.w0[7:0]:exact;hdr.first.w1[31:24]:exact;hdr.first.w1[23:16]:exact;hdr.first.w1[15:0]:exact;hdr.tail.status:exact;}
 actions={eligible;NoAction;}size=2;const default_action=NoAction();const entries={(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w3,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w4,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();}}
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_head;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_body;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;
action input_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table input_head_t{actions={input_head;}size=1;const default_action=input_head();}
action input_body(){m.bcrc=hash_body.get({hdr.first.w0[31:24],hdr.first.w0[23:16],hdr.first.w0[15:8],hdr.first.w0[7:0],hdr.first.w1[31:24],hdr.first.w1[23:16],hdr.first.w1[15:0],hdr.first.w2[31:16],hdr.first.w2[15:8],hdr.first.w2[7:0],hdr.first.w3});}
table input_body_t{actions={input_body;}size=1;const default_action=input_body();}
action input_tail(){m.tcrc=hash_tail.get({hdr.tail.off,hdr.tail.status});}
table input_tail_t{actions={input_tail;}size=1;const default_action=input_tail();}
table response_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:0]:exact;hdr.first.w1:exact;hdr.first.w2[31:16]:exact;hdr.second.w1[15:0]:exact;hdr.second.w2:exact;hdr.response_tail.w2:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w46,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,16w0x8100,32w0x000c0128,16w0x0100,16w0x000c,32w0x01280100,8w0):eligible();}}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_first;
action response_crc0(){m.bcrc=hash_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}
table response_crc0_t{actions={response_crc0;}size=1;const default_action=response_crc0();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_second;
action response_crc1(){m.crc1=hash_second.get({hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3});}
table response_crc1_t{actions={response_crc1;}size=1;const default_action=response_crc1();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_tail;
action response_crct(){m.tcrc=hash_response_tail.get({hdr.response_tail.w0,hdr.response_tail.w1,hdr.response_tail.w2});}
table response_crct_t{actions={response_crct;}size=1;const default_action=response_crct();}
WorkRecord() work;
Register<bit<32>,bit<1>>(1,0) counter;
RegisterAction<bit<32>,bit<1>,bit<32>>(counter) allocate={void apply(inout bit<32> v,out bit<32> r){r=32w0;if((int<32>)v!=-1){v=v+32w1;r=v;}}};
action mint(){m.generation=allocate.execute(1w0);m.work_op=8w1;}
table mint_t{actions={mint;}size=1;const default_action=mint();}
Register<publication_cell_t,bit<1>>(1,{0,4}) published;
RegisterAction<publication_cell_t,bit<1>,bit<32>>(published) read_published={void apply(inout publication_cell_t v,out bit<32> r){r=v.generation;}};
RegisterAction<publication_cell_t,bit<1>,bit<32>>(published) publish={void apply(inout publication_cell_t v,out bit<32> r){if(v.phase==4){v.generation=hdr.generation.generation;v.phase=5;}r=v.generation;}};
action load_published(){m.context_generation=read_published.execute(1w0);}
action commit_published(){m.context_generation=publish.execute(1w0);}
table published_t{key={m.stage:exact;m.kind:exact;m.work_op:exact;m.work_phase:exact;}actions={load_published;commit_published;}size=1;const entries={(8w1,8w1,8w2,32w1):commit_published();}const default_action=load_published();}
action calculate_native_end(){m.native_end=hdr.tcp.seq+32w35;}
table calculate_native_end_t{actions={calculate_native_end;}size=1;const default_action=calculate_native_end();}
Register<bit<32>,bit<1>>(1,0) application;
RegisterAction<bit<32>,bit<1>,bit<32>>(application) write_application={void apply(inout bit<32> v,out bit<32> r){v=m.compare_application;r=v;}};
RegisterAction<bit<32>,bit<1>,bit<32>>(application) read_op_application={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_application;}};RegisterAction<bit<32>,bit<1>,bit<32>>(application) read_rsp_application={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_application;}};
action compare_rsp_application(){m.diff_application=read_rsp_application.execute(1w0);}
action compare_application(){m.diff_application=read_op_application.execute(1w0);}
action store_application(){write_application.execute(1w0);}
table application_t{key={m.cache_mode:exact;}actions={store_application;compare_application;compare_rsp_application;NoAction;}size=3;const entries={8w1:store_application();8w2:compare_application();8w3:compare_rsp_application();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) frozen_decoy_off;
RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_off) write_frozen_decoy_off={void apply(inout bit<32> v,out bit<32> r){v=m.compare_frozen_decoy_off;r=v;}};
RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_off) read_op_frozen_decoy_off={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_frozen_decoy_off;}};RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_off) read_rsp_frozen_decoy_off={void apply(inout bit<32> v,out bit<32> r){r=v-m.compare_frozen_decoy_off;}};
action compare_rsp_frozen_decoy_off(){m.diff_frozen_decoy_off=read_rsp_frozen_decoy_off.execute(1w0);}
action compare_frozen_decoy_off(){m.diff_frozen_decoy_off=read_op_frozen_decoy_off.execute(1w0);}
action store_frozen_decoy_off(){write_frozen_decoy_off.execute(1w0);}
table frozen_decoy_off_t{key={m.cache_mode:exact;}actions={store_frozen_decoy_off;compare_frozen_decoy_off;compare_rsp_frozen_decoy_off;NoAction;}size=3;const entries={8w1:store_frozen_decoy_off();8w2:compare_frozen_decoy_off();8w3:compare_rsp_frozen_decoy_off();}const default_action=NoAction();}
Register<object_pair_t,bit<1>>(1,{0,0}) pair_real_links_real_tcp_src;
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_real_links_real_tcp_src) write_real_links={void apply(inout object_pair_t v,out bit<32> r){v.first=m.compare_real_links;v.second=m.compare_real_tcp_src;r=32w0;}};
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_real_links_real_tcp_src) read_real_links={void apply(inout object_pair_t v,out bit<32> r){r=32w0;if(v.first!=m.compare_real_links||v.second!=m.compare_real_tcp_src){r=32w1;}}};
action store_real_links(){write_real_links.execute(1w0);}
action compare_real_links(){m.diff_real_links=read_real_links.execute(1w0);m.diff_real_tcp_src=m.diff_real_links;}
table real_links_t{key={m.cache_mode:exact;}actions={store_real_links;compare_real_links;NoAction;}size=3;const entries={8w1:store_real_links();8w2:compare_real_links();8w3:compare_real_links();}const default_action=NoAction();}
Register<object_pair_t,bit<1>>(1,{0,0}) pair_real_tcp_dst_real_tcp_ports;
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_real_tcp_dst_real_tcp_ports) write_real_tcp_dst={void apply(inout object_pair_t v,out bit<32> r){v.first=m.compare_real_tcp_dst;v.second=m.compare_real_tcp_ports;r=32w0;}};
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_real_tcp_dst_real_tcp_ports) read_real_tcp_dst={void apply(inout object_pair_t v,out bit<32> r){r=32w0;if(v.first!=m.compare_real_tcp_dst||v.second!=m.compare_real_tcp_ports){r=32w1;}}};
action store_real_tcp_dst(){write_real_tcp_dst.execute(1w0);}
action compare_real_tcp_dst(){m.diff_real_tcp_dst=read_real_tcp_dst.execute(1w0);m.diff_real_tcp_ports=m.diff_real_tcp_dst;}
table real_tcp_dst_t{key={m.cache_mode:exact;}actions={store_real_tcp_dst;compare_real_tcp_dst;NoAction;}size=3;const entries={8w1:store_real_tcp_dst();8w2:compare_real_tcp_dst();8w3:compare_real_tcp_dst();}const default_action=NoAction();}
Register<object_pair_t,bit<1>>(1,{0,0}) pair_real_object_real_on;
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_real_object_real_on) write_real_object={void apply(inout object_pair_t v,out bit<32> r){v.first=m.compare_real_object;v.second=m.compare_real_on;r=32w0;}};
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_real_object_real_on) read_real_object={void apply(inout object_pair_t v,out bit<32> r){r=32w0;if(v.first!=m.compare_real_object||v.second!=m.compare_real_on){r=32w1;}}};
action store_real_object(){write_real_object.execute(1w0);}
action compare_real_object(){m.diff_real_object=read_real_object.execute(1w0);m.diff_real_on=m.diff_real_object;}
table real_object_t{key={m.cache_mode:exact;}actions={store_real_object;compare_real_object;NoAction;}size=3;const entries={8w1:store_real_object();8w2:compare_real_object();8w3:compare_real_object();}const default_action=NoAction();}
Register<object_pair_t,bit<1>>(1,{0,0}) pair_real_off_native_start;
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_real_off_native_start) write_real_off={void apply(inout object_pair_t v,out bit<32> r){v.first=m.compare_real_off;v.second=m.compare_native_start;r=32w0;}};
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_real_off_native_start) read_real_off={void apply(inout object_pair_t v,out bit<32> r){r=32w0;if(v.first!=m.compare_real_off||v.second!=m.compare_native_start){r=32w1;}}};
action store_real_off(){write_real_off.execute(1w0);}
action compare_real_off(){m.diff_real_off=read_real_off.execute(1w0);m.diff_native_start=m.diff_real_off;}
table real_off_t{key={m.cache_mode:exact;}actions={store_real_off;compare_real_off;NoAction;}size=3;const entries={8w1:store_real_off();8w2:compare_real_off();8w3:compare_real_off();}const default_action=NoAction();}
Register<object_pair_t,bit<1>>(1,{0,0}) pair_native_end_server_start;
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_native_end_server_start) write_native_end={void apply(inout object_pair_t v,out bit<32> r){v.first=m.compare_native_end;v.second=m.compare_server_start;r=32w0;}};
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_native_end_server_start) read_native_end={void apply(inout object_pair_t v,out bit<32> r){r=32w0;if(v.first!=m.compare_native_end||v.second!=m.compare_server_start){r=32w1;}}};
action store_native_end(){write_native_end.execute(1w0);}
action compare_native_end(){m.diff_native_end=read_native_end.execute(1w0);m.diff_server_start=m.diff_native_end;}
table native_end_t{key={m.cache_mode:exact;}actions={store_native_end;compare_native_end;NoAction;}size=3;const entries={8w1:store_native_end();8w2:compare_native_end();8w3:compare_native_end();}const default_action=NoAction();}
Register<object_pair_t,bit<1>>(1,{0,0}) pair_frozen_decoy_object_frozen_decoy_on;
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_frozen_decoy_object_frozen_decoy_on) write_frozen_decoy_object={void apply(inout object_pair_t v,out bit<32> r){v.first=m.compare_frozen_decoy_object;v.second=m.compare_frozen_decoy_on;r=32w0;}};
RegisterAction<object_pair_t,bit<1>,bit<32>>(pair_frozen_decoy_object_frozen_decoy_on) read_frozen_decoy_object={void apply(inout object_pair_t v,out bit<32> r){r=32w0;if(v.first!=m.compare_frozen_decoy_object||v.second!=m.compare_frozen_decoy_on){r=32w1;}}};
action store_frozen_decoy_object(){write_frozen_decoy_object.execute(1w0);}
action compare_frozen_decoy_object(){m.diff_frozen_decoy_object=read_frozen_decoy_object.execute(1w0);m.diff_frozen_decoy_on=m.diff_frozen_decoy_object;}
table frozen_decoy_object_t{key={m.cache_mode:exact;}actions={store_frozen_decoy_object;compare_frozen_decoy_object;NoAction;}size=3;const entries={8w1:store_frozen_decoy_object();8w2:compare_frozen_decoy_object();8w3:compare_frozen_decoy_object();}const default_action=NoAction();}
action start_work(){hdr.epoch.setValid();hdr.generation.setValid();hdr.expected.setValid();hdr.event.setValid();hdr.epoch.epoch=m.generation;hdr.generation.generation=m.generation;hdr.expected.expected=32w0;hdr.event.event=16w0x0101;hdr.event.reserved=16w0;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}
table start_work_t{actions={start_work;}size=1;const default_action=start_work();}
action abort_work(){hdr.event.event=16w0x01ff;}
table abort_t{actions={abort_work;}size=1;const default_action=abort_work();}
action next_work(){hdr.event.event=hdr.event.event+16w0x100;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}
table next_work_t{actions={next_work;}size=1;const default_action=next_work();}
Register<bit<32>,bit<1>>(1,0) qualified_operate;
RegisterAction<bit<32>,bit<1>,bit<32>>(qualified_operate) record_operate={void apply(inout bit<32> v,out bit<32> r){r=v;if((int<32>)v!=-1){v=v+32w1;}}};
action prefix_identity(){m.prefix_difference=hdr.epoch.epoch-hdr.generation.generation;}
table prefix_identity_t{actions={prefix_identity;}size=1;const default_action=prefix_identity();}
action compare_response_inputs(){m.compare_real_links=(bit<32>)(hdr.dl.src++hdr.dl.dst);m.compare_real_tcp_src=(bit<32>)(hdr.ip.dst);m.compare_real_tcp_dst=(bit<32>)(hdr.ip.src);m.compare_real_tcp_ports=(bit<32>)(hdr.tcp.dport++hdr.tcp.sport);m.compare_real_object=(bit<32>)(hdr.first.w2[15:0]++hdr.first.w3[31:16]);m.compare_real_on=(bit<32>)(hdr.first.w3[15:0]++hdr.second.w0[31:16]);m.compare_real_off=(bit<32>)(hdr.second.w0[15:0]++hdr.second.w1[31:16]);m.compare_native_start=(bit<32>)(hdr.tcp.ack-32w55);m.compare_native_end=(bit<32>)(hdr.tcp.ack-32w20);m.compare_server_start=(bit<32>)(hdr.tcp.seq);m.compare_application=(bit<32>)(hdr.first.w0[23:16]);m.compare_frozen_decoy_object=(bit<32>)(hdr.second.w3);m.compare_frozen_decoy_on=(bit<32>)(hdr.response_tail.w0);m.compare_frozen_decoy_off=(bit<32>)(hdr.response_tail.w1);}
table compare_response_inputs_t{actions={compare_response_inputs;}size=1;const default_action=compare_response_inputs();}
action compare_operate_inputs(){m.compare_real_links=(bit<32>)(hdr.dl.dst++hdr.dl.src);m.compare_real_tcp_src=(bit<32>)(hdr.ip.src);m.compare_real_tcp_dst=(bit<32>)(hdr.ip.dst);m.compare_real_tcp_ports=(bit<32>)(hdr.tcp.sport++hdr.tcp.dport);m.compare_real_object=(bit<32>)(hdr.first.w2[31:16]++hdr.first.w2[15:8]++hdr.first.w2[7:0]);m.compare_real_on=(bit<32>)(hdr.first.w3);m.compare_real_off=(bit<32>)(hdr.tail.off);m.compare_native_start=(bit<32>)(hdr.tcp.seq-32w35);m.compare_native_end=(bit<32>)(hdr.tcp.seq);m.compare_server_start=(bit<32>)(hdr.tcp.ack-32w57);m.compare_application=(bit<32>)(hdr.first.w0[23:16]);m.compare_frozen_decoy_object=(bit<32>)(m.decoy_index++m.decoy_code++m.decoy_repeat);m.compare_frozen_decoy_on=(bit<32>)(m.decoy_on);m.compare_frozen_decoy_off=(bit<32>)(m.decoy_off);}
table compare_operate_inputs_t{actions={compare_operate_inputs;}size=1;const default_action=compare_operate_inputs();}
Register<publication_cell_t,bit<1>>(1,{0,4}) accepted;
RegisterAction<publication_cell_t,bit<1>,bit<32>>(accepted) read_accepted={void apply(inout publication_cell_t v,out bit<32> r){r=32w1;if(v.phase==5&&v.generation==m.context_generation){r=32w0;}}};
RegisterAction<publication_cell_t,bit<1>,bit<32>>(accepted) accept_response={void apply(inout publication_cell_t v,out bit<32> r){r=32w1;if(v.phase==4){v.generation=m.context_generation;v.phase=5;}if(v.phase==5&&v.generation==m.context_generation){r=32w0;}}};
action match_response(){m.matched=8w1;m.accepted_diff=accept_response.execute(1w0);}
action match_operate(){m.matched=8w1;m.accepted_diff=read_accepted.execute(1w0);}
table object_match{key={m.response:exact;m.diff_real_links:exact;m.diff_real_tcp_src:exact;m.diff_real_tcp_dst:exact;m.diff_real_tcp_ports:exact;m.diff_real_object:exact;m.diff_real_on:exact;m.diff_real_off:exact;m.diff_native_start:exact;m.diff_native_end:exact;m.diff_server_start:exact;m.diff_application:exact;m.diff_frozen_decoy_object:exact;m.diff_frozen_decoy_on:exact;m.diff_frozen_decoy_off:exact;}actions={match_response;match_operate;NoAction;}size=3;const default_action=NoAction();const entries={(8w1,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0):match_response();(8w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w4294967295,32w0,32w0,32w0):match_operate();(8w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w0,32w15,32w0,32w0,32w0):match_operate();}}
// Qualification produces an internal diagnostic mark only. No scheduler or
// actual connection-authority mutation exists in this isolated component.
action operate_qualified(){m.operate_qualified=8w1;record_operate.execute(1w0);}
table operate_qualified_t{key={m.matched:exact;m.accepted_diff:exact;hdr.first.w0[15:8]:exact;}actions={operate_qualified;NoAction;}size=1;const entries={(8w1,32w0,8w4):operate_qualified();}const default_action=NoAction();}
action association_allowed(){m.association_allowed=8w1;}
table association_admission{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;}actions={association_allowed;NoAction;}size=1;const entries={(8w0,8w0,32w4):association_allowed();}const default_action=NoAction();}
action compare_select_inputs(){m.compare_real_links=(bit<32>)(hdr.dl.dst++hdr.dl.src);m.compare_real_tcp_src=(bit<32>)(hdr.ip.src);m.compare_real_tcp_dst=(bit<32>)(hdr.ip.dst);m.compare_real_tcp_ports=(bit<32>)(hdr.tcp.sport++hdr.tcp.dport);m.compare_real_object=(bit<32>)(hdr.first.w2[31:16]++hdr.first.w2[15:8]++hdr.first.w2[7:0]);m.compare_real_on=(bit<32>)(hdr.first.w3);m.compare_real_off=(bit<32>)(hdr.tail.off);m.compare_native_start=(bit<32>)(hdr.tcp.seq);m.compare_native_end=(bit<32>)(m.native_end);m.compare_server_start=(bit<32>)(hdr.tcp.ack);m.compare_application=(bit<32>)(hdr.first.w0[23:16]);m.compare_frozen_decoy_object=(bit<32>)(m.decoy_index++m.decoy_code++m.decoy_repeat);m.compare_frozen_decoy_on=(bit<32>)(m.decoy_on);m.compare_frozen_decoy_off=(bit<32>)(m.decoy_off);}
table compare_select_inputs_t{actions={compare_select_inputs;}size=1;const default_action=compare_select_inputs();}
action cache_store(){m.cache_mode=8w1;}
action cache_op(){m.cache_mode=8w2;}
action cache_response(){m.cache_mode=8w3;}
table cache_access{key={m.response:exact;m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:ternary;}actions={cache_store;cache_op;cache_response;NoAction;}size=3;const entries={(8w0,8w0,8w1,32w4,32w0):cache_store();(8w0,8w0,8w0,32w4,_):cache_op();(8w1,8w0,8w0,32w4,_):cache_response();}const default_action=NoAction();}
action return_nonce(){m.generation=hdr.generation.generation;m.work_op=8w2;}
table return_packet{key={m.response:exact;hdr.first.w0[15:8]:exact;}actions={return_nonce;deny;}size=1;const entries={(8w0,8w3):return_nonce();}const default_action=deny();}
apply{m.work_op=8w0;m.generation=32w0;forwarding.apply();
 if(m.port_valid==8w1&&m.parsed==8w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
 connection.apply();if(m.response==8w1){response_profile.apply();}else{profile.apply();}if(m.enabled==8w1&&m.profile==8w1){
 input_head_t.apply();if(m.response==8w1){response_crc0_t.apply();response_crc1_t.apply();response_crct_t.apply();}else{input_body_t.apply();input_tail_t.apply();}
 if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=8w1;}
 if(m.response==8w1){
 if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}
 if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=8w1;}
 if(hdr.response_tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}
 }else{
 if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}
 if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}

 if(m.badh==8w0&&m.badb==8w0&&m.bad1==8w0&&m.badt==8w0){
 if(m.stage==8w0){if(m.response==8w0&&hdr.first.w0[15:8]==8w3&&hdr.first.w2[31:16]!=m.decoy_index){mint_t.apply();}}else{return_packet.apply();prefix_identity_t.apply();if(m.prefix_difference!=32w0){m.work_op=8w0;deny();}}
 work.apply(m.work_op,m.generation,m.work_phase);published_t.apply();calculate_native_end_t.apply();if(m.response==8w1){compare_response_inputs_t.apply();}else{if(hdr.first.w0[15:8]==8w3){compare_select_inputs_t.apply();}else{compare_operate_inputs_t.apply();}}
cache_access.apply();real_links_t.apply();real_tcp_dst_t.apply();real_object_t.apply();real_off_t.apply();native_end_t.apply();application_t.apply();frozen_decoy_object_t.apply();frozen_decoy_off_t.apply();
 association_admission.apply();if(m.association_allowed==8w1&&m.context_generation!=32w0){object_match.apply();if(m.response==8w0){operate_qualified_t.apply();}}

 if(m.stage==8w0){if(m.work_op==8w1&&m.work_phase==32w4){start_work_t.apply();if(m.context_generation!=32w0){abort_t.apply();}}}
 else if(m.work_phase==32w1||m.work_phase==32w2){next_work_t.apply();}
 else if(m.work_phase==32w3){hdr.epoch.setInvalid();hdr.generation.setInvalid();hdr.expected.setInvalid();hdr.event.setInvalid();}
 else{deny();}
 }}
 }else if(m.stage!=8w0){deny();}
}

}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

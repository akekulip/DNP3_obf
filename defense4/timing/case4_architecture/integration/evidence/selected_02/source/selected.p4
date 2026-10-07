/* Autonomous actual native35 SELECT context publisher experiment.
 * Four processing passes; full network/profile/all3CRC validation precedes work.
 * Transaction epoch equals nonwrapping allocated work generation; it is NOT
 * yet the live connection epoch. No verified reset/reuse or RESPONSE/OP target
 * association. Stored REAL object and frozen configured decoy are distinct.
 */
#include <core.p4>
#include <tna.p4>
#include "work_record.p4"
const PortId_t RETURN_PORT=9w68;
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header native_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<16> crc;}
header tail_h{bit<32> off;bit<8> status;bit<16> crc;}
header epoch_h{bit<32> epoch;}
header generation_h{bit<32> generation;}
header expected_h{bit<32> expected;}
header event_h{bit<16> event;bit<16> reserved;}
struct headers_t{epoch_h epoch;generation_h generation;expected_h expected;event_h event;eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;native_h native;tail_h tail;}
struct meta_t{bit<1> port_valid;bit<8> stage;bit<8> kind;bit<8> work_op;bit<32> generation;bit<32> work_phase;bit<32> context_generation;bit<32> native_end;bit<1> parsed;bit<1> enabled;bit<1> profile;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=1w0;m.port_valid=1w0;m.stage=8w0;m.kind=8w0;m.enabled=1w0;m.profile=1w0;m.changed=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;transition select(ig.ingress_port){RETURN_PORT:epoch;default:eth;}}
 state epoch{pkt.extract(hdr.epoch);transition select(hdr.epoch.epoch){32w0:accept;default:generation;}}
 state generation{pkt.extract(hdr.generation);transition select(hdr.generation.generation){32w0:accept;default:expected;}}
 state expected{pkt.extract(hdr.expected);pkt.extract(hdr.event);m.stage=hdr.event.event[15:8];m.kind=hdr.event.event[7:0];transition reserved;}
 state reserved{transition select(hdr.event.reserved){16w0:events;default:accept;}}
 state events{transition select(hdr.event.event){16w0x0101:eth;16w0x0201:eth;16w0x0301:eth;16w0x01ff:eth;16w0x02ff:eth;16w0x03ff:eth;default:accept;}}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w75,8w6):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):dl;(4w5,4w0,8w0x18,16w0):dl;default:accept;}}
 state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native;}
 state native{pkt.extract(hdr.native);tc.subtract(hdr.native);transition tail;}
 state tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.port_valid=1w1;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action configure(bit<16> index,bit<8> code,bit<8> repeat,bit<32> on,bit<32> off){m.enabled=1w1;m.decoy_index=index;m.decoy_code=code;m.decoy_repeat=repeat;m.decoy_on=on;m.decoy_off=off;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=1;default_action=NoAction();}
 action eligible(){m.profile=1w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.native.tp:ternary;hdr.native.app:ternary;hdr.native.func:exact;hdr.native.group:exact;hdr.native.variation:exact;hdr.native.qualifier:exact;hdr.native.count:exact;hdr.tail.status:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w3,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();}}
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_head;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_body;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;
action input_head(){m.hcrc=hash_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table input_head_t{actions={input_head;}size=1;const default_action=input_head();}
action input_body(){m.bcrc=hash_body.get({hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on});}
table input_body_t{actions={input_body;}size=1;const default_action=input_body();}
action input_tail(){m.tcrc=hash_tail.get({hdr.tail.off,hdr.tail.status});}
table input_tail_t{actions={input_tail;}size=1;const default_action=input_tail();}
WorkRecord() work;
Register<bit<32>,bit<1>>(1,0) counter;
RegisterAction<bit<32>,bit<1>,bit<32>>(counter) allocate={void apply(inout bit<32> v,out bit<32> r){r=32w0;if((int<32>)v!=-1){v=v+32w1;r=v;}}};
action mint(){m.generation=allocate.execute(1w0);m.work_op=8w1;}
table mint_t{actions={mint;}size=1;const default_action=mint();}
Register<bit<32>,bit<1>>(1,0) published;
RegisterAction<bit<32>,bit<1>,bit<32>>(published) read_published={void apply(inout bit<32> v,out bit<32> r){r=v;}};
RegisterAction<bit<32>,bit<1>,bit<32>>(published) publish={void apply(inout bit<32> v,out bit<32> r){if(v==0){v=hdr.generation.generation;}r=v;}};
action load_published(){m.context_generation=read_published.execute(1w0);}
action commit_published(){m.context_generation=publish.execute(1w0);}
table published_t{key={m.stage:exact;m.kind:exact;m.work_op:exact;m.work_phase:exact;}actions={load_published;commit_published;}size=1;const entries={(8w1,8w1,8w2,32w1):commit_published();}const default_action=load_published();}
action calculate_native_end(){m.native_end=hdr.tcp.seq+32w35;}
table calculate_native_end_t{actions={calculate_native_end;}size=1;const default_action=calculate_native_end();}
Register<bit<32>,bit<1>>(1,0) real_links;
RegisterAction<bit<32>,bit<1>,bit<32>>(real_links) write_real_links={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(hdr.dl.dst++hdr.dl.src);r=v;}};
action store_real_links(){write_real_links.execute(1w0);}
table real_links_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_real_links;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_real_links();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) real_index;
RegisterAction<bit<32>,bit<1>,bit<32>>(real_index) write_real_index={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(hdr.native.index);r=v;}};
action store_real_index(){write_real_index.execute(1w0);}
table real_index_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_real_index;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_real_index();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) real_code_repeat;
RegisterAction<bit<32>,bit<1>,bit<32>>(real_code_repeat) write_real_code_repeat={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(hdr.native.code++hdr.native.repeat);r=v;}};
action store_real_code_repeat(){write_real_code_repeat.execute(1w0);}
table real_code_repeat_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_real_code_repeat;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_real_code_repeat();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) real_on;
RegisterAction<bit<32>,bit<1>,bit<32>>(real_on) write_real_on={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(hdr.native.on);r=v;}};
action store_real_on(){write_real_on.execute(1w0);}
table real_on_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_real_on;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_real_on();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) real_off;
RegisterAction<bit<32>,bit<1>,bit<32>>(real_off) write_real_off={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(hdr.tail.off);r=v;}};
action store_real_off(){write_real_off.execute(1w0);}
table real_off_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_real_off;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_real_off();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) native_start;
RegisterAction<bit<32>,bit<1>,bit<32>>(native_start) write_native_start={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(hdr.tcp.seq);r=v;}};
action store_native_start(){write_native_start.execute(1w0);}
table native_start_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_native_start;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_native_start();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) native_end;
RegisterAction<bit<32>,bit<1>,bit<32>>(native_end) write_native_end={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(m.native_end);r=v;}};
action store_native_end(){write_native_end.execute(1w0);}
table native_end_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_native_end;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_native_end();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) server_start;
RegisterAction<bit<32>,bit<1>,bit<32>>(server_start) write_server_start={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(hdr.tcp.ack);r=v;}};
action store_server_start(){write_server_start.execute(1w0);}
table server_start_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_server_start;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_server_start();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) application;
RegisterAction<bit<32>,bit<1>,bit<32>>(application) write_application={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(hdr.native.app);r=v;}};
action store_application(){write_application.execute(1w0);}
table application_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_application;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_application();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) frozen_decoy_index;
RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_index) write_frozen_decoy_index={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(m.decoy_index);r=v;}};
action store_frozen_decoy_index(){write_frozen_decoy_index.execute(1w0);}
table frozen_decoy_index_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_frozen_decoy_index;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_frozen_decoy_index();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) frozen_decoy_code_repeat;
RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_code_repeat) write_frozen_decoy_code_repeat={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(m.decoy_code++m.decoy_repeat);r=v;}};
action store_frozen_decoy_code_repeat(){write_frozen_decoy_code_repeat.execute(1w0);}
table frozen_decoy_code_repeat_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_frozen_decoy_code_repeat;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_frozen_decoy_code_repeat();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) frozen_decoy_on;
RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_on) write_frozen_decoy_on={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(m.decoy_on);r=v;}};
action store_frozen_decoy_on(){write_frozen_decoy_on.execute(1w0);}
table frozen_decoy_on_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_frozen_decoy_on;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_frozen_decoy_on();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) frozen_decoy_off;
RegisterAction<bit<32>,bit<1>,bit<32>>(frozen_decoy_off) write_frozen_decoy_off={void apply(inout bit<32> v,out bit<32> r){v=(bit<32>)(m.decoy_off);r=v;}};
action store_frozen_decoy_off(){write_frozen_decoy_off.execute(1w0);}
table frozen_decoy_off_t{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}actions={store_frozen_decoy_off;NoAction;}size=1;const entries={(8w0,8w1,32w4,32w0):store_frozen_decoy_off();}const default_action=NoAction();}
action start_work(){hdr.epoch.setValid();hdr.generation.setValid();hdr.expected.setValid();hdr.event.setValid();hdr.epoch.epoch=m.generation;hdr.generation.generation=m.generation;hdr.expected.expected=32w0;hdr.event.event=16w0x0101;hdr.event.reserved=16w0;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}
table start_work_t{actions={start_work;}size=1;const default_action=start_work();}
action abort_work(){hdr.event.event=16w0x01ff;}
table abort_t{actions={abort_work;}size=1;const default_action=abort_work();}
action next_work(){hdr.event.event=hdr.event.event+16w0x100;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}
table next_work_t{actions={next_work;}size=1;const default_action=next_work();}
apply{m.work_op=8w0;m.generation=32w0;forwarding.apply();
 if(m.port_valid==1w1&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
 connection.apply();profile.apply();if(m.enabled==1w1&&m.profile==1w1){
 input_head_t.apply();input_body_t.apply();input_tail_t.apply();
 if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}
 if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}
 if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
 if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0&&hdr.native.index!=m.decoy_index){
 if(m.stage==8w0){mint_t.apply();}else{m.generation=hdr.generation.generation;m.work_op=8w2;}
 work.apply(m.work_op,m.generation,m.work_phase);published_t.apply();calculate_native_end_t.apply();
real_links_t.apply();real_index_t.apply();real_code_repeat_t.apply();real_on_t.apply();real_off_t.apply();native_start_t.apply();native_end_t.apply();server_start_t.apply();application_t.apply();frozen_decoy_index_t.apply();frozen_decoy_code_repeat_t.apply();frozen_decoy_on_t.apply();frozen_decoy_off_t.apply();
 if(m.stage==8w0){if(m.work_phase==32w4){start_work_t.apply();if(m.context_generation!=32w0){abort_t.apply();}}}
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

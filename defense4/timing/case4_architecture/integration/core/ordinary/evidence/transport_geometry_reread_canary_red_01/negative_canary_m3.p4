/* Partial ordinary SELECT M prepare: actual N28 handoff, full native35 validation,
 * captured decoy construction and persistent producer reservation. No release
 * authority: E must finish all image stores before ready; N commits afterward. */
#include <core.p4>
#include <tna.p4>
header mapping_snapshot_h{bit<32> marker;bit<32> generation;bit<32> owner;bit<32> boundary;bit<32> position;}
header response_extra_h{bit<16> value;}
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header dl_h{bit<16> magic;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header native_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<16> crc;}
header tail_h{bit<32> off;bit<8> status;bit<16> crc;}
header appended_h{bit<32> off;bit<8> status;bit<8> group;bit<8> variation;bit<8> qualifier;bit<16> count;bit<16> index;bit<8> code;bit<8> repeat;bit<16> on_first;bit<16> crc;}
header final_h{bit<16> on_last;bit<32> off;bit<8> status;bit<16> crc;}
header reference_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;}
header captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header cache_reference_h{bit<32> generation;bit<32> expected_owner;}
header image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
struct context_t{bit<32> epoch;bit<32> owner;}
struct ledger_tag_t{bit<32> epoch;bit<32> generation;}
struct producer_cell_t{bit<32> generation;bit<32> phase;}
header completion_epoch_h{bit<32> epoch;}
struct headers_t{mapping_snapshot_h map_snapshot;reference_h reference;captured_decoy_h captured;cache_reference_h cache;completion_epoch_h completion;eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;native_h native;tail_h tail;appended_h appended;final_h last;image_h image;response_extra_h response_extra;}
struct meta_t{bit<32> snapshot_boundary_diff;bit<32> snapshot_position_diff;bit<32> ledger_generation;bit<1> reverse_changed;bit<1> reverse_allowed;bit<32> map_generation;bit<32> map_epoch;bit<32> map_owner;bit<32> map_context_epoch;bit<32> map_generation_diff;bit<32> map_epoch_diff;bit<32> boundary;bit<32> map_position;bit<32> geometry_diff;bit<32> boundary_minus35;bit<32> wire_ack;bit<32> window32;bit<32> left;bit<32> right;bit<32> left_offset;bit<32> right_offset;bit<32> window_after;bit<16> repair_sum;bit<8> role;bit<32> stamp_diff;bit<32> context_owner;bit<32> context_grant;bit<32> ref_gen_diff;bit<32> ref_owner_diff;bit<32> activation_grant;bit<1> geometry_done;bit<1> position_done;bit<1> ledger_done;bit<32> reservation_grant;bit<1> parsed;bit<1> enabled;bit<1> profile;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;Checksum() rc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.role=8w0;m.reverse_allowed=1w0;m.reverse_changed=1w0;m.geometry_done=1w0;m.position_done=1w0;m.ledger_done=1w0;m.parsed=1w0;m.enabled=1w0;m.profile=1w0;m.changed=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;transition select(ig.ingress_port){9w196:reference;9w198:terminal_reference;9w199:reverse_entry;default:accept;}}
 state reverse_entry{transition select(pkt.lookahead<bit<32>>()){32w0x16c40006:reverse_snapshot;default:reverse_raw;}}
 state reverse_raw{m.role=8w3;transition reverse_eth;}
 state reverse_snapshot{m.role=8w4;pkt.extract(hdr.map_snapshot);transition select(hdr.map_snapshot.generation){32w0:accept;default:reverse_snapshot_owner;}}
 state reverse_snapshot_owner{transition select(hdr.map_snapshot.owner[31:16],hdr.map_snapshot.owner[15:0]){(16w9,16w0):accept;(16w9,_):reverse_eth;default:accept;}}
 state reverse_eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:reverse_ip;default:accept;}}
 state reverse_ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto){(4w4,4w5,8w6):reverse_flags;default:accept;}}
 state reverse_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):reverse_tcp;(13w0,3w2):reverse_tcp;default:accept;}}
 state reverse_tcp{pkt.extract(hdr.tcp);rc.subtract({hdr.tcp.checksum,hdr.tcp.ack,hdr.tcp.window});tc.subtract({hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.checksum,hdr.tcp.urgent});transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags,hdr.ip.len){(4w5,4w0,16w0,8w16,16w40):reverse_ack_finish;(4w5,4w0,16w0,8w16,16w97):reverse_image;(4w5,4w0,16w0,8w24,16w97):reverse_image;default:accept;}}
 state reverse_ack_finish{m.tcp_sum=tc.get();m.repair_sum=rc.get();m.parsed=1w1;transition accept;}
 state reverse_image{pkt.extract(hdr.image);tc.subtract(hdr.image);pkt.extract(hdr.response_extra);tc.subtract(hdr.response_extra);transition reverse_finish;}
 state reverse_finish{m.tcp_sum=tc.get();m.repair_sum=rc.get();m.parsed=1w1;transition accept;}
 state terminal_reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:accept;default:terminal_generation;}}
 state terminal_generation{transition select(hdr.reference.generation){32w0:accept;default:terminal_owner;}}
 state terminal_owner{transition select(hdr.reference.expected_owner[31:16]){16w17:terminal_cookie;default:accept;}}
 state terminal_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:accept;default:terminal_event;}}
 state terminal_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0814,16w3):terminal_cache;default:accept;}}
 state reference{pkt.extract(hdr.reference);transition select(hdr.reference.epoch){32w0:accept;default:reference_generation;}}
 state reference_generation{transition select(hdr.reference.generation){32w0:accept;default:reference_owner;}}
 state reference_owner{transition select(hdr.reference.expected_owner[31:16]){16w9:reference_cookie;16w17:activation_cookie;default:accept;}}
 state activation_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:accept;default:activation_event;}}
 state activation_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0714,16w2):activation_cache;default:accept;}}
 state activation_cache{m.role=8w1;pkt.extract(hdr.cache);transition activation_eth;}
 state terminal_cache{m.role=8w2;pkt.extract(hdr.cache);pkt.extract(hdr.completion);transition activation_eth;}
 state activation_eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:activation_ip;default:accept;}}
 state activation_ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.len,hdr.ip.proto){(4w4,4w5,16w95,8w6):activation_ip_flags;default:accept;}}
 state activation_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):activation_tcp;(13w0,3w2):activation_tcp;default:accept;}}
 state activation_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):activation_image;(4w5,4w0,8w0x18,16w0):activation_image;default:accept;}}
 state activation_image{pkt.extract(hdr.image);tc.subtract(hdr.image);m.tcp_sum=tc.get();m.parsed=1w1;transition accept;}
 state reference_cookie{transition select(hdr.reference.expected_owner[15:0]){16w0:accept;default:reference_event;}}
 state reference_event{transition select(hdr.reference.event,hdr.reference.format){(16w0x0305,16w1):captured;default:accept;}}
 state captured{pkt.extract(hdr.captured);transition eth;}
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
 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w0;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action allow_connection(){m.enabled=1w1;}
 action allow_reverse(){m.enabled=1w1;m.reverse_allowed=1w1;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={allow_connection;allow_reverse;NoAction;}size=2;default_action=NoAction();}
 Register<producer_cell_t,bit<1>>(1,{0,4}) reservation;
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) reserve={
  void apply(inout producer_cell_t value,out bit<32> granted){
   granted=32w0;
   if(value.phase==32w4&&value.generation<hdr.reference.generation){
    value.generation=hdr.reference.generation;value.phase=32w1;granted=32w1;
   }
  }
 };
 action reserve_producer(){m.reservation_grant=reserve.execute(1w0);}
 table reserve_t{actions={reserve_producer;}size=1;const default_action=reserve_producer();}

 Register<context_t,bit<1>>(1,{0,0}) producer_context;
 RegisterAction<context_t,bit<1>,bit<32>>(producer_context) context_write={void apply(inout context_t value,out bit<32> result){value.epoch=hdr.reference.epoch;value.owner=m.context_owner;result=32w0;}};
 RegisterAction<context_t,bit<1>,bit<32>>(producer_context) context_check={void apply(inout context_t value,out bit<32> result){result=32w0;if(value.epoch!=hdr.reference.epoch||value.owner!=m.context_owner){result=32w1;}}};
 action qualify_context(){m.context_grant=context_check.execute(1w0);}
 table qualify_context_t{actions={qualify_context;}size=1;const default_action=qualify_context();}
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) inspect={void apply(inout producer_cell_t value,out bit<32> result){result=32w0;if(value.generation==hdr.reference.generation&&value.phase==32w1){result=32w1;}}};
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) retire={void apply(inout producer_cell_t value,out bit<32> result){result=32w0;if(value.generation==hdr.reference.generation&&value.phase==32w1){value.phase=32w4;result=32w1;}}};
 action inspect_reservation(){m.reservation_grant=inspect.execute(1w0);}
 action retire_reservation(){m.reservation_grant=retire.execute(1w0);}
 table activation_reservation_t{key={m.role:exact;}actions={inspect_reservation;retire_reservation;NoAction;}size=2;const default_action=NoAction();const entries={8w1:inspect_reservation();8w2:retire_reservation();}}
 Register<bit<32>,bit<1>>(1,0) activation_receipt;
 RegisterAction<bit<32>,bit<1>,bit<32>>(activation_receipt) claim_activation={void apply(inout bit<32> value,out bit<32> result){result=32w0;if(value<hdr.reference.generation){value=hdr.reference.generation;result=32w1;}}};
 action claim_once(){m.activation_grant=claim_activation.execute(1w0);}
 table claim_once_t{actions={claim_once;}size=1;const default_action=claim_once();}
 Register<bit<32>,bit<1>>(1,0) geo_first;
 RegisterAction<bit<32>,bit<1>,bit<1>>(geo_first) write_geometry={void apply(inout bit<32> value,out bit<1> done){value=hdr.tcp.seq+32w35;done=1w1;}};
 action activate_geometry(){m.geometry_done=write_geometry.execute(1w0);}
 table activate_geometry_t{actions={activate_geometry;}size=1;const default_action=activate_geometry();}
 Register<bit<32>,bit<1>>(1,0) ledger_position;
 RegisterAction<bit<32>,bit<1>,bit<1>>(ledger_position) write_position={void apply(inout bit<32> value,out bit<1> done){value=hdr.tcp.seq;done=1w1;}};
 action activate_position(){m.position_done=write_position.execute(1w0);}
 table activate_position_t{actions={activate_position;}size=1;const default_action=activate_position();}
 action prepare_cached_generation(){m.ledger_generation=hdr.cache.generation;}
 action prepare_snapshot_generation(){m.ledger_generation=hdr.map_snapshot.generation;}
 action no_ledger_generation(){m.ledger_generation=32w0;}
 table ledger_generation_t{key={m.role:exact;}actions={prepare_cached_generation;prepare_snapshot_generation;no_ledger_generation;}size=2;const entries={8w1:prepare_cached_generation();8w4:prepare_snapshot_generation();}const default_action=no_ledger_generation();}
 Register<ledger_tag_t,bit<1>>(1,{0,0}) ledger_tag;
 RegisterAction<ledger_tag_t,bit<1>,bit<1>>(ledger_tag) write_ledger={void apply(inout ledger_tag_t value,out bit<1> done){value.epoch=hdr.reference.epoch;value.generation=m.ledger_generation;done=1w1;}};
 action activate_ledger(){m.ledger_done=write_ledger.execute(1w0);}
 table activate_ledger_t{key={m.geometry_done:exact;m.position_done:exact;}actions={activate_ledger;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1):activate_ledger();}}
 action dirty_return(){hdr.completion.setValid();hdr.completion.epoch=hdr.reference.epoch;hdr.reference.format=16w3;hdr.reference.event=16w0x0814;tm.ucast_egress_port=9w198;tm.bypass_egress=1w1;}
 table dirty_return_t{key={m.ledger_done:exact;}actions={dirty_return;deny;}size=1;const default_action=deny();const entries={1w1:dirty_return();}}
 action to_endpoint_egress(){hdr.completion.setInvalid();hdr.reference.format=16w2;hdr.reference.event=16w0x0914;tm.ucast_egress_port=9w452;tm.bypass_egress=1w0;}
 table terminal_result_t{key={m.reservation_grant:exact;}actions={to_endpoint_egress;deny;}size=1;const default_action=deny();const entries={32w1:to_endpoint_egress();}}
 action reference_differences(){m.ref_gen_diff=hdr.reference.generation-hdr.cache.generation;m.ref_owner_diff=hdr.reference.expected_owner-hdr.cache.expected_owner;}
 table reference_differences_t{actions={reference_differences;}size=1;const default_action=reference_differences();}
 action no_stamp(){m.stamp_diff=32w0;}
 action compare_stamp(){m.stamp_diff=hdr.reference.epoch-hdr.completion.epoch;}
 table stamp_t{key={m.role:exact;}actions={no_stamp;compare_stamp;}size=1;const default_action=no_stamp();const entries={8w2:compare_stamp();}}
 action activate_allowed(){m.profile=1w1;}
 table activation_identity_t{key={m.ref_gen_diff:exact;m.ref_owner_diff:exact;m.stamp_diff:exact;}actions={activate_allowed;NoAction;}size=1;const default_action=NoAction();const entries={(32w0,32w0x80000,32w0):activate_allowed();}}
 action mapping_context_owner(){m.context_owner=hdr.map_snapshot.owner;}
 action no_context_owner(){m.context_owner=32w0;}
 action prepare_context_owner(){m.context_owner=hdr.reference.expected_owner;}
 action activation_context_owner(){m.context_owner=hdr.cache.expected_owner;}
 table context_owner_t{key={m.role:exact;}actions={prepare_context_owner;activation_context_owner;mapping_context_owner;no_context_owner;}size=4;const entries={8w1:activation_context_owner();8w2:activation_context_owner();8w3:no_context_owner();8w4:mapping_context_owner();}const default_action=prepare_context_owner();}
 action eligible(){m.profile=1w1;}
 table profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.native.tp:ternary;hdr.native.app:ternary;hdr.native.func:exact;hdr.native.group:exact;hdr.native.variation:exact;hdr.native.qualifier:exact;hdr.native.count:exact;hdr.tail.status:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w3,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();}}
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
action construct(){context_write.execute(1w0);hdr.appended.setValid();hdr.last.setValid();hdr.appended.off=hdr.tail.off;hdr.appended.status=hdr.tail.status;hdr.appended.group=8w12;hdr.appended.variation=8w1;hdr.appended.qualifier=8w0x28;hdr.appended.count=16w0x0100;hdr.appended.index=hdr.captured.index;hdr.appended.code=hdr.captured.code;hdr.appended.repeat=hdr.captured.repeat;hdr.appended.on_first=hdr.captured.on[31:16];hdr.last.on_last=hdr.captured.on[15:0];hdr.last.off=hdr.captured.off;hdr.last.status=8w0;hdr.tail.setInvalid();hdr.dl.len=8w44;hdr.ip.len=16w95;m.tcp_length=16w75;m.changed=1w1;hdr.cache.setValid();hdr.cache.generation=hdr.reference.generation;hdr.cache.expected_owner=hdr.reference.expected_owner;hdr.reference.event=16w0x0405;hdr.reference.format=16w2;}
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
 RegisterAction<producer_cell_t,bit<1>,bit<32>>(reservation) read_map_reservation={void apply(inout producer_cell_t value,out bit<32> result){result=32w0;if(value.phase==32w4){result=value.generation;}}};
 RegisterAction<ledger_tag_t,bit<1>,bit<32>>(ledger_tag) read_map_tag={void apply(inout ledger_tag_t value,out bit<32> result){result=32w0;if(value.generation==m.ledger_generation){result=value.epoch;}}};
 RegisterAction<context_t,bit<1>,bit<32>>(producer_context) read_map_context={void apply(inout context_t value,out bit<32> result){result=32w0;if(value.owner==m.context_owner){result=value.epoch;}}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(geo_first) read_boundary={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(ledger_position) read_map_position={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 RegisterAction<context_t,bit<1>,bit<32>>(producer_context) read_map_raw_owner={void apply(inout context_t value,out bit<32> result){result=value.owner;}};
 action mapping_raw_owner(){m.map_owner=read_map_raw_owner.execute(1w0);}
 table mapping_raw_owner_t{actions={mapping_raw_owner;}size=1;const default_action=mapping_raw_owner();}
 action capture_mapping_owner(){hdr.map_snapshot.setValid();hdr.map_snapshot.owner=m.map_owner;hdr.map_snapshot.boundary=m.boundary;hdr.map_snapshot.position=m.map_position;}
 table capture_mapping_owner_t{actions={capture_mapping_owner;}size=1;const default_action=capture_mapping_owner();}
 action emit_mapping_snapshot(){hdr.map_snapshot.setValid();hdr.map_snapshot.marker=32w0x16c40006;hdr.map_snapshot.generation=m.map_generation;tm.ucast_egress_port=9w199;tm.bypass_egress=1w1;}
 table emit_mapping_snapshot_t{key={m.reverse_allowed:exact;m.map_owner[31:16]:exact;m.map_generation:ternary;m.map_owner[15:0]:ternary;}actions={emit_mapping_snapshot;deny;}size=3;const default_action=deny();const entries={(1w1,16w9,32w0,_):deny();(1w1,16w9,_,16w0):deny();(1w1,16w9,_,_):emit_mapping_snapshot();}}
 action check_mapping_snapshot(){m.map_generation_diff=m.map_generation-hdr.map_snapshot.generation;m.map_epoch_diff=m.map_epoch-m.map_context_epoch;m.snapshot_boundary_diff=32w0;m.snapshot_position_diff=32w0;}
 table check_mapping_snapshot_t{actions={check_mapping_snapshot;}size=1;const default_action=check_mapping_snapshot();}
 action mapping_reservation(){m.map_generation=read_map_reservation.execute(1w0);}
 table mapping_reservation_t{actions={mapping_reservation;}size=1;const default_action=mapping_reservation();}
 action mapping_tag(){m.map_epoch=read_map_tag.execute(1w0);}
 table mapping_tag_t{actions={mapping_tag;}size=1;const default_action=mapping_tag();}
 action mapping_context(){m.map_context_epoch=read_map_context.execute(1w0);}
 table mapping_context_t{actions={mapping_context;}size=1;const default_action=mapping_context();}
 action mapping_boundary(){m.boundary=read_boundary.execute(1w0);}
 table mapping_boundary_t{actions={mapping_boundary;}size=1;const default_action=mapping_boundary();}
 action mapping_position(){m.map_position=read_map_position.execute(1w0);}
 table mapping_position_t{actions={mapping_position;}size=1;const default_action=mapping_position();}
 action prepare_packet_edges(){m.wire_ack=hdr.tcp.ack;m.window32=16w0++hdr.tcp.window;}
 table prepare_packet_edges_t{actions={prepare_packet_edges;}size=1;const default_action=prepare_packet_edges();}
 action prepare_edges(){m.left=m.wire_ack;m.right=m.wire_ack+m.window32;m.left_offset=m.wire_ack-hdr.map_snapshot.boundary;m.boundary_minus35=hdr.map_snapshot.boundary-32w35;}
 table prepare_edges_t{actions={prepare_edges;}size=1;const default_action=prepare_edges();}
 action prepare_right_offset(){m.right_offset=m.right-hdr.map_snapshot.boundary;}
 table prepare_right_offset_t{actions={prepare_right_offset;}size=1;const default_action=prepare_right_offset();}
 action check_geometry(){m.geometry_diff=m.boundary_minus35-hdr.map_snapshot.position;}
 table check_geometry_t{actions={check_geometry;}size=1;const default_action=check_geometry();}
 action map_ack_high(){hdr.tcp.ack[31:16]=m.left[31:16];m.reverse_changed=1w1;}
 action map_ack_low(){hdr.tcp.ack[15:0]=m.left[15:0];}
 table map_ack_low_t{actions={map_ack_low;}size=1;const default_action=map_ack_low();}
 action emit_normalized(){hdr.tcp.window=m.window_after[15:0];m.tcp_length=hdr.ip.len-16w20;hdr.reference.setValid();hdr.reference.epoch=m.map_epoch;hdr.reference.generation=m.map_generation;hdr.reference.expected_owner=hdr.map_snapshot.owner;hdr.reference.event=16w0x0000;hdr.reference.format=16w4;hdr.map_snapshot.setInvalid();tm.ucast_egress_port=9w68;tm.bypass_egress=1w1;}
 table emit_normalized_t{actions={emit_normalized;}size=1;const default_action=emit_normalized();}
 // Full current-generation equality to the parser-qualified nonzero snapshot
 // also proves reread generation nonzero; phase4 qualified that SALU output.
 // upper16==0 exactly enforces full32 window_after in0..65535.
 table map_return_t{key={m.reverse_allowed:exact;m.geometry_diff:exact;m.map_generation_diff:exact;m.map_epoch_diff:exact;m.snapshot_boundary_diff:exact;m.snapshot_position_diff:exact;m.map_epoch:ternary;m.window_after[31:16]:exact;}actions={map_ack_high;deny;}size=2;const default_action=deny();const entries={(1w1,32w0,32w0,32w0,32w0,32w0,32w0,16w0):deny();(1w1,32w0,32w0,32w0,32w0,32w0,_,16w0):map_ack_high();}}
 action inverse_left_clamp(){m.left=hdr.map_snapshot.boundary-32w1;}
 action inverse_left_shift(){m.left=m.left-32w20;}
 table inverse_left{key={m.left_offset:ternary;}actions={inverse_left_clamp;inverse_left_shift;NoAction;}size=30;const default_action=NoAction();const entries={(32w0x0&&&32w0xfffffff0):inverse_left_clamp();(32w0x10&&&32w0xfffffffc):inverse_left_clamp();(32w0x14&&&32w0xfffffffc):inverse_left_shift();(32w0x18&&&32w0xfffffff8):inverse_left_shift();(32w0x20&&&32w0xffffffe0):inverse_left_shift();(32w0x40&&&32w0xffffffc0):inverse_left_shift();(32w0x80&&&32w0xffffff80):inverse_left_shift();(32w0x100&&&32w0xffffff00):inverse_left_shift();(32w0x200&&&32w0xfffffe00):inverse_left_shift();(32w0x400&&&32w0xfffffc00):inverse_left_shift();(32w0x800&&&32w0xfffff800):inverse_left_shift();(32w0x1000&&&32w0xfffff000):inverse_left_shift();(32w0x2000&&&32w0xffffe000):inverse_left_shift();(32w0x4000&&&32w0xffffc000):inverse_left_shift();(32w0x8000&&&32w0xffff8000):inverse_left_shift();(32w0x10000&&&32w0xffff0000):inverse_left_shift();(32w0x20000&&&32w0xfffe0000):inverse_left_shift();(32w0x40000&&&32w0xfffc0000):inverse_left_shift();(32w0x80000&&&32w0xfff80000):inverse_left_shift();(32w0x100000&&&32w0xfff00000):inverse_left_shift();(32w0x200000&&&32w0xffe00000):inverse_left_shift();(32w0x400000&&&32w0xffc00000):inverse_left_shift();(32w0x800000&&&32w0xff800000):inverse_left_shift();(32w0x1000000&&&32w0xff000000):inverse_left_shift();(32w0x2000000&&&32w0xfe000000):inverse_left_shift();(32w0x4000000&&&32w0xfc000000):inverse_left_shift();(32w0x8000000&&&32w0xf8000000):inverse_left_shift();(32w0x10000000&&&32w0xf0000000):inverse_left_shift();(32w0x20000000&&&32w0xe0000000):inverse_left_shift();(32w0x40000000&&&32w0xc0000000):inverse_left_shift();}}
 action inverse_right_clamp(){m.right=hdr.map_snapshot.boundary-32w1;}
 action inverse_right_shift(){m.right=m.right-32w20;}
 table inverse_right{key={m.right_offset:ternary;}actions={inverse_right_clamp;inverse_right_shift;NoAction;}size=30;const default_action=NoAction();const entries={(32w0x0&&&32w0xfffffff0):inverse_right_clamp();(32w0x10&&&32w0xfffffffc):inverse_right_clamp();(32w0x14&&&32w0xfffffffc):inverse_right_shift();(32w0x18&&&32w0xfffffff8):inverse_right_shift();(32w0x20&&&32w0xffffffe0):inverse_right_shift();(32w0x40&&&32w0xffffffc0):inverse_right_shift();(32w0x80&&&32w0xffffff80):inverse_right_shift();(32w0x100&&&32w0xffffff00):inverse_right_shift();(32w0x200&&&32w0xfffffe00):inverse_right_shift();(32w0x400&&&32w0xfffffc00):inverse_right_shift();(32w0x800&&&32w0xfffff800):inverse_right_shift();(32w0x1000&&&32w0xfffff000):inverse_right_shift();(32w0x2000&&&32w0xffffe000):inverse_right_shift();(32w0x4000&&&32w0xffffc000):inverse_right_shift();(32w0x8000&&&32w0xffff8000):inverse_right_shift();(32w0x10000&&&32w0xffff0000):inverse_right_shift();(32w0x20000&&&32w0xfffe0000):inverse_right_shift();(32w0x40000&&&32w0xfffc0000):inverse_right_shift();(32w0x80000&&&32w0xfff80000):inverse_right_shift();(32w0x100000&&&32w0xfff00000):inverse_right_shift();(32w0x200000&&&32w0xffe00000):inverse_right_shift();(32w0x400000&&&32w0xffc00000):inverse_right_shift();(32w0x800000&&&32w0xff800000):inverse_right_shift();(32w0x1000000&&&32w0xff000000):inverse_right_shift();(32w0x2000000&&&32w0xfe000000):inverse_right_shift();(32w0x4000000&&&32w0xfc000000):inverse_right_shift();(32w0x8000000&&&32w0xf8000000):inverse_right_shift();(32w0x10000000&&&32w0xf0000000):inverse_right_shift();(32w0x20000000&&&32w0xe0000000):inverse_right_shift();(32w0x40000000&&&32w0xc0000000):inverse_right_shift();}}
 action finish_window(){m.window_after=m.right-m.left;}
 table finish_window_t{actions={finish_window;}size=1;const default_action=finish_window();}
 apply{
 stamp_t.apply();context_owner_t.apply();ledger_generation_t.apply();if(m.role!=8w3&&m.role!=8w4){forwarding.apply();}
 if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
  connection.apply();
 if(m.role==8w4){prepare_packet_edges_t.apply();prepare_edges_t.apply();prepare_right_offset_t.apply();inverse_left.apply();inverse_right.apply();finish_window_t.apply();check_geometry_t.apply();}
 if(m.role==8w3||m.role==8w4){mapping_reservation_t.apply();
  if(m.role==8w3){mapping_raw_owner_t.apply();}else{mapping_context_t.apply();mapping_tag_t.apply();}
  mapping_boundary_t.apply();mapping_position_t.apply();
 }
 if(m.role==8w3){
  capture_mapping_owner_t.apply();emit_mapping_snapshot_t.apply();
 }else if(m.role==8w4){
  check_mapping_snapshot_t.apply();map_return_t.apply();
  if(m.reverse_changed==1w1){map_ack_low_t.apply();emit_normalized_t.apply();}
 }else  if(m.role==8w1||m.role==8w2){
   reference_differences_t.apply();activation_identity_t.apply();
   if(m.enabled==1w1&&m.profile==1w1){
    activation_reservation_t.apply();
    if(m.role==8w2){terminal_result_t.apply();}else if(m.reservation_grant==32w1){
     qualify_context_t.apply();
     if(m.context_grant==32w0){
      claim_once_t.apply();
      if(m.activation_grant==32w1){activate_geometry_t.apply();activate_position_t.apply();activate_ledger_t.apply();dirty_return_t.apply();}else{deny();}
     }else{deny();}
    }else{deny();}
   }else{deny();}
  }else{profile.apply();
  if(m.enabled==1w1&&m.profile==1w1){
   input_head_t.apply();input_body_t.apply();input_tail_t.apply();
   if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}
   if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}
   if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
   if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0&&hdr.native.index!=hdr.captured.index){
    reserve_t.apply();
    if(m.reservation_grant==32w1){
     construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();
    }else{deny();}
   }else{deny();}
  }else{deny();}
 }
 }else{deny();}
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;Checksum() rcd;apply{if(m.reverse_changed==1w1){hdr.tcp.checksum=rcd.update({m.repair_sum,hdr.tcp.ack,hdr.tcp.window});}if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on,hdr.native.crc,hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first,hdr.appended.crc,hdr.last.on_last,hdr.last.off,hdr.last.status,hdr.last.crc});}pkt.emit(hdr.map_snapshot);pkt.emit(hdr.reference);pkt.emit(hdr.cache);pkt.emit(hdr.completion);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.native);pkt.emit(hdr.tail);pkt.emit(hdr.appended);pkt.emit(hdr.last);pkt.emit(hdr.image);pkt.emit(hdr.response_extra);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
#ifndef ORDINARY_M_NO_MAIN
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

#endif

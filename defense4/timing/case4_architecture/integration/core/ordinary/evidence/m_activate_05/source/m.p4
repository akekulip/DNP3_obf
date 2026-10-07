/* Partial ordinary SELECT M prepare: actual N28 handoff, full native35 validation,
 * captured decoy construction and persistent producer reservation. No release
 * authority: E must finish all image stores before ready; N commits afterward. */
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
header reference_h{bit<32> epoch;bit<32> generation;bit<32> expected_owner;bit<16> event;bit<16> format;}
header captured_decoy_h{bit<16> index;bit<8> code;bit<8> repeat;bit<32> on;bit<32> off;}
header cache_reference_h{bit<32> generation;bit<32> expected_owner;}
header image_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<32> w4;bit<32> w5;bit<32> w6;bit<32> w7;bit<32> w8;bit<32> w9;bit<32> w10;bit<32> w11;bit<32> w12;bit<24> w13;}
struct context_t{bit<32> epoch;bit<32> owner;}
struct ledger_tag_t{bit<32> epoch;bit<32> generation;}
struct producer_cell_t{bit<32> generation;bit<32> phase;}
header completion_epoch_h{bit<32> epoch;}
struct headers_t{reference_h reference;captured_decoy_h captured;cache_reference_h cache;completion_epoch_h completion;eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;native_h native;tail_h tail;appended_h appended;final_h last;image_h image;}
struct meta_t{bit<8> role;bit<32> stamp_diff;bit<32> context_owner;bit<32> context_grant;bit<32> ref_gen_diff;bit<32> ref_owner_diff;bit<32> activation_grant;bit<1> geometry_done;bit<1> position_done;bit<1> ledger_done;bit<32> reservation_grant;bit<1> parsed;bit<1> enabled;bit<1> profile;bit<1> changed;bool ip_error;bit<16> tcp_sum;bit<16> tcp_length;bit<16> decoy_index;bit<8> decoy_code;bit<8> decoy_repeat;bit<32> decoy_on;bit<32> decoy_off;bit<16> hcrc;bit<16> bcrc;bit<16> tcrc;bit<1> badh;bit<1> badb;bit<1> badt;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.role=8w0;m.geometry_done=1w0;m.position_done=1w0;m.ledger_done=1w0;m.parsed=1w0;m.enabled=1w0;m.profile=1w0;m.changed=1w0;m.badh=1w0;m.badb=1w0;m.badt=1w0;transition select(ig.ingress_port){9w196:reference;9w198:terminal_reference;default:accept;}}
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
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={allow_connection;NoAction;}size=1;default_action=NoAction();}
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
 Register<ledger_tag_t,bit<1>>(1,{0,0}) ledger_tag;
 RegisterAction<ledger_tag_t,bit<1>,bit<1>>(ledger_tag) write_ledger={void apply(inout ledger_tag_t value,out bit<1> done){value.epoch=hdr.reference.epoch;value.generation=hdr.cache.generation;done=1w1;}};
 action activate_ledger(){m.ledger_done=write_ledger.execute(1w0);}
 table activate_ledger_t{key={m.geometry_done:exact;m.position_done:exact;}actions={activate_ledger;NoAction;}size=1;const default_action=NoAction();const entries={(1w1,1w1):activate_ledger();}}
 action dirty_return(){hdr.completion.setValid();hdr.completion.epoch=hdr.reference.epoch;hdr.reference.format=16w3;hdr.reference.event=16w0x0814;tm.ucast_egress_port=9w198;tm.bypass_egress=1w1;}
 table dirty_return_t{key={m.ledger_done:exact;}actions={dirty_return;deny;}size=1;const default_action=deny();const entries={1w1:dirty_return();}}
 action to_endpoint_egress(){hdr.completion.setInvalid();hdr.reference.format=16w2;hdr.reference.event=16w0x0914;tm.ucast_egress_port=9w2;tm.bypass_egress=1w0;}
 table terminal_result_t{key={m.reservation_grant:exact;}actions={to_endpoint_egress;deny;}size=1;const default_action=deny();const entries={32w1:to_endpoint_egress();}}
 action reference_differences(){m.ref_gen_diff=hdr.reference.generation-hdr.cache.generation;m.ref_owner_diff=hdr.reference.expected_owner-hdr.cache.expected_owner;}
 table reference_differences_t{actions={reference_differences;}size=1;const default_action=reference_differences();}
 action no_stamp(){m.stamp_diff=32w0;}
 action compare_stamp(){m.stamp_diff=hdr.reference.epoch-hdr.completion.epoch;}
 table stamp_t{key={m.role:exact;}actions={no_stamp;compare_stamp;}size=1;const default_action=no_stamp();const entries={8w2:compare_stamp();}}
 action activate_allowed(){m.profile=1w1;}
 table activation_identity_t{key={m.ref_gen_diff:exact;m.ref_owner_diff:exact;m.stamp_diff:exact;}actions={activate_allowed;NoAction;}size=1;const default_action=NoAction();const entries={(32w0,32w0x80000,32w0):activate_allowed();}}
 action prepare_context_owner(){m.context_owner=hdr.reference.expected_owner;}
 action activation_context_owner(){m.context_owner=hdr.cache.expected_owner;}
 table context_owner_t{key={m.role:exact;}actions={prepare_context_owner;activation_context_owner;}size=2;const entries={8w1:activation_context_owner();8w2:activation_context_owner();}const default_action=prepare_context_owner();}
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
 apply{
 stamp_t.apply();context_owner_t.apply();forwarding.apply();
 if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
  connection.apply();
  if(m.role==8w1||m.role==8w2){
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
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() ic;Checksum() tc;apply{if(m.changed==1w1){hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,hdr.native.tp,hdr.native.app,hdr.native.func,hdr.native.group,hdr.native.variation,hdr.native.qualifier,hdr.native.count,hdr.native.index,hdr.native.code,hdr.native.repeat,hdr.native.on,hdr.native.crc,hdr.appended.off,hdr.appended.status,hdr.appended.group,hdr.appended.variation,hdr.appended.qualifier,hdr.appended.count,hdr.appended.index,hdr.appended.code,hdr.appended.repeat,hdr.appended.on_first,hdr.appended.crc,hdr.last.on_last,hdr.last.off,hdr.last.status,hdr.last.crc});}pkt.emit(hdr.reference);pkt.emit(hdr.cache);pkt.emit(hdr.completion);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);pkt.emit(hdr.native);pkt.emit(hdr.tail);pkt.emit(hdr.appended);pkt.emit(hdr.last);pkt.emit(hdr.image);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
#ifndef ORDINARY_M_NO_MAIN
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

#endif

/* Protected real-packet handshake candidate. No device configuration.
 * Four passes: validate/reserve/snapshot; write/current-owner CAS;
 * current-owner publication; actual WorkRecord terminal return.
 * Fixed stage order WorkRecord -> epoch/client/server banks -> owner.
 * Lost original/producer remains pinned. No verified retirement/reuse.
 * MSS-only TCP: final ACK+SELECT still REQUIRED and blocked in this P4.
 * Epoch/work are full32. Owner generation16 is nonwrapping.
 */
#include <core.p4>
#include <tna.p4>
#include "connection/work_record.p4"
const PortId_t RETURN_PORT=9w68;
header eth_h{bit<48> dst;bit<48> src;bit<16> type;}
header ip_h{bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h{bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header mss_h{bit<8> kind;bit<8> len;bit<16> value;}
header envelope_h{bit<32> epoch;bit<32> generation;bit<32> expected_cell;bit<16> event;bit<16> reserved;}
struct headers_t{envelope_h envelope;eth_h eth;ip_h ip;tcp_h tcp;mss_h mss;}
struct meta_t{bit<8> parsed;bit<8> port_valid;bit<8> direction;bit<8> network_valid;bit<8> shape_valid;bit<8> stage;bit<8> kind;bit<8> work_op;bit<8> owner_op;bit<8> sequence_valid;bit<8> epoch_valid;bit<8> emit_loop;bool ip_error;bit<16> tcp_sum;bit<32> counter;bit<32> generation;bit<32> work_phase;bit<32> epoch;bit<32> client;bit<32> server;bit<32> new_seq;bit<32> client_diff;bit<32> server_diff;bit<32> epoch_diff;bit<32> expected;bit<32> desired;bit<32> observed;bit<32> owner_diff;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 Checksum() ic;Checksum() tc;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=8w0;m.stage=8w0;m.kind=8w0;m.port_valid=8w0;m.direction=8w0;m.network_valid=8w0;m.shape_valid=8w0;m.sequence_valid=8w0;m.epoch_valid=8w0;m.emit_loop=8w0;transition select(ig.ingress_port){RETURN_PORT:envelope;default:eth;}}
 state envelope{pkt.extract(hdr.envelope);m.stage=hdr.envelope.event[15:8];m.kind=hdr.envelope.event[7:0];transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.frag,hdr.ip.flags,hdr.ip.len){(4w4,4w5,8w6,13w0,3w0,16w40):tcp;(4w4,4w5,8w6,13w0,3w2,16w40):tcp;(4w4,4w5,8w6,13w0,3w0,16w44):tcp;(4w4,4w5,8w6,13w0,3w2,16w44):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.ip.len){(4w6,16w44):mss;(4w5,16w40):finish;default:accept;}}
 state mss{pkt.extract(hdr.mss);tc.subtract(hdr.mss);transition finish;}
 state finish{m.tcp_sum=tc.get();m.parsed=8w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 WorkRecord() work;
 Register<bit<32>,bit<1>>(1,0) counter;
 RegisterAction<bit<32>,bit<1>,bit<32>>(counter) allocate={void apply(inout bit<32> v,out bit<32> r){r=v;if((int<32>)v!=-1){v=v+32w1;}}};
 Register<bit<32>,bit<1>>(1,0) owner;
 RegisterAction<bit<32>,bit<1>,bit<32>>(owner) read_owner={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(owner) compare_owner={void apply(inout bit<32> v,out bit<32> r){r=v;if(v==m.expected){v=m.desired;}}};
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.port_valid=8w1;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table ports{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action forward_flow(PortId_t port){m.direction=8w1;tm.ucast_egress_port=port;}
 action reverse_flow(PortId_t port){m.direction=8w2;tm.ucast_egress_port=port;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={forward_flow;reverse_flow;NoAction;}size=2;default_action=NoAction();}
 action network_accept(){m.network_valid=8w1;}
 table network{key={m.parsed:exact;m.ip_error:exact;m.tcp_sum:exact;hdr.ip.ttl:range;hdr.tcp.reserved:exact;hdr.tcp.urgent:exact;}actions={network_accept;NoAction;}size=1;const default_action=NoAction();const entries={(8w1,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();}}
 action syn_shape(){m.shape_valid=8w1;m.kind=8w1;}
 action synack_shape(){m.shape_valid=8w1;m.kind=8w2;}
 table syn_shapes{key={m.direction:exact;hdr.tcp.flags:exact;hdr.mss.kind:exact;hdr.mss.len:exact;hdr.mss.value:range;}
 actions={syn_shape;synack_shape;NoAction;}size=2;const default_action=NoAction();const entries={(8w1,8w2,8w2,8w4,16w57..16w65535):syn_shape();(8w2,8w18,8w2,8w4,16w57..16w65535):synack_shape();}}
 action ack_shape(){m.shape_valid=8w1;m.kind=8w3;}
 action close_shape(){m.shape_valid=8w1;m.kind=8w4;}
 table short_shapes{key={m.direction:exact;hdr.tcp.flags:exact;}
 actions={ack_shape;close_shape;NoAction;}size=7;const default_action=NoAction();const entries={(8w1,8w16):ack_shape();(8w1,8w17):close_shape();(8w2,8w17):close_shape();(8w1,8w20):close_shape();(8w2,8w20):close_shape();(8w1,8w4):close_shape();(8w2,8w4):close_shape();}}
 action mint(){m.counter=allocate.execute(1w0);}
 table mint_t{actions={mint;}size=1;const default_action=mint();}
 action available(){m.work_op=8w1;m.generation=m.counter+32w1;}
 table available_t{key={m.counter:exact;}actions={available;NoAction;}size=1;const entries={32w0xffffffff:NoAction();}const default_action=available();}
 Register<bit<32>,bit<1>>(1,0) epoch;
 RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) read_epoch={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) write_epoch={void apply(inout bit<32> v,out bit<32> r){v=hdr.envelope.epoch;r=v;}};
 action load_epoch(){m.epoch=read_epoch.execute(1w0);}
 action store_epoch(){m.epoch=write_epoch.execute(1w0);}
 table epoch_t{key={m.stage:exact;m.kind:exact;m.work_phase:exact;}actions={load_epoch;store_epoch;}size=1;
 const entries={(8w1,8w1,32w1):store_epoch();}const default_action=load_epoch();}
 Register<bit<32>,bit<1>>(1,0) client;
 RegisterAction<bit<32>,bit<1>,bit<32>>(client) read_client={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(client) write_client={void apply(inout bit<32> v,out bit<32> r){r=v;v=m.new_seq;}};
 action load_client(){m.client=read_client.execute(1w0);}
 action store_client(){m.client=write_client.execute(1w0);}
 table client_t{key={m.stage:exact;m.kind:exact;m.work_phase:exact;}actions={load_client;store_client;}size=1;
 const entries={(8w1,8w1,32w1):store_client();}const default_action=load_client();}
 Register<bit<32>,bit<1>>(1,0) server;
 RegisterAction<bit<32>,bit<1>,bit<32>>(server) read_server={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(server) write_server={void apply(inout bit<32> v,out bit<32> r){r=v;v=m.new_seq;}};
 action load_server(){m.server=read_server.execute(1w0);}
 action store_server(){m.server=write_server.execute(1w0);}
 table server_t{key={m.stage:exact;m.kind:exact;m.work_phase:exact;}actions={load_server;store_server;}size=1;
 const entries={(8w1,8w2,32w1):store_server();}const default_action=load_server();}
 action next_seq(){m.new_seq=hdr.tcp.seq+32w1;}
 table next_seq_t{actions={next_seq;}size=1;const default_action=next_seq();}
 action diff_syn(){m.client_diff=hdr.tcp.ack;m.server_diff=32w0;}
 action diff_synack(){m.client_diff=hdr.tcp.ack-m.client;m.server_diff=32w0;}
 action diff_forward(){m.client_diff=hdr.tcp.seq-m.client;m.server_diff=hdr.tcp.ack-m.server;}
 action diff_reverse(){m.client_diff=hdr.tcp.seq-m.server;m.server_diff=hdr.tcp.ack-m.client;}
 action diff_reset_forward(){m.client_diff=hdr.tcp.seq-m.client;m.server_diff=32w0;}
 action diff_reset_reverse(){m.client_diff=hdr.tcp.seq-m.server;m.server_diff=32w0;}
 table sequence_diff{key={m.direction:exact;hdr.tcp.flags:exact;}
 actions={diff_syn;diff_synack;diff_forward;diff_reverse;diff_reset_forward;diff_reset_reverse;NoAction;}size=8;const default_action=NoAction();
 const entries={(8w1,8w2):diff_syn();(8w2,8w18):diff_synack();(8w1,8w16):diff_forward();(8w1,8w17):diff_forward();(8w2,8w17):diff_reverse();(8w1,8w20):diff_forward();(8w2,8w20):diff_reverse();(8w1,8w4):diff_reset_forward();(8w2,8w4):diff_reset_reverse();}}
 action seq_ok(){m.sequence_valid=8w1;}
 table sequence_guard{key={m.client_diff:exact;m.server_diff:exact;}actions={seq_ok;NoAction;}size=1;const entries={(32w0,32w0):seq_ok();}const default_action=NoAction();}
 action epoch_difference(){m.epoch_diff=hdr.envelope.epoch-m.epoch;}
 table epoch_diff_t{actions={epoch_difference;}size=1;const default_action=epoch_difference();}
 action epoch_ok(){m.epoch_valid=8w1;}
 table epoch_guard{key={m.epoch_diff:exact;}actions={epoch_ok;NoAction;}size=1;const entries={32w0:epoch_ok();}const default_action=NoAction();}
 action claim_syn(){m.expected=hdr.envelope.expected_cell;m.desired=hdr.envelope.expected_cell+32w0x10001;m.owner_op=8w1;}
 action claim_synack(){m.expected=hdr.envelope.expected_cell;m.desired=hdr.envelope.expected_cell+32w0x10000;m.owner_op=8w1;}
 action claim_ack(){m.expected=hdr.envelope.expected_cell;m.desired=hdr.envelope.expected_cell+32w0x10000;m.owner_op=8w1;}
 action publish_syn(){m.expected=hdr.envelope.expected_cell;m.desired=hdr.envelope.expected_cell+32w0x10000;m.owner_op=8w1;}
 action publish_synack(){m.expected=hdr.envelope.expected_cell;m.desired=hdr.envelope.expected_cell+32w0x10000;m.owner_op=8w1;}
 action publish_ack(){m.expected=hdr.envelope.expected_cell;m.desired=hdr.envelope.expected_cell;m.owner_op=8w1;}
 action close_pending(){m.expected=hdr.envelope.expected_cell;m.desired=16w6++hdr.envelope.expected_cell[15:0];m.owner_op=8w1;}
 action close_free(){m.expected=hdr.envelope.expected_cell;m.desired=16w7++hdr.envelope.expected_cell[15:0];m.owner_op=8w1;}
 table owner_command{key={m.stage:exact;m.kind:exact;m.work_phase:exact;m.epoch_valid:exact;}
 actions={claim_syn;claim_synack;claim_ack;publish_syn;publish_synack;publish_ack;close_pending;close_free;NoAction;}size=10;const default_action=NoAction();
 const entries={(8w1,8w1,32w1,8w1):claim_syn();(8w1,8w2,32w1,8w1):claim_synack();(8w1,8w3,32w1,8w1):claim_ack();(8w2,8w1,32w2,8w1):publish_syn();(8w2,8w2,32w2,8w1):publish_synack();(8w2,8w3,32w2,8w1):publish_ack();(8w1,8w4,32w4,8w1):close_free();(8w1,8w4,32w1,8w1):close_pending();(8w1,8w4,32w2,8w1):close_pending();(8w1,8w4,32w3,8w1):close_pending();}}
 action owner_read(){m.observed=read_owner.execute(1w0);}
 action owner_cas(){m.observed=compare_owner.execute(1w0);}
 table owner_t{key={m.owner_op:exact;}actions={owner_read;owner_cas;}size=1;const entries={8w1:owner_cas();}const default_action=owner_read();}
 action difference_owner(){m.owner_diff=m.observed-m.expected;}
 table owner_diff_t{actions={difference_owner;}size=1;const default_action=difference_owner();}
 action snapshot(){hdr.envelope.setValid();hdr.envelope.expected_cell=m.observed;hdr.envelope.generation=m.generation;hdr.envelope.epoch=m.epoch;hdr.envelope.event=16w0x01ff;hdr.envelope.reserved=16w0;m.emit_loop=8w1;}
 table snapshot_t{actions={snapshot;}size=1;const default_action=snapshot();}
 action first_syn(){hdr.envelope.epoch=m.generation;hdr.envelope.event=16w0x0101;}
 action first_synack(){hdr.envelope.event=16w0x0102;}
 action first_ack(){hdr.envelope.event=16w0x0103;}
 action first_close(){hdr.envelope.event=16w0x0104;}
 table first_event{key={m.kind:exact;m.sequence_valid:exact;m.observed:ternary;}
 actions={first_syn;first_synack;first_ack;first_close;NoAction;}size=9;const default_action=NoAction();
 const entries={(8w1,8w1,32w0):first_syn();(8w2,8w1,32w0x20000&&&32w0xffff0000):first_synack();(8w3,8w1,32w0x40000&&&32w0xffff0000):first_ack();(8w4,8w1,32w0x20000&&&32w0xffff0000):first_close();(8w4,8w1,32w0x30000&&&32w0xffff0000):first_close();(8w4,8w1,32w0x40000&&&32w0xffff0000):first_close();(8w4,8w1,32w0x50000&&&32w0xffff0000):first_close();}}
 action next_stage(){hdr.envelope.event=hdr.envelope.event+16w0x100;m.emit_loop=8w1;}
 table next_stage_t{actions={next_stage;}size=1;const default_action=next_stage();}
 action carry_current(){hdr.envelope.expected_cell=m.desired;}
 table carry_t{actions={carry_current;}size=1;const default_action=carry_current();}
 action abort_work(){hdr.envelope.event[7:0]=8w255;}
 table abort_t{actions={abort_work;}size=1;const default_action=abort_work();}
 apply{
  m.work_op=8w0;m.owner_op=8w0;m.generation=32w0;m.expected=32w0;m.desired=32w0;
  ports.apply();network.apply();
  if(m.port_valid==8w1&&m.network_valid==8w1){
   connection.apply();
   if(m.direction!=8w0){
    if(m.stage==8w0){
     if(hdr.mss.isValid()){syn_shapes.apply();}else{short_shapes.apply();}
     if(m.shape_valid==8w1&&m.kind!=8w4){mint_t.apply();available_t.apply();}
    }else if(hdr.envelope.reserved==16w0){m.generation=hdr.envelope.generation;if(m.kind!=8w4){m.work_op=8w2;}}
    work.apply(m.work_op,m.generation,m.work_phase);
    next_seq_t.apply();epoch_t.apply();client_t.apply();server_t.apply();
    if(m.stage==8w0){sequence_diff.apply();sequence_guard.apply();}
    else{epoch_diff_t.apply();epoch_guard.apply();owner_command.apply();}
    owner_t.apply();
    if(m.stage==8w0){
     if((m.work_op==8w1&&m.work_phase==32w4)||(m.kind==8w4&&m.shape_valid==8w1)){
      snapshot_t.apply();first_event.apply();
      if(m.kind==8w4&&hdr.envelope.event==16w0x01ff){m.emit_loop=8w0;hdr.envelope.setInvalid();}
     }
    }else if(m.kind==8w4){hdr.envelope.setInvalid();if(m.owner_op!=8w1){deny();}}
    else if(m.work_phase==32w1||m.work_phase==32w2){
     owner_diff_t.apply();if(m.owner_op==8w1&&m.owner_diff==32w0){carry_t.apply();}else{abort_t.apply();}
     next_stage_t.apply();
    }else if(m.work_phase==32w3){hdr.envelope.setInvalid();if(m.kind==8w255){deny();}}
    else{deny();}
    if(m.emit_loop==8w1){tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}
   }
  }
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;

#!/usr/bin/env python3
"""Four-pass full-cell/WorkRecord handshake experiment, not a complete target.

Record RW banks precede owner CAS; WorkRecord generation qualifies every write.
The MSS-only candidate explicitly lacks the oracle's finalACK+SELECT data path,
verified retirement/reuse, arbitrary options and independent lost-work recovery.
Private recirculation port68 is a local compile role, not a topology qualification.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def generate():
    text = '''/* Protected real-packet handshake candidate. No device configuration.
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
 state ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w40):ip_flags;(4w4,4w5,8w6,16w44):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
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
'''
    for name in ('epoch','client','server'):
        input_value = 'hdr.envelope.epoch' if name == 'epoch' else 'm.new_seq'
        write_body = f'v={input_value};r=v;' if name == 'epoch' else f'r=v;v={input_value};'
        text += f''' Register<bit<32>,bit<1>>(1,0) {name};
 RegisterAction<bit<32>,bit<1>,bit<32>>({name}) read_{name}={{void apply(inout bit<32> v,out bit<32> r){{r=v;}}}};
 RegisterAction<bit<32>,bit<1>,bit<32>>({name}) write_{name}={{void apply(inout bit<32> v,out bit<32> r){{{write_body}}}}};
 action load_{name}(){{m.{name}=read_{name}.execute(1w0);}}
 action store_{name}(){{m.{name}=write_{name}.execute(1w0);}}
 table {name}_t{{key={{m.stage:exact;m.kind:exact;m.work_phase:exact;m.work_op:exact;}}actions={{load_{name};store_{name};}}size=1;
 const entries={{(8w1,8w{1 if name != 'server' else 2},32w1,8w2):store_{name}();}}const default_action=load_{name}();}}
'''
    text += ''' action next_seq(){m.new_seq=hdr.tcp.seq+32w1;}
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
  if(m.port_valid==8w1&&m.network_valid==8w1&&(m.stage==8w0||hdr.envelope.reserved==16w0)){
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
  }else if(m.stage!=8w0){deny();}
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
'''
    # Structural reduction: validate exact TCP/MSS shape in the parser, rather
    # than serial MAU shape tables before generation allocation/WorkRecord.
    text=text.replace('bit<8> shape_valid;', 'bit<8> shape_valid;bit<8> packet_kind;')
    begin=text.index(' state tcp{')
    end=text.index('\n}',begin)
    text=text[:begin]+''' state tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.ip.len,hdr.tcp.flags){(4w6,16w44,8w2):mss_syn;(4w6,16w44,8w18):mss_synack;(4w5,16w40,8w16):ack;(4w5,16w40,8w17):close;(4w5,16w40,8w20):close;(4w5,16w40,8w4):close;default:accept;}}
 state mss_syn{pkt.extract(hdr.mss);tc.subtract(hdr.mss);m.packet_kind=8w1;transition mss_check;}
 state mss_synack{pkt.extract(hdr.mss);tc.subtract(hdr.mss);m.packet_kind=8w2;transition mss_check;}
 state mss_check{transition select(hdr.mss.kind,hdr.mss.len,hdr.mss.value){(8w2,8w4,16w57..16w65535):finish;default:accept;}}
 state ack{m.packet_kind=8w3;transition finish;}
 state close{m.packet_kind=8w4;transition finish;}
 state finish{m.tcp_sum=tc.get();m.parsed=8w1;m.shape_valid=8w1;transition accept;}
'''+text[end:]
    text=text.replace('r=v;if((int<32>)v!=-1){v=v+32w1;}',
        'r=32w0;if((int<32>)v!=-1){v=v+32w1;r=v;}')
    text=text.replace('m.counter=allocate.execute(1w0)', 'm.generation=allocate.execute(1w0)')
    text=text.replace('m.work_op=8w1;m.generation=m.counter+32w1;', 'm.work_op=8w1;')
    text=text.replace('table available_t{key={m.counter:exact;}', 'table available_t{key={m.generation:exact;}')
    text=text.replace('const entries={32w0xffffffff:NoAction();}const default_action=available();',
        'const entries={32w0:NoAction();}const default_action=available();')
    text=text.replace('if(hdr.mss.isValid()){syn_shapes.apply();}else{short_shapes.apply();}',
        'm.kind=m.packet_kind;direction_guard.apply();')
    marker=text.index(' action mint()')
    text=text[:marker]+''' action unsupported_direction(){m.shape_valid=8w0;}
 table direction_guard{key={m.kind:exact;m.direction:exact;}actions={unsupported_direction;NoAction;}size=5;const default_action=unsupported_direction();const entries={(8w1,8w1):NoAction();(8w2,8w2):NoAction();(8w3,8w1):NoAction();(8w4,8w1):NoAction();(8w4,8w2):NoAction();}}
'''+text[marker:]
    text=text.replace('m.work_phase:exact;m.epoch_valid:exact;', 'm.work_phase:exact;m.epoch_diff:exact;')
    marker=text.index(' table owner_command{')
    stop=text.index(' action owner_read()',marker)
    command=text[marker:stop].replace(',8w1):', ',32w0):')
    text=text[:marker]+command+text[stop:]
    text=text.replace('epoch_diff_t.apply();epoch_guard.apply();owner_command.apply();',
        'epoch_diff_t.apply();owner_command.apply();')
    # Fold exhausted-generation refusal into the existing WorkRecord dispatch.
    # Route recirculation within actions already dependent on the owner result.
    text=text.replace('bit<8> emit_loop;', 'bit<8> emit_loop;PortId_t output_port;')
    text=text.replace('m.direction=8w1;tm.ucast_egress_port=port;', 'm.direction=8w1;m.output_port=port;tm.ucast_egress_port=port;')
    text=text.replace('m.direction=8w2;tm.ucast_egress_port=port;', 'm.direction=8w2;m.output_port=port;tm.ucast_egress_port=port;')
    text=text.replace('m.generation=allocate.execute(1w0);', 'm.generation=allocate.execute(1w0);m.work_op=8w1;')
    text=text.replace('mint_t.apply();available_t.apply();', 'mint_t.apply();')
    text=text.replace('m.emit_loop=8w1;}', 'm.emit_loop=8w1;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}')
    text=text.replace('m.emit_loop=8w0;hdr.envelope.setInvalid();', 'm.emit_loop=8w0;hdr.envelope.setInvalid();tm.ucast_egress_port=m.output_port;')
    text=text.replace('    if(m.emit_loop==8w1){tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}','')
    # A private return cannot impersonate a fresh network packet, carry a zero
    # generation, or relabel the original SYN/SYNACK/ACK/close packet kind.
    text=text.replace('m.kind=hdr.envelope.event[7:0];transition eth;',
        'm.kind=hdr.envelope.event[7:0];transition envelope_reserved;')
    marker=text.index(' state eth{')
    events=(0x101,0x102,0x103,0x104,0x1ff,0x201,0x202,0x203,0x2ff,
        0x301,0x302,0x303,0x3ff)
    checks=' state envelope_reserved{transition select(hdr.envelope.reserved){16w0:envelope_event;default:accept;}}\n'
    checks+=' state envelope_event{transition select(hdr.envelope.event){'+''.join(
        f'16w0x{event:04x}:envelope_epoch;' for event in events)+'default:accept;}}\n'
    checks+=' state envelope_epoch{transition select(hdr.envelope.epoch){32w0:accept;default:envelope_generation;}}\n'
    checks+=' state envelope_generation{transition select(hdr.envelope.generation){32w0:accept;default:eth;}}\n'
    text=text[:marker]+checks+text[marker:]
    text=text.replace('state finish{m.tcp_sum=tc.get();m.parsed=8w1;m.shape_valid=8w1;transition accept;}',
        'state finish{m.tcp_sum=tc.get();transition select(ig.ingress_port){RETURN_PORT:finish_kind;default:finished;}}\n state finish_kind{transition select(hdr.envelope.event[7:0],hdr.tcp.flags){(8w1,8w2):finished;(8w2,8w18):finished;(8w3,8w16):finished;(8w4,8w17):finished;(8w4,8w20):finished;(8w4,8w4):finished;(8w255,_):finished;default:accept;}}\n state finished{m.parsed=8w1;m.shape_valid=8w1;transition accept;}')
    text=text.replace('hdr.envelope.event=16w0x0104;', 'hdr.envelope.event=16w0x0104;hdr.envelope.generation=m.epoch;')
    # Extract prefix words in order to bound the parser match-register lifetime.
    # The serialization remains16 bytes, including expectedCell/event/reserved.
    text=text.replace('header envelope_h{bit<32> epoch;bit<32> generation;bit<32> expected_cell;bit<16> event;bit<16> reserved;}',
        'header envelope_h{bit<32> epoch;}\nheader work_generation_h{bit<32> generation;}\nheader expected_cell_h{bit<32> expected_cell;}\nheader event_h{bit<16> event;bit<16> reserved;}')
    text=text.replace('envelope_h envelope;eth_h eth;',
        'envelope_h envelope;work_generation_h work_generation;expected_cell_h expected_cell;event_h event;eth_h eth;')
    for field,header in (('generation','work_generation'),('expected_cell','expected_cell'),('event','event'),('reserved','event')):
        text=text.replace('hdr.envelope.'+field,'hdr.'+header+'.'+field)
    start=text.index(' state envelope{');stop=text.index(' state eth{',start)
    states=' state envelope{pkt.extract(hdr.envelope);transition select(hdr.envelope.epoch){32w0:accept;default:envelope_generation;}}\n'
    states+=' state envelope_generation{pkt.extract(hdr.work_generation);transition select(hdr.work_generation.generation){32w0:accept;default:envelope_expected;}}\n'
    states+=' state envelope_expected{pkt.extract(hdr.expected_cell);pkt.extract(hdr.event);m.stage=hdr.event.event[15:8];m.kind=hdr.event.event[7:0];transition envelope_reserved;}\n'
    states+=' state envelope_reserved{transition select(hdr.event.reserved){16w0:envelope_event;default:accept;}}\n'
    states+=' state envelope_event{transition select(hdr.event.event){'+''.join(f'16w0x{event:04x}:eth;' for event in events)+'default:accept;}}\n'
    text=text[:start]+states+text[stop:]
    text=text.replace('hdr.envelope.setValid();',
        'hdr.envelope.setValid();hdr.work_generation.setValid();hdr.expected_cell.setValid();hdr.event.setValid();')
    text=text.replace('hdr.envelope.setInvalid();',
        'hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();')
    # Re-reading the intrinsic ingress port at the end of parsing kept its match
    # register live through every prefix word. Qualify kind against actual flags
    # in the existing network table instead, with no new serial MAU dependency.
    start=text.index(' state finish{');stop=text.index('\n}',start)
    text=text[:start]+' state finish{m.tcp_sum=tc.get();m.parsed=8w1;m.shape_valid=8w1;transition accept;}\n'+text[stop:]
    text=text.replace('m.parsed:exact;m.ip_error:exact;',
        'm.parsed:exact;m.kind:exact;hdr.tcp.flags:ternary;m.ip_error:exact;')
    old='const entries={(8w1,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();}'
    entries=''.join(f'(8w1,8w{kind},{flag},false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'
        for kind,flag in ((0,'_'),(1,'8w2'),(2,'8w18'),(3,'8w16'),
            (4,'8w17'),(4,'8w20'),(4,'8w4'),(255,'_')))
    text=text.replace(old,'const entries={'+entries+'}')
    text=text.replace('size=1;const default_action=NoAction();const entries={(8w1,8w0,',
        'size=8;const default_action=NoAction();const entries={(8w1,8w0,')
    return text


if __name__ == '__main__':
    (ROOT/'handshake.p4').write_text(generate())

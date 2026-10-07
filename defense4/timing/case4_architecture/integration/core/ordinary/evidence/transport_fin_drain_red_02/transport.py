#!/usr/bin/env python3
"""Partial SELECT reverse normalization; no physical/full-target qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import split
from compose import role

HERE=Path(__file__).resolve().parent
replace=split.replace


def masks(low,high):
    result=[]
    while low<=high:
        size=(low&-low) if low else 1<<32
        while size>high-low+1:size//=2
        result.append((low,((1<<32)-size)&0xffffffff));low+=size
    return result


def inverse_table(name,offset,target):
    entries=[]
    for lo,hi,action in ((0,19,name+'_clamp'),(20,0x7fffffff,name+'_shift')):
        entries += [f'(32w0x{value:x}&&&32w0x{mask:08x}):{action}();' for value,mask in masks(lo,hi)]
    return (" action NAME_clamp(){TARGET=m.boundary-32w1;}\n"
            " action NAME_shift(){TARGET=TARGET-32w20;}\n"
            " table NAME{key={OFFSET:ternary;}actions={NAME_clamp;NAME_shift;NoAction;}size=SIZE;const default_action=NoAction();const entries={ENTRIES}}\n").replace('NAME',name).replace('TARGET',target).replace('OFFSET',offset).replace('SIZE',str(len(entries))).replace('ENTRIES',''.join(entries))



def generate_roles():
    roles=split.generate_roles();n=roles['n3.p4'];m=roles['m3.p4']

    # Direct existing SALU full equality avoids adding a MAU arithmetic group.
    n=replace(n,'m.work_op:ternary;}actions={load_epoch;', 'm.work_op:ternary;m.normalized:ternary;}actions={load_epoch;')
    n=replace(n,'actions={load_epoch;diff_epoch;store_epoch;}size=3;', 'actions={load_epoch;diff_epoch;store_epoch;}size=4;')
    n=replace(n,'(8w1,8w1,32w1,8w2):store_epoch();(8w0,_,_,_):load_epoch();', '(8w1,8w1,32w1,8w2,_):store_epoch();(8w1,8w21,_,_,_):load_epoch();(8w0,_,_,_,1w1):diff_epoch();(8w0,_,_,_,_):load_epoch();')
    n=replace(n,'action snapshot(){', 'action normalized_snapshot(){hdr.envelope.setValid();hdr.work_generation.setValid();hdr.expected_cell.setValid();hdr.event.setValid();hdr.expected_cell.expected_cell=m.observed;hdr.work_generation.generation=m.generation;hdr.event.event=16w0x01ff;hdr.event.reserved=16w4;m.emit_loop=8w1;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}\n action snapshot(){')
    n=replace(n,'table snapshot_t{key={m.epoch:exact;}actions={snapshot;snapshot_epoch_zero;}size=1;const entries={32w0:snapshot_epoch_zero();}', 'table snapshot_t{key={m.epoch:ternary;m.normalized:exact;}actions={snapshot;normalized_snapshot;snapshot_epoch_zero;}size=2;const entries={(32w0,1w0):snapshot_epoch_zero();(_,1w1):normalized_snapshot();}')
    n=replace(n,'size=3;const default_action=NoAction();const entries={(8w1,32w4,_):store_active_generation();', 'size=4;const default_action=NoAction();const entries={(_,_,8w21):check_active_generation();(8w1,32w4,_):store_active_generation();')
    n=replace(n,'go_ret_abort;NoAction;}size=57;', 'go_ret_abort;NoAction;}size=58;')
    n=replace(n,'const entries={(8w16,8w20,8w20,8w1,8w1,', 'const entries={(8w1,_,8w21,8w2,8w1,_,_,_,_,_,_,_,_,_):go_ret_work();(8w16,8w20,8w20,8w1,8w1,')
    n=replace(n,'if(m.kind==8w20){ready_result_t.apply();}', 'if(m.kind==8w21){abort_epoch_stamp_t.apply();}else if(m.kind==8w20){ready_result_t.apply();}')
    n=replace(n,'(8w1,8w20,8w16,false,', '(8w1,8w21,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w21,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();(8w1,8w20,8w16,false,')
    n=replace(n,'bit<32> terminal_diff;','bit<1> normalized;bit<32> terminal_diff;')
    n=replace(n,'m.parsed=8w0;','m.normalized=1w0;m.parsed=8w0;')
    n=replace(n,'16w3:terminal_event;','16w3:terminal_event;16w4:normalized_event;')
    n=replace(n,' state ready_event{', ''' state normalized_event{m.normalized=1w1;transition select(hdr.event.event){16w0x0013:eth;default:normalized_return;}}\n state normalized_return{transition select(hdr.event.event){16w0x0106:eth;16w0x0206:eth;16w0x0306:eth;16w0x0108:eth;16w0x0208:eth;16w0x0308:eth;16w0x0115:eth;16w0x01ff:eth;16w0x02ff:eth;16w0x03ff:eth;default:accept;}}
 state ready_event{''')
    n=replace(n,'action ack_native(){m.ack_native=hdr.tcp.ack-32w20;}', 'action ack_native(){m.ack_native=hdr.tcp.ack-32w20;}\n action normalized_ack_native(){m.ack_native=hdr.tcp.ack;}')
    n=replace(n,'table ack_native_t{actions={ack_native;}size=1;const default_action=ack_native();}', 'table ack_native_t{key={m.normalized:exact;}actions={ack_native;normalized_ack_native;}size=1;const entries={1w1:normalized_ack_native();}const default_action=ack_native();}')
    n=replace(n,'m.compare_native_start=(bit<32>)(hdr.tcp.ack-32w55);m.compare_native_end=(bit<32>)(hdr.tcp.ack);', 'm.compare_native_start=(bit<32>)(hdr.tcp.ack-32w35);m.compare_native_end=(bit<32>)(hdr.tcp.ack+32w20);')
    # Response comparison is now deliberately normalized-only in this candidate.
    n=replace(n,'(8w6,8w1,8w1,32w0x90000&&&32w0xffff0000):first_response();','(8w6,8w1,8w1,32w0x120000&&&32w0xffff0000):first_response();')
    extra=''' action stamp_normalized_abort(){hdr.envelope.epoch=m.epoch;hdr.event.event=16w0x02ff;hdr.event.reserved=16w4;m.emit_loop=8w1;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}
 table abort_epoch_stamp_t{key={m.work_phase:exact;m.active_gen_diff:exact;m.owner_diff:exact;}actions={stamp_normalized_abort;deny;}size=1;const default_action=deny();const entries={(32w1,32w0,32w0):stamp_normalized_abort();}}
 action initial_normalized(){m.kind=8w0;}
 table normalized_classification_t{key={ig.ingress_port:exact;hdr.event.reserved:exact;hdr.event.event:exact;}actions={initial_normalized;NoAction;}size=1;const default_action=NoAction();const entries={(9w68,16w4,16w0x0013):initial_normalized();}}
 action reverse_to_m(){tm.ucast_egress_port=9w199;tm.bypass_egress=1w1;}
 table reverse_route{key={ig.ingress_port:exact;m.normalized:exact;m.direction:exact;m.packet_kind:exact;}actions={reverse_to_m;NoAction;}size=2;const default_action=NoAction();const entries={(9w2,1w0,8w2,8w3):reverse_to_m();(9w2,1w0,8w2,8w6):reverse_to_m();}}
 table partial_ack_t{key={m.normalized:exact;m.packet_kind:exact;m.direction:exact;m.client_diff:exact;m.server_diff:ternary;}actions={seq_ok;NoAction;}size=3;const default_action=NoAction();const entries={(1w1,8w3,8w2,32w0,32w0xffffffdd&&&32w0xffffffff):seq_ok();(1w1,8w3,8w2,32w0,32w0xffffffde&&&32w0xfffffffe):seq_ok();(1w1,8w3,8w2,32w0,32w0xffffffe0&&&32w0xffffffe0):seq_ok();}}
 action retain_normalized(){hdr.event.reserved=16w4;}
 action normalized_abort(){hdr.event.reserved=16w4;hdr.event.event=16w0x0115;}
 table normalized_result_t{key={m.normalized:exact;m.epoch_diff:exact;m.sequence_valid:exact;}actions={retain_normalized;normalized_abort;NoAction;}size=1;const entries={(1w1,32w0,8w1):retain_normalized();}const default_action=normalized_abort();}
'''
    n=replace(n,' apply{\n  m.return_abort=',extra+' apply{\n  m.return_abort=')
    n=replace(n,' apply{\n  m.return_abort=', ' apply{\n  normalized_classification_t.apply();\n  m.return_abort=')
    n=replace(n,'   guard.apply();','   reverse_route.apply();\n   if(tm.ucast_egress_port!=9w199){\n   guard.apply();')

    n=replace(n,'sequence_diff.apply();sequence_guard.apply();','sequence_diff.apply();sequence_guard.apply();partial_ack_t.apply();')
    n=replace(n,'}else if(m.work_op==8w1){busy_t.apply();}', '}else if(m.work_op==8w1){if(m.normalized==1w1){deny();}else{busy_t.apply();}}')
    n=replace(n,'snapshot_t.apply();first_event.apply();','snapshot_t.apply();first_event.apply();\n      if(m.normalized==1w1){normalized_result_t.apply();}')
    n=replace(n,' }\n}\ncontrol IgDeparser', ' if(ig.ingress_port==RETURN_PORT&&m.go!=8w1){deny();}\n }\n}\ncontrol IgDeparser')
    n=replace(n,'   }else if(m.stage!=8w0){deny();}\n  }else if', '   }else if(m.stage!=8w0){deny();}\n   }\n  }else if')

    m=replace(m,'header eth_h {','header response_extra_h{bit<16> value;}\nheader eth_h {')
    m=replace(m,'image_h image;}','image_h image;response_extra_h response_extra;}')
    m=replace(m,'struct meta_t{','struct meta_t{bit<1> reverse_changed;bit<1> reverse_allowed;bit<64> map_reservation;bit<64> map_tag;bit<64> map_context;bit<32> boundary;bit<32> map_position;bit<32> geometry_diff;bit<32> map_epoch_diff;bit<32> map_generation_diff;bit<32> left;bit<32> right;bit<32> left_offset;bit<32> right_offset;bit<32> window_after;bit<16> repair_sum;')
    m=replace(m,'9w198:terminal_reference;','9w198:terminal_reference;9w199:reverse_eth;')
    parser=''' state reverse_eth{m.role=8w3;pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:reverse_ip;default:accept;}}
 state reverse_ip{pkt.extract(hdr.ip);ic.add(hdr.ip);m.ip_error=ic.verify();tc.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto){(4w4,4w5,8w6):reverse_flags;default:accept;}}
 state reverse_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):reverse_tcp;(13w0,3w2):reverse_tcp;default:accept;}}
 state reverse_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags,hdr.ip.len){(4w5,4w0,16w0,8w16,16w40):reverse_ack_finish;(4w5,4w0,16w0,8w16,16w97):reverse_image;(4w5,4w0,16w0,8w24,16w97):reverse_image;default:accept;}}
 state reverse_ack_finish{m.tcp_sum=tc.get();m.repair_sum=16w0;m.parsed=1w1;transition accept;}\n state reverse_image{pkt.extract(hdr.image);tc.subtract(hdr.image);pkt.extract(hdr.response_extra);tc.subtract(hdr.response_extra);transition reverse_finish;}
 state reverse_finish{m.tcp_sum=tc.get();m.repair_sum=m.tcp_sum;m.parsed=1w1;transition accept;}
'''
    m=replace(m,' state terminal_reference{',parser+' state terminal_reference{')
    m=replace(m,'action allow_connection(){m.enabled=1w1;}','action allow_connection(){m.enabled=1w1;}\n action allow_reverse(){m.enabled=1w1;m.reverse_allowed=1w1;}')
    m=replace(m,'actions={allow_connection;NoAction;}size=1;','actions={allow_connection;allow_reverse;NoAction;}size=2;')
    m=replace(m,'Register<producer_cell_t,bit<1>>(1,{0,4}) reservation;', 'Register<producer_cell_t,bit<1>>(1,{0,4}) reservation;')
    extra=''' RegisterAction<producer_cell_t,bit<1>,bit<64>>(reservation) read_map_reservation={void apply(inout producer_cell_t value,out bit<64> result){result[63:32]=value.generation;result[31:0]=value.phase;}};
 RegisterAction<ledger_tag_t,bit<1>,bit<64>>(ledger_tag) read_map_tag={void apply(inout ledger_tag_t value,out bit<64> result){result[63:32]=value.epoch;result[31:0]=value.generation;}};
 RegisterAction<context_t,bit<1>,bit<64>>(producer_context) read_map_context={void apply(inout context_t value,out bit<64> result){result[63:32]=value.epoch;result[31:0]=value.owner;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(geo_first) read_boundary={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(ledger_position) read_map_position={void apply(inout bit<32> value,out bit<32> result){result=value;}};
 action mapping_reads(){m.map_reservation=read_map_reservation.execute(1w0);m.map_tag=read_map_tag.execute(1w0);m.map_context=read_map_context.execute(1w0);m.boundary=read_boundary.execute(1w0);m.map_position=read_map_position.execute(1w0);}
 table mapping_reads_t{actions={mapping_reads;}size=1;const default_action=mapping_reads();}
 action prepare_edges(){m.left=hdr.tcp.ack;m.right=hdr.tcp.ack+(bit<32>)hdr.tcp.window;m.left_offset=hdr.tcp.ack-m.boundary;m.right_offset=m.right-m.boundary;m.geometry_diff=m.boundary-m.map_position-32w35;m.map_epoch_diff=m.map_context[63:32]-m.map_tag[63:32];m.map_generation_diff=m.map_reservation[63:32]-m.map_tag[31:0];}
 table prepare_edges_t{actions={prepare_edges;}size=1;const default_action=prepare_edges();}
 action map_allowed(){m.profile=1w1;}
 table mapping_identity_t{key={m.reverse_allowed:exact;m.map_reservation[31:0]:exact;m.map_generation_diff:exact;m.map_epoch_diff:exact;m.geometry_diff:exact;m.map_tag[63:32]:ternary;m.map_tag[31:0]:ternary;m.map_context[31:0]:ternary;}actions={map_allowed;deny;}size=3;const default_action=map_allowed();const entries={(1w1,32w4,32w0,32w0,32w0,32w0,_ ,_):deny();(1w1,32w4,32w0,32w0,32w0,_,32w0,_):deny();}}
 action map_return(){hdr.tcp.ack=m.left;hdr.tcp.window=m.window_after[15:0];m.reverse_changed=1w1;m.tcp_length=hdr.ip.len-16w20;hdr.reference.setValid();hdr.reference.epoch=m.map_tag[63:32];hdr.reference.generation=m.map_tag[31:0];hdr.reference.expected_owner=m.map_context[31:0];hdr.reference.event=16w0x0013;hdr.reference.format=16w4;tm.ucast_egress_port=9w68;tm.bypass_egress=1w1;}
 table map_return_t{key={m.window_after:range;}actions={map_return;deny;}size=1;const default_action=deny();const entries={32w0..32w65535:map_return();}}
'''
    # Refusal is explicit before arithmetic; no tag/geometry default can qualify.
    extra=extra[:extra.index(' table mapping_identity_t')]+''' table mapping_identity_t{key={m.reverse_allowed:exact;m.map_reservation[31:0]:exact;m.map_generation_diff:exact;m.map_epoch_diff:exact;m.geometry_diff:exact;m.map_context[31:16]:exact;}actions={map_allowed;deny;}size=1;const default_action=deny();const entries={(1w1,32w4,32w0,32w0,32w0,16w9):map_allowed();}}
'''+extra[extra.index(' action map_return'):]
    extra+=inverse_table('inverse_left','m.left_offset','m.left')+inverse_table('inverse_right','m.right_offset','m.right')
    extra+=''' action finish_window(){m.window_after=m.right-m.left;}
 table finish_window_t{actions={finish_window;}size=1;const default_action=finish_window();}
'''
    m=replace(m,' apply{\n',extra+' apply{\n')
    # Exact outer apply seam inspected below; preserve all prepare/activation paths.
    start=m.index(' apply{',m.index('table construct_t')) if 'table construct_t' in m else -1
    old='  if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xffeb&&hdr.ip.ttl!=8w0){'
    if old not in m:old='  if(m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){'
    # Branch after actual network/tuple admission. Restore forwarding refusal for
    # port199 only within this explicitly parsed role3, not arbitrary ports.
    m=replace(m,'forwarding.apply();','if(m.role!=8w3){forwarding.apply();}')
    needle='  if(m.role==8w1||m.role==8w2){'
    branch=''' if(m.role==8w3){
  mapping_reads_t.apply();prepare_edges_t.apply();mapping_identity_t.apply();
  if(m.profile==1w1&&m.map_tag[63:32]!=32w0&&m.map_tag[31:0]!=32w0&&m.map_context[15:0]!=16w0){inverse_left.apply();inverse_right.apply();finish_window_t.apply();map_return_t.apply();}else{deny();}
 }else'''
    m=replace(m,needle,branch+needle)
    # TCP checksum repair uses actual incoming checksum residual, preserving57
    # payload bytes without consuming their huge fields in a second deparser list.
    m=replace(m,'m.repair_sum=m.tcp_sum;', 'm.repair_sum=16w0;')
    m=replace(m,'tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags,hdr.ip.len)', 'tc.subtract({hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.checksum,hdr.tcp.urgent});transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags,hdr.ip.len)')
    # Installed primary SDK tna_checksum.p4 parser92/deparser263 uses this
    # direct residual pattern, including the original checksum itself.
    m=replace(m,'ig){Checksum() ic;Checksum() tc;', 'ig){Checksum() ic;Checksum() tc;Checksum() rc;')
    m=replace(m,'state reverse_tcp{pkt.extract(hdr.tcp);', 'state reverse_tcp{pkt.extract(hdr.tcp);rc.subtract({hdr.tcp.checksum,hdr.tcp.ack,hdr.tcp.window});')
    m=replace(m,'m.repair_sum=16w0;m.parsed=1w1;', 'm.repair_sum=rc.get();m.parsed=1w1;',2)
    m=replace(m,'apply{if(m.changed==1w1){hdr.ip.checksum=', 'apply{if(m.reverse_changed==1w1){hdr.tcp.checksum=rcd.update({m.repair_sum,hdr.tcp.ack,hdr.tcp.window});}if(m.changed==1w1){hdr.ip.checksum=')
    m=replace(m,'md){Checksum() ic;Checksum() tc;', 'md){Checksum() ic;Checksum() tc;Checksum() rcd;')
    m=replace(m,'pkt.emit(hdr.image);}}','pkt.emit(hdr.image);pkt.emit(hdr.response_extra);}}')
    roles['n3.p4']=n;roles['m3.p4']=m
    return roles


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('output',type=Path);args=p.parse_args();args.output.mkdir(exist_ok=True)
    roles=generate_roles()
    for name,text in roles.items():(args.output/name).write_text(text)
    nf='/* Partial reverse SELECT candidate, offline only. */\n#include <core.p4>\n#include <tna.p4>\n'+role((HERE/'work_record.p4').read_text()+'\n'+roles['n3.p4'],'n')+role(roles['f.p4'],'f')+'\nPipeline(n_IgParser(),n_Ingress(),n_IgDeparser(),f_EgParser(),f_Egress(),f_EgDeparser()) p0;Switch(p0) main;\n'
    (args.output/'nf.p4').write_text(nf);(args.output/'work_record.p4').write_bytes((HERE/'work_record.p4').read_bytes())
    (args.output/'inputs.json').write_text(json.dumps({'generated':{n:hashlib.sha256((args.output/n).read_bytes()).hexdigest() for n in (*roles,'nf.p4')},'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'full_target':False},indent=2)+'\n')


if __name__=='__main__':main()

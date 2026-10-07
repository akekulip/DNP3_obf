"""Actual native SELECT/response/OP binding to the SYN-produced authority.

Single authority, shared work pin, actual CRC/network validation, live epoch
carried with full owner. Not a complete target: receipt retirement and composed
transport/holding remain qualification gates. Historical parents stay untouched.
"""
import re
from pathlib import Path

HERE=Path(__file__).resolve().parent
CONNECTION=HERE.parent
ARCH=HERE.parents[2]


def braced(text,marker):
    start=text.index('{',text.index(marker));end=start+1;depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start+1:end-1]


def once(text,old,new):
    """Replace exactly one occurrence; a changed upstream source must fail loudly."""
    assert text.count(old)==1,(text.count(old),old[:90])
    return text.replace(old,new)


def drop_line(text,prefix):
    """Delete the single source line that starts (after blanks) with prefix."""
    lines=text.split('\n');hits=[i for i,l in enumerate(lines) if l.lstrip().startswith(prefix)]
    assert len(hits)==1,(prefix,hits)
    del lines[hits[0]]
    return '\n'.join(lines)


def generate():
    handshake=(ARCH/'integration/handshake.p4').read_text()
    selected=(CONNECTION/'selected.p4').read_text()
    text=handshake.replace('#include "connection/work_record.p4"','#include "work_record.p4"')
    text=text.replace('/* Protected real-packet handshake candidate.',
        '/* Actual native binding structural experiment, not full target qualification.\n * No receipt/reuse qualification or physical deployment.\n * Protected real-packet handshake candidate.')
    extras=''.join(re.search(r'(header '+name+r'\{[^\n]+\n)',selected)[1] for name in
        ('dl_h','block_h','tail_h','response_tail_h'))
    extras+=re.search(r'(struct object_pair_t\{[^\n]+\n)',selected)[1]
    text=text.replace('header eth_h{',extras+'header eth_h{')
    text=text.replace('mss_h mss;}', 'mss_h mss;dl_h dl;block_h first;block_h second;tail_h tail;response_tail_h response_tail;}')
    existing={name for kind,name in re.findall(r'(bit<\d+>|bool|PortId_t) (\w+);',braced(text,'struct meta_t'))}
    added=''.join(kind+' '+name+';' for kind,name in re.findall(r'(bit<\d+>|bool|PortId_t) (\w+);',braced(selected,'struct meta_t')) if name not in existing)
    text=text.replace('struct meta_t{','struct meta_t{'+added+'bit<8> data_valid;bit<32> ack_native;bit<32> expected_work_phase;bit<8> go;')
    text=text.replace('WorkRecord() work;','ExpectedWorkRecord() work;')
    text=text.replace('MSS-only TCP: final ACK+SELECT still REQUIRED and blocked in this P4.',
        'Actual native35 final ACK+SELECT admitted; composed transformation remains blocked.')
    text=text.replace('m.parsed=8w0;', 'm.parsed=8w0;m.enabled=8w0;m.profile=8w0;m.response=8w0;m.matched=8w0;m.data_valid=8w0;m.cache_mode=8w0;m.badh=8w0;m.badb=8w0;m.bad1=8w0;m.badt=8w0;')
    # Role paths avoid retaining IP-length PMRs across later TCP selectors.
    text=text.replace('(4w4,4w5,8w6,16w44):ip_flags;', '(4w4,4w5,8w6,16w44):ip_flags;(4w4,4w5,8w6,16w75):native_ip_flags;(4w4,4w5,8w6,16w97):response_ip_flags;')
    mark=text.index(' state finish{')
    states=''
    for role,next_state in (('native','native_block'),('response','response_block')):
        states+=f''' state {role}_ip_flags{{transition select(hdr.ip.frag,hdr.ip.flags){{(13w0,3w0):{role}_tcp;(13w0,3w2):{role}_tcp;default:accept;}}}}
 state {role}_tcp{{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){{(4w5,4w0,16w0,8w16):{role}_dl;(4w5,4w0,16w0,8w24):{role}_dl;default:accept;}}}}
 state {role}_dl{{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition {next_state};}}
'''
    states+=''' state native_block{pkt.extract(hdr.first);tc.subtract(hdr.first);transition native_tail;}
 state native_tail{pkt.extract(hdr.tail);tc.subtract(hdr.tail);transition select(hdr.first.w0[15:8]){8w3:select_finish;8w4:operate_finish;default:accept;}}
 state select_finish{m.packet_kind=8w5;transition finish;}
 state operate_finish{m.packet_kind=8w7;transition finish;}
 state response_block{pkt.extract(hdr.first);tc.subtract(hdr.first);transition response_second;}
 state response_second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition response_tail;}
 state response_tail{pkt.extract(hdr.response_tail);tc.subtract(hdr.response_tail);m.response=8w1;m.packet_kind=8w6;transition finish;}
'''
    text=text[:mark]+states+text[mark:]
    # The private envelope carries original operation, never a supplied CRC bit.
    marker=text.index(' state envelope_event{');end=text.index('\n',marker)
    line=text[marker:end]
    line=line.replace('default:accept;', ''.join(f'16w0x{s:02x}{k:02x}:eth;' for s in (1,2,3) for k in (5,6,7,8))+'default:accept;')
    text=text[:marker]+line+text[end:]
    network_start=text.index(' table network{');network_end=text.index('\n action syn_shape',network_start)
    network=text[network_start:network_end]
    network=network.replace('size=8;', 'size=20;').replace('size=9;', 'size=21;')
    at=network.rindex('}}')
    rows=''.join(f'(8w1,8w{k},8w{flags},false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();' for k in (5,6,7) for flags in (16,24))
    # The private forwarding pass (kind 8) re-enters on the original SYN, SYNACK or ACK flags.
    rows+=''.join(f'(8w1,8w8,8w{flags},false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();' for flags in (2,18,16))
    network=network[:at]+rows+network[at:]
    text=text[:network_start]+network+text[network_end:]
    # Reuse the actual selected22 native/response/profile/CRC source algorithms.
    start=selected.index(' action configure(');end=selected.index('WorkRecord() work;')
    validation=selected[start:end].replace('table connection{','table data_connection{')
    mark=text.index(' action available()');text=text[:mark]+validation+text[mark:]
    # Tables replaced by the single `guard` table and the folded stateful outputs.
    for prefix in ('action unsupported_direction()','table direction_guard{','action mint()','table mint_t{',
            'action epoch_difference()','table epoch_diff_t{','action difference_owner()','table owner_diff_t{'):
        text=drop_line(text,prefix)
    # Saved object banks use the shared authority WorkRecord, not a second pin.
    bank_text=''
    for name in ('application','frozen_decoy_off','pair_real_links_real_tcp_src',
            'pair_real_tcp_dst_real_tcp_ports','pair_real_object_real_on',
            'pair_real_off_native_start','pair_native_end_server_start',
            'pair_frozen_decoy_object_frozen_decoy_on'):
        found=re.search(r'Register<[^\n]+>\([^\n]+\) '+name+r';\n',selected)
        start=found.start();end=selected.index('\n',selected.index('table ',start))+1
        bank_text+=selected[start:end]
    # Each bank is keyed directly on the packet's own qualification: store on the
    # SELECT return of the live epoch, compare on the READ response (kind 6) and the
    # OPERATE (kind 7) once WorkRecord reports the claimed pin (phase 4). This replaces
    # the old binding_access table and its epoch_diff=0 overwrite at stage 0.
    def bank_keys(match):
        table=match.group(0).replace('key={m.cache_mode:exact;}','key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}')
        table=re.sub(r'8w1:(store_\w+\(\));',r'(8w1,8w5,32w1,32w0):\1;',table)
        table=re.sub(r'8w2:(compare_\w+\(\));',r'(8w0,8w7,32w4,_):\1;',table)
        return re.sub(r'8w3:(compare_\w+\(\));',r'(8w0,8w6,32w4,_):\1;',table)
    bank_text,banks=re.subn(r'table \w+_t\{key=\{m\.cache_mode:exact;\}[^\n]*',bank_keys,bank_text)
    assert banks==8,banks
    for name in ('compare_response_inputs','compare_operate_inputs','compare_select_inputs'):
        start=selected.index('action '+name+'(');end=selected.index('\n',selected.index('table '+name+'_t',start))+1
        bank_text+=selected[start:end]
    start=selected.index('table object_match{');end=selected.index('\n',start)
    match=selected[start:end].replace('match_response;match_operate;','matched;').replace(':match_response();',':matched();').replace(':match_operate();',':matched();')
    bank_text+='action matched(){m.matched=8w1;}\n'+match+'\n'
    bank_text+='''action calculate_native_end(){m.native_end=hdr.tcp.seq+32w35;}
table calculate_native_end_t{actions={calculate_native_end;}size=1;const default_action=calculate_native_end();}
'''
    # One ternary guard replaces data_guard, return_kind_guard, direction_guard and mint_t.
    # A hit is the old condition `direction!=0 && data_valid==1` (after return_kind_guard at
    # stage!=0 and direction_guard/shape at stage 0), and the action also does the old
    # mint (stage 0) or the old return-pass work_op/generation assignment. A miss skips the
    # counter and everything below it, as the old condition did.
    good='8w1,8w1,8w0,8w0,8w0,8w0'   # enabled, profile, badh, badb, bad1, badt
    wild='_,_,_,_,_,_'
    rows=[]
    for pk,direction in ((1,1),(2,2),(3,1),(4,1),(4,2),(5,1),(6,2),(7,1)):
        rows.append('(8w0,8w%d,8w0,8w%d,8w1,%s):%s;'%(pk,direction,good if pk>=5 else wild,'go_keep(8w4)' if pk==4 else 'go_new(8w%d)'%pk))
    for kind,pk in [(k,k) for k in range(1,8)]+[(8,1),(8,2),(8,3)]:
        rows.append('(_,8w%d,8w%d,_,_,%s):%s;'%(pk,kind,good if pk>=5 else wild,'go_ret_nowork()' if kind==4 else 'go_ret_work()'))
    for pk in (5,6,7):
        rows.append('(_,8w%d,8w255,_,_,%s):go_ret_work();'%(pk,good))
    for pk in (5,6,7):
        rows.append('(_,8w%d,8w255,_,_,_,_,_,_,_,_):NoAction();'%pk)
    rows.append('(_,_,8w255,_,_,%s):go_ret_work();'%wild)
    guard='''action go_new(bit<8> k){m.go=8w1;m.kind=k;m.generation=allocate.execute(1w0);m.work_op=8w1;}
action go_keep(bit<8> k){m.go=8w1;m.kind=k;}
action go_ret_work(){m.go=8w1;m.generation=hdr.work_generation.generation;m.work_op=8w2;}
action go_ret_nowork(){m.go=8w1;m.generation=hdr.work_generation.generation;}
table guard{key={m.stage:ternary;m.packet_kind:ternary;m.kind:ternary;m.direction:ternary;m.shape_valid:ternary;m.enabled:ternary;m.profile:ternary;m.badh:ternary;m.badb:ternary;m.bad1:ternary;m.badt:ternary;}
actions={go_new;go_keep;go_ret_work;go_ret_nowork;NoAction;}size=40;const default_action=NoAction();const entries={'''+''.join(rows)+'}}\n'
    mark=text.index(' apply{\n  m.work_op=');text=text[:mark]+bank_text+guard+text[mark:]
    # Both commits use actual validated payload sizes; no nominal timer inputs.
    text=once(text,'table next_seq_t{actions={next_seq;}',
        'action next_control(){m.new_seq=hdr.tcp.seq+32w35;}\n action next_response(){m.new_seq=hdr.tcp.seq+32w57;}\n table next_seq_t{key={m.packet_kind:exact;}actions={next_seq;next_control;next_response;}')
    text=once(text,'size=1;const default_action=next_seq();}',
        'size=3;const entries={8w5:next_control();8w7:next_control();8w6:next_response();}const default_action=next_seq();}')
    for bank,kinds in (('client',(5,7)),('server',(6,))):
        begin=text.index(' table '+bank+'_t{');stop=text.index('\n',text.index(' const entries=',begin))
        bank_table=text[begin:stop]
        where=bank_table.index('}const default_action=')
        bank_table=bank_table[:where]+''.join('(8w1,8w'+str(k)+',32w1,8w2):store_'+bank+'();' for k in kinds)+bank_table[where:]
        bank_table=bank_table.replace('size=1;', 'size='+str(1+len(kinds))+';')
        text=text[:begin]+bank_table+text[stop:]
    text=once(text,'table sequence_diff{','action ack_native(){m.ack_native=hdr.tcp.ack-32w20;}\n table ack_native_t{actions={ack_native;}size=1;const default_action=ack_native();}\n action diff_response(){m.client_diff=m.ack_native-m.client;m.server_diff=hdr.tcp.seq-m.server;}\n table data_sequence_diff{key={m.packet_kind:exact;}actions={diff_forward;diff_response;NoAction;}size=3;const entries={8w5:diff_forward();8w6:diff_response();8w7:diff_forward();}const default_action=NoAction();}\n table sequence_diff{')
    # Epoch authority: the bank returns the live difference (zero means equal) and the
    # install returns zero, so epoch_diff_t is gone. The difference is reg-minus-header
    # (the old table computed header-minus-reg); every consumer only tests it against zero.
    begin=text.index(' RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) read_epoch');stop=text.index(' Register<bit<32>,bit<1>>(1,0) client;')
    text=text[:begin]+''' RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) read_epoch={void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) read_epoch_diff={void apply(inout bit<32> v,out bit<32> r){r=v-hdr.envelope.epoch;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(epoch) write_epoch={void apply(inout bit<32> v,out bit<32> r){v=hdr.envelope.epoch;r=32w0;}};
 action load_epoch(){m.epoch=read_epoch.execute(1w0);}
 action diff_epoch(){m.epoch_diff=read_epoch_diff.execute(1w0);}
 action store_epoch(){m.epoch_diff=write_epoch.execute(1w0);}
 table epoch_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.work_op:ternary;}actions={load_epoch;diff_epoch;store_epoch;}size=3;
 const entries={(8w1,8w1,32w1,8w2):store_epoch();(8w0,_,_,_):load_epoch();}const default_action=diff_epoch();}
'''+text[stop:]
    # Owner CAS returns observed-minus-expected (still compare-and-swap on equality).
    text=once(text,'(owner) compare_owner={void apply(inout bit<32> v,out bit<32> r){r=v;if(v==m.expected){v=m.desired;}}};',
        '(owner) compare_owner={void apply(inout bit<32> v,out bit<32> r){r=v-m.expected;if(v==m.expected){v=m.desired;}}};')
    text=once(text,'action owner_cas(){m.observed=compare_owner.execute(1w0);}','action owner_cas(){m.owner_diff=compare_owner.execute(1w0);}')
    # Native SELECT/response/OPERATE owner commands for the claim and publication passes.
    marker=text.index(' table owner_command{');end=text.index(' action owner_read()',marker)
    command=text[marker:end].replace('close_free;NoAction;', 'close_free;claim_select;publish_select;claim_response;publish_response;claim_operate;publish_operate;NoAction;').replace('size=10;', 'size=16;')
    at=command.rindex('}}')
    command=command[:at]+''.join(f'(8w{s},8w{k},32w{s},32w0):{a}();' for s,k,a in
        ((1,5,'claim_select'),(2,5,'publish_select'),(1,6,'claim_response'),(2,6,'publish_response'),(1,7,'claim_operate'),(2,7,'publish_operate')))+command[at:]
    actions=''.join(f'action {name}(){{m.expected=hdr.expected_cell.expected_cell;m.desired=16w{phase}++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}}\n' for name,phase in
        (('claim_select',8),('publish_select',9),('claim_response',10),('publish_response',10),('claim_operate',11),('publish_operate',12)))
    text=text[:marker]+actions+command+text[end:]
    # first_event now also carries the transparent-forward rows and the kind-4 strip row.
    # Entry order is semantics: first_* rows, then forward_original rows, then close_forward.
    marker=text.index(' table first_event{');end=text.index('\n action next_stage',marker)
    first=text[marker:end].replace('m.kind:exact;m.sequence_valid:exact;', 'm.kind:ternary;m.sequence_valid:ternary;m.matched:ternary;')
    first=re.sub(r'\(8w(\d+),8w1,32w',r'(8w\1,8w1,8w0,32w',first)
    first=first.replace('first_close;NoAction;', 'first_close;first_select;first_response;first_operate;forward_original;close_forward;NoAction;')
    first=first.replace('size=9;', 'size=40;')
    at=first.rindex('}}')
    phases={1:(2,3),2:(3,4,5),3:(5,8,9,10,11,12)}
    forward=''.join('(8w%d,8w1,8w0,32w%s&&&32w0xffff0000):forward_original();'%(kind,hex(phase<<16)) for kind in (1,2,3) for phase in phases[kind])
    first=first[:at]+'''(8w5,8w1,8w0,32w0x40000&&&32w0xffff0000):first_select();(8w5,8w1,8w0,32w0x50000&&&32w0xffff0000):first_select();(8w6,8w1,8w1,32w0x90000&&&32w0xffff0000):first_response();(8w7,8w1,8w1,32w0xa0000&&&32w0xffff0000):first_operate();'''+''.join('(8w4,8w1,8w0,32w'+hex(phase<<16)+'&&&32w0xffff0000):first_close();' for phase in range(8,13))+forward+'(8w4,_,_,_):close_forward();'+first[at:]
    text=text[:marker]+'''action first_select(){hdr.event.event=16w0x0105;}
action first_response(){hdr.event.event=16w0x0106;}
action first_operate(){hdr.event.event=16w0x0107;}
 action forward_original(){hdr.event.event=16w0x0108;}
 action close_forward(){hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();m.emit_loop=8w0;tm.ucast_egress_port=m.output_port;}
'''+first+text[end:]
    # Valid retries and established ACKs: the claimed work travels the normal four
    # passes with no owner command, then the original leaves unchanged. Qualified by
    # exact owner phase and sequence; everything else keeps the abort/deny path.
    # Control flow is flat: header-only work and the owner stage are unconditional once
    # `guard` hits, so no table waits on the far side of an if/else join.
    mark=text.index(' apply{\n  m.work_op=');stop=text.index('control IgDeparser')
    text=text[:mark]+''' apply{
  m.work_op=8w0;m.owner_op=8w0;m.generation=32w0;m.expected=32w0;m.desired=32w0;m.go=8w0;m.owner_diff=32w1;m.expected_work_phase=(bit<32>)m.stage;
  ports.apply();network.apply();
  if(m.port_valid==8w1&&m.network_valid==8w1&&(m.stage==8w0||hdr.event.reserved==16w0)){
   connection.apply();
   if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){
    data_connection.apply();if(m.response==8w1){response_profile.apply();}else{profile.apply();}
    input_head_t.apply();if(m.response==8w1){response_crc0_t.apply();response_crc1_t.apply();response_crct_t.apply();}else{input_body_t.apply();input_tail_t.apply();}
    if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=8w1;}
    if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}
    if(m.response==8w1){if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=8w1;}if(hdr.response_tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}
    else{if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}
   }
   if(m.direction!=8w0){guard.apply();}
   if(m.go==8w1){
    if(m.packet_kind>=8w5){
     calculate_native_end_t.apply();if(m.response==8w1){compare_response_inputs_t.apply();}else{if(m.packet_kind==8w5){compare_select_inputs_t.apply();}else{compare_operate_inputs_t.apply();}}
    }
    if(m.packet_kind>=8w5){ack_native_t.apply();}
    work.apply(m.work_op,m.generation,m.expected_work_phase,m.work_phase);
    next_seq_t.apply();epoch_t.apply();client_t.apply();server_t.apply();
    if(m.packet_kind>=8w5){data_sequence_diff.apply();}else{sequence_diff.apply();}sequence_guard.apply();
    owner_command.apply();owner_t.apply();
    if(m.packet_kind>=8w5){
     real_links_t.apply();real_tcp_dst_t.apply();real_object_t.apply();real_off_t.apply();native_end_t.apply();application_t.apply();frozen_decoy_object_t.apply();frozen_decoy_off_t.apply();
    }
    if(m.stage==8w0){
     if(m.packet_kind==8w6||m.packet_kind==8w7){object_match.apply();}
     if((m.work_op==8w1&&m.work_phase==32w4)||(m.kind==8w4&&m.shape_valid==8w1)){
      snapshot_t.apply();first_event.apply();
     }
    }else if(m.kind==8w4){hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();if(m.owner_op!=8w1){deny();}}
    else if(m.work_phase==32w1||m.work_phase==32w2){
     if(m.kind!=8w8){if(m.owner_op==8w1&&m.owner_diff==32w0){carry_t.apply();}else{abort_t.apply();}}
     next_stage_t.apply();
    }else if(m.work_phase==32w3){hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();if(m.kind==8w255){deny();}}
    else{deny();}
   }
  }else if(m.stage!=8w0){deny();}
 }
}
'''+text[stop:]
    return text


if __name__=='__main__':
    # This is a frozen owned copy. Do not silently replace it with the older
    # generation-only parent helper or an independently changing source.
    import hashlib
    expected='26b2019ec6e549e22e98cf8361ee208952bd1cc94021d2ea56b9f8bc88571ef2'
    assert hashlib.sha256((HERE/'work_record.p4').read_bytes()).hexdigest()==expected
    (HERE/'native_binding.p4').write_text(generate())

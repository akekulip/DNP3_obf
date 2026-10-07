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
    text=text.replace('struct meta_t{','struct meta_t{'+added+'bit<8> data_valid;bit<32> ack_native;bit<32> expected_work_phase;')
    text=text.replace('WorkRecord() work;','ExpectedWorkRecord() work;')
    text=text.replace('work.apply(m.work_op,m.generation,m.work_phase);',
        'm.expected_work_phase=(bit<32>)m.stage;work.apply(m.work_op,m.generation,m.expected_work_phase,m.work_phase);')
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
    line=line.replace('default:accept;', ''.join(f'16w0x{s:02x}{k:02x}:eth;' for s in (1,2,3) for k in (5,6,7))+'default:accept;')
    text=text[:marker]+line+text[end:]
    network_start=text.index(' table network{');network_end=text.index('\n action syn_shape',network_start)
    network=text[network_start:network_end]
    network=network.replace('size=8;', 'size=16;').replace('size=9;', 'size=17;')
    at=network.rindex('}}')
    rows=''.join(f'(8w1,8w{k},8w{flags},false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();' for k in (5,6,7) for flags in (16,24))
    network=network[:at]+rows+network[at:]
    text=text[:network_start]+network+text[network_end:]
    # Reuse the actual selected22 native/response/profile/CRC source algorithms.
    start=selected.index(' action configure(');end=selected.index('WorkRecord() work;')
    validation=selected[start:end].replace('table connection{','table data_connection{')
    mark=text.index(' action mint()');text=text[:mark]+validation+text[mark:]
    text=text.replace('(8w4,8w2):NoAction();','(8w4,8w2):NoAction();(8w5,8w1):NoAction();(8w6,8w2):NoAction();(8w7,8w1):NoAction();').replace('size=5;const default_action=unsupported_direction()', 'size=8;const default_action=unsupported_direction()')
    # Saved object banks use the shared authority WorkRecord, not a second pin.
    bank_text=''
    for name in ('application','frozen_decoy_off','pair_real_links_real_tcp_src',
            'pair_real_tcp_dst_real_tcp_ports','pair_real_object_real_on',
            'pair_real_off_native_start','pair_native_end_server_start',
            'pair_frozen_decoy_object_frozen_decoy_on'):
        start=selected.index('Register<',selected.index('Register<') if name=='application' else 0)
        found=re.search(r'Register<[^\n]+>\([^\n]+\) '+name+r';\n',selected)
        start=found.start();end=selected.index('\n',selected.index('table ',start))+1
        bank_text+=selected[start:end]
    for name in ('compare_response_inputs','compare_operate_inputs','compare_select_inputs'):
        start=selected.index('action '+name+'(');end=selected.index('\n',selected.index('table '+name+'_t',start))+1
        bank_text+=selected[start:end]
    start=selected.index('table object_match{');end=selected.index('\n',start)
    match=selected[start:end].replace('match_response;match_operate;','matched;').replace(':match_response();',':matched();').replace(':match_operate();',':matched();')
    bank_text+='action matched(){m.matched=8w1;}\n'+match+'\n'
    bank_text+='''action binding_store(){m.cache_mode=8w1;}
action binding_op(){m.cache_mode=8w2;}
action binding_response(){m.cache_mode=8w3;}
table binding_access{key={m.stage:exact;m.kind:exact;m.work_phase:exact;m.epoch_diff:exact;}actions={binding_store;binding_op;binding_response;NoAction;}size=3;const entries={(8w1,8w5,32w1,32w0):binding_store();(8w0,8w6,32w4,32w0):binding_response();(8w0,8w7,32w4,32w0):binding_op();}const default_action=NoAction();}
action calculate_native_end(){m.native_end=hdr.tcp.seq+32w35;}
table calculate_native_end_t{actions={calculate_native_end;}size=1;const default_action=calculate_native_end();}
action data_ok(){m.data_valid=8w1;}
table data_guard{key={m.enabled:exact;m.profile:exact;m.badh:exact;m.badb:exact;m.bad1:exact;m.badt:exact;}actions={data_ok;NoAction;}size=1;const entries={(8w1,8w1,8w0,8w0,8w0,8w0):data_ok();}const default_action=NoAction();}
'''
    mark=text.index(' apply{\n  m.work_op=');text=text[:mark]+bank_text+text[mark:]
    mark=text.index(' apply{\n  m.work_op=')
    typed='action invalid_kind(){m.data_valid=8w0;}\ntable return_kind_guard{key={m.kind:exact;m.packet_kind:ternary;}actions={invalid_kind;NoAction;}size=8;const entries={'+''.join('(8w'+str(k)+',8w'+str(k)+'):NoAction();' for k in range(1,8))+'(8w255,_):NoAction();}const default_action=invalid_kind();}\n'
    text=text[:mark]+typed+text[mark:]
    # A failed/default profile never reaches WorkRecord or a saved bank.
    mark=text.index('   if(m.direction!=8w0){')
    before='''   if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){
    data_connection.apply();if(m.response==8w1){response_profile.apply();}else{profile.apply();}
    input_head_t.apply();if(m.response==8w1){response_crc0_t.apply();response_crc1_t.apply();response_crct_t.apply();}else{input_body_t.apply();input_tail_t.apply();}
    if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=8w1;}
    if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}
    if(m.response==8w1){if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=8w1;}if(hdr.response_tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}
    else{if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}
    data_guard.apply();
   }else{m.data_valid=8w1;}
'''
    text=text[:mark]+before+text[mark:]
    text=text.replace('if(m.direction!=8w0){','if(m.stage!=8w0){return_kind_guard.apply();}if(m.direction!=8w0&&m.data_valid==8w1){')
    # Both commits use actual validated payload sizes; no nominal timer inputs.
    text=text.replace('table next_seq_t{actions={next_seq;}',
        'action next_control(){m.new_seq=hdr.tcp.seq+32w35;}\n action next_response(){m.new_seq=hdr.tcp.seq+32w57;}\n table next_seq_t{key={m.packet_kind:exact;}actions={next_seq;next_control;next_response;}')
    text=text.replace('size=1;const default_action=next_seq();}',
        'size=3;const entries={8w5:next_control();8w7:next_control();8w6:next_response();}const default_action=next_seq();}')
    for bank,kinds in (('client',(5,7)),('server',(6,))):
        begin=text.index(' table '+bank+'_t{');stop=text.index('\n',text.index(' const entries=',begin))
        bank_table=text[begin:stop]
        where=bank_table.index('}const default_action=')
        bank_table=bank_table[:where]+''.join('(8w1,8w'+str(k)+',32w1,8w2):store_'+bank+'();' for k in kinds)+bank_table[where:]
        bank_table=bank_table.replace('size=1;', 'size='+str(1+len(kinds))+';')
        text=text[:begin]+bank_table+text[stop:]
    # SELECT/response TCP sequence positions are updated by actual packet bytes.
    text=text.replace('m.new_seq=hdr.tcp.seq+32w1;', 'm.new_seq=hdr.tcp.seq+32w1;')
    text=text.replace('table sequence_diff{','action ack_native(){m.ack_native=hdr.tcp.ack-32w20;}\n table ack_native_t{actions={ack_native;}size=1;const default_action=ack_native();}\n action diff_response(){m.client_diff=m.ack_native-m.client;m.server_diff=hdr.tcp.seq-m.server;}\n table data_sequence_diff{key={m.packet_kind:exact;}actions={diff_forward;diff_response;NoAction;}size=3;const entries={8w5:diff_forward();8w6:diff_response();8w7:diff_forward();}const default_action=NoAction();}\n table sequence_diff{')
    text=text.replace('if(m.stage==8w0){sequence_diff.apply();sequence_guard.apply();}', 'if(m.stage==8w0){if(m.packet_kind>=8w5){ack_native_t.apply();data_sequence_diff.apply();}else{sequence_diff.apply();}sequence_guard.apply();}')
    marker=text.index(' table first_event{');end=text.index('\n action next_stage',marker)
    first=text[marker:end].replace('m.kind:exact;m.sequence_valid:exact;', 'm.kind:exact;m.sequence_valid:exact;m.matched:exact;')
    first=re.sub(r'\(8w(\d+),8w1,32w',r'(8w\1,8w1,8w0,32w',first)
    first=first.replace('first_close;NoAction;', 'first_close;first_select;first_response;first_operate;NoAction;')
    first=first.replace('size=9;', 'size=18;')
    at=first.rindex('}}')
    first=first[:at]+'''(8w5,8w1,8w0,32w0x40000&&&32w0xffff0000):first_select();(8w5,8w1,8w0,32w0x50000&&&32w0xffff0000):first_select();(8w6,8w1,8w1,32w0x90000&&&32w0xffff0000):first_response();(8w7,8w1,8w1,32w0xa0000&&&32w0xffff0000):first_operate();'''+''.join('(8w4,8w1,8w0,32w'+hex(phase<<16)+'&&&32w0xffff0000):first_close();' for phase in range(8,13))+first[at:]
    text=text[:marker]+'''action first_select(){hdr.event.event=16w0x0105;}
action first_response(){hdr.event.event=16w0x0106;}
action first_operate(){hdr.event.event=16w0x0107;}
'''+first+text[end:]
    marker=text.index(' table owner_command{');end=text.index(' action owner_read()',marker)
    command=text[marker:end].replace('close_free;NoAction;', 'close_free;claim_select;publish_select;claim_response;publish_response;claim_operate;publish_operate;NoAction;').replace('size=10;', 'size=16;')
    at=command.rindex('}}')
    command=command[:at]+''.join(f'(8w{s},8w{k},32w{s},32w0):{a}();' for s,k,a in
        ((1,5,'claim_select'),(2,5,'publish_select'),(1,6,'claim_response'),(2,6,'publish_response'),(1,7,'claim_operate'),(2,7,'publish_operate')))+command[at:]
    actions=''.join(f'action {name}(){{m.expected=hdr.expected_cell.expected_cell;m.desired=16w{phase}++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}}\n' for name,phase in
        (('claim_select',8),('publish_select',9),('claim_response',10),('publish_response',10),('claim_operate',11),('publish_operate',12)))
    text=text[:marker]+actions+command+text[end:]
    # Raw frames compare stored context; protected first return writes SELECT.
    old='    owner_t.apply();'
    work='''    if(m.packet_kind>=8w5){
     calculate_native_end_t.apply();if(m.response==8w1){compare_response_inputs_t.apply();}else{if(m.packet_kind==8w5){compare_select_inputs_t.apply();}else{compare_operate_inputs_t.apply();}}
     if(m.stage==8w0){m.epoch_diff=32w0;}
     binding_access.apply();real_links_t.apply();real_tcp_dst_t.apply();real_object_t.apply();real_off_t.apply();native_end_t.apply();application_t.apply();frozen_decoy_object_t.apply();frozen_decoy_off_t.apply();
     if(m.stage==8w0&&(m.packet_kind==8w6||m.packet_kind==8w7)){object_match.apply();}
    }
'''
    text=text.replace(old,work+old)
    return text


if __name__=='__main__':
    # This is a frozen owned copy. Do not silently replace it with the older
    # generation-only parent helper or an independently changing source.
    import hashlib
    expected='26b2019ec6e549e22e98cf8361ee208952bd1cc94021d2ea56b9f8bc88571ef2'
    assert hashlib.sha256((HERE/'work_record.p4').read_bytes()).hexdigest()==expected
    (HERE/'native_binding.p4').write_text(generate())

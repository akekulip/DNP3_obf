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
    # READ (kinds 9..11): the 20-byte request body, the 3-byte response tail, and the private
    # 4-byte pass-0 timestamp that rides with the envelope until the terminal builds the `tev`.
    extras+='header read_req_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}\n'
    extras+='header read_tail_h{bit<8> value;bit<16> crc;}\nheader t0_h{bit<32> t0q;}\nheader replay_h{bit<8> value;}\n'
    text=text.replace('header eth_h{',extras+'header eth_h{')
    text=once(text,'event_h event;eth_h eth;','event_h event;t0_h t0;eth_h eth;')
    text=text.replace('mss_h mss;}', 'mss_h mss;dl_h dl;block_h first;block_h second;tail_h tail;response_tail_h response_tail;read_req_h rd_req;read_tail_h rd_tail;replay_h rb;}')
    # N-to-T and N-to-M handoff egress, device ports (pipe*128+local) from the model
    # cross-pipe probe (evidence/model_28/PORTS_PROPOSAL.md, gate G-PORTS still required
    # on the switch): T_IN is pipe 2 local 69 = 325; M's N-facing port is pipe 1 local 68 = 196.
    text=once(text,'const PortId_t RETURN_PORT=9w68;','const PortId_t RETURN_PORT=9w68;\nconst PortId_t READ_HANDOFF_PORT=9w325;\nconst PortId_t STEP3_M_PORT=9w196;')
    existing={name for kind,name in re.findall(r'(bit<\d+>|bool|PortId_t) (\w+);',braced(text,'struct meta_t'))}
    added=''.join(kind+' '+name+';' for kind,name in re.findall(r'(bit<\d+>|bool|PortId_t) (\w+);',braced(selected,'struct meta_t')) if name not in existing)
    text=text.replace('struct meta_t{','struct meta_t{'+added+'bit<8> data_valid;bit<32> ack_native;bit<32> expected_work_phase;bit<8> go;bit<16> link_dst;bit<16> link_src;bit<32> compare_read_app;')
    text=text.replace('WorkRecord() work;','ExpectedWorkRecord() work;')
    text=text.replace('MSS-only TCP: final ACK+SELECT still REQUIRED and blocked in this P4.',
        'Actual native35 final ACK+SELECT admitted; composed transformation remains blocked.')
    text=text.replace('m.parsed=8w0;', 'm.parsed=8w0;m.enabled=8w0;m.profile=8w0;m.response=8w0;m.matched=8w0;m.data_valid=8w0;m.cache_mode=8w0;m.badh=8w0;m.badb=8w0;m.bad1=8w0;m.badt=8w0;')
    # Role paths avoid retaining IP-length PMRs across later TCP selectors.
    text=text.replace('(4w4,4w5,8w6,16w44):ip_flags;', '(4w4,4w5,8w6,16w44):ip_flags;(4w4,4w5,8w6,16w75):native_ip_flags;(4w4,4w5,8w6,16w97):response_ip_flags;(4w4,4w5,8w6,16w60):read_ip_flags;(4w4,4w5,8w6,16w89):read_response_ip_flags;(4w4,4w5,8w6,16w41):replay_ip_flags;')
    mark=text.index(' state finish{')
    states=''
    for role,next_state in (('native','native_block'),('response','response_block')):
        states+=f''' state {role}_ip_flags{{transition select(hdr.ip.frag,hdr.ip.flags){{(13w0,3w0):{role}_tcp;(13w0,3w2):{role}_tcp;default:accept;}}}}
 state {role}_tcp{{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){{(4w5,4w0,16w0,8w16):{role}_dl;(4w5,4w0,16w0,8w24):{role}_dl;default:accept;}}}}
 state {role}_dl{{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition {next_state};}}
'''
    for role,next_state in (('read','read_request'),('read_response','read_response_block')):
        states+=f''' state {role}_ip_flags{{transition select(hdr.ip.frag,hdr.ip.flags){{(13w0,3w0):{role}_tcp;(13w0,3w2):{role}_tcp;default:accept;}}}}
 state {role}_tcp{{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){{(4w5,4w0,16w0,8w16):{role}_dl;(4w5,4w0,16w0,8w24):{role}_dl;default:accept;}}}}
 state {role}_dl{{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition {next_state};}}
'''
    states+=''' state replay_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):replay_tcp;(13w0,3w2):replay_tcp;default:accept;}}
 state replay_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.urgent,hdr.tcp.flags){(4w5,4w0,16w0,8w16):replay_byte;default:accept;}}
 state replay_byte{pkt.extract(hdr.rb);tc.subtract(hdr.rb);m.packet_kind=8w12;transition finish;}
'''
    states+=''' state read_request{pkt.extract(hdr.rd_req);tc.subtract(hdr.rd_req);m.packet_kind=8w9;transition finish;}
 state read_response_block{pkt.extract(hdr.first);tc.subtract(hdr.first);transition read_response_second;}
 state read_response_second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition read_response_tail;}
 state read_response_tail{pkt.extract(hdr.rd_tail);tc.subtract(hdr.rd_tail);m.packet_kind=8w11;transition finish;}
 state read_t0{pkt.extract(hdr.t0);transition eth;}
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
    line=line.replace('default:accept;', ''.join(f'16w0x{s:02x}{k:02x}:eth;' for s in (1,2,3) for k in (5,6,7,8))+''.join(f'16w0x{s:02x}{k:02x}:read_t0;' for s in (1,2,3) for k in (9,10,11))+''.join(f'16w0x{s:02x}{k:02x}:eth;' for s in (1,2,3) for k in (0x10,0x0c))+'default:accept;')
    text=text[:marker]+line+text[end:]
    network_start=text.index(' table network{');network_end=text.index('\n action syn_shape',network_start)
    network=text[network_start:network_end]
    network=network.replace('size=8;', 'size=32;').replace('size=9;', 'size=33;')
    at=network.rindex('}}')
    rows=''.join(f'(8w1,8w{k},8w{flags},false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();' for k in (5,6,7) for flags in (16,24))
    # The private forwarding pass (kind 8) re-enters on the original SYN, SYNACK or ACK flags.
    rows+=''.join(f'(8w1,8w8,8w{flags},false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();' for flags in (2,18,16))
    # READ private passes: request and response ride TCP flags 16 or 24, the server ACK flags 16.
    rows+=''.join(f'(8w1,8w{k},8w{flags},false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();' for k,fl in ((9,(16,24)),(10,(16,)),(11,(16,24)),(16,(16,24)),(12,(16,))) for flags in fl)
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
        if re.match(r'table (native_end_t|real_off_t|application_t)\{',table):
            # The OPERATE re-stores these banks so the response to it (ex 2, acknowledged native + 40)
            # compares against its own positions and application sequence.
            table=re.sub(r'\(8w1,8w5,32w1,32w0\):(store_\w+\(\));',r'(8w1,8w5,32w1,32w0):\1;(8w1,8w7,32w1,32w0):\1;',table).replace('size=3;','size=4;')
        table=re.sub(r'8w2:(compare_\w+\(\));',r'(8w0,8w7,32w4,_):\1;',table)
        return re.sub(r'8w3:(compare_\w+\(\));',r'(8w0,8w6,32w4,_):\1;',table)
    bank_text,banks=re.subn(r'table \w+_t\{key=\{m\.cache_mode:exact;\}[^\n]*',bank_keys,bank_text)
    assert banks==8,banks
    for name in ('compare_response_inputs','compare_operate_inputs','compare_select_inputs'):
        start=selected.index('action '+name+'(');end=selected.index('\n',selected.index('table '+name+'_t',start))+1
        bank_text+=selected[start:end]
    # Stored positions include the acknowledged insertion: after SELECT native + 20, after OPERATE native + 40,
    # so a response compares ack directly in either exchange and no offset is hard-coded in the compare.
    bank_text=once(bank_text,'m.compare_native_end=(bit<32>)(hdr.tcp.ack-32w20);','m.compare_native_end=(bit<32>)(hdr.tcp.ack);')
    bank_text=once(bank_text,'m.compare_native_end=(bit<32>)(hdr.tcp.seq);','m.compare_native_end=(bit<32>)(hdr.tcp.seq+32w20);')
    operate=re.search(r'action compare_operate_inputs\(\)\{[^\n]*\n',bank_text)[0]
    store_inputs=operate.replace('compare_operate_inputs','compare_operate_store_inputs').replace('hdr.tcp.seq-32w35','hdr.tcp.seq+32w20').replace('(hdr.tcp.seq+32w20);m.compare_server_start','(hdr.tcp.seq+32w75);m.compare_server_start').replace('hdr.tcp.ack-32w57','hdr.tcp.ack')
    assert store_inputs.count('32w75')==1 and store_inputs.count('32w20')==1,store_inputs
    bank_text=once(bank_text,'table compare_operate_inputs_t{actions={compare_operate_inputs;}size=1;const default_action=compare_operate_inputs();}',
        store_inputs.rstrip('\n')+'\ntable compare_operate_inputs_t{key={m.stage:exact;}actions={compare_operate_inputs;compare_operate_store_inputs;}size=2;const entries={8w1:compare_operate_store_inputs();}const default_action=compare_operate_inputs();}')
    start=selected.index('table object_match{');end=selected.index('\n',start)
    match=selected[start:end].replace('match_response;match_operate;','matched;').replace(':match_response();',':matched();').replace(':match_operate();',':matched();')
    bank_text+='action matched(){m.matched=8w1;}\n'+match+'\n'
    bank_text+='''action calculate_native_end(){m.native_end=hdr.tcp.seq+32w55;}
table calculate_native_end_t{actions={calculate_native_end;}size=1;const default_action=calculate_native_end();}
'''
    # Native READ (kinds 9..11), validated like the frozen validator.p4 observer: tuple and link
    # addresses from the controller, the exact profile, and every DNP3 CRC. The application
    # sequence of the request is stored and the response is matched against it, in one register
    # that is separate from the SELECT/OPERATE banks, which READ never touches.
    bank_text+='''action read_configure(bit<16> dst,bit<16> src){m.enabled=8w1;m.link_dst=dst;m.link_src=src;}
table read_connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={read_configure;NoAction;}size=2;default_action=NoAction();}
table read_request_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req.tp:ternary;hdr.rd_req.app:ternary;hdr.rd_req.func:exact;hdr.rd_req.group:exact;hdr.rd_req.variation:exact;hdr.rd_req.qualifier:exact;hdr.rd_req.first:exact;hdr.rd_req.last:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();}}
table read_response_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:8]:exact;hdr.first.w1[23:16]:exact;hdr.first.w1[15:8]:exact;hdr.first.w1[7:0]:exact;hdr.first.w2[31:24]:exact;hdr.first.w2[23:16]:exact;}
 actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):eligible();}}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_head;
action rd_head_crc(){m.hcrc=hash_rd_head.get({hdr.dl.magic,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
table rd_head_t{actions={rd_head_crc;}size=1;const default_action=rd_head_crc();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_first;
action rd_first_crc(){m.bcrc=hash_rd_first.get({hdr.first.w0,hdr.first.w1,hdr.first.w2,hdr.first.w3});}
table rd_first_crc_t{actions={rd_first_crc;}size=1;const default_action=rd_first_crc();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_second;
action rd_second_crc(){m.crc1=hash_rd_second.get({hdr.second.w0,hdr.second.w1,hdr.second.w2,hdr.second.w3});}
table rd_second_crc_t{actions={rd_second_crc;}size=1;const default_action=rd_second_crc();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_request;
action rd_request_crc(){m.bcrc=hash_rd_request.get({hdr.rd_req.tp,hdr.rd_req.app,hdr.rd_req.func,hdr.rd_req.group,hdr.rd_req.variation,hdr.rd_req.qualifier,hdr.rd_req.first,hdr.rd_req.last});}
table rd_request_crc_t{actions={rd_request_crc;}size=1;const default_action=rd_request_crc();}
Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_tail;
action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value});}
table rd_tail_crc_t{actions={rd_tail_crc;}size=1;const default_action=rd_tail_crc();}
action read_request_input(){m.compare_read_app=(bit<32>)(hdr.rd_req.app[3:0]);}
action read_response_input(){m.compare_read_app=(bit<32>)(hdr.first.w0[19:16]);}
table read_input_t{key={m.packet_kind:exact;}actions={read_request_input;read_response_input;NoAction;}size=2;const entries={8w9:read_request_input();8w11:read_response_input();}const default_action=NoAction();}
Register<bit<32>,bit<1>>(1,0) read_app;
RegisterAction<bit<32>,bit<1>,bit<32>>(read_app) write_read_app={void apply(inout bit<32> v,out bit<32> r){v=m.compare_read_app;r=v;}};
RegisterAction<bit<32>,bit<1>,bit<8>>(read_app) check_read_app={void apply(inout bit<32> v,out bit<8> r){r=8w0;if(v==m.compare_read_app){r=8w1;}}};
action store_read_app(){write_read_app.execute(1w0);}
action match_read_app(){m.matched=check_read_app.execute(1w0);}
table read_app_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_read_app;match_read_app;NoAction;}size=2;const entries={(8w1,8w9,32w1,32w0):store_read_app();(8w0,8w11,32w4,_):match_read_app();}const default_action=NoAction();}
action emit_tev(bit<16> event){hdr.expected_cell.expected_cell=hdr.t0.t0q;hdr.event.event=event;hdr.t0.setInvalid();tm.ucast_egress_port=READ_HANDOFF_PORT;m.emit_loop=8w0;}
action terminal_strip(){hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();}
action terminal_abort(){hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();md.drop_ctl=3w1;}
action emit_replay(){tm.ucast_egress_port=STEP3_M_PORT;m.emit_loop=8w0;count_term_bump.execute(4w0);}
table read_terminal_t{key={m.kind:exact;}actions={emit_tev;emit_replay;terminal_strip;terminal_abort;}size=5;const entries={8w9:emit_tev(16w0x0900);8w10:emit_tev(16w0x0a00);8w11:emit_tev(16w0x0b00);8w12:emit_replay();8w255:terminal_abort();}const default_action=terminal_strip();}
'''
    # Exposed counters (read by the controller; a WorkRecord reset does not clear them). A register belongs to
    # one table, so there is one array per counting table: count_first (first_event), count_busy (busy_t),
    # count_term (read_terminal_t).
    bank_text+='''action busy_drop(){md.drop_ctl=3w1;count_busy_bump.execute(4w0);}
action busy_pass(){count_busy_bump.execute(4w1);}
table busy_t{key={m.kind:exact;}actions={busy_drop;busy_pass;}size=6;const entries={8w5:busy_drop();8w6:busy_drop();8w7:busy_drop();8w9:busy_drop();8w11:busy_drop();8w12:busy_drop();}const default_action=busy_pass();}
'''
    text=once(text,' action deny(){md.drop_ctl=3w1;}',''' Register<bit<32>,bit<4>>(4,0) count_first;
RegisterAction<bit<32>,bit<4>,bit<32>>(count_first) count_first_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};
Register<bit<32>,bit<4>>(4,0) count_busy;
RegisterAction<bit<32>,bit<4>,bit<32>>(count_busy) count_busy_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};
Register<bit<32>,bit<4>>(4,0) count_term;
RegisterAction<bit<32>,bit<4>,bit<32>>(count_term) count_term_bump={void apply(inout bit<32> v,out bit<32> r){if((int<32>)v!=-1){v=v+32w1;}r=v;}};
 action deny(){md.drop_ctl=3w1;}''')
    # One ternary guard replaces data_guard, return_kind_guard, direction_guard and mint_t.
    # A hit is the old condition `direction!=0 && data_valid==1` (after return_kind_guard at
    # stage!=0 and direction_guard/shape at stage 0), and the action also does the old
    # mint (stage 0) or the old return-pass work_op/generation assignment. A miss skips the
    # counter and everything below it, as the old condition did.
    good='8w1,8w1,8w0,8w0,8w0,8w0'   # enabled, profile, badh, badb, bad1, badt
    wild='_,_,_,_,_,_'
    rows=[]
    # A return pass whose flow lookup missed (direction 0: the flow entry was removed mid-flight) is
    # released as an abort so the work pin goes back through the normal passes. Stage-0 rows all need a
    # nonzero direction, so ordinary foreign traffic still misses and is forwarded untouched.
    rows+=['(8w%d,_,_,8w0,_,%s):go_ret_abort();'%(stage,wild) for stage in (1,2,3)]
    validated=(5,6,7,9,11)   # packet kinds whose frame passed profile and CRC validation
    # (packet kind, direction, event kind). Kind 10 is a server pure ACK (packet kind 3).
    for pk,direction,kind in ((1,1,1),(2,2,2),(3,1,3),(4,1,4),(4,2,4),(5,1,5),(6,2,6),(7,1,7),(9,1,9),(11,2,11),(3,2,10),(12,1,12)):
        rows.append('(8w0,8w%d,8w0,8w%d,8w1,%s):%s;'%(pk,direction,good if pk in validated else wild,'go_keep(8w4)' if pk==4 else 'go_new(8w%d)'%kind))
    for kind,pk in [(k,k) for k in range(1,8)]+[(8,1),(8,2),(8,3),(9,9),(10,3),(11,11),(16,6),(12,12)]:
        rows.append('(_,8w%d,8w%d,_,_,%s):%s;'%(pk,kind,good if pk in validated else wild,'go_ret_nowork()' if kind==4 else 'go_ret_work()'))
    # Kind 255 (abort) passes carry no validation: they only return the work pin and deny.
    rows.append('(_,_,8w255,_,_,%s):go_ret_work();'%wild)
    # A return pass nothing above admits (profile or flow entry removed mid-flight, a relabelled
    # event, a bad flag): it is aborted as kind 255 but still returns its work pin, so the packet
    # is denied at the terminal and never leaves with a private envelope.
    rows+=['(8w%d,_,_,_,_,%s):go_ret_abort();'%(stage,wild) for stage in (1,2,3)]
    guard='''action go_new(bit<8> k){m.go=8w1;m.kind=k;m.generation=allocate.execute(1w0);m.work_op=8w1;}
action go_keep(bit<8> k){m.go=8w1;m.kind=k;}
action go_ret_work(){m.go=8w1;m.generation=hdr.work_generation.generation;m.work_op=8w2;}
action go_ret_nowork(){m.go=8w1;m.generation=hdr.work_generation.generation;}
action go_ret_abort(){m.go=8w1;m.kind=8w255;m.generation=hdr.work_generation.generation;m.work_op=8w2;hdr.event.event[7:0]=8w255;hdr.t0.setInvalid();}
table guard{key={m.stage:ternary;m.packet_kind:ternary;m.kind:ternary;m.direction:ternary;m.shape_valid:ternary;m.enabled:ternary;m.profile:ternary;m.badh:ternary;m.badb:ternary;m.bad1:ternary;m.badt:ternary;}
actions={go_new;go_keep;go_ret_work;go_ret_nowork;go_ret_abort;NoAction;}size=48;const default_action=NoAction();const entries={'''+''.join(rows)+'}}\n'
    mark=text.index(' apply{\n  m.work_op=');text=text[:mark]+bank_text+guard+text[mark:]
    # Both commits use actual validated payload sizes; no nominal timer inputs.
    text=once(text,'table next_seq_t{actions={next_seq;}',
        'action next_control(){m.new_seq=hdr.tcp.seq+32w35;}\n action next_response(){m.new_seq=hdr.tcp.seq+32w57;}\n action next_read_request(){m.new_seq=hdr.tcp.seq+32w20;}\n action next_read_response(){m.new_seq=hdr.tcp.seq+32w49;}\n table next_seq_t{key={m.packet_kind:exact;}actions={next_seq;next_control;next_response;next_read_request;next_read_response;}')
    text=once(text,'size=1;const default_action=next_seq();}',
        'size=5;const entries={8w5:next_control();8w7:next_control();8w6:next_response();8w9:next_read_request();8w11:next_read_response();}const default_action=next_seq();}')
    for bank,kinds in (('client',(5,7,9)),('server',(6,11,16))):
        begin=text.index(' table '+bank+'_t{');stop=text.index('\n',text.index(' const entries=',begin))
        bank_table=text[begin:stop]
        where=bank_table.index('}const default_action=')
        bank_table=bank_table[:where]+''.join('(8w1,8w'+str(k)+',32w1,8w2):store_'+bank+'();' for k in kinds)+bank_table[where:]
        bank_table=bank_table.replace('size=1;', 'size='+str(1+len(kinds))+';')
        text=text[:begin]+bank_table+text[stop:]
    # A response acknowledges native + 20 after SELECT and native + 40 after OPERATE (the client bank then
    # already holds the OPERATE end), which is a client difference of 0 or 20 once 20 is taken off the ack.
    # sequence_valid 1 is the first exchange; 2 only the second (first_event pairs it with owner phase 12).
    text=once(text,'actions={seq_ok;NoAction;}size=1;const entries={(32w0,32w0):seq_ok();}','actions={seq_ok;seq_ok_second;seq_resent;seq_replay;NoAction;}size=4;const entries={(32w0,32w0):seq_ok();(32w20,32w0):seq_ok_second();(32w0xffffffdd,32w0):seq_resent();(32w0xffffffff,32w0):seq_replay();}')
    text=once(text,' action seq_ok(){m.sequence_valid=8w1;}',' action seq_ok(){m.sequence_valid=8w1;}\n action seq_ok_second(){m.sequence_valid=8w2;}\n action seq_resent(){m.sequence_valid=8w3;}\n action seq_replay(){m.sequence_valid=8w4;}')
    # One ternary sequence table: data frames are selected by packet kind (no `>=5` ordering,
    # so the READ kinds 9 and 11 are never mistaken for SELECT/OPERATE), everything else by
    # direction and flags exactly as before. First match wins.
    begin=text.index(' table sequence_diff{');stop=text.index('\n',text.index(' const entries=',begin))
    old_rows=re.findall(r'\((8w\d+),(8w\d+)\):(\w+\(\));',text[begin:stop])
    assert len(old_rows)==9 and text[begin:stop].endswith('}}'),old_rows
    data_rows=((5,'diff_forward'),(6,'diff_response'),(7,'diff_forward'),(9,'diff_forward'),(11,'diff_read_response'))
    rows=''.join('(8w%d,_,_):%s();'%r for r in data_rows)+''.join('(_,%s,%s):%s;'%r for r in old_rows)+'(8w3,8w2,8w16):diff_reverse();'
    text=text[:begin]+''' action ack_native(){m.ack_native=hdr.tcp.ack-32w20;}
 table ack_native_t{actions={ack_native;}size=1;const default_action=ack_native();}
 action diff_response(){m.client_diff=m.ack_native-m.client;m.server_diff=hdr.tcp.seq-m.server;}
 action diff_read_response(){m.client_diff=hdr.tcp.ack-m.client;m.server_diff=hdr.tcp.seq-m.server;}
 table sequence_diff{key={m.packet_kind:ternary;m.direction:ternary;hdr.tcp.flags:ternary;}
 actions={diff_syn;diff_synack;diff_forward;diff_reverse;diff_reset_forward;diff_reset_reverse;diff_response;diff_read_response;NoAction;}size=20;const default_action=NoAction();
 const entries={'''+rows+'}}'+text[stop:]
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
    # H1: the epoch register powers on at 0, which the envelope parser treats as "no envelope". A
    # snapshot must never carry 0, so snapshot_t has a second action, chosen by the epoch itself in the
    # same table (no extra stage), that writes a nonzero sentinel instead.
    snap=re.search(r' action snapshot\(\)\{[^\n]*\n table snapshot_t\{[^\n]*\n',text)
    assert snap and text.count(' action snapshot()')==1
    action=re.search(r' action snapshot\(\)\{[^\n]*\}',snap[0])[0]
    zero=action.replace('action snapshot()','action snapshot_epoch_zero()').replace('hdr.envelope.epoch=m.epoch;','hdr.envelope.epoch=32w0xffffffff;')
    assert zero!=action.replace('snapshot()','snapshot_epoch_zero()')
    table=' table snapshot_t{key={m.epoch:exact;}actions={snapshot;snapshot_epoch_zero;}size=1;const entries={32w0:snapshot_epoch_zero();}const default_action=snapshot();}\n'
    text=text.replace(snap[0],action+'\n'+zero+'\n'+table)
    text=once(text,'hdr.work_generation.generation=m.epoch;}','hdr.work_generation.generation=hdr.envelope.epoch;}')   # nonzero even at power-on
    # An abort drops the READ timestamp word with the kind, so the next pass parses a plain kind-255 envelope.
    text=once(text,'action abort_work(){hdr.event.event[7:0]=8w255;}','action abort_work(){hdr.event.event[7:0]=8w255;hdr.t0.setInvalid();}')
    text=once(text,'action owner_cas(){m.observed=compare_owner.execute(1w0);}','action owner_cas(){m.owner_diff=compare_owner.execute(1w0);}')
    # Native SELECT/response/OPERATE owner commands for the claim and publication passes.
    marker=text.index(' table owner_command{');end=text.index(' action owner_read()',marker)
    command=text[marker:end].replace('close_free;NoAction;', 'close_free;claim_select;publish_select;claim_response;publish_response;claim_operate;publish_operate;claim_read;publish_read;claim_read_rsp;publish_read_rsp;claim_response_op;publish_response_op;NoAction;').replace('size=10;', 'size=22;')
    at=command.rindex('}}')
    command=command[:at]+''.join(f'(8w{s},8w{k},32w{s},32w0):{a}();' for s,k,a in
        ((1,5,'claim_select'),(2,5,'publish_select'),(1,6,'claim_response'),(2,6,'publish_response'),(1,7,'claim_operate'),(2,7,'publish_operate'),(1,9,'claim_read'),(2,9,'publish_read'),(1,11,'claim_read_rsp'),(2,11,'publish_read_rsp'),(1,16,'claim_response_op'),(2,16,'publish_response_op')))+command[at:]
    actions=''.join(f'action {name}(){{m.expected=hdr.expected_cell.expected_cell;m.desired=16w{phase}++hdr.expected_cell.expected_cell[15:0];m.owner_op=8w1;}}\n' for name,phase in
        (('claim_select',8),('publish_select',9),('claim_response',10),('publish_response',10),('claim_operate',11),('publish_operate',12),
        ('claim_read',13),('publish_read',14),('claim_read_rsp',15),('publish_read_rsp',5),('claim_response_op',16),('publish_response_op',5)))
    text=text[:marker]+actions+command+text[end:]
    # first_event now also carries the transparent-forward rows and the kind-4 strip row.
    # Entry order is semantics: first_* rows, then forward_original rows, then close_forward.
    marker=text.index(' table first_event{');end=text.index('\n action next_stage',marker)
    first=text[marker:end].replace('m.kind:exact;m.sequence_valid:exact;', 'm.kind:ternary;m.sequence_valid:ternary;m.matched:ternary;')
    first=re.sub(r'\(8w(\d+),8w1,32w',r'(8w\1,8w1,8w0,32w',first)
    first=first.replace('first_close;NoAction;', 'first_close;first_select;first_response;first_operate;first_read_request;first_read_ack;first_read_response;first_response_op;first_replay;count_refused;count_resent;count_replay_refused;forward_original;close_forward;NoAction;')
    first=first.replace('size=9;', 'size=64;')
    at=first.rindex('}}')
    phases={1:(2,3),2:(3,4,5),3:(5,8,9,10,11,12)}
    # READ: a request needs the idle owner (phase 5), a response the outstanding owner (phase 14)
    # and the stored application sequence (matched), an ACK the outstanding owner. An ACK that
    # does not qualify is not a READ ACK: it is forwarded unchanged as a kind-8 original.
    READ_FIRST=('(8w9,8w1,8w0,32w0x50000&&&32w0xffff0000):first_read_request();(8w11,8w1,8w1,32w0xe0000&&&32w0xffff0000):first_read_response();'
        '(8w10,8w1,8w0,32w0xe0000&&&32w0xffff0000):first_read_ack();(8w10,_,_,_):forward_original();'
        # the response to OPERATE: owner phase 12, second-exchange sequence, banks re-stored by the OPERATE
        '(8w6,8w2,8w1,32w0xc0000&&&32w0xffff0000):first_response_op();'
        # whole-segment resend (client position minus 35), the one-byte replay and every other refusal are
        # counted; none of them changes the event, so the packet is aborted and dropped as before.
        '(8w12,8w4,8w0,32w0x90000&&&32w0xffff0000):first_replay();(8w12,8w4,8w0,32w0xc0000&&&32w0xffff0000):first_replay();(8w12,_,_,_):count_replay_refused();'
        '(8w5,8w3,_,_):count_resent();(8w7,8w3,_,_):count_resent();'
        '(8w5,_,_,_):count_refused();(8w6,_,_,_):count_refused();(8w7,_,_,_):count_refused();(8w9,_,_,_):count_refused();(8w11,_,_,_):count_refused();')
    forward=''.join('(8w%d,8w1,8w0,32w%s&&&32w0xffff0000):forward_original();'%(kind,hex(phase<<16)) for kind in (1,2,3) for phase in phases[kind])
    first=first[:at]+'''(8w5,8w1,8w0,32w0x40000&&&32w0xffff0000):first_select();(8w5,8w1,8w0,32w0x50000&&&32w0xffff0000):first_select();(8w6,8w1,8w1,32w0x90000&&&32w0xffff0000):first_response();(8w7,8w1,8w1,32w0xa0000&&&32w0xffff0000):first_operate();'''+''.join('(8w4,8w1,8w0,32w'+hex(phase<<16)+'&&&32w0xffff0000):first_close();' for phase in range(8,13))+forward+'(8w4,_,_,_):close_forward();'+READ_FIRST+first[at:]
    text=text[:marker]+'''action first_select(){hdr.event.event=16w0x0105;}
action first_response(){hdr.event.event=16w0x0106;}
action first_operate(){hdr.event.event=16w0x0107;}
 action forward_original(){hdr.event.event=16w0x0108;}
 action first_response_op(){hdr.event.event=16w0x0110;}
 action first_replay(){hdr.event.event=16w0x010c;}
 action count_refused(){count_first_bump.execute(4w0);}
 action count_resent(){count_first_bump.execute(4w1);}
 action count_replay_refused(){count_first_bump.execute(4w2);}
 action first_read_request(){hdr.event.event=16w0x0109;hdr.t0.setValid();hdr.t0.t0q=p.global_tstamp[31:8]++8w0;}
 action first_read_ack(){hdr.event.event=16w0x010a;hdr.t0.setValid();hdr.t0.t0q=p.global_tstamp[31:8]++8w0;}
 action first_read_response(){hdr.event.event=16w0x010b;hdr.t0.setValid();hdr.t0.t0q=p.global_tstamp[31:8]++8w0;}
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
   }else if(m.packet_kind==8w9||m.packet_kind==8w11){
    read_connection.apply();rd_head_t.apply();
    if(m.packet_kind==8w9){read_request_profile.apply();rd_request_crc_t.apply();}else{read_response_profile.apply();rd_first_crc_t.apply();rd_second_crc_t.apply();rd_tail_crc_t.apply();}
    if(hdr.dl.dst!=m.link_dst||hdr.dl.src!=m.link_src){m.badh=8w1;}
    if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=8w1;}
    if(m.packet_kind==8w9){if(hdr.rd_req.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}}
    else{if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=8w1;}if(hdr.rd_tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}
   }
   guard.apply();
   if(m.go==8w1){
    if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){
     calculate_native_end_t.apply();if(m.response==8w1){compare_response_inputs_t.apply();}else{if(m.packet_kind==8w5){compare_select_inputs_t.apply();}else{compare_operate_inputs_t.apply();}}
    }
    ack_native_t.apply();read_input_t.apply();
    work.apply(m.work_op,m.generation,m.expected_work_phase,m.work_phase);
    next_seq_t.apply();epoch_t.apply();client_t.apply();server_t.apply();
    sequence_diff.apply();sequence_guard.apply();
    owner_command.apply();owner_t.apply();
    if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){
     real_links_t.apply();real_tcp_dst_t.apply();real_object_t.apply();real_off_t.apply();native_end_t.apply();application_t.apply();frozen_decoy_object_t.apply();frozen_decoy_off_t.apply();
    }
    read_app_t.apply();
    if(m.stage==8w0){
     if(m.packet_kind==8w6||m.packet_kind==8w7){object_match.apply();}
     if((m.work_op==8w1&&m.work_phase==32w4)||(m.kind==8w4&&m.shape_valid==8w1)){
      snapshot_t.apply();first_event.apply();
     }else if(m.work_op==8w1){busy_t.apply();}
    }else if(m.kind==8w4){hdr.envelope.setInvalid();hdr.work_generation.setInvalid();hdr.expected_cell.setInvalid();hdr.event.setInvalid();if(m.owner_op!=8w1){deny();}}
    else if(m.work_phase==32w1||m.work_phase==32w2){
     if(m.kind!=8w8&&m.kind!=8w10&&m.kind!=8w12){if(m.owner_op==8w1&&m.owner_diff==32w0){carry_t.apply();}else{abort_t.apply();}}
     next_stage_t.apply();
    }else if(m.work_phase==32w3){read_terminal_t.apply();}
    else{deny();}
   }else if(m.stage!=8w0){deny();}
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

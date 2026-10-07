"""Compose actual57 response association and stored-object OP comparisons.

No actual established-connection epoch composition or hardware qualification.
Standalone publisher banks are single-association, monotone/no-reuse experiments.
"""
import re

FIELDS=('real_links','real_tcp_src','real_tcp_dst','real_tcp_ports','real_object','real_on','real_off','native_start',
    'native_end','server_start','application','frozen_decoy_object',
    'frozen_decoy_on','frozen_decoy_off')


def extend(text):
    text=text.replace('No verified reset/reuse or RESPONSE/OP target\n * association.',
        'Actual response57/allstatuses and OP comparisons; no verified reset/reuse\n * or live connection-epoch composition.')
    text=text.replace('header epoch_h{','header block_h{bit<32> w0;bit<32> w1;bit<32> w2;bit<32> w3;bit<16> crc;}\nheader response_tail_h{bit<32> w0;bit<32> w1;bit<8> w2;bit<16> crc;}\nheader epoch_h{')
    text=text.replace('native_h native;tail_h tail;','native_h native;tail_h tail;block_h first;block_h second;response_tail_h response_tail;')
    metadata='bit<1> response;bit<1> matched;bit<32> prefix_difference;bit<32> accepted_generation;bit<32> accepted_diff;bit<16> crc1;bit<1> bad1;'
    metadata+=''.join(f'bit<32> compare_{name};bit<32> diff_{name};' for name in FIELDS)
    text=text.replace('struct meta_t{','struct meta_t{'+metadata)
    # Both directions must be explicitly configured; actual saved packet tuple
    # comparison below prevents a different configured flow sharing this record.
    text=text.replace('actions={configure;NoAction;}size=1;',
        'actions={configure;NoAction;}size=2;')
    text=text.replace('m.parsed=1w0;', 'm.parsed=1w0;m.response=1w0;m.matched=1w0;m.bad1=1w0;')
    text=text.replace('(4w4,4w5,16w75,8w6):ip_flags;', '(4w4,4w5,16w75,8w6):ip_flags;(4w4,4w5,16w97,8w6):ip_flags;')
    text=text.replace('state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition native;}',
        'state dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition select(hdr.ip.len){16w75:native;16w97:first;default:accept;}}')
    start=text.index('\n}',text.index('parser IgParser'))
    text=text[:start]+''' state first{pkt.extract(hdr.first);tc.subtract(hdr.first);transition second;}
 state second{pkt.extract(hdr.second);tc.subtract(hdr.second);transition response_tail;}
 state response_tail{pkt.extract(hdr.response_tail);tc.subtract(hdr.response_tail);m.tcp_sum=tc.get();m.response=1w1;m.parsed=1w1;transition accept;}
'''+text[start:]
    text=text.replace('size=1;const default_action=NoAction();const entries={(16w0x0564,8w26,',
        'size=2;const default_action=NoAction();const entries={(16w0x0564,8w26,')
    profile_end=text.index('}}',text.index('table profile'))
    text=text[:profile_end]+'''(16w0x0564,8w26,8w0xC4,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w4,8w12,8w1,8w0x28,16w0x0100,8w0):eligible();'''+text[profile_end:]
    mark=text.index('WorkRecord() work;')
    extra='''table response_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:0]:exact;hdr.first.w1:exact;hdr.first.w2[31:16]:exact;hdr.second.w1[15:0]:exact;hdr.second.w2:exact;hdr.response_tail.w2:exact;}
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
'''
    text=text[:mark]+extra+text[mark:]
    # The existing bank placement supports both write and comparison. SALU
    # returns the full32 difference; no user-supplied match bit authorizes OP.
    for name in FIELDS:
        marker=f'action store_{name}()'
        start=text.index(marker)
        extra=f'''RegisterAction<bit<32>,bit<1>,bit<32>>({name}) read_{name}={{void apply(inout bit<32> v,out bit<32> r){{r=v-m.compare_{name};}}}};
action compare_{name}(){{m.diff_{name}=read_{name}.execute(1w0);}}
'''
        text=text[:start]+extra+text[start:]
        pattern=r'(table '+name+r'_t\{.*?actions=\{store_'+name+r';)NoAction;(\}.*?const default_action=)NoAction\(\);'
        text=re.sub(pattern,lambda m:m[1]+'compare_'+name+';'+m[2]+'compare_'+name+'();',text,flags=re.S)
    response=dict(real_links='hdr.dl.src++hdr.dl.dst',real_tcp_src='hdr.ip.dst',
        real_tcp_dst='hdr.ip.src',real_tcp_ports='hdr.tcp.dport++hdr.tcp.sport',real_object='hdr.first.w2[15:0]++hdr.first.w3[31:16]',real_on='hdr.first.w3[15:0]++hdr.second.w0[31:16]',
        real_off='hdr.second.w0[15:0]++hdr.second.w1[31:16]',native_start='hdr.tcp.ack-32w55',
        native_end='hdr.tcp.ack-32w20',server_start='hdr.tcp.seq',application='hdr.first.w0[23:16]',
        frozen_decoy_object='hdr.second.w3',
        frozen_decoy_on='hdr.response_tail.w0',frozen_decoy_off='hdr.response_tail.w1')
    operate=dict(real_links='hdr.dl.dst++hdr.dl.src',real_tcp_src='hdr.ip.src',
        real_tcp_dst='hdr.ip.dst',real_tcp_ports='hdr.tcp.sport++hdr.tcp.dport',real_object='hdr.native.index++hdr.native.code++hdr.native.repeat',real_on='hdr.native.on',real_off='hdr.tail.off',
        native_start='hdr.tcp.seq-32w35',native_end='hdr.tcp.seq',server_start='hdr.tcp.ack-32w57',
        application='8w0xc0++(hdr.native.app[3:0]-4w1)',frozen_decoy_object='m.decoy_index++m.decoy_code++m.decoy_repeat',frozen_decoy_on='m.decoy_on',frozen_decoy_off='m.decoy_off')
    # Use four C high bits, not an eight-bit prefix, to preserve the raw app byte.
    # Compare whole raw app bytes in the SALU. RESP needs equality; OP needs
    # stored-minus-input == -1 or15 (CF->C0), avoiding4-bit MAU arithmetic.
    operate['application']='hdr.native.app'
    extra=''
    for label,values in (('response',response),('operate',operate)):
        extra+='action compare_'+label+'_inputs(){'+''.join(
            f'm.compare_{name}=(bit<32>)({value});' for name,value in values.items())+'}\n'
        extra+=f'table compare_{label}_inputs_t{{actions={{compare_{label}_inputs;}}size=1;const default_action=compare_{label}_inputs();}}\n'
    extra+='action matched(){m.matched=1w1;}\n'
    rows=''.join('('+f'8w{response},'+','.join(
        f'32w{difference}' if name=='application' else '32w0' for name in FIELDS)+'):matched();'
        for response,difference in ((1,0),(0,0xffffffff),(0,15)))
    extra+='table object_match{key={m.response:exact;'+''.join(f'm.diff_{name}:exact;' for name in FIELDS)+'}actions={matched;NoAction;}size=3;const default_action=NoAction();const entries={'+rows+'}}\n'
    extra+='''Register<bit<32>,bit<1>>(1,0) accepted;
RegisterAction<bit<32>,bit<1>,bit<32>>(accepted) read_accepted={void apply(inout bit<32> v,out bit<32> r){r=v;}};
RegisterAction<bit<32>,bit<1>,bit<32>>(accepted) accept_response={void apply(inout bit<32> v,out bit<32> r){if(v==0){v=m.context_generation;}r=v;}};
action load_accepted(){m.accepted_generation=read_accepted.execute(1w0);}
action commit_accepted(){m.accepted_generation=accept_response.execute(1w0);}
table accepted_t{key={m.response:exact;m.matched:exact;}actions={load_accepted;commit_accepted;}size=1;const entries={(1w1,1w1):commit_accepted();}const default_action=load_accepted();}
action accepted_difference(){m.accepted_diff=m.accepted_generation-m.context_generation;}
table accepted_difference_t{actions={accepted_difference;}size=1;const default_action=accepted_difference();}
// Qualification produces an internal diagnostic mark only. No scheduler or
// actual connection-authority mutation exists in this isolated component.
action operate_qualified(){hdr.expected.setValid();hdr.expected.expected=32w0x4f50514c;}
table operate_qualified_t{key={m.matched:exact;m.accepted_diff:exact;hdr.native.func:exact;}actions={operate_qualified;NoAction;}size=1;const entries={(1w1,32w0,8w4):operate_qualified();}const default_action=NoAction();}
'''
    # Retain an observable qualified-event counter. An unused metadata mark can
    # be compiler-pruned and cannot establish that OP qualification was built.
    text=text.replace('bit<1> matched;', 'bit<1> matched;bit<1> operate_qualified;')
    extra='''Register<bit<32>,bit<1>>(1,0) qualified_operate;
RegisterAction<bit<32>,bit<1>,bit<32>>(qualified_operate) record_operate={void apply(inout bit<32> v,out bit<32> r){r=v;if((int<32>)v!=-1){v=v+32w1;}}};
action prefix_identity(){m.prefix_difference=hdr.epoch.epoch-hdr.generation.generation;}
table prefix_identity_t{actions={prefix_identity;}size=1;const default_action=prefix_identity();}
'''+extra
    extra=extra.replace('hdr.expected.setValid();hdr.expected.expected=32w0x4f50514c;',
        'm.operate_qualified=1w1;record_operate.execute(1w0);')
    mark=text.index('apply{m.work_op=8w0;')
    text=text[:mark]+extra+text[mark:]
    text=text.replace('connection.apply();profile.apply();',
        'connection.apply();if(m.response==1w1){response_profile.apply();}else{profile.apply();}')
    text=text.replace('input_head_t.apply();input_body_t.apply();input_tail_t.apply();',
        'input_head_t.apply();if(m.response==1w1){response_crc0_t.apply();response_crc1_t.apply();response_crct_t.apply();}else{input_body_t.apply();input_tail_t.apply();}')
    first=text.index(' if(hdr.native.crc!=');end=text.index('\n if(m.badh==',first)
    text=text[:first]+''' if(m.response==1w1){
 if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}
 if(hdr.second.crc!=(m.crc1[7:0]++m.crc1[15:8])){m.bad1=1w1;}
 if(hdr.response_tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
 }else{
 if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}
 if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}}
'''+text[end:]
    text=text.replace('m.badb==1w0&&m.badt==1w0&&hdr.native.index!=m.decoy_index',
        'm.badb==1w0&&m.bad1==1w0&&m.badt==1w0')
    text=text.replace('if(m.stage==8w0){mint_t.apply();}else{',
        'if(m.stage==8w0){if(m.response==1w0&&hdr.native.func==8w3&&hdr.native.index!=m.decoy_index){mint_t.apply();}}else{')
    text=text.replace('m.generation=hdr.generation.generation;m.work_op=8w2;}',
        'm.generation=hdr.generation.generation;m.work_op=8w2;prefix_identity_t.apply();if(m.prefix_difference!=32w0){m.work_op=8w0;deny();}}')
    text=text.replace('published_t.apply();calculate_native_end_t.apply();',
        'published_t.apply();calculate_native_end_t.apply();if(m.response==1w1){compare_response_inputs_t.apply();}else{compare_operate_inputs_t.apply();}')
    mark=text.index('\n if(m.stage==8w0){if(m.work_phase')
    text=text[:mark]+'''
 if(m.stage==8w0&&m.work_op==8w0&&m.work_phase==32w4&&m.context_generation!=32w0){object_match.apply();accepted_t.apply();accepted_difference_t.apply();if(m.response==1w0){operate_qualified_t.apply();}}
'''+text[mark:]
    text=text.replace('if(m.stage==8w0){if(m.work_phase==32w4){start_work_t.apply();',
        'if(m.stage==8w0){if(m.work_op==8w1&&m.work_phase==32w4){start_work_t.apply();')
    return text


def common_first_block(text):
    """Actual wire layouts share one18-byte user16+CRC header, not dual PHV copies."""
    text=re.sub(r'header native_h\{.*?\}\n','',text)
    text=text.replace('native_h native;tail_h tail;block_h first;', 'block_h first;tail_h tail;')
    fields=dict(tp='w0[31:24]',app='w0[23:16]',func='w0[15:8]',group='w0[7:0]',
        variation='w1[31:24]',qualifier='w1[23:16]',count='w1[15:0]',index='w2[31:16]',
        code='w2[15:8]',repeat='w2[7:0]',on='w3',crc='crc')
    for field,position in fields.items():
        text=text.replace('hdr.native.'+field,'hdr.first.'+position)
    text=text.replace('pkt.extract(hdr.native);tc.subtract(hdr.native);',
        'pkt.extract(hdr.first);tc.subtract(hdr.first);')
    # Normalize nested nibble slices after changing the actual app field view.
    text=text.replace('hdr.first.w0[23:16][3:0]','hdr.first.w0[19:16]')
    # Nonzero phase authority avoids an in-SALU zero-sentinel optimization
    # ambiguity while preserving the full32 nonwrapping published generation.
    text=text.replace('header epoch_h{',
        'struct publication_cell_t{bit<32> generation;bit<32> phase;}\nheader epoch_h{')
    for bank,reader,writer,value in (('published','read_published','publish','hdr.generation.generation'),
            ('accepted','read_accepted','accept_response','m.context_generation')):
        text=text.replace(f'Register<bit<32>,bit<1>>(1,0) {bank};',
            f'Register<publication_cell_t,bit<1>>(1,{{0,4}}) {bank};')
        text=text.replace(f'RegisterAction<bit<32>,bit<1>,bit<32>>({bank}) {reader}={{void apply(inout bit<32> v,out bit<32> r){{r=v;}}}};',
            f'RegisterAction<publication_cell_t,bit<1>,bit<32>>({bank}) {reader}={{void apply(inout publication_cell_t v,out bit<32> r){{r=v.generation;}}}};')
        text=text.replace(f'RegisterAction<bit<32>,bit<1>,bit<32>>({bank}) {writer}={{void apply(inout bit<32> v,out bit<32> r){{if(v==0){{v={value};}}r=v;}}}};',
            f'RegisterAction<publication_cell_t,bit<1>,bit<32>>({bank}) {writer}={{void apply(inout publication_cell_t v,out bit<32> r){{if(v.phase==4){{v.generation={value};v.phase=5;}}r=v.generation;}}}};')
    start=text.index('struct meta_t{');end=text.index('parser IgParser',start)
    text=text[:start]+text[start:end].replace('bit<1>','bit<8>')+text[end:]
    flags='parsed|response|matched|operate_qualified|bad1|port_valid|enabled|profile|changed|badh|badb|badt'
    text=re.sub(r'(m\.(?:'+flags+r')(?:==|!=|=))1w([01])',r'\g<1>8w\2',text)
    text=text.replace('(1w1,1w1):commit_accepted()', '(8w1,8w1):commit_accepted()')
    text=text.replace('(1w1,32w0,8w4):operate_qualified()', '(8w1,32w0,8w4):operate_qualified()')
    # Native and response layouts place the same object bytes at different
    # offsets. Separate compare operands and SALU actions avoid a single32-bit
    # mux forcing incompatible PHV positions across those parser branches.
    for name in FIELDS:
        text=text.replace('bit<32> compare_'+name+';',
            'bit<32> compare_op_'+name+';bit<32> compare_rsp_'+name+';')
        pattern=r'(RegisterAction<bit<32>,bit<1>,bit<32>>\('+name+r'\) read_'+name+r'=\{void apply\(inout bit<32> v,out bit<32> r\)\{r=v-m.compare_'+name+r';\}\};)'
        def reads(match):
            return ''.join(match[1].replace('read_'+name,'read_'+label+'_'+name).replace(
                'm.compare_'+name,'m.compare_'+label+'_'+name) for label in ('op','rsp'))
        text=re.sub(pattern,reads,text)
        text=text.replace('read_'+name+'.execute(1w0);','read_op_'+name+'.execute(1w0);')
        marker='action compare_'+name+'(){'
        start=text.index(marker)
        text=text[:start]+f'action compare_rsp_{name}(){{m.diff_{name}=read_rsp_{name}.execute(1w0);}}\n'+text[start:]
        table_start=text.index('table '+name+'_t{');table_end=text.index('\n',table_start)
        table=text[table_start:table_end]
        table=table.replace('m.stage:exact;','m.response:exact;m.stage:exact;')
        table=table.replace('compare_'+name+';}','compare_'+name+';compare_rsp_'+name+';}')
        table=table.replace('size=1;', 'size=2;')
        table=table.replace('(8w0,8w1,32w4,32w0):','(8w0,8w0,8w1,32w4,32w0):')
        table=table.replace('}const default_action=',f'(8w1,8w0,8w0,32w4,_):compare_rsp_{name}();}}const default_action=')
        # The only response comparison occurs on a raw fully-validated frame.
        table=table.replace('m.context_generation:exact;','m.context_generation:ternary;')
        text=text[:table_start]+table+text[table_end:]
    for action,label in (('compare_response_inputs','rsp'),('compare_operate_inputs','op')):
        start=text.index('action '+action+'(){');end=text.index('}\n',start)
        text=text[:start]+text[start:end].replace('m.compare_','m.compare_'+label+'_')+text[end:]
    text=text.replace('struct meta_t{','struct meta_t{bit<8> association_allowed;')
    text=text.replace('m.parsed=8w0;', 'm.parsed=8w0;m.association_allowed=8w0;')
    marker=text.index('apply{m.work_op=8w0;')
    text=text[:marker]+'''action association_allowed(){m.association_allowed=8w1;}
table association_admission{key={m.stage:exact;m.work_op:exact;m.work_phase:exact;}actions={association_allowed;NoAction;}size=1;const entries={(8w0,8w0,32w4):association_allowed();}const default_action=NoAction();}
'''+text[marker:]
    text=text.replace('if(m.stage==8w0&&m.work_op==8w0&&m.work_phase==32w4&&m.context_generation!=32w0)',
        'association_admission.apply();if(m.association_allowed==8w1&&m.context_generation!=32w0)')
    return text


def compact_bank_dispatch(text):
    """Each bank uses two PHV operands: decoded native input and decoded response.

    SELECT stores from the same native operand used for OP comparison. The raw
    SELECT decoder is source-derived, not caller-provided metadata. One qualified
    shared dispatch selects store/OP/RSP instead of repeating88-bit bank keys.
    """
    values={}
    for name in FIELDS:
        marker='RegisterAction<bit<32>,bit<1>,bit<32>>('+name+') write_'+name
        start=text.index(marker);end=text.index('\n',start)
        declaration=text[start:end]
        match=re.search(r'v=\(bit<32>\)\((.*?)\);r=v;',declaration)
        if match is None:raise ValueError('missing actual source writer '+name)
        values[name]=match[1]
        declaration=declaration[:match.start()]+'v=m.compare_op_'+name+';r=v;'+declaration[match.end():]
        text=text[:start]+declaration+text[end:]
        start=text.index('table '+name+'_t{');end=text.index('\n',start)
        table=f'''table {name}_t{{key={{m.cache_mode:exact;}}actions={{store_{name};compare_{name};compare_rsp_{name};NoAction;}}size=3;const entries={{8w1:store_{name}();8w2:compare_{name}();8w3:compare_rsp_{name}();}}const default_action=NoAction();}}'''
        text=text[:start]+table+text[end:]
    text=text.replace('struct meta_t{','struct meta_t{bit<8> cache_mode;')
    text=text.replace('m.parsed=8w0;','m.parsed=8w0;m.cache_mode=8w0;')
    extra='action compare_select_inputs(){'+''.join(
        f'm.compare_op_{name}=(bit<32>)({value});' for name,value in values.items())+'}\n'
    extra+='table compare_select_inputs_t{actions={compare_select_inputs;}size=1;const default_action=compare_select_inputs();}\n'
    extra+='''action cache_store(){m.cache_mode=8w1;}
action cache_op(){m.cache_mode=8w2;}
action cache_response(){m.cache_mode=8w3;}
table cache_access{key={m.response:exact;m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:ternary;}actions={cache_store;cache_op;cache_response;NoAction;}size=3;const entries={(8w0,8w0,8w1,32w4,32w0):cache_store();(8w0,8w0,8w0,32w4,_):cache_op();(8w1,8w0,8w0,32w4,_):cache_response();}const default_action=NoAction();}
'''
    marker=text.index('apply{m.work_op=8w0;');text=text[:marker]+extra+text[marker:]
    text=text.replace('else{compare_operate_inputs_t.apply();}',
        'else{if(hdr.first.w0[15:8]==8w3){compare_select_inputs_t.apply();}else{compare_operate_inputs_t.apply();}}')
    text=text.replace('real_links_t.apply();','cache_access.apply();real_links_t.apply();')
    return text


def parser_role_paths(text):
    """Do not retain IP length match registers across32-bit TCP selectors."""
    text=text.replace('(4w4,4w5,16w75,8w6):ip_flags;', '(4w4,4w5,16w75,8w6):native_ip_flags;')
    text=text.replace('(4w4,4w5,16w97,8w6):ip_flags;', '(4w4,4w5,16w97,8w6):response_ip_flags;')
    start=text.index(' state ip_flags{');end=text.index(' state native{',start)
    original=text[start:end]
    flags=re.search(r' state ip_flags\{[^\n]+',original)[0]
    tcp=re.search(r' state tcp\{[^\n]+',original)[0]
    states=''
    for role,next_state in (('native','native'),('response','first')):
        states+=flags.replace('state ip_flags','state '+role+'_ip_flags').replace(':tcp;',':'+role+'_tcp;')+'\n'
        states+=tcp.replace('state tcp','state '+role+'_tcp').replace(':dl;',':'+role+'_dl;')+'\n'
        states+=f' state {role}_dl{{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition {next_state};}}\n'
    text=text[:start]+states+text[end:]
    extra='''action return_nonce(){m.generation=hdr.generation.generation;m.work_op=8w2;}
table return_packet{key={m.response:exact;hdr.first.w0[15:8]:exact;}actions={return_nonce;deny;}size=1;const entries={(8w0,8w3):return_nonce();}const default_action=deny();}
'''
    mark=text.index('apply{m.work_op=8w0;');text=text[:mark]+extra+text[mark:]
    text=text.replace('m.generation=hdr.generation.generation;m.work_op=8w2;prefix_identity_t.apply();',
        'return_packet.apply();prefix_identity_t.apply();')
    return text

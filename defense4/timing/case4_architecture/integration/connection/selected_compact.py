"""Paired object cells and directly qualified acceptance, compile experiment.

Two decoded PHV operands per paired cell; no implied live epoch or target fit.
"""
import re
from selected_association import FIELDS

PAIRS=(('real_links','real_tcp_src'),('real_tcp_dst','real_tcp_ports'),
    ('real_object','real_on'),('real_off','native_start'),
    ('native_end','server_start'),('frozen_decoy_object','frozen_decoy_on'))

CHECK_FIELDS=tuple(name for name in FIELDS if name not in {b for a,b in PAIRS})

def compact(text):
    text=text.replace('m.compare_op_','m.compare_').replace('m.compare_rsp_','m.compare_')
    text=re.sub(r'bit<32> compare_(?:op|rsp)_', 'bit<32> compare_',text)
    text=re.sub(r'(bit<32> compare_\w+;)\1',r'\1',text)
    text=text.replace('struct publication_cell_t{','struct object_pair_t{bit<32> first;bit<32> second;}\nstruct publication_cell_t{')
    for left,right in PAIRS:
        for name in (left,right):
            text=re.sub(r'Register<bit<32>,bit<1>>\(1,0\) '+name+r';\n.*?table '+name+r'_t\{[^\n]+\n','',text,flags=re.S)
        bank='pair_'+left+'_'+right
        body=f'''Register<object_pair_t,bit<1>>(1,{{0,0}}) {bank};
RegisterAction<object_pair_t,bit<1>,bit<32>>({bank}) write_{left}={{void apply(inout object_pair_t v,out bit<32> r){{v.first=m.compare_{left};v.second=m.compare_{right};r=32w0;}}}};
RegisterAction<object_pair_t,bit<1>,bit<32>>({bank}) read_{left}={{void apply(inout object_pair_t v,out bit<32> r){{if(v.first!=m.compare_{left}||v.second!=m.compare_{right}){{r=32w1;}}else{{r=32w0;}}}}}};
action store_{left}(){{write_{left}.execute(1w0);}}
action compare_{left}(){{m.diff_{left}=read_{left}.execute(1w0);}}
table {left}_t{{key={{m.cache_mode:exact;}}actions={{store_{left};compare_{left};NoAction;}}size=3;const entries={{8w1:store_{left}();8w2:compare_{left}();8w3:compare_{left}();}}const default_action=NoAction();}}
'''
        marker=text.index('action start_work()')
        text=text[:marker]+body+text[marker:]
        text=text.replace(right+'_t.apply();','').replace('bit<32> diff_'+right+';','')
    # Scalar application comparison retains exact -1 and CF->C0 differences.
    text=text.replace('bit<32> accepted_generation;','')
    start=text.index('action matched()');end=text.index('// Qualification produces',start)
    rows=''.join('('+f'8w{response},'+','.join(
        f'32w{difference}' if name=='application' else '32w0' for name in CHECK_FIELDS)+
        '):'+('match_response' if response else 'match_operate')+'();'
        for response,difference in ((1,0),(0,0xffffffff),(0,15)))
    table=('table object_match{key={m.response:exact;'+''.join(
        f'm.diff_{name}:exact;' for name in CHECK_FIELDS)+
        '}actions={match_response;match_operate;NoAction;}size=3;const default_action=NoAction();const entries={'+rows+'}}')
    body='''Register<publication_cell_t,bit<1>>(1,{0,4}) accepted;
RegisterAction<publication_cell_t,bit<1>,bit<32>>(accepted) read_accepted={void apply(inout publication_cell_t v,out bit<32> r){if(v.phase>=5&&v.generation==m.context_generation){v.phase=6;r=32w0;}else{r=32w1;}}};
RegisterAction<publication_cell_t,bit<1>,bit<32>>(accepted) accept_response={void apply(inout publication_cell_t v,out bit<32> r){if(v.phase==4){v.generation=m.context_generation;v.phase=5;}r=v.generation;}};
action match_response(){m.matched=8w1;m.accepted_diff=accept_response.execute(1w0);}
action match_operate(){m.matched=8w1;m.accepted_diff=read_accepted.execute(1w0);}
'''
    text=text[:start]+body+table+'\n'+text[end:]
    text=text.replace('object_match.apply();accepted_t.apply();accepted_difference_t.apply();','object_match.apply();')
    text=re.sub(r'Register<bit<32>,bit<1>>\(1,0\) qualified_operate;\nRegisterAction[^\n]+\n','',text)
    text=re.sub(r'action operate_qualified\(\)\{[^\n]+\n','',text)
    text=re.sub(r'table operate_qualified_t\{[^\n]+\n','',text)
    text=text.replace('if(m.response==8w0){operate_qualified_t.apply();}','')
    text=text.replace('// Qualification produces an internal diagnostic mark only. No scheduler or', '// Matching OP atomically stamps accepted.phase6, an observed Boolean, not an event count.\n// Generation is immutable; phases are initialized4, response5, matchedOP6. No scheduler or')
    return text

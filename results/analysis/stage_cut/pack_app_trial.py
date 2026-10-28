"""Pack bounded DNP3 application identities into one 32-bit cell."""
import importlib.util
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('layout',HERE/'n_layout_trial.py')
layout=importlib.util.module_from_spec(spec);spec.loader.exec_module(layout)

def transform(source):
    # Reachable CROB identity is function-byte + application-control byte.
    # READ identity is shape0x100/0x200 plus four-bit sequence, or invalid0xffff.
    begin=source.index('Register<bit<32>,bit<1>>(1,0) application;')
    end=source.index('Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_links_native_start;',begin)
    source=source[:begin]+source[end:]
    begin=source.index('Register<bit<32>,bit<1>>(1,0) read_app;')
    old_table=layout.block(source,'table','read_app_t')
    end=source.index(old_table,begin)+len(old_table)
    definitions='''Register<bit<32>,bit<1>>(1,0) application_state;
RegisterAction<bit<32>,bit<1>,bit<32>>(application_state) write_control_state={void apply(inout bit<32> v,out bit<32> r){v[15:0]=m.compare_application[15:0];v[31:16]=16w0xffff;r=32w0;}};
RegisterAction<bit<32>,bit<1>,bit<32>>(application_state) write_read_state={void apply(inout bit<32> v,out bit<32> r){v[31:16]=m.compare_read_app[15:0];r=32w0;}};
RegisterAction<bit<32>,bit<1>,bit<16>>(application_state) check_control_state={void apply(inout bit<32> v,out bit<16> r){r=v[15:0]-m.compare_application[15:0];}};
RegisterAction<bit<32>,bit<1>,bit<8>>(application_state) check_read_state={void apply(inout bit<32> v,out bit<8> r){r=8w0;if(v[31:16]==m.compare_read_app[15:0]){r=8w1;}}};
action store_control_state(){write_control_state.execute(1w0);}
action store_read_state(){write_read_state.execute(1w0);}
action compare_control_state(){m.diff_application=check_control_state.execute(1w0);}
action compare_read_state(){m.matched=(bit<1>)(check_read_state.execute(1w0));}
table application_state_t{key={m.stage:ternary;m.kind:ternary;m.work_phase:ternary;m.epoch_diff:ternary;}actions={store_control_state;store_read_state;compare_control_state;compare_read_state;NoAction;}size=8;const entries={
(2w1,8w5,32w1,32w0):store_control_state();
(2w1,8w7,32w1,32w0):store_control_state();
(2w0,8w5,32w4,_):compare_control_state();
(2w0,8w7,32w4,_):compare_control_state();
(2w0,8w6,32w4,_):compare_control_state();
(2w1,8w9,32w1,32w0):store_read_state();
(2w0,8w9,32w4,_):compare_read_state();
(2w0,8w11,32w4,_):compare_read_state();
}const default_action=NoAction();}
'''
    source=source[:begin]+definitions+source[end:]
    source=source.replace('application_t.apply();','').replace('read_app_t.apply();','application_state_t.apply();')
    source=source.replace('bit<32> diff_application;','bit<16> diff_application;')
    table=layout.block(source,'table','first_event')
    rows=[]
    for key,action,argument in layout.entries(table):
        if key[12]!='_':
            value,mask=layout.ternary(key[12],32)
            key[12]=f'16w0x{value&65535:x}&&&16w0x{mask&65535:x}'
        rows.append((key,action,argument))
    prefix=table.split('const entries={',1)[0]
    body=''.join('('+','.join(k)+'):'+a+'('+arg+');' for k,a,arg in rows)
    source=source.replace(table,prefix+'const entries={'+body+'}}')
    return source

if __name__=='__main__':
    root=HERE.parents[2]
    (root/'p4/response_only.p4').write_text(transform((root/'results/builds/c72_ne_06/response_only.p4').read_text()))

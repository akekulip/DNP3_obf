"""Reuse a redundant fixed-peer IP lane; add no persistent state or packet pass."""
import importlib.util
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('layout',HERE/'n_layout_trial.py')
layout=importlib.util.module_from_spec(spec);spec.loader.exec_module(layout)

def transform(source):
    # Eligibility already requires one of the two reciprocal sealed endpoint
    # tuples. Thus the stored master-IP lane cannot differ on qualified paths.
    begin=source.index('Register<bit<32>,bit<1>>(1,0) pair_real_off_native_start;')
    table=layout.block(source,'table','real_off_t')
    end=source.index(table,begin)+len(table)
    source=source[:begin]+source[end:]
    source=source.replace('real_off_t.apply();','')
    source=source.replace('pair_real_links_real_tcp_src','pair_real_links_native_start')
    source=source.replace('v.second=m.compare_real_tcp_src;','v.second=m.compare_native_start;')
    source=source.replace('v.second!=m.compare_real_tcp_src','v.second!=m.compare_native_start')
    anchor=layout.block(source,'action','store_real_links')
    addition=('\nRegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_links_native_start) write_native_start='
              '{void apply(inout n_object_pair_t v,out bit<32> r){v.second=m.compare_native_start;r=32w0;}};'
              '\naction store_native_start(){write_native_start.execute(1w0);}')
    source=source.replace(anchor,anchor+addition)
    table=layout.block(source,'table','real_links_t')
    replacement=table.replace('actions={','actions={store_native_start;',1).replace('size=3;','size=4;')
    replacement=replacement.replace('const entries={','const entries={(2w1,8w7,32w1,32w0):store_native_start();',1)
    source=source.replace(table,replacement)
    source=source.replace('bit<8> diff_real_off;','').replace('bit<32> compare_real_tcp_src;','')
    import re
    source=re.sub(r'm\.compare_real_tcp_src=[^;]+;','',source)
    source=source.replace('@pa_solitary("ingress", "m.diff_real_off")\n','')
    table=layout.block(source,'table','first_event')
    rows=layout.entries(table)
    assert all(len(k)==18 for k,a,arg in rows)
    body=''.join('('+','.join(k[:15]+k[16:])+'):'+a+'('+arg+');' for k,a,arg in rows)
    prefix=table.split('const entries={',1)[0].replace('m.diff_real_off:ternary;','')
    source=source.replace(table,prefix+'const entries={'+body+'}}')
    assert 'diff_real_off' not in source and 'compare_real_tcp_src' not in source
    return source

if __name__=='__main__':
    root=HERE.parents[2]
    (root/'p4/response_only.p4').write_text(transform((root/'results/builds/c72_ne_05/response_only.p4').read_text()))

"""Eliminate the intermediate object-admission lookup without weakening its checks."""
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('layout',HERE/'n_layout_trial.py')
layout=importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)

def transform(source):
    first=layout.block(source,'table','first_event')
    rows=[]
    for key,action,argument in layout.entries(first):
        extra=['_']*5
        if key[0] in ('8w6','8w7') and key[2]=='1w1':
            response=key[0]=='8w6'
            for app in ((0x300,0x400) if response else (0xfffffeff,0xffffff0f)):
                k=key.copy()
                k[12]=layout.intersect(k[12],f'32w0x{app:x}',32)
                if k[12] is None:continue
                k[2]='_'
                rows.append((k+['8w0']*4+['1w1' if response else '1w0'],action,argument))
        else:
            assert not (key[0] in ('8w6','8w7') and key[2]!='_'),key
            rows.append((key+extra,action,argument))
    key_end=first.index('}\n actions=')
    prefix=first[:key_end]+'m.diff_real_links:ternary;m.diff_real_tcp_dst:ternary;'+\
           'm.diff_real_off:ternary;m.diff_native_end:ternary;m.response:ternary;'+first[key_end:]
    prefix=prefix.split('const entries={',1)[0]
    import re
    prefix=re.sub(r'size=\d+;',f'size={len(rows)};',prefix)
    body=''.join('('+','.join(k)+'):'+a+'('+arg+');' for k,a,arg in rows)
    source=source.replace(first,prefix+'const entries={'+body+'}}')
    source=source.replace('if(m.packet_kind==8w6||m.packet_kind==8w7){object_match.apply();}','')
    source=source.replace(layout.block(source,'table','object_match'),'')
    source=source.replace(layout.block(source,'action','matched'),'')
    return source

if __name__=='__main__':
    root=HERE.parents[2]
    source=(root/'results/builds/c72_ne_04/response_only.p4').read_text()
    (root/'p4/response_only.p4').write_text(transform(source))

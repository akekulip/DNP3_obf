"""One return-phase dispatch removes serialization between mutually exclusive paths."""
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('layout',HERE/'n_layout_trial.py')
layout=importlib.util.module_from_spec(spec);spec.loader.exec_module(layout)

def transform(source):
    terminal=layout.block(source,'table','terminal_t')
    read=layout.block(source,'table','read_terminal_t')
    rows=[]
    actions=[]
    for phase in (1,2):
        for k,a,arg in layout.entries(terminal):
            rows.append(([f'32w{phase}']+k+['_','_'],a,arg));actions.append(a)
        rows.append(([f'32w{phase}']+['_']*7,'abort_work',''));actions.append('abort_work')
    for k,a,arg in layout.entries(read):
        kind,owner,epoch,direction,packet=k
        rows.append((['32w3',epoch,kind,'_','_',owner,direction,packet],a,arg));actions.append(a)
    rows.append((['32w3']+['_']*7,'terminal_abort',''));actions.extend(('terminal_abort','deny'))
    new='@stage(9) table continuation_t{key={m.work_phase:ternary;m.epoch_diff:ternary;m.kind:ternary;m.stage:ternary;m.owner_op:ternary;m.owner_diff:ternary;m.direction:ternary;m.packet_kind:ternary;}'
    new+='actions={'+''.join(a+';' for a in dict.fromkeys(actions))+'}size='+str(len(rows))+';const entries={'
    new+=''.join('('+','.join(k)+'):'+a+'('+arg+');' for k,a,arg in rows)+'}const default_action=deny();}'
    source=source.replace('@stage(9) '+terminal,'').replace('@stage(9) '+read,new)
    old='''    else {
     if(m.work_phase==32w3){read_terminal_t.apply();}
     if(m.work_phase==32w1||m.work_phase==32w2){terminal_t.apply();}
     if(m.work_phase!=32w1&&m.work_phase!=32w2&&m.work_phase!=32w3){deny();}
    }'''
    assert source.count(old)==1
    source=source.replace(old,'    else {continuation_t.apply();}')
    return source,{'terminal':layout.entries(terminal),'read_terminal':layout.entries(read)}

if __name__=='__main__':
    root=HERE.parents[2]
    source,proof=transform((root/'results/builds/c72_ne_12/response_only.p4').read_text())
    (root/'p4/response_only.p4').write_text(source)
    (root/'tests/fixtures/p4/n_continuation_tables.json').write_text(json.dumps(proof,indent=2)+'\n')

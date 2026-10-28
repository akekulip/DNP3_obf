"""Fold ordered sequence classification into the event table's existing diff keys."""
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('layout',HERE/'n_layout_trial.py')
layout=importlib.util.module_from_spec(spec);spec.loader.exec_module(layout)

def intersection(a,b):
    if any((av^bv)&am&bm for (av,am),(bv,bm) in zip(a,b)):
        return None
    return tuple(((av&am)|(bv&bm),am|bm) for (av,am),(bv,bm) in zip(a,b))

def subtract(cube,cut):
    if intersection(cube,cut) is None:return [cube]
    inside=list(cube);out=[]
    for index,((v,mask),(cv,cmask)) in enumerate(zip(cube,cut)):
        extra=cmask&~mask
        while extra:
            bit=extra&-extra
            iv,im=inside[index]
            outside=inside.copy();outside[index]=((iv&~bit)|((~cv)&bit),im|bit)
            out.append(tuple(outside))
            inside[index]=((iv&~bit)|(cv&bit),im|bit)
            extra-=bit
    return out

def minimize(cubes):
    current={((a<<32)|b,(am<<32)|bm) for (a,am),(b,bm) in cubes}
    while True:
        used=set();merged=set()
        for value,mask in current:
            bits=mask
            while bits:
                bit=bits&-bits;bits-=bit
                partner=(value^bit,mask)
                if partner in current:
                    used.add((value,mask));used.add(partner)
                    merged.add((value&~bit,mask&~bit))
        if not used:break
        current=(current-used)|merged
    return [((value>>32,mask>>32),(value&0xffffffff,mask&0xffffffff)) for value,mask in sorted(current)]

def transform(source):
    guard=layout.block(source,'table','sequence_guard')
    rows=layout.entries(guard)
    values={}
    for action in ('seq_ok','seq_fresh','seq_forward_fresh','seq_retx','seq_resent','seq_replay','seq_fin'):
        body=layout.block(source,'action',action)
        values[action]=int(re.search(r'8w(\d+)',body).group(1))
    remaining=[((0,0),(0,0))];partition=[]
    for key,action,_ in rows:
        cut=tuple(layout.ternary(k,32) for k in key)
        new=[]
        for cube in remaining:
            overlap=intersection(cube,cut)
            if overlap is not None:partition.append((overlap,values[action]))
            new.extend(subtract(cube,cut))
        remaining=new
    partition.extend((cube,values['seq_fresh']) for cube in remaining)
    first=layout.block(source,'table','first_event');out=[]
    for key,action,argument in layout.entries(first):
        if key[1]=='_':
            out.append((key[:1]+key[2:],action,argument));continue
        value,mask=layout.ternary(key[1],3)
        original=tuple(layout.ternary(key[i],32) for i in (4,5))
        pending=[original];qualified=[]
        for seqkey,seqaction,_ in rows:
            cut=tuple(layout.ternary(k,32) for k in seqkey)
            after=[]
            for cube in pending:
                overlap=intersection(cube,cut)
                if overlap is not None and values[seqaction]&mask==value:
                    qualified.append(overlap)
                after.extend(subtract(cube,cut))
            pending=after
        if values['seq_fresh']&mask==value:qualified.extend(pending)
        for overlap in minimize(qualified):
            merged=key.copy()
            for index,(v,m) in zip((4,5),overlap):
                merged[index]='_' if not m else f'32w0x{v:x}&&&32w0x{m:x}'
            out.append((merged[:1]+merged[2:],action,argument))
    prefix=first.split('const entries={',1)[0].replace('m.sequence_valid:ternary;','')
    prefix=re.sub(r'size=\d+;',f'size={len(out)};',prefix)
    body=''.join('('+','.join(k)+'):'+a+'('+arg+');' for k,a,arg in out)
    source=source.replace(first,prefix+'const entries={'+body+'}}')
    source=source.replace(guard,'').replace('sequence_guard.apply();','')
    for action in values:source=source.replace(layout.block(source,'action',action),'')
    source=source.replace('bit<3> sequence_valid;','').replace('m.sequence_valid=(bit<3>)(8w0);','')
    return source,{'guard':rows,'values':values,'default':'seq_fresh','partition_count':len(partition),'event_rows':len(out)}

if __name__=='__main__':
    root=HERE.parents[2]
    source,proof=transform((root/'results/builds/c72_ne_10/response_only.p4').read_text())
    (root/'p4/response_only.p4').write_text(source)
    (root/'tests/fixtures/p4/n_sequence_guard.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({k:proof[k] for k in ('partition_count','event_rows')}))

#!/usr/bin/env python3
"""Wire-role experiment with one shared Ethernet/IP/TCP header lifetime.

Preserves role-specific payload headers and validators. Only valid headers emit.
No owner, queue service or autonomous connection publication is inferred.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import compose


def end_block(text, at):
    at=text.index('{',at);depth=1;end=at+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return end


def unify(source, roles):
    structures={}
    for role in roles:
        body=re.search(r'struct\s+'+role+r'_headers_t\s*\{([^}]*)\}',source)[1]
        structures[role]=re.findall(r'(\w+)\s+(\w+);',body)
    header_defs=dict(re.findall(r'header\s+(\w+)\s*\{([^}]*)\}',source))
    first=dict((field,kind) for kind,field in structures[roles[0]])
    shared={name:first[name] for name in ('eth','ip','tcp')}
    for role,fields in structures.items():
        by_name={field:kind for kind,field in fields}
        for name,kind in shared.items():
            actual=re.findall(r'bit<(\d+)>\s+(\w+);',header_defs[by_name[name]])
            expected=re.findall(r'bit<(\d+)>\s+(\w+);',header_defs[kind])
            if actual!=expected:raise ValueError('wire header layouts differ: '+role+'/'+name)
    # Payload fields stay separate; only actual identical network headers alias.
    for role in roles:
        names={field:(field if field in shared else role+'_'+field)
               for _,field in structures[role]}
        matches=list(re.finditer(r'\b(?:parser|control)\s+'+role+r'_\w+\s*\(',source))
        for match in reversed(matches):
            end=end_block(source,match.start())
            body=source[match.start():end]
            body=re.sub(r'\bhdr\.(\w+)',lambda m:'hdr.'+names[m[1]],body)
            source=source[:match.start()]+body+source[end:]
        source=compose.remove_blocks(source,r'^struct\s+'+role+r'_headers_t\b')
        source=re.sub(r'\b'+role+r'_headers_t\b','headers_t',source)
        source=re.sub(r'\bhdr\.'+role+r'\.(\w+)',lambda m:'hdr.'+names[m[1]],source)
        source=re.sub(r'\bhdr\.'+role+r'\b','hdr',source)
    source=compose.remove_blocks(source,r'^struct\s+headers_t\b')
    fields=''.join(kind+' '+name+';' for name,kind in shared.items())
    fields+=''.join(kind+' '+role+'_'+name+';' for role in roles for kind,name in structures[role] if name not in shared)
    # Move all header declarations before the single shared struct.
    declarations=re.findall(r'header\s+\w+\s*\{[^}]*\}',source)
    source=re.sub(r'header\s+\w+\s*\{[^}]*\}','',source)
    includes=''.join(re.findall(r'^#include.*\n',source,re.M))
    source=re.sub(r'^#include.*\n','',source,flags=re.M)
    source=includes+'\n'.join(declarations)+'\nstruct headers_t{'+fields+'}\n'+source
    # Role controls compute checksums first. One final emission serializes the
    # common prefix once, then the selected valid payload in declaration order.
    source=re.sub(r'pkt\.emit\(hdr\.[^;)]+\);','',source)
    for name in ('IgDeparser','EgDeparser'):
        start=source.index('control '+name+'(')
        apply=source.index('apply{',start)
        end=end_block(source,apply)
        source=source[:end-1]+'pkt.emit(hdr);'+source[end-1:]
    return source


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--roles',nargs='+',choices=compose.ROLE_FILES,default=list(compose.ROLE_FILES))
    args=parser.parse_args()
    source=compose.generate(args.roles,shared_cache=True,early_cache=True)
    args.output.write_text(unify(source,args.roles))
    inputs={r:hashlib.sha256((compose.ROOT/'protocol'/compose.ROLE_FILES[r]).read_bytes()).hexdigest() for r in args.roles}
    inputs['compose.py']=hashlib.sha256(Path(compose.__file__).read_bytes()).hexdigest()
    args.output.with_suffix('.inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')


if __name__=='__main__':main()

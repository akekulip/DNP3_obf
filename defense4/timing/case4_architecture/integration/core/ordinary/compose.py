#!/usr/bin/env python3
"""Namespace the actual ordinary role sources into N0/E0 and M1 pipelines.

No behavior, proof tables, initial owner values or packet processing are added.
Compiled target coexistence and external packet model execution remain gates.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent


def role(text,namespace):
    # Remove only SDK includes and the standalone role's main package.
    text=re.sub(r'^#include [^\n]+\n','',text,flags=re.M)
    text=re.split(r'^#ifndef (?:NATIVE_BINDING|ORDINARY_[ME])_NO_MAIN\b',text,flags=re.M)[0]
    names=set(re.findall(r'\b(?:header|struct|parser|control)\s+(\w+)',text))
    names.update(re.findall(r'\bconst\s+\w+\s+(\w+)\s*=',text))
    return re.sub(r'\b('+ '|'.join(sorted(names,key=len,reverse=True))+r')\b',lambda m:namespace+'_'+m[0],text)


def generate(program='joined'):
    if program not in ('joined','ne'):raise ValueError('unsupported program')
    names=('n.p4','m.p4','e.p4','work_record.p4') if program=='joined' else ('n.p4','e.p4','work_record.p4')
    inputs={name:(HERE/name).read_bytes() for name in names}
    n=inputs['work_record.p4'].decode()+'\n'+inputs['n.p4'].decode()
    source='/* Partial ordinary SELECT, local compiler/model only. */\n#include <core.p4>\n#include <tna.p4>\n'
    source+='\n'.join((role(n,'n'),role(inputs['e.p4'].decode(),'e')))
    if program=='joined':source+=role(inputs['m.p4'].decode(),'m')
    source+='\nPipeline(n_IgParser(),n_Ingress(),n_IgDeparser(),e_EgParser(),e_Egress(),e_EgDeparser()) p0;\n'
    if program=='joined':
        source+='Pipeline(m_IgParser(),m_Ingress(),m_IgDeparser(),m_EgParser(),m_Egress(),m_EgDeparser()) p1;\n'
        source+='Switch(p0,p1) main;\n'
    else:source+='Switch(p0) main;\n'
    return source,{name:hashlib.sha256(data).hexdigest() for name,data in inputs.items()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--program',choices=('joined','ne'),default='joined')
    args=parser.parse_args()
    source,inputs=generate(args.program)
    # Own generated candidate paths only; evidence directories use build.py's reservation.
    args.output.write_text(source)
    args.output.with_suffix('.inputs.json').write_text(json.dumps({'inputs':inputs,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'full_target':False},indent=2)+'\n')


if __name__=='__main__':main()

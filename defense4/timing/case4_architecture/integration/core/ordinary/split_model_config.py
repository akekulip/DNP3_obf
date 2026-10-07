#!/usr/bin/env python3
"""Exact artifact-scoped NF0/M1/E3 configuration, isolated licensed model only."""
import argparse
import copy
import json
from pathlib import Path
from make_model_config import load


def combine(nf,m,e):
    programs=[]
    for config,scope in zip((nf,m,e),([0],[1],[3])):
        devices=config.get('p4_devices',[])
        if len(devices)!=1 or devices[0].get('device-id')!=0:
            raise ValueError('same single model device0 required')
        items=devices[0].get('p4_programs',[])
        if len(items)!=1 or len(items[0].get('p4_pipelines',[]))!=1:
            raise ValueError('one source-bound pipeline per compiled program required')
        program=copy.deepcopy(items[0]);program['p4_pipelines'][0]['pipe_scope']=scope
        programs.append(program)
    if len({p['program-name'] for p in programs})!=3:
        raise ValueError('distinct program identities required')
    result=copy.deepcopy(nf);result['p4_devices'][0]['p4_programs']=programs
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('nf','m','e','output'):parser.add_argument(name,type=Path)
    args=parser.parse_args()
    nf,nb=load(args.nf);m,mb=load(args.m);e,eb=load(args.e)
    config=combine(nf,m,e)
    args.output.mkdir() # immutable attempt reservation
    (args.output/'ordinary.conf').write_text(json.dumps(config,indent=2)+'\n')
    (args.output/'bindings.json').write_text(json.dumps({'physical':False,'full_target':False,
        'programs':{'nf':nb,'m':mb,'e':eb},'pipe_scopes':{'nf':[0],'m':[1],'e':[3]}},indent=2)+'\n')


if __name__=='__main__':main()

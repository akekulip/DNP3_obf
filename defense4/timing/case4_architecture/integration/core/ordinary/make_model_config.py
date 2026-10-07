#!/usr/bin/env python3
"""Prepare configuration for licensed LOCAL model only, never target deployment.

Two independently verified programs share one modeled device with scopes0/1.
Missing SDK artifacts or stale source/snapshots fail closed. Programs are not
qualified as a complete Case4 target by these compiler or local model inputs.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[2]))
from build import verify_evidence


def combine(ne,m):
    result=copy.deepcopy(ne)
    for config in (result,m):
        if len(config.get('p4_devices',[]))!=1 or config['p4_devices'][0].get('device-id')!=0:
            raise ValueError('both programs must belong to the same single local device0')
        programs=config['p4_devices'][0].get('p4_programs',[])
        if len(programs)!=1 or len(programs[0].get('p4_pipelines',[]))!=1:
            raise ValueError('expected one exact compiled pipeline per program')
    second=copy.deepcopy(m['p4_devices'][0]['p4_programs'][0])
    first=result['p4_devices'][0]['p4_programs'][0]
    if first['program-name']==second['program-name']:raise ValueError('distinct program identities required')
    first['p4_pipelines'][0]['pipe_scope']=[0]
    second['p4_pipelines'][0]['pipe_scope']=[1]
    result['p4_devices'][0]['p4_programs'].append(second)
    return result


def load(evidence):
    gate=verify_evidence(evidence)
    for required in ('source_matches','snapshots_match','compiled_artifacts_verified'):
        if gate.get(required) is not True:raise ValueError('unverified '+str(evidence)+': '+required)
    manifest=json.loads((evidence/'manifest.json').read_text())
    if manifest['milestone']!='primitive_compiled':raise ValueError('exact source was not compiled')
    configs=list((evidence/'out').glob('*.conf'))
    if len(configs)!=1:raise ValueError('expected one compiled program configuration')
    return json.loads(configs[0].read_text()),{'evidence':str(evidence.resolve()),'manifest_sha256':hashlib.sha256((evidence/'manifest.json').read_bytes()).hexdigest(),'source_sha256':manifest['source_sha256'],'artifact_sha256':manifest['artifact_sha256']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ne',type=Path);parser.add_argument('m',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args()
    ne,nb=load(args.ne);m,mb=load(args.m)
    config=combine(ne,m)
    args.output.mkdir() # exclusive reservation, never overwrite an earlier trial
    (args.output/'ordinary.conf').write_text(json.dumps(config,indent=2)+'\n')
    (args.output/'bindings.json').write_text(json.dumps({'physical':False,'full_target':False,'programs':{'ne':nb,'m':mb},'pipe_scopes':{'ne':[0],'m':[1]}},indent=2)+'\n')


if __name__=='__main__':main()

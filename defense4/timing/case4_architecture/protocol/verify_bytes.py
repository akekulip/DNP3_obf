#!/usr/bin/env python3
"""Retain exact expected/source-control output bytes in an exclusive offline record.

No target model, packet acquisition, CP install or physical interface is used.
"""
import hashlib
import json
from pathlib import Path
import sys
import unittest
import primitives
from source_eval import Source,block
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/'framework/size'))
import case4_padding as codec

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def parsed(text,data,headers):
    s=Source(text,{'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb});start=0
    for header in headers:
        fields=[(f,w) for f,w in s.width.items() if f.startswith('hdr.'+header+'.')];count=sum(w for _,w in fields)//8
        bits=int.from_bytes(data[start:start+count],'big');left=count*8
        for field,width in fields:left-=width;s.env[field]=(bits>>left)&((1<<width)-1)
        start+=count
    if start!=len(data):raise ValueError('fixture parse coverage mismatch')
    return s

def run(output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    sources={p.name:digest(p) for p in HERE.glob('*.p4')}
    sources.update({p.name:digest(p) for p in HERE.glob('*.py')})
    sources.update({'tests/'+p.name:digest(p) for p in (HERE/'tests').glob('*.py')})
    report={'scope':'offline source-control fragments and independent byte codec; parser checksum outcomes supplied; no target execution','full_target':False,'source_sha256':sources,'success':False}
    try:
        decoy=codec.Decoy(201,bytes.fromhex('0101640000006400000000'));vectors=[]
        for fc,tp,app in ((3,255,207),(4,192,192)):
            native=codec.build_frame(bytes.fromhex('05641ac4ffff0100'),bytes((tp,app,fc))+bytes.fromhex('0c01280100ffff8102ffffffff0102030400'))
            expected=codec.expand_control(native,decoy)[0]
            text=(HERE/'tagged_cache_writer.p4').read_text();s=parsed(text,native,('dl','native','tail'))
            s.registers={(f'image_{i}',fc-3):{'generation':0,'data':0} for i in range(14)}
            s.runtime={'forwarding':('route',(12,)),'connection':('configure',(0xc900,1,1,0x64000000,0x64000000,1))}
            s.run(block(block(text,'control Ingress'),'apply{'))
            actual=b''.join(s.registers[(f'image_{i}',fc-3)]['data'].to_bytes(4,'big') for i in range(14))[:55]
            assert actual==expected
            vectors.append({'function':fc,'native_hex':native.hex(),'expected_image_hex':expected.hex(),'source_written_image_hex':actual.hex(),'oracle_tail21_hex':expected[34:].hex(),'full_replay55_hex':expected.hex()})
        head,user=codec.decode_frame(bytes.fromhex(vectors[0]['expected_image_hex']));head=bytearray(head);head[3]=0x44
        user=bytearray(user[:2]+b'\x81\0\0'+user[3:]);user[22]=3;user[40]=4;response=codec.build_frame(head,user)
        parts=[]
        for action in ('render_first','render_second'):
            s=parsed((HERE/'selected_carving.p4').read_text(),response,('dl','first','second','tail'))
            s.env.update({'hdr.tcp.seq':0xfffffff0,'hdr.tcp.flags':24});s.action(action)
            payload=b''.join(s.render(h) for h in ('dl','first','second','tail') if s.valid.get(h,True));parts.append({'payload_hex':payload.hex(),'seq':s.env['hdr.tcp.seq'],'flags':s.env['hdr.tcp.flags'],'ip_length':s.env['hdr.ip.len']})
        assert bytes.fromhex(parts[0]['payload_hex'])+bytes.fromhex(parts[1]['payload_hex'])==response
        (output/'vectors.json').write_text(json.dumps({'requests':vectors,'response_hex':response.hex(),'response_statuses':[3,4],'source_carves':parts},indent=2)+'\n')
        suite=unittest.defaultTestLoader.discover(str(HERE/'tests'))
        with (output/'tests.log').open('w') as log:result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
        report.update(tests=result.testsRun,success=result.wasSuccessful(),artifact_sha256={name:digest(output/name) for name in ('vectors.json','tests.log')})
    except BaseException as exc:
        report['error']=f'{type(exc).__name__}: {exc}';raise
    finally:(output/'manifest.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return report
if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: verify_bytes.py NEW_EVIDENCE_DIR')
    result=run(sys.argv[1]);print(json.dumps(result,indent=2));raise SystemExit(0 if result['success'] else 1)

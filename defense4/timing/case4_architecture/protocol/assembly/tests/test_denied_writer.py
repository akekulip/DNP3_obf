"""Characterize frozen admission bug without editing old source; repaired source fragment differs."""
import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];PROTO=HERE.parent
sys.path.insert(0,str(PROTO));sys.path.insert(0,str(PROTO.parents[1]/'framework/size'))
import case4_padding as padding
from source_eval import Source,block
class DeniedWriter(unittest.TestCase):
    def load(self,text):
        native=padding.build_frame(bytes.fromhex('05641ac4ffff0100'),bytes.fromhex('ffcF030c01280100ffff8102ffffffff0102030400'))
        s=Source(text,{'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb});at=0
        for header in ('dl','native','tail'):
            fields=[(f,w) for f,w in s.width.items() if f.startswith('hdr.'+header+'.')];count=sum(w for _,w in fields)//8;left=count*8;bits=int.from_bytes(native[at:at+count],'big')
            for field,width in fields:left-=width;s.env[field]=(bits>>left)&((1<<width)-1)
            at+=count
        s.runtime={'forwarding':('deny',()),'connection':('configure',(0xc900,1,1,0x64000000,0x64000000))};return s
    def test_frozen_denial_still_writes_and_admission_guard_prevents_it(self):
        text=(PROTO/'padding_cache_writer.p4').read_text();body=block(block(text,'control Ingress'),'apply{')
        baseline=self.load(text);baseline.run(body)
        self.assertEqual(baseline.env['md.drop_ctl'],1)
        self.assertEqual(len(baseline.registers),14) # Concrete unsafe frozen behavior.
        # Differential proposed source guard, not a claim of compiled root fix.
        guarded=self.load(text);tail=body[len('forwarding.apply();'):]
        guarded.run('forwarding.apply();if(md.drop_ctl==3w0){'+tail+'}')
        self.assertEqual(guarded.env['md.drop_ctl'],1);self.assertEqual(guarded.registers,{})

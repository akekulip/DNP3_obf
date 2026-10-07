import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parents[1]/'framework/size'))
import case4_padding as padding
import test_protocol as fixtures
from test_selected import parsed
from source_eval import block
class WriterBytes(unittest.TestCase):
    def test_all_actual_word_writes_are_exact_validated_image(self):
        decoy=padding.Decoy(201,bytes.fromhex('0101640000006400000000'))
        for name,tagged in (('padding_cache_writer.p4',False),('tagged_cache_writer.p4',True)):
            text=(HERE/name).read_text()
            for fc in (3,4):
                for broken in (None,8,26,33):
                    native=bytearray(fixtures.ExactImages().native(fc))
                    if broken is not None:native[broken]^=1
                    s=parsed(text,native)
                    if tagged:s.registers={(f'image_{i}',fc-3):{'generation':0,'data':0} for i in range(14)}
                    args=(0xc900,1,1,0x64000000,0x64000000)+( (2,) if tagged else () )
                    s.runtime={'forwarding':('route',(12,)),'connection':('configure',args)}
                    before={key:dict(value) if tagged else value for key,value in s.registers.items()}
                    s.run(block(block(text,'control Ingress'),'apply{'))
                    if broken is not None:self.assertEqual(s.registers,before);continue
                    words=[s.registers[(f'image_{i}',fc-3)] for i in range(14)]
                    if tagged:
                        self.assertEqual([w['generation'] for w in words],[2]*14);words=[w['data'] for w in words]
                    image=b''.join(w.to_bytes(4,'big') for w in words)
                    self.assertEqual(image[:55],padding.expand_control(bytes(native),decoy)[0]);self.assertEqual(image[55:],b'\0')
                    self.assertEqual(s.env.get('md.drop_ctl',0),0)
    def test_partial_word_conflict_cannot_forward_but_is_not_atomic_image(self):
        text=(HERE/'tagged_cache_writer.p4').read_text();native=fixtures.ExactImages().native(3);s=parsed(text,native)
        s.registers={(f'image_{i}',0):{'generation':0,'data':0} for i in range(14)}
        s.registers[('image_13',0)]={'generation':3,'data':123}
        s.runtime={'forwarding':('route',(12,)),'connection':('configure',(0xc900,1,1,0x64000000,0x64000000,2))}
        s.run(block(block(text,'control Ingress'),'apply{'))
        self.assertEqual(s.env['md.drop_ctl'],1)
        self.assertEqual(s.registers[('image_13',0)],{'generation':3,'data':123})
        self.assertEqual(s.registers[('image_0',0)]['generation'],2)

"""Source-fragment differential evidence, not full parser/target execution."""
from pathlib import Path
import sys
import unittest
HERE=Path(__file__).resolve().parents[1];PROTOCOL=HERE.parent;ARCH=PROTOCOL.parent
sys.path[:0]=[str(ARCH/'tests'),str(PROTOCOL),str(PROTOCOL/'tests'),str(ARCH.parent/'framework/size')]
from source_control import Source
from source_eval import block
import case4_padding as padding
import test_protocol as fixtures

TEXT=(HERE/'shared_egress.p4').read_text()

def ingest(native,allowed=True,broken_network=False,generation=2):
 s=Source(TEXT,{'m.parsed':1,'m.descriptor_valid':0,'m.replay_parsed':0,'m.ip_error':int(broken_network),'m.tcp_sum':0xffeb})
 offset=0
 for header in ('dl','native','tail'):
  for field,width in s.width.items():
   if field.startswith('hdr.'+header+'.'):
    count=width//8;s.env[field]=int.from_bytes(native[offset:offset+count],'big');offset+=count
 s.env['hdr.tcp.seq']=0xfffffff0;s.env['hdr.tcp.ack']=908;s.env['hdr.tcp.window']=812;s.env['hdr.tcp.flags']=0x18
 s.runtime={'forwarding':('route',(12,)) if allowed else ('deny',()),'connection':('configure',(0xc900,1,1,0x64000000,0x64000000,generation))}
 s.run(block(block(TEXT,'control Ingress('),' apply{'))
 return s

def image_writer(image,slot,registers=None):
 s=Source(TEXT,{'hdr.descriptor.generation':2,'hdr.descriptor.operation':2,'hdr.descriptor.slot':slot},registers=registers)
 for i in range(14):s.env[f'hdr.image.w{i}']=int.from_bytes(image[i*4:(i+1)*4],'big')
 s.run(block(block(TEXT,'control Egress('),' apply{'));return s

class SharedEgress(unittest.TestCase):
 def test_actual_native_validation_produces_exact_bytes_and_two_bank_slots(self):
  banks={}
  for fc in (3,4):
   native=fixtures.ExactImages().native(fc);s=ingest(native)
   self.assertEqual(s.env['m.descriptor_valid'],1);self.assertEqual(s.env['hdr.descriptor.slot'],fc-3)
   actual=b''.join(s.render(h) for h in ('dl','native','appended','last'))
   expected=padding.expand_control(native,padding.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
   self.assertEqual(actual,expected)
   eg=image_writer(actual,fc-3,banks);banks=eg.registers
   cached=b''.join(banks[(f'image_{i}',fc-3)].to_bytes(4,'big') for i in range(14))
   self.assertEqual(cached,expected+b'\0')
   self.assertNotEqual(eg.env.get('md.drop_ctl',0),1)
  self.assertEqual(len(banks),28)
 def test_denied_malformed_disabled_inputs_cannot_create_descriptor(self):
  native=fixtures.ExactImages().native(3)
  for bad in (8,26,33):
   damaged=bytearray(native);damaged[bad]^=1
   s=ingest(damaged);self.assertEqual(s.env['m.descriptor_valid'],0);self.assertEqual(s.env['md.drop_ctl'],1)
  for kwargs in ({'allowed':False},{'broken_network':True},{'generation':0}):
   s=ingest(native,**kwargs);self.assertEqual(s.env['m.descriptor_valid'],0);self.assertEqual(s.env['md.drop_ctl'],1)
  s=ingest(native,allowed=False);self.assertEqual(s.env.get('m.changed',0),0)
 def test_replay_exact_last_byte_then_shared_bank_render_keeps_current_tcp(self):
  for fc in (3,4):
   native=fixtures.ExactImages().native(fc);p=ingest(native);image=b''.join(p.render(h) for h in ('dl','native','appended','last'));banks=image_writer(image,fc-3).registers
   for allowed,matching,network,generation in ((True,True,True,2),(False,True,True,2),(True,False,True,2),(True,True,False,2),(True,True,True,0)):
    fields={'m.parsed':0,'m.descriptor_valid':0,'m.replay_parsed':1,'m.ip_error':int(not network),'m.tcp_sum':0xffeb,'hdr.replay.data':native[-1] if matching else native[-1]^1,'hdr.tcp.ack':123456,'hdr.tcp.window':50,'hdr.tcp.flags':0x18,'hdr.ip.id':420}
    s=Source(TEXT,fields,{'forwarding':('route',(12,)) if allowed else ('deny',()),'replay_context':('cached',(generation,0xfffffff0,native[-1],fc-3))})
    s.run(block(block(TEXT,'control Ingress('),' apply{'))
    valid=allowed and matching and network and generation>0
    self.assertEqual(s.env['m.descriptor_valid'],valid)
    if not valid:continue
    eg=Source(TEXT,s.env,registers=banks);before=dict(banks);eg.run(block(block(TEXT,'control Egress('),' apply{'))
    self.assertEqual(eg.render('image'),image);self.assertEqual(eg.registers,before)
    self.assertEqual(eg.env['hdr.tcp.seq'],0xfffffff0);self.assertEqual(eg.env['hdr.ip.len'],95)
    for key in ('hdr.tcp.ack','hdr.tcp.window','hdr.tcp.flags','hdr.ip.id'):self.assertEqual(eg.env[key],fields[key])
 def test_control_apply_is_outer_not_register_action(self):
  body=block(block(TEXT,'control Egress('),' apply{')
  self.assertIn('form_last_t.apply()',body);self.assertNotIn('rv=v',body)
 def test_unsupported_egress_op_and_zero_generation_never_touch_banks(self):
  for gen,op in ((0,2),(2,0),(2,3)):
   s=Source(TEXT,{'hdr.descriptor.generation':gen,'hdr.descriptor.operation':op})
   s.run(block(block(TEXT,'control Egress('),' apply{'))
   self.assertEqual(s.registers,{});self.assertEqual(s.env['md.drop_ctl'],1)

if __name__=='__main__':unittest.main()

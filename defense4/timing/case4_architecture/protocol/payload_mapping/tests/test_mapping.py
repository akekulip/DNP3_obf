"""Independent payload bytes/serial arithmetic, source-fragment execution only."""
import sys
from pathlib import Path
import struct
import unittest
HERE=Path(__file__).resolve().parents[1];ARCH=HERE.parents[1]
sys.path[:0]=[str(ARCH/'protocol/egress'),str(ARCH/'protocol/tests'),str(ARCH.parent/'framework/size')]
from source_packets import Source as PacketSource
import test_protocol as fixtures
from test_carving import response
import case4_padding as codec
from scapy.layers.inet import IP,TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

MASK=(1<<32)-1

def offset(value,origin):
 value=(value-origin)&MASK
 return value if value<(1<<31) else value-(1<<32)

def forward(value,base,valid=3):
 return (value+(20 if valid&1 and offset(value,base)>=35 else 0)+(20 if valid&2 and offset(value,(base+35)&MASK)>=35 else 0))&MASK

def inverse(value,base,valid=3):
 pos=offset(value,base)
 if valid&2 and pos>=90:
  return (base+(69 if pos<110 else pos-40))&MASK
 if valid&1 and pos>=35:
  return (base+(34 if pos<55 else pos-20))&MASK
 return value

def packet(payload,seq,ack,window=20,flags=0x18):
 return bytes(Ether(dst='00:11:22:33:44:55',src='66:77:88:99:aa:bb')/IP(src='10.0.0.1',dst='10.0.0.2',id=420,flags='DF')/TCP(sport=42000,dport=20000,seq=seq,ack=ack,window=window,flags=flags)/Raw(payload))

class Source(PacketSource):
 def table(self,name):
  if name!='network_gate':return super().table(name)
  import re
  from source_eval import block
  body=block(self.text,'table '+name+'{')
  keys=re.findall(r'((?:hdr\.\w+\.\w+|m\.\w+)):(?:exact|range);',body)
  for values,action in re.findall(r'\(([^()]+)\):(\w+)\(\);',body):
   terms=values.split(',');assert len(terms)==len(keys)
   matches=True
   for key,term in zip(keys,terms):
    if '..' in term:
     lo,hi=term.split('..');matches&=self.expr(lo)<=self.expr(key)<=self.expr(hi)
    else:matches&=self.expr(key)==self.expr(term)
   if matches:self.action(action);return
  self.action(re.search(r'default_action=(\w+)\(\)',body)[1])
 def expr(self,text):
  import re
  if '^' in text:
   left,right=text.split('^');return self.expr(left)^self.expr(right)
  text=re.sub(r'\b(?:ig\.ingress_port|p\.parser_err)\b',lambda m:str(self.env.get(m[0],0)),text)
  return super().expr(text)

def run(direction,payload,seq,ack,window=20,base=1000,valid=3,epoch=7,generation=2,port=68,parser_error=0,raw=None,second=None,route=True):
 text=(HERE/f'{"forward" if direction==1 else "reverse"}.p4').read_text().replace('ipcheck','ic').replace('tcpcheck','tc').replace('repaircheck','tc')
 prefix=struct.pack('!IIIHH',epoch,generation,5,3,0);raw=raw if raw is not None else packet(payload,seq,ack,window)
 source=Source(text,{'ig.ingress_port':port,'p.parser_err':parser_error})
 accepted,cursor=source.packet_parser(prefix+raw)
 keys={'hdr.ip.src':0x0a000001,'hdr.ip.dst':0x0a000002,'hdr.tcp.sport':42000,'hdr.tcp.dport':20000,'hdr.work.epoch':7}
 source.runtime={'forwarding':('route',(69,)) if route else ('deny',()),'connection':{'keys':keys,'action':'configure','args':(base,(base+35)&MASK if second is None else second,valid,direction)}}
 source.apply_control('Ingress')
 output=source.deparse('IgDeparser',('work','eth','ip','tcp'))+(prefix+raw)[cursor:]
 return source,output,prefix,accepted

class PayloadMapping(unittest.TestCase):
 def test_complete_bytes_all_payload_profiles_preserved_with_correct_incremental_checksum(self):
  native=fixtures.ExactImages().native(4)
  padded=codec.expand_control(native,codec.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
  read=bytes.fromhex('05640dc400000100f387c0c0010a020000165a2c')
  read_response=codec.build_frame(bytes.fromhex('0564004401000000'),bytes.fromhex('c0c08180000a02000016')+bytes(range(23)))
  payloads=(native,padded,response(),read,read_response,b'',native[-1:])
  for base in (1000,0xfffffff0):
   for direction in (1,2):
    for payload in payloads:
     seq=(base+35)&MASK;ack=(base+110)&MASK;window=20
     source,out,prefix,accepted=run(direction,payload,seq,ack,window,base)
     self.assertTrue(accepted);self.assertEqual(source.env.get('md.drop_ctl',0),0)
     mapped_seq=forward(seq,base) if direction==1 else seq
     mapped_ack=inverse(ack,base) if direction==2 else ack
     mapped_window=((inverse((ack+window)&MASK,base)-mapped_ack)&MASK) if direction==2 else window
     self.assertEqual(out,prefix+packet(payload,mapped_seq,mapped_ack,mapped_window))
     self.assertEqual(out[-len(payload):],payload) if payload else None
 def test_both_boundary_partial_ack_clamps_window_edges_and_wrap(self):
  for base in (1000,0xfffffff0):
   for position in (-1,0,34,35,36,54,55,69,89,90,91,109,110,130):
    for window in (0,1,20,65535):
     ack=(base+position)&MASK
     source,out,prefix,_=run(2,bytes(range(57)),700,ack,window,base)
     expected_ack=inverse(ack,base);expected_window=(inverse((ack+window)&MASK,base)-expected_ack)&MASK
     self.assertEqual(source.env.get('md.drop_ctl',0),0)
     self.assertEqual(out,prefix+packet(bytes(range(57)),700,expected_ack,expected_window))
 def test_sequence_boundaries_and_zero_one_two_insertions(self):
  for base in (1000,0xfffffff0):
   for valid in (0,1,3):
    for position in (-1,0,34,35,36,69,70,71,130):
     seq=(base+position)&MASK
     source,out,prefix,_=run(1,b'unchanged',seq,700,base=base,valid=valid)
     self.assertEqual(source.env.get('md.drop_ctl',0),0)
     self.assertEqual(out,prefix+packet(b'unchanged',forward(seq,base,valid),700))
    source,out,prefix,_=run(2,b'unchanged',700,(base+54)&MASK,20,base,valid=valid)
    ack=inverse((base+54)&MASK,base,valid);window=(inverse((base+74)&MASK,base,valid)-ack)&MASK
    self.assertEqual(out,prefix+packet(b'unchanged',700,ack,window))
 def test_incremental_checksum_zero_representation_matches_full_recompute(self):
  for direction in (1,2):
   seq,ack=(1035,700) if direction==1 else (700,1110)
   new_seq,new_ack=(1055,700) if direction==1 else (700,1070)
   for zero_after in (False,True):
    # Scapy supplies the complementary payload word that forces checksum0.
    basis=packet(b'\0\0',new_seq if zero_after else seq,new_ack if zero_after else ack)
    payload=basis[50:52]
    source,out,prefix,_=run(direction,payload,seq,ack)
    expected=packet(payload,new_seq,new_ack)
    self.assertEqual(out,prefix+expected)
    self.assertEqual((expected if zero_after else packet(payload,seq,ack))[50:52],b'\0\0')
 def test_half_range_positive_inverse_window_growth_is_refused(self):
  source,_,_,_=run(2,b'payload',700,(35+0x7ffffff6)&MASK,20,base=0)
  self.assertEqual(source.env['md.drop_ctl'],1)
  self.assertEqual(source.env.get('m.changed',0),0)
 def test_private_admission_epoch_generation_flags_and_geometry_refuse(self):
  for kwargs in ({'epoch':8},{'generation':0},{'port':9},{'parser_error':1},{'valid':2},{'valid':255},{'second':1040}):
   source,_,_,_=run(1,b'ABC',1000,700,**kwargs)
   self.assertEqual(source.env['md.drop_ctl'],1,kwargs);self.assertEqual(source.env.get('m.changed',0),0,kwargs)
  for mutate in (lambda p:setattr(p[IP],'version',6),lambda p:setattr(p[TCP],'flags','FA'),lambda p:setattr(p[TCP],'urgptr',1),lambda p:setattr(p[IP],'flags','MF'),lambda p:setattr(p[IP],'ttl',0)):
   raw=Ether(packet(b'ABC',1000,700));mutate(raw);del raw[IP].chksum;del raw[TCP].chksum
   source,_,_,_=run(1,b'ABC',1000,700,raw=bytes(raw))
   self.assertEqual(source.env['md.drop_ctl'],1);self.assertEqual(source.env.get('m.changed',0),0)
 def test_missing_route_wrong_tuple_bad_ip_checksum_and_parser_error_do_not_map(self):
  for direction in (1,2):
   for kwargs in ({'route':False},{'parser_error':1},{'epoch':8},{'generation':0}):
    source,_,_,_=run(direction,b'payload',1035,1110,**kwargs)
    self.assertEqual(source.env['md.drop_ctl'],1)
    self.assertEqual(source.env.get('m.changed',0),0)
   wrong_tuple=Ether(packet(b'payload',1035,1110));wrong_tuple[TCP].sport=43000
   del wrong_tuple[TCP].chksum
   bad_ip=bytearray(packet(b'payload',1035,1110));bad_ip[24]^=1
   for raw in (bytes(wrong_tuple),bytes(bad_ip)):
    source,_,_,_=run(direction,b'payload',1035,1110,raw=raw)
    self.assertEqual(source.env['md.drop_ctl'],1)
    self.assertEqual(source.env.get('m.changed',0),0)
 def test_upstream_full_tcp_validation_is_a_material_gate(self):
  raw=bytearray(packet(b'ABC',1035,700));raw[-1]^=1
  source,_,_,_=run(1,b'ABC',1035,700,raw=bytes(raw))
  # Private pass does not pretend to revalidate arbitrary payload/TCP checksum.
  self.assertEqual(source.env.get('md.drop_ctl',0),0)
  self.assertEqual(source.env['m.changed'],1)
 def test_current_work_record_authority_is_a_material_gate(self):
  # A nonzero generation is syntactic admission, not a current-owner lookup.
  for direction in (1,2):
   source,_,_,_=run(direction,b'payload',1035,1110,generation=999)
   self.assertEqual(source.env.get('md.drop_ctl',0),0)
   self.assertEqual(source.env['m.changed'],1)

if __name__=='__main__':unittest.main()

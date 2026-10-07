"""Counterexamples in root composition, source fragments only; no target traffic."""
from pathlib import Path
import re
import sys
import unittest
HERE=Path(__file__).resolve().parent;ARCH=HERE.parents[1]
sys.path[:0]=[str(ARCH/'protocol/egress'),str(ARCH/'protocol/egress/tests'),str(ARCH/'protocol/tests'),str(ARCH/'tests'),str(ARCH.parent/'framework/size')]
from source_packets import Source
from source_eval import block
from test_packets import packet
from test_carving import response

CURRENT=(ARCH/'integration/egress_wire.p4').read_text()
TEXT=(ARCH/'integration/evidence/egress_wire_02/source/egress_wire.p4').read_text()

def role_source(role,start,end,text=TEXT):
 return text[text.index(start):text.index(end)].replace(role+'_','')

class RootComposition(unittest.TestCase):
 def test_unicast_response_without_split_context_reaches_cache_and_writes(self):
  carving=role_source('carving','header carving_eth_h','/* Native READ20')
  # Valid57 response + Ethernet suffix. MAC positions8/9 impersonate op2/slot0
  # only after root wrongly sends a descriptor-free unicast into its cache parser.
  wire=bytearray(packet(response()));wire[6:12]=bytes.fromhex('aabb0200ccdd');wire=bytes(wire)+b'\0'*10
  ig=Source(carving);accepted,consumed=ig.packet_parser(wire)
  self.assertTrue(accepted);self.assertEqual(ig.env['m.tcp_sum'],0xffeb)
  ig.runtime={'forwarding':('route',(64,))};ig.run(block(block(carving,'control Ingress('),'\napply{'))
  self.assertEqual(ig.env.get('md.drop_ctl',0),0)
  self.assertEqual(ig.env.get('tm.mcast_grp_a',0),0)
  self.assertEqual(ig.env.get('tm.bypass_egress',0),0)
  forwarded=ig.deparse('IgDeparser',('eth','ip','tcp','dl','first','second','tail'))+wire[consumed:]
  self.assertEqual(forwarded,wire)
  rootparser=block(TEXT,'parser EgParser(')
  select=block(block(rootparser,'state start{'),'select(eg.egress_rid)')
  self.assertIn('default:cache_state;',select) # Unicast RID0 selects cache.
  cache=role_source('cache','/* Actual native35','header forward_eth_h')
  eg=Source(cache);accepted,consumed=eg.packet_parser(forwarded,'EgParser')
  self.assertTrue(accepted);self.assertEqual(consumed,len(forwarded))
  self.assertEqual(eg.env['hdr.descriptor.operation'],2)
  self.assertEqual(eg.env['hdr.descriptor.slot'],0)
  eg.apply_control('Egress')
  self.assertEqual(len(eg.registers),14) # Descriptor-free external bytes mutated allbanks.
  self.assertEqual(eg.env.get('md.drop_ctl',0),0)
 def test_repaired_unicast_bypasses_egress_and_valid_split_still_enters(self):
  carving=role_source('carving','header carving_eth_h','/* Native READ20',CURRENT)
  for allowed,split,broken in ((True,False,False),(True,True,False),(False,True,False),(True,True,True)):
   frame=bytearray(response())
   if broken:frame[26]^=1
   ig=Source(carving);ig.packet_parser(packet(bytes(frame)))
   ig.runtime={'forwarding':('route',(64,)) if allowed else ('deny',())}
   if split:ig.runtime['connection']=('split',(7,))
   ig.run(block(block(carving,'control Ingress('),'\napply{'))
   valid=allowed and split and not broken
   self.assertEqual(ig.env.get('tm.mcast_grp_a',0),7 if valid else 0)
   if allowed:self.assertEqual(ig.env['tm.bypass_egress'],0 if valid else 1)
   if not allowed:self.assertEqual(ig.env['md.drop_ctl'],1)
 def test_carver_admission_deny_still_sets_multicast_metadata(self):
  carving=role_source('carving','header carving_eth_h','/* Native READ20')
  ig=Source(carving);ig.packet_parser(packet(response()))
  ig.runtime={'forwarding':('deny',()),'connection':('split',(7,))}
  ig.run(block(block(carving,'control Ingress('),'\napply{'))
  self.assertEqual(ig.env['md.drop_ctl'],1)
  self.assertEqual(ig.env['tm.mcast_grp_a'],7)
  # Drop metadata may suppress all copies; this is an admission guard gap,
  # not independent evidence that denied traffic physically escapes.

if __name__=='__main__':unittest.main()

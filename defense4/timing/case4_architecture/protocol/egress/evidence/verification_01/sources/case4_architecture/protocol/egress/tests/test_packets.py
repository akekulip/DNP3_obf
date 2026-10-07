"""Raw-byte source-parser differential; explicitly not switch-model evidence."""
from pathlib import Path
import sys
import struct
import unittest
HERE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(HERE),str(HERE.parent/'tests'),str(HERE.parents[2]/'framework/size')]
from source_packets import Source,checksum,folded
import test_protocol as fixtures
import case4_padding as codec
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP,TCP
from scapy.packet import Raw
TEXT=(HERE/'shared_egress.p4').read_text()
ETH=bytes.fromhex('00112233445566778899aabb0800');SRC=bytes((10,0,0,1));DST=bytes((10,0,0,2))

def packet(payload,seq=0xfffffff0,ack=123456,window=812,version=4,ihl=5,flags=0x18,reserved=0,urgent=0,fragment=0x4000,offset=5):
 tcp=struct.pack('!HHIIBBHHH',42000,20000,seq,ack,(offset<<4)|reserved,flags,window,0,urgent)+payload
 pseudo=SRC+DST+bytes((0,6))+len(tcp).to_bytes(2,'big');cs=checksum(pseudo+tcp);tcp=tcp[:16]+cs.to_bytes(2,'big')+tcp[18:]
 ip=struct.pack('!BBHHHBBH4s4s',(version<<4)|ihl,0,20+len(tcp),420,fragment,64,6,0,SRC,DST)
 ip=ip[:10]+checksum(ip).to_bytes(2,'big')+ip[12:]
 return ETH+ip+tcp

def expected_packet(payload,seq=0xfffffff0,ack=123456,window=812,flags=0x18):
 # Independent existing-library serialization/checksum implementation; no sends.
 return bytes(Ether(dst='00:11:22:33:44:55',src='66:77:88:99:aa:bb',type=0x0800)/
              IP(version=4,ihl=5,tos=0,id=420,flags=2,frag=0,ttl=64,proto=6,src='10.0.0.1',dst='10.0.0.2')/
              TCP(sport=42000,dport=20000,seq=seq,ack=ack,dataofs=5,reserved=0,flags=flags,window=window,urgptr=0)/Raw(payload))

def ingress(raw,allowed=True,replay=None):
 source=Source(TEXT);source.packet_parser(raw)
 source.runtime={'forwarding':('route',(12,)) if allowed else ('deny',()),'connection':('configure',(0xc900,1,1,0x64000000,0x64000000,2))}
 if replay is not None:source.runtime['replay_context']=('cached',replay)
 source.apply_control('Ingress');return source

def output(source,banks=None):
 internal=source.deparse('IgDeparser',('descriptor','eth','ip','tcp','replay','dl','native','tail','appended','last'))
 eg=Source(TEXT,registers=banks);accepted,consumed=eg.packet_parser(internal,'EgParser')
 assert accepted and consumed==len(internal)
 eg.apply_control('Egress');raw=eg.deparse('EgDeparser',('eth','ip','tcp','image'))
 return raw,eg,internal

class RawPackets(unittest.TestCase):
 def test_actual_select_operate_store_then_tail_replay_are_exact_complete_packets(self):
  banks={}
  for fc in (3,4):
   native=fixtures.ExactImages().native(fc);expected=codec.expand_control(native,codec.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
   source=ingress(packet(native));self.assertEqual(source.env['m.tcp_sum'],0xffeb);self.assertEqual(source.env['m.descriptor_valid'],1)
   raw,eg,internal=output(source,banks);banks=eg.registers
   self.assertEqual(raw,expected_packet(expected));self.assertEqual(len(internal),12+len(raw));self.assertEqual(len(banks),14*(fc-2))
   replay=ingress(packet(native[-1:],seq=18,ack=987654,window=0,flags=0x10),replay=(2,0xfffffff0,native[-1],fc-3))
   self.assertEqual(replay.env['m.descriptor_valid'],1)
   raw,eg,internal=output(replay,banks)
   self.assertEqual(raw,expected_packet(expected,seq=0xfffffff0,ack=987654,window=0,flags=0x10));self.assertEqual(len(internal),12+14+20+21)
   self.assertEqual(folded(raw[14:34]),65535)
   self.assertEqual(folded(SRC+DST+bytes((0,6))+len(raw[34:]).to_bytes(2,'big')+raw[34:]),65535)
 def test_checksummed_unsupported_ip_tcp_headers_do_not_produce_descriptor(self):
  native=fixtures.ExactImages().native(3)
  for change in ({'version':6},{'ihl':6},{'offset':6},{'reserved':1},{'urgent':1},{'fragment':0x2000},{'fragment':0x8000},{'fragment':1},{'flags':0x19},{'flags':0x14},{'flags':2}):
   for payload in (native,native[-1:]):
    source=ingress(packet(payload,**change),replay=(2,0xfffffff0,native[-1],0))
    self.assertEqual(source.env['m.descriptor_valid'],0,change);self.assertEqual(source.env['md.drop_ctl'],1)
 def test_all_crc_blocks_bad_network_truncation_missing_context_and_denial_refused(self):
  native=fixtures.ExactImages().native(3)
  for offset in (8,26,33):
   broken=bytearray(native);broken[offset]^=1;self.assertEqual(ingress(packet(broken)).env['m.descriptor_valid'],0)
  good=packet(native)
  for offset in (24,50,70):
   broken=bytearray(good);broken[offset]^=1;self.assertEqual(ingress(bytes(broken)).env['m.descriptor_valid'],0)
  for end in (0,14,34,54,70,len(good)-1):self.assertEqual(ingress(good[:end]).env['m.descriptor_valid'],0)
  self.assertEqual(ingress(good,allowed=False).env['m.descriptor_valid'],0)
  self.assertEqual(ingress(packet(native[-1:],seq=18)).env['m.descriptor_valid'],0)
 def test_crc_valid_unsupported_object_shapes_refused(self):
  native=fixtures.ExactImages().native(3);head,user=codec.decode_frame(native)
  for index,value in ((2,5),(3,11),(4,2),(5,0x17),(6,2),(20,1)):
   wrong=bytearray(user);wrong[index]=value
   self.assertEqual(ingress(packet(codec.build_frame(head,bytes(wrong)))).env['m.descriptor_valid'],0)
 def test_selection_authority_is_explicitly_missing_from_primitive(self):
  native=fixtures.ExactImages().native(4);head,user=codec.decode_frame(native)
  wrong=bytearray(user);wrong[10]^=1 # Change CRC-valid real CROB code after SELECT.
  different=codec.build_frame(head,bytes(wrong));source=ingress(packet(different))
  self.assertEqual(source.env['m.descriptor_valid'],1)
  raw,eg,_=output(source)
  expected=codec.expand_control(different,codec.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
  self.assertEqual(raw,expected_packet(expected)) # This is NOT a selected-object association proof.
 def test_ethernet_prefix_cannot_supply_internal_descriptor(self):
  native=fixtures.ExactImages().native(3)
  # Bytes that would resemble valid internal op2 descriptor are still parsed as Ethernet.
  forged=bytes.fromhex('00000002fffffff002000000')+packet(native)
  self.assertEqual(ingress(forged).env['m.descriptor_valid'],0)

if __name__=='__main__':unittest.main()

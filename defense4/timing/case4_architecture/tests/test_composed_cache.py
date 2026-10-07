"""Actual composed cache controls; no intrinsic/TM/target execution implied."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'protocol/egress/tests'),str(ROOT/'protocol/egress'),str(ROOT/'protocol/tests')]
import test_packets as fixtures
from source_packets import Source


class SharedDispatch(unittest.TestCase):
    def setUp(self):
        text=(ROOT/'integration/egress_selected_wire.p4').read_text()
        self.text=text[text.index('/* Actual native35'):text.index('header forward_eth_h')].replace('cache_','')

    def ingress(self,wire,replay=None):
        source=Source(self.text)
        source.packet_parser(wire)
        source.runtime={'forwarding':('route',(12,)),
            'connection':('configure',(0xc900,1,1,0x64000000,0x64000000,2))}
        if replay:source.runtime['replay_context']=('cached',replay)
        source.apply_control('Ingress')
        return source.deparse('IgDeparser',('descriptor','eth','ip','tcp','replay','dl','native','tail','appended','last'))

    def egress(self,internal,banks):
        source=Source(self.text,registers=banks)
        accepted,consumed=source.packet_parser(internal,'EgParser')
        self.assertTrue(accepted)
        self.assertEqual(consumed,len(internal))
        source.apply_control('Egress')
        return source,source.deparse('EgDeparser',('eth','ip','tcp','image'))

    def test_same_dispatch_banks_store_and_replay_both_exact_phase_packets(self):
        banks={}
        for function in (3,4):
            native=fixtures.fixtures.ExactImages().native(function)
            expected=fixtures.codec.expand_control(native,fixtures.codec.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
            source,wire=self.egress(self.ingress(fixtures.packet(native)),banks)
            banks=source.registers
            self.assertEqual(wire,fixtures.expected_packet(expected))
            self.assertEqual(len(source.registers),14*(function-2))
            source,wire=self.egress(self.ingress(fixtures.packet(native[-1:],seq=18,ack=987654,window=0,flags=0x10),
                replay=(2,0xfffffff0,native[-1],function-3)),banks)
            self.assertEqual(wire,fixtures.expected_packet(expected,ack=987654,window=0,flags=0x10))
            self.assertEqual(len(source.registers),14*(function-2))

    def test_zero_descriptor_generation_never_mutates_the_shared_banks(self):
        native=fixtures.fixtures.ExactImages().native(3)
        internal=bytearray(self.ingress(fixtures.packet(native)))
        internal[:4]=bytes(4)
        source,_=self.egress(bytes(internal),{})
        self.assertEqual(source.registers,{})
        self.assertEqual(source.env['md.drop_ctl'],1)


if __name__=='__main__':unittest.main()

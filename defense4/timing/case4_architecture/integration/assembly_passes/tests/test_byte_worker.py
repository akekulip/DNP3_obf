"""Independent per-byte expectations for the separate stateless merge worker."""
from pathlib import Path
import sys
import unittest

ARCH=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ARCH/'protocol/assembly'),str(ARCH/'protocol'),str(ARCH/'tests'),str(ARCH/'integration/assembly_passes')]
from assembly_eval import Source as RangeSource
from source_control import Source as CheckedSource
from source_eval import block
from generate import byte_worker


class Source(RangeSource,CheckedSource):pass


class ByteMerge(unittest.TestCase):
    def setUp(self):
        self.text=byte_worker()
        self.bytes=bytes((index*17+3)&255 for index in range(35))

    def fragment(self,offset,data,expected):
        env={'p.parser_err':0,'m.private':1,'m.parsed':1,'m.ip_error':False,
            'm.tcp_sum':0xffeb,'m.length':len(data),'m.full_length':len(data),
            'hdr.ip.ttl':64,'hdr.ref.epoch':1,'hdr.ref.generation':7,
            'hdr.ref.reserved':0,'hdr.fragment.reserved':0,
            'hdr.fragment.offset':offset,'hdr.fragment.length':len(data),
            'hdr.fragment.hops':1,'hdr.ref.event':3,
            **{f'hdr.b{i}.data':value for i,value in enumerate(data)}}
        for bank,word in enumerate(expected):
            env[f'hdr.expected.mask{bank}']=word>>24
            for j in range(3):env[f'hdr.expected.data{bank}_{j}']=(word>>(16-8*j))&255
        for _ in range(3):
            source=Source(self.text,env)
            source.run(block(block(self.text,'control Ingress('),'apply{'))
            self.assertEqual(source.registers,{})
            if source.env.get('hdr.ref.event')==6 or source.env.get('md.drop_ctl',0):return source,None
            env=source.env
        got=[]
        for bank in range(12):
            word=env[f'hdr.candidate.mask{bank}']<<24
            for j in range(3):word|=env[f'hdr.candidate.data{bank}_{j}']<<(16-8*j)
            got.append(word)
        return source,got

    def test_every_offset_duplicates_and_reordered_join_preserve_word_wire_layout(self):
        for offset in range(35):
            source,got=self.fragment(offset,self.bytes[offset:],[0]*12)
            wanted=[0]*12
            for position in range(offset,35):
                bank,j=divmod(position,3)
                wanted[bank]|=(1<<(24+j))|(self.bytes[position]<<(16-8*j))
            self.assertEqual(got,wanted)
            _,duplicate=self.fragment(offset,self.bytes[offset:],wanted)
            self.assertEqual(duplicate,wanted)
            _,joined=self.fragment(0,self.bytes[:offset] or self.bytes[:1],wanted)
            for position in range(35):
                bank,j=divmod(position,3)
                self.assertEqual((joined[bank]>>(16-8*j))&255,self.bytes[position])
                self.assertEqual((joined[bank]>>(24+j))&1,1)

    def test_conflicts_and_invalid_presence_return_fault_without_scratch_mutation(self):
        source,got=self.fragment(1,b'\x08',[(2<<24)|(7<<8)]+[0]*11)
        self.assertIsNone(got)
        self.assertEqual(source.env['hdr.ref.event'],6)
        self.assertEqual(source.env['hdr.expected.data0_1'],7)
        source,got=self.fragment(0,self.bytes,[0x80000000]+[0]*11)
        self.assertIsNone(got)
        self.assertEqual(source.env['hdr.ref.event'],6)


if __name__=='__main__':unittest.main()

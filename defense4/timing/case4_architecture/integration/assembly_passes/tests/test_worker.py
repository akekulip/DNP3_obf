"""Separate worker keeps snapshots immutable and carries exact merged words."""
from pathlib import Path
import sys
import unittest

ARCH=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ARCH/'protocol/assembly'),str(ARCH/'protocol'),str(ARCH/'tests'),str(ARCH/'integration/assembly_passes')]
from assembly_eval import Source as RangeSource
from source_control import Source as CheckedSource
from source_eval import block
from generate import worker


class Source(RangeSource,CheckedSource):pass


class MergeWorker(unittest.TestCase):
    def run_worker(self,offset,length,**changes):
        text=worker()
        expected=bytes((index*17+3)&255 for index in range(35))
        fields={'p.parser_err':0,'m.private':1,'m.parsed':1,'m.ip_error':False,
            'm.tcp_sum':0xffeb,'m.length':length,'m.full_length':length,
            'hdr.ip.ttl':64,'hdr.ref.epoch':1,'hdr.ref.generation':7,
            'hdr.ref.reserved':0,'hdr.fragment.reserved':0,
            'hdr.fragment.offset':offset,'hdr.fragment.length':length,
            'hdr.fragment.hops':1,'hdr.ref.event':3,
            **{f'hdr.b{i}.data':value for i,value in enumerate(expected[offset:offset+length])},
            **{f'hdr.expected.w{i}':0 for i in range(12)}}
        fields.update(changes)
        observed=[]
        for _ in range(3):
            source=Source(text,fields)
            source.run(block(block(text,'control Ingress('),'apply{'))
            observed.append(source.env.get('hdr.ref.event'))
            if source.env.get('md.drop_ctl',0):break
            fields=source.env
        return source,observed,expected

    def test_all_offsets_and_consistent_payload_leave_only_expected_candidate(self):
        for offset in range(35):
            source,events,expected=self.run_worker(offset,35-offset)
            self.assertEqual(events,[7,8,2])
            self.assertEqual(source.registers,{})
            for bank in range(12):
                wanted=0
                for j in range(min(3,35-3*bank)):
                    position=3*bank+j
                    if position>=offset:
                        wanted|=(1<<(24+j))|(expected[position]<<(16-8*j))
                self.assertEqual(source.env[f'hdr.candidate.w{bank}'],wanted)
                self.assertEqual(source.env[f'hdr.expected.w{bank}'],0)

    def test_errors_bad_extent_and_unknown_events_do_not_merge(self):
        for changes in ({'p.parser_err':1},{'hdr.ip.ttl':0},
            {'hdr.fragment.hops':16},{'hdr.ref.epoch':0},
            {'hdr.fragment.reserved':1},{'hdr.fragment.offset':34}):
            source,_,_=self.run_worker(0,35,**changes)
            self.assertEqual(source.env.get('md.drop_ctl'),1)
            self.assertNotIn('hdr.candidate.w0',source.env)
        source,events,_=self.run_worker(0,35,**{'hdr.ref.event':99})
        self.assertEqual(events[0],6)
        self.assertNotIn('hdr.candidate.w0',source.env)


if __name__=='__main__':unittest.main()

"""Actual source branches; supplied network checks are supporting evidence only."""
from pathlib import Path
import sys
import unittest

ARCH=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ARCH/'protocol/assembly/tests'),str(ARCH/'protocol/assembly'),
    str(ARCH/'protocol'),str(ARCH/'tests')]
import test_producer as fixture
from assembly_eval import Source as RangeSource
from source_control import Source as CheckedSource
from source_eval import block


class Source(RangeSource,CheckedSource):
    pass


class AssemblyReturns(unittest.TestCase):
    def setUp(self):
        self.text=(ARCH/'integration/assembly_passes/producer.p4').read_text()
        self.old_source=fixture.Source
        fixture.Source=Source
        self.fixture=fixture.Producer()

    def tearDown(self):
        fixture.Source=self.old_source

    def test_three_merge_returns_touch_only_their_four_banks(self):
        payload=self.fixture.native()
        fields=self.fixture.fields(0,payload,1000)
        banks={('origin',0):{'generation':0,'observation':0}}
        observed=[]
        for hop in range(8):
            source=self.fixture.advance(self.text,fields,banks,hop*1024,1000)
            event=source.env.get('hdr.ref.event',0)
            observed.append(event)
            if source.env.get('m.publish'):
                self.assertEqual(source.render('frame'),payload)
                break
            self.assertFalse(source.env.get('md.drop_ctl',0))
            fields={key:value for key,value in source.env.items() if key.startswith('hdr.')}
            fields.update({'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb,
                'm.private':1,'m.length':35,'m.full_length':35})
        self.assertEqual(observed,[3,7,8,2,4,4])
        apply=block(block(self.text,'control Ingress'),'apply{')
        for event,first in ((3,0),(7,4),(8,8)):
            branch=block(apply,'else if(hdr.ref.event==16w'+str(event)+')')
            for bank in range(12):
                self.assertEqual('patch_'+str(bank)+'.apply();' in branch,first<=bank<first+4)

    def test_reordered_overlap_crc_fault_and_wrap_still_obey_real_source(self):
        # Independent codec bytes and retained adversarial fixtures, executed
        # against this source and the corrected common-suffix interpreter.
        old=fixture.HERE
        try:
            fixture.HERE=ARCH/'integration/assembly_passes'
            for test in ('test_actual_reordered_fragments_origin_zero_wrap_and_full_crc',
                'test_bad_complete_crc_sticky_and_expired_do_not_publish',
                'test_foreign_private_cookie_cannot_poison_and_hops_are_bounded'):
                getattr(self.fixture,test)()
        finally:
            fixture.HERE=old

    def test_parser_error_never_mints_origin_or_mutates_scratch(self):
        banks={('origin',0):{'generation':0,'observation':0}}
        fields=self.fixture.fields(0,self.fixture.native(),1000)
        fields['p.parser_err']=1
        source=self.fixture.advance(self.text,fields,banks,0,1000)
        self.assertEqual(source.env.get('md.drop_ctl',0),1)
        self.assertEqual(banks,{('origin',0):{'generation':0,'observation':0}})


if __name__=='__main__':unittest.main()

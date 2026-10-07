import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parent))
from reference import Assembly
from source_eval import Source
class Buckets(unittest.TestCase):
    def test_atomic_cas_reads_and_stale_conflict(self):
        text=(HERE/'buckets.p4').read_text()
        for bank in range(12):
            for oldgen,gen,old,expected,new,success in ((1,1,0,0,0x7010203,True),(1,1,0x7010203,0x7010203,0x7010203,True),(1,1,5,6,7,False),(2,1,5,5,7,False)):
                s=Source(text,{'m.generation':gen,f'hdr.expected.w{bank}':expected,f'hdr.candidate.w{bank}':new},registers={(f'bucket_{bank}',0):{'generation':oldgen,'encoded':old}})
                status=s.register(f'cas_{bank}',0)
                self.assertEqual(status==0,success)
                self.assertEqual(s.registers[(f'bucket_{bank}',0)],{'generation':oldgen,'encoded':new if success else old})
    def test_reference_zero_wrap_reorder_duplicates_conflicts_deadline(self):
        for origin in (0,0xfffffff0):
            a=Assembly(8);self.assertEqual(a.add(8,17,b'x'*18,origin),'pending');self.assertEqual(a.origin,origin)
            self.assertEqual(a.add(8,0,b'y'*17,(origin+1)&0xffffffff),'complete')
            self.assertEqual(a.add(8,17,b'x'*18,(origin+2)&0xffffffff),'complete')
            self.assertEqual(a.add(7,0,b'z',origin),'foreign');self.assertFalse(a.fault)
            self.assertEqual(a.add(8,0,b'z',(origin+3)&0xffffffff),'fault')
            b=Assembly(9);b.add(9,0,b'x',origin);self.assertEqual(b.add(9,1,b'y',(origin+30_000_000)&0xffffffff),'fault')
            c=Assembly(10);self.assertEqual(c.add(10,0,b'x',origin,17),'fault')

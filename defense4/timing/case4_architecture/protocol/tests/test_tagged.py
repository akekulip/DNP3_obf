import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from source_eval import Source
class TaggedWords(unittest.TestCase):
    def test_actual_atomic_bodies_newer_equal_conflict_stale_and_max(self):
        text=(HERE/'tagged_cache_writer.p4').read_text()
        for bank in range(14):
            for oldgen,newgen,oldword,newword,accepted in ((0,1,0,123,True),(1,1,123,123,True),(1,1,123,124,False),(2,1,123,123,False),(2,1,123,124,False),(0xfffffffe,0xffffffff,123,124,True),(0xffffffff,1,123,124,False)):
                old={'generation':oldgen,'data':oldword}
                s=Source(text,{'m.work_generation':newgen,f'm.image_word{bank}':newword},registers={(f'image_{bank}',0):old})
                s.env[f'm.status{bank}']=s.register(f'write_{bank}',0)
                s.action(f'check_{bank}')
                status=s.env[f'm.status{bank}']
                self.assertEqual(status==0,accepted)
                self.assertEqual(s.registers[(f'image_{bank}',0)],{'generation':newgen,'data':newword} if accepted else old)
    def test_publication_requires_every_full_status_zero(self):
        text=(HERE/'tagged_cache_writer.p4').read_text()
        for bank in range(14):
            for status in (1,2,0x80000000,0xfffffffe):
                s=Source(text,{f'm.status{bank}':status});s.table('cache_results')
                self.assertEqual(s.env['md.drop_ctl'],1)
        s=Source(text);s.table('cache_results');self.assertEqual(s.env.get('md.drop_ctl',0),0)

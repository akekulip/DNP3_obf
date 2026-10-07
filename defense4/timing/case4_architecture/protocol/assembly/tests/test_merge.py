import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE.parent));sys.path.insert(0,str(HERE))
from assembly_eval import Source
class Merge(unittest.TestCase):
    def test_actual_offset_tables_all_reordered_overlaps_and_duplicates(self):
        text=(HERE/'merge.p4').read_text();original=bytes((i*17+3)&255 for i in range(35))
        for offset in range(35):
            for length in (1,35-offset):
                for overlap in (False,True):
                    fields={'m.offset':offset,'m.length':length}
                    for relative in range(length):fields[f'hdr.b{relative}.data']=original[offset+relative]
                    for bank in range(12):
                        data=original[3*bank:3*bank+3];mask=(1<<len(data))-1 if overlap else 0
                        fields[f'hdr.expected.w{bank}']=(mask<<24)|int.from_bytes(data.ljust(3,b'\0'),'big') if overlap else 0
                    s=Source(text,fields)
                    for bank in range(12):
                        for table in ('patch','oldmask','masks','difference','conflict','guard','retain','merge','finish'):
                            s.table(f'{table}_{bank}'+('_t' if table in ('oldmask','difference','conflict','retain','merge','finish') else ''))
                        got=s.env[f'hdr.candidate.w{bank}'];expected=s.env.get(f'hdr.expected.w{bank}',0)
                        for j in range(min(3,35-3*bank)):
                            position=3*bank+j
                            if offset<=position<offset+length:
                                expected=(expected&~(255<<(16-8*j)))|(original[position]<<(16-8*j))|(1<<(24+j))
                        self.assertEqual(got,expected,(offset,length,bank))
                    self.assertEqual(s.env.get('m.fault',0),0,(offset,length,overlap,[(b,s.env.get(f'm.diff{b}')) for b in range(12)]))
    def test_existing_byte_conflict_is_fault_before_cas(self):
        text=(HERE/'merge.p4').read_text()
        s=Source(text,{'m.offset':1,'m.length':1,'hdr.b0.data':8,'hdr.expected.w0':(2<<24)|(7<<8)})
        for table in ('patch_0','oldmask_0_t','masks_0','difference_0_t','conflict_0_t','guard_0'):s.table(table)
        self.assertEqual(s.env['m.fault'],1)

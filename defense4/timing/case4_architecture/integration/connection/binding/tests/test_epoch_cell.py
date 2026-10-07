"""Actual source SALU fragment semantics; not a parser/connection proof."""
import re
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE.parents[2]/'protocol'))
from source_eval import Source


class EpochCell(unittest.TestCase):
    def source(self,epoch,transition,cell):
        text=(HERE/'cell_probe.p4').read_text()
        text+='\n'+(HERE/'epoch_cell.p4').read_text()
        text=re.sub(r'\br\b','rv',text)
        text=text.replace('(int<32>)v.phase==-1','v.phase==32w0xffffffff')
        # Widening unsigned16 to unsigned32 is identity. The fragment evaluator
        # supports casts at expression start only; keep the actual predicate.
        text=re.sub(r'\(bit<32>\)(m\.phase_word\[\d+:\d+\])',r'\1',text)
        return Source(text,{'m.epoch':epoch,'m.expected':transition>>16},
            registers={('connection_cell',0):dict(cell)})

    def test_full_epoch_and_full_expected_phase_qualify_transition_atomically(self):
        for epoch,phase,expected in ((0x12345678,3,1),(0x92345678,3,0),
                (0x12345678,4,0),(0x12345678,0x10003,0)):
            source=self.source(epoch,3<<16|4,{'epoch':0x12345678,'phase':phase})
            result=source.register('transition_cell',0)
            self.assertEqual(result,expected)
            self.assertEqual(source.registers[('connection_cell',0)],
                {'epoch':0x12345678,'phase':4 if expected else phase})

    def test_close_prevents_late_publication_and_wrong_epoch_cannot_close(self):
        source=self.source(17,4<<16|5,{'epoch':17,'phase':4})
        self.assertEqual(source.register('close_cell',0),1)
        self.assertEqual(source.register('transition_cell',0),0)
        self.assertEqual(source.registers[('connection_cell',0)],{'epoch':17,'phase':0xffffffff})
        stale=self.source(16,7<<16|0,{'epoch':17,'phase':4})
        self.assertEqual(stale.register('close_cell',0),0)
        self.assertEqual(stale.registers[('connection_cell',0)],{'epoch':17,'phase':4})

    def test_busy_claim_cannot_replace_epoch_or_reset_phase(self):
        source=self.source(19,0,{'epoch':17,'phase':3})
        self.assertEqual(source.register('claim_cell',0),0)
        self.assertEqual(source.registers[('connection_cell',0)],{'epoch':17,'phase':3})

    def test_wrapper_refuses_terminal_phase_increment_wrap(self):
        source=self.source(17,0xffffffff<<16,{'epoch':17,'phase':0xffffffff})
        source.text=source.text.replace(',_):',',32w0&&&32w0):')
        source.env.update({'m.operation':2,'hdr.diagnostic.result':42})
        source.table('dispatch')
        self.assertEqual(source.env['hdr.diagnostic.result'],42)
        self.assertEqual(source.registers[('connection_cell',0)],{'epoch':17,'phase':0xffffffff})

if __name__=='__main__':unittest.main()

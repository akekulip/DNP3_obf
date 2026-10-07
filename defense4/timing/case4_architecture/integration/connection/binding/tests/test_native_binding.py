"""Source-fragment authority regressions, never a full parser/pipeline proof."""
import re
import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE.parents[2]/'protocol'))
from source_eval import Source


class NativeBinding(unittest.TestCase):
    def source(self,values,registers=None):
        text=(HERE/'native_binding.p4').read_text()
        text=re.sub(r'\br\b','rv',text)
        text=text.replace('RETURN_PORT','9w68').replace(',_):',',8w0&&&8w0):')
        # Equivalent one-key constant syntax; evaluator otherwise defaults.
        text=re.sub(r'(8w\d+):(\w+\(\);)',r'(\1):\2',text)
        return Source(text,values,registers=registers)

    def test_native_select_carries_installed_epoch_not_new_work_nonce(self):
        source=self.source({'m.observed':0x50001,'m.generation':29,'m.epoch':17,
            'm.kind':5,'m.sequence_valid':1,'m.matched':0})
        source.table('snapshot_t');source.table('first_event')
        self.assertEqual(source.env['hdr.envelope.epoch'],17)
        self.assertEqual(source.env['hdr.work_generation.generation'],29)
        self.assertEqual(source.env['hdr.expected_cell.expected_cell'],0x50001)
        self.assertEqual(source.env['hdr.event.event'],0x105)

    def test_coalesced_final_ack_select_and_established_select_are_allowed(self):
        for owner,expected in ((0x40001,0x105),(0x50001,0x105),(0x60001,0x1ff)):
            source=self.source({'m.observed':owner,'m.kind':5,'m.sequence_valid':1,
                'm.matched':0,'hdr.event.event':0x1ff})
            source.table('first_event')
            self.assertEqual(source.env['hdr.event.event'],expected)

    def test_publication_requires_full_current_epoch_and_owner_cookie(self):
        for epoch_diff,owner,expected in ((0,0x80001,0x90001),(1,0x80001,0x80001),
                (0,0x60001,0x60001),(0,0x80002,0x80002)):
            source=self.source({'m.stage':2,'m.kind':5,'m.work_phase':2,'m.epoch_diff':epoch_diff,
                'm.owner_op':0,'hdr.expected_cell.expected_cell':0x80001,
                'm.expected':0,'m.desired':0},registers={('owner',0):owner})
            source.table('owner_command');source.table('owner_t')
            self.assertEqual(source.registers[('owner',0)],expected)

    def test_private_event_cannot_relabel_actual_operate_as_select(self):
        for kind,actual,expected in ((5,5,1),(5,7,0),(6,5,0),(7,7,1)):
            source=self.source({'m.kind':kind,'m.packet_kind':actual,'m.data_valid':1})
            source.table('return_kind_guard')
            self.assertEqual(source.env['m.data_valid'],expected)

    def test_real_close_can_quarantine_every_native_producer_phase(self):
        for phase in range(8,13):
            source=self.source({'m.observed':phase<<16|1,'m.kind':4,'m.sequence_valid':1,
                'm.matched':0,'m.epoch':17,'hdr.event.event':0x1ff})
            source.table('first_event')
            self.assertEqual(source.env['hdr.event.event'],0x104)

    def test_select_client_position_comes_from_actual_native_length(self):
        source=self.source({'hdr.tcp.seq':101,'m.packet_kind':5,'m.stage':1,
            'm.kind':5,'m.work_phase':1,'m.work_op':2},registers={('client',0):101})
        source.table('next_seq_t');source.table('client_t')
        self.assertEqual(source.registers[('client',0)],136)

    def test_duplicate_or_reordered_return_cannot_consume_a_later_phase(self):
        text=(HERE/'native_binding.p4').read_text()+'\n'+(HERE/'work_record.p4').read_text()
        text=re.sub(r'\b(advance|claim|inspect|read)\s+=',r'\1=',text)
        text=re.sub(r'\bvalue\b','v',text)
        text=re.sub(r'\bold_phase\b','rv',text)
        text=re.sub(r'(?<![=!<>])\s*=\s*(?!=)','=',text)
        text=text.replace('== work_generation','== m.generation').replace('== generation','== m.generation')
        text=text.replace('== expected_phase','== m.expected_work_phase')
        for current,expected in ((2,1),(3,1),(1,2),(4,3)):
            source=Source(text,{'m.generation':29,
                'm.expected_work_phase':expected},registers={('work',0):
                    {'generation':29,'phase':current}})
            self.assertEqual(source.register('advance',0),0)
            self.assertEqual(source.registers[('work',0)],
                {'generation':29,'phase':current})

    def test_return_expectation_is_derived_from_emitted_private_stage(self):
        text=(HERE/'native_binding.p4').read_text()
        self.assertIn('m.expected_work_phase=(bit<32>)m.stage;',text)
        self.assertIn('work.apply(m.work_op,m.generation,m.expected_work_phase,m.work_phase)',text)

if __name__=='__main__':unittest.main()

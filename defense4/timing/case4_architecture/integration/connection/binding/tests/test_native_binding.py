"""Source-fragment authority regressions, never a full parser/pipeline proof."""
import re
import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE.parents[2]/'protocol'))
sys.path.insert(0,str(HERE.parents[2]/'integration/core/harness'))
from source_eval import Source, block
from interp_ext import ExtSource


def normalized(text):
    """Fragment-evaluator syntax: sliced reads, wildcard terms and one-key entries."""
    text=re.sub(r'\br\b','rv',text)
    text=text.replace('RETURN_PORT','9w68')
    text=re.sub(r'(?<=[(,])_(?=[,)])','8w0&&&8w0',text)
    # Equivalent one-key constant syntax; evaluator otherwise defaults.
    return re.sub(r'(8w\d+):(\w+\(\);)',r'(\1):\2',text)


class NativeBinding(unittest.TestCase):
    def source(self,values,registers=None):
        return Source(normalized((HERE/'native_binding.p4').read_text()),values,registers=registers)

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
        # Rewritten from return_kind_guard (data_valid) to the merged `guard` table (m.go):
        # the same kind/packet-kind pairing property, with a valid data frame and stage 1.
        for kind,actual,expected in ((5,5,1),(5,7,0),(6,5,0),(7,7,1)):
            source=self.source({'m.stage':1,'m.kind':kind,'m.packet_kind':actual,'m.direction':1,'m.shape_valid':1,
                'm.enabled':1,'m.profile':1,'m.go':0})
            source.table('guard')
            self.assertEqual(source.env['m.go'],expected)

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
        # Restructure: the assignment moved from its own stage before work.apply to the
        # initialisation at the top of apply. The pinned semantics are unchanged: ExpectedWorkRecord is
        # still qualified by generation AND the phase expected from the emitted stage, `m.stage` is never
        # written after parsing, and the initialisation precedes both the guard and the work call.
        body=text[text.index(' apply{\n  m.work_op='):]
        self.assertEqual(body.count('m.expected_work_phase='),1)
        self.assertLess(body.index('m.expected_work_phase=(bit<32>)m.stage;'),body.index('guard.apply()'))
        self.assertLess(body.index('guard.apply()'),body.index('work.apply(m.work_op'))
        self.assertIsNone(re.search(r'm\.stage\s*=(?!=)',body))
        self.assertEqual(body.count('work.apply(m.work_op'),1)


class TransparentForwarding(unittest.TestCase):
    """Valid retries and established ACKs must leave the switch as the original frame.

    Source-fragment passes: stage 0 tail, then stages 1-3 of the same private event.
    The parser, connection and WorkRecord controls are not executed here.
    """
    OUT = 7

    def setUp(self):
        self.text = normalized((HERE / 'native_binding.p4').read_text())
        # the evaluator has no slice assignment; this is the same low-byte write
        self.text = self.text.replace('hdr.event.event[7:0]=8w255;',
                                      'hdr.event.event=(hdr.event.event&16w0xff00)|16w255;')
        # stage-0 tail plus the return-pass chain; first_event now also holds the forward and strip rows
        start = self.text.index('    if(m.stage==8w0){\n     if(m.packet_kind==8w6')
        end = self.text.index('else{deny();}', start) + len('else{deny();}')
        self.chain = self.text[start:end]
        self.stage0 = block(self.text, 'if((m.work_op==8w1&&m.work_phase==32w4)')

    def passes(self, kind, owner, sequence_valid=1, matched=0):
        s = Source(self.text, {'m.kind': kind, 'm.packet_kind': kind, 'm.shape_valid': 1,
                               'm.sequence_valid': sequence_valid, 'm.matched': matched,
                               'm.observed': owner, 'm.generation': 29, 'm.epoch': 17,
                               'm.output_port': self.OUT, 'm.stage': 0, 'm.work_op': 1,
                               'm.work_phase': 4, 'm.owner_op': 0, 'm.expected': 0,
                               'm.desired': 0, 'm.epoch_diff': 0, 'md.drop_ctl': 0,
                               'tm.ucast_egress_port': self.OUT, 'hdr.envelope.epoch': 17},
                   registers={('owner', 0): owner, ('epoch', 0): 17})
        s.run(self.stage0)
        events = [s.env['hdr.event.event']]
        for stage in (1, 2, 3):
            s.env.update({'m.stage': stage, 'm.kind': events[-1] & 255, 'm.work_phase': stage,
                          'm.work_op': 2, 'm.owner_op': 0, 'm.expected': 0, 'm.desired': 0,
                          'tm.ucast_egress_port': self.OUT})
            # epoch_diff_t is folded into the epoch bank: epoch_t returns register minus envelope
            s.table('epoch_t'); s.table('owner_command'); s.table('owner_t')
            s.run(self.chain)
            events.append(s.env['hdr.event.event'])
        return s, events

    def assert_forwarded(self, s, owner):
        self.assertEqual(s.env['md.drop_ctl'], 0)
        self.assertEqual(s.env['tm.ucast_egress_port'], self.OUT)
        self.assertEqual(s.registers[('owner', 0)], owner)
        for name in ('envelope', 'work_generation', 'expected_cell', 'event'):
            self.assertFalse(s.valid[name], name)

    def test_four_retained_witnesses_are_forwarded_without_owner_change(self):
        for label, kind, owner in (('SYN retry', 1, 0x20001), ('SYNACK retry', 2, 0x40001),
                                   ('final ACK retry', 3, 0x50001), ('established ACK', 3, 0x90001)):
            with self.subTest(label):
                s, events = self.passes(kind, owner)
                self.assertEqual(events, [0x108, 0x208, 0x308, 0x308])
                self.assert_forwarded(s, owner)

    def test_established_acks_in_every_native_phase_are_forwarded(self):
        for phase in (8, 9, 10, 11, 12):
            with self.subTest(phase=phase):
                s, _ = self.passes(3, phase << 16 | 1)
                self.assert_forwarded(s, phase << 16 | 1)

    def test_retry_is_not_minted_as_first_contact(self):
        for kind, owner in ((1, 0x20001), (2, 0x40001), (3, 0x50001), (3, 0x90001)):
            s = Source(self.text, {'m.kind': kind, 'm.sequence_valid': 1, 'm.matched': 0,
                                   'm.observed': owner, 'm.generation': 29, 'm.epoch': 17})
            s.table('snapshot_t'); s.table('first_event')
            # Rewritten: first_event now also carries the forward rows, so the retry no longer leaves
            # the table as 0x1ff; the property is that it is the forward event, never a first-contact
            # event (0x101/0x102/0x103) and never a quarantine.
            self.assertEqual(s.env['hdr.event.event'], 0x108)
            self.assertNotIn(s.env['hdr.event.event'], (0x101, 0x102, 0x103, 0x104))

    def test_out_of_sequence_or_foreign_phase_is_still_denied_without_mutation(self):
        for kind, owner, valid in ((3, 0x90001, 0), (1, 0x20001, 0), (2, 0x90001, 1),
                                   (1, 0x90001, 1), (3, 0x30001, 1)):
            with self.subTest(kind=kind, owner=hex(owner), valid=valid):
                s, events = self.passes(kind, owner, sequence_valid=valid)
                self.assertEqual(events[0], 0x1ff)
                self.assertEqual(s.env['md.drop_ctl'], 1)
                self.assertEqual(s.registers[('owner', 0)], owner)

    def test_forwarding_event_never_issues_an_owner_command(self):
        for stage in (1, 2):
            s = Source(self.text, {'m.stage': stage, 'm.kind': 8, 'm.work_phase': stage,
                                   'm.epoch_diff': 0, 'm.owner_op': 0},
                       registers={('owner', 0): 0x90001})
            s.table('owner_command')
            self.assertEqual(s.env['m.owner_op'], 0)

    def test_reverse_pure_ack_is_not_claimed(self):
        # Rewritten from direction_guard (shape_valid) to the merged `guard` table at stage 0: an ACK
        # (packet kind 3) is claimed only in the forward direction, so the reverse one is a miss, which
        # is the old direction_guard default. The forward ACK is the positive control (ExtSource runs
        # the parametrised go_new action, which the fragment evaluator cannot).
        for direction, expected in ((1, 1), (2, 0), (0, 0)):
            s = ExtSource(self.text.replace('8w0&&&8w0', '_'), HERE)
            s.env.update({'m.stage': 0, 'm.packet_kind': 3, 'm.kind': 0, 'm.direction': direction, 'm.shape_valid': 1})
            s.table('guard')
            self.assertEqual(s.env.get('m.go', 0), expected, direction)

    def test_private_forwarding_kind_requires_a_matching_real_packet(self):
        # Rewritten from return_kind_guard (data_valid) to `guard` (m.go) on a stage-1 forwarding pass.
        for actual, expected in ((1, 1), (2, 1), (3, 1), (4, 0), (5, 0), (6, 0), (7, 0)):
            s = Source(self.text, {'m.stage': 1, 'm.kind': 8, 'm.packet_kind': actual, 'm.direction': 1,
                                   'm.shape_valid': 1, 'm.enabled': 1, 'm.profile': 1, 'm.go': 0})
            s.table('guard')
            self.assertEqual(s.env['m.go'], expected)

    def test_network_admits_the_private_forwarding_pass_for_kind_8(self):
        # The step-1 fragment tests never applied `network`, so the missing kind-8 row (private pass 2
        # denied at `else if(m.stage!=8w0){deny();}`) went unseen. Apply the real table.
        plain = self.text.replace('8w0&&&8w0', '_')
        for flags, expected in ((2, 1), (18, 1), (16, 1), (24, 0), (17, 0), (20, 0), (4, 0), (0, 0)):
            s = ExtSource(plain, HERE)
            s.env.update({'m.parsed': 1, 'm.kind': 8, 'hdr.tcp.flags': flags, 'm.ip_error': 0, 'm.tcp_sum': 0xffeb,
                          'hdr.ip.ttl': 64, 'hdr.tcp.reserved': 0, 'hdr.tcp.urgent': 0, 'm.network_valid': 0})
            s.table('network')
            self.assertEqual(s.env['m.network_valid'], expected, flags)
        for field, bad in (('m.ip_error', 1), ('m.tcp_sum', 0xffea), ('hdr.ip.ttl', 0), ('hdr.tcp.urgent', 1),
                           ('hdr.tcp.reserved', 1), ('m.parsed', 0)):
            s = ExtSource(plain, HERE)
            env = {'m.parsed': 1, 'm.kind': 8, 'hdr.tcp.flags': 2, 'm.ip_error': 0, 'm.tcp_sum': 0xffeb,
                   'hdr.ip.ttl': 64, 'hdr.tcp.reserved': 0, 'hdr.tcp.urgent': 0, 'm.network_valid': 0}
            env[field] = bad
            s.env.update(env)
            s.table('network')
            self.assertEqual(s.env['m.network_valid'], 0, field)

if __name__=='__main__':unittest.main()

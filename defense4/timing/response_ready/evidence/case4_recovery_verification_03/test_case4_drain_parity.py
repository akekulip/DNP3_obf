"""Actual source transitions and real-byte fixtures; queues remain idealised."""
import unittest
from p4_pass_sim import P4Sim
from test_case4_packet_parity import wire, FLOW, MS


class DrainParity(unittest.TestCase):
    def sim(self):
        return P4Sim(10*MS, MS, configured_flow=FLOW, expiry_enabled=1)

    def test_duplicate_ack_never_creates_second_original(self):
        s=self.sim(); s.request(0,raw=wire('REQ'))
        s.pure_ack(MS,raw=wire('ACK')); s.pure_ack(2*MS,raw=wire('ACK'))
        self.assertEqual(len(s.held_packets['ACK']),1)
        self.assertEqual(s.regs['reg_originals'] & 7,1)
        self.assertEqual(s.counters['dup_ack_dropped'],1)

    def test_source_removal_operand_mutation_changes_actual_credit(self):
        s=self.sim();s.request(0,raw=wire('REQ'));s.pure_ack(MS,raw=wire('ACK'));s.response(2*MS,raw=wire('RESP'))
        s.src=s.src.replace('meta.drain_mask = 16w0xFFFE','meta.drain_mask = 16w0xFFFC')
        s._complete_original('ACK',3*MS,s.cookie)
        self.assertEqual(s.regs['reg_originals'],0)

    def test_source_enclosing_predicate_mutation_blocks_terminal_removal(self):
        s=self.sim();s.request(0,raw=wire('REQ'));s.pure_ack(MS,raw=wire('ACK'))
        s.src=s.src.replace('if (meta.drain_cookie == meta.drain_key) {',
                            'if (meta.drain_cookie == meta.drain_key && meta.held_valid == 8w0) {',1)
        s._complete_original('ACK',2*MS,s.cookie)
        self.assertEqual(s.regs['reg_originals'],1)

    def test_source_duplicate_guard_mutation_drives_packet_drop(self):
        s=self.sim();s.request(0,raw=wire('REQ'))
        s.src=s.src.replace('(meta.drain_word & 16w1) != 16w0','(meta.drain_word & 16w1) == 16w0')
        s.pure_ack(MS,raw=wire('ACK'))
        self.assertEqual(len(s.held_packets['ACK']),0)

    def test_stale_original_cannot_remove_current_credit(self):
        s=self.sim();s.request(0,raw=wire('REQ'));s.pure_ack(MS,raw=wire('ACK'))
        before=s.regs['reg_originals']
        s._complete_original('ACK',2*MS,s.cookie+1)
        self.assertEqual(s.regs['reg_originals'],before)
        s.drain_scan(3*MS,0x40000002)
        self.assertEqual(s.trace[-1][2],'finish_expiry_drop')

    def test_quarantine_waits_for_both_originals_and_matching_completion(self):
        s=self.sim(); s.request(0,raw=wire('REQ'))
        s.pure_ack(MS,raw=wire('ACK')); s.response(2*MS,raw=wire('RESP'))
        cookie=s.cookie
        s.reg('owner_retire',3*MS,cookie_in=cookie,owner_nextstate=0x40000000)
        draining=s.regs['reg_owner']
        self.assertEqual(s.request(4*MS,raw=wire('REQ',seq=2000)), 'OUT_ARM_BUSY')
        s.drain_scan(5*MS,draining)
        self.assertEqual(s.regs['reg_owner'],draining)
        for slot in ('ACK','RESP'):
            packet=s.held_packets[slot][0]
            s._native_held(slot,6*MS,packet)
            s._native_held(slot,7*MS,packet)  # removal idempotent, no new credit
        self.assertEqual(s.regs['reg_originals'] & 7,0)
        s.drain_complete(8*MS,draining+1)
        self.assertEqual(s.regs['reg_owner'],draining)
        s.drain_scan(9*MS,draining)
        s.drain_complete(10*MS,draining)
        self.assertEqual(s.regs['reg_owner'],1)
        self.assertEqual(s.request(11*MS,raw=wire('REQ',seq=2000)), 'OUT_ARM_FRESH')
        self.assertEqual(s.regs['reg_exp_ack'],2020)

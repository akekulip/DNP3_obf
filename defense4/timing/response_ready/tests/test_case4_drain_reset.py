"""Source-driven recovery decisions; compiler/runtime evidence stays separate."""
import unittest

from test_p4_release import SOURCE, sem, table_effect
from test_p4_recovery import execute


class DrainReset(unittest.TestCase):
    def setUp(self):
        self.s = SOURCE.read_text()
        self.c = sem.extract_consts(self.s)

    def test_retirement_quarantines_until_count_qualified_completion(self):
        _, owner = execute(self.s, 'owner_retire', 0x80000001, cookie_in=0x80000001)
        self.assertEqual(owner, 0x40000001)
        _, blocked = execute(self.s, 'owner_arm', owner, cookie_in=0)
        self.assertEqual(blocked, owner)
        _, idle = execute(self.s, 'owner_retire', owner, cookie_in=owner, owner_nextstate=0)
        self.assertEqual(idle, 1)
        _, stale = execute(self.s, 'owner_retire', owner, cookie_in=0x40000002, owner_nextstate=0)
        self.assertEqual(stale, owner)

    def test_quarantine_cannot_overwrite_trackers(self):
        self.assertEqual(table_effect(self.s, 'tbl_tracker_admission',
                         {'read_release': 1, 'owner': 0x40000001}), 'block_trackers')

    def test_drain_completion_requires_matching_cookie_and_zero_originals(self):
        self.assertTrue('table tbl_case4_drain_complete' in self.s, 'drain completion gate missing')
        fields = dict(drain_cookie_match=1, drain_pending=0,
                      role=self.c['ROLE_DRAIN_SCAN'])
        table = sem.parse_const_table(self.s, 'tbl_case4_drain_complete', self.c)
        self.assertEqual(table.apply(fields), 'finish_drain_complete')
        for change in ({'drain_pending': 1}, {'drain_cookie_match': 0}):
            self.assertEqual(table.apply(dict(fields, **change)), 'finish_expiry_drop')

    def test_operate_return_cannot_release_before_its_deadline(self):
        self.assertTrue('table tbl_case4_operate_release' in self.s, 'OPERATE release guard missing')
        fields = dict(bor_pc=self.c['BPC_RELEASE'], owner_valid=1,
                      age_topj=0xffffff00, reset_qualified=0)
        self.assertEqual(table_effect(self.s, 'tbl_case4_operate_release', fields), 'operate_wait')
        fields['age_topj'] = 0
        self.assertEqual(table_effect(self.s, 'tbl_case4_operate_release', fields), 'operate_commit')
        fields['owner_valid'] = 0
        self.assertEqual(table_effect(self.s, 'tbl_case4_operate_release', fields), 'operate_abort')

    def test_reset_requires_validated_connection_and_sequence(self):
        self.assertTrue('table tbl_case4_reset_qualification' in self.s, 'reset qualification missing')
        fields = dict(validity_flags=0x1d, connection_diff=0, reset_flag=1)
        self.assertEqual(table_effect(self.s, 'tbl_case4_reset_qualification', fields), 'qualify_reset')
        for change in ({'validity_flags': 0x0d}, {'connection_diff': 1}, {'reset_flag': 0}):
            self.assertEqual(table_effect(self.s, 'tbl_case4_reset_qualification', dict(fields, **change)), 'ignore_reset')

    def test_operate_commit_gate_preserves_historical_release_and_wait_phase(self):
        self.assertTrue('table tbl_case4_bor_commit' in self.s, 'BOR commit guard missing')
        table=sem.parse_const_table(self.s,'tbl_case4_bor_commit',self.c)
        base=dict(bor_pc=self.c['BPC_RELEASE'],owner_valid=1,held_valid=0)
        self.assertEqual(table.apply(base),'bor_commit_yes')
        self.assertEqual(table.apply(dict(base,held_valid=4)),'bor_commit_yes')
        self.assertEqual(table.apply(dict(base,held_valid=3)),'bor_commit_no')
        self.assertEqual(table.apply(dict(base,held_valid=4,owner_valid=0)),'bor_commit_no')

    def test_qualified_reset_aborts_owner_without_affecting_normal_read(self):
        for owner in (0x80000001,0xc0000001):
            _,unchanged=execute(self.s,'owner_read',owner,cookie_in=0,owner_nextstate=0)
            self.assertEqual(unchanged,owner)
            _,draining=execute(self.s,'owner_read',owner,cookie_in=0,owner_nextstate=0x40000000)
            self.assertEqual(draining,0x40000001)

    def test_generated_cookie_has_one_parser_assignment(self):
        body = sem._extract_block_after(self.s, self.s.index('state parse_generated_token'))
        self.assertNotIn('meta.cookie_in =', body)
        self.assertIn('meta.generated_cookie =', body)

    def test_internal_instrumentation_is_bounded_and_has_no_wire_claim(self):
        self.assertTrue('struct case4_observation_digest_t' in self.s, 'instrument digest missing')
        block = sem._extract_block_after(self.s, self.s.index('struct case4_observation_digest_t'))
        import re
        self.assertLessEqual(sum(map(int, re.findall(r'bit<(\d+)>', block))), 48 * 8)
        deparser = self.s[self.s.index('control IgDeparser'):self.s.index('struct eg_meta_t')]
        self.assertTrue('case4_observation_digest.pack' in deparser)
        self.assertNotIn('wire_departure', block)
        self.assertNotIn('pkt.emit(hdr.validated)', deparser)

    def test_original_pair_uses_two_independent_scalar_banks(self):
        import re
        for name,width in (('reg_original_cookie',32),('reg_originals',16)):
            self.assertRegex(self.s,r'Register<bit<'+str(width)+r'>,\s*bit<1>>\(1,\s*0\)\s+'+name)
        self.assertIn('meta.drain_cookie = originals_cookie_read.execute(0)',self.s)
        self.assertIn('if (meta.drain_cookie == meta.drain_key)',self.s)

    def test_original_pair_has_independent_cookie_and_mask(self):
        key=0xffff
        _,cookie=execute(self.s,'originals_cookie_init',0,drain_key=key)
        rv,mask=execute(self.s,'originals_add',2,drain_mask=1)
        self.assertEqual((cookie,rv,mask),(key,2,3))
        returned,unchanged=execute(self.s,'originals_cookie_read',cookie)
        self.assertEqual((returned,unchanged),(key,key))
        self.assertNotEqual(returned,1)  # stale cookie cannot enter the MAU mask branch
        self.assertIn('if (meta.drain_cookie == meta.drain_key)',self.s)

    def test_original_mask_parser_default_does_not_invent_credit(self):
        import re
        start=sem._extract_block_after(self.s,self.s.index('state start'))
        defaults=re.findall(r'meta\.drain_mask\s*=\s*((?:16|32)w(?:0x[0-9a-fA-F]+|\d+));',start)
        self.assertTrue(defaults)
        self.assertEqual(sem.parse_p4_int(defaults[-1]),0)
        for field in ('cookie_in','generated_cookie','owner_nextstate','drain_key'):
            values=re.findall(r'meta\.'+field+r'\s*=\s*((?:16|32)w(?:0x[0-9a-fA-F]+|\d+));',start)
            self.assertTrue(values,field)
            self.assertEqual(sem.parse_p4_int(values[-1]),0,field)

    def test_original_mask_add_remove_conserve_cookie(self):
        _,cookie=execute(self.s,'originals_cookie_init',0,drain_key=2)
        _,word=execute(self.s,'originals_init',0,drain_mask=4)
        self.assertEqual(word,4)
        _,word=execute(self.s,'originals_add',word,drain_mask=1)
        self.assertEqual(word,5)
        _,duplicate=execute(self.s,'originals_add',word,drain_mask=1)
        self.assertEqual(duplicate,word)
        _,word=execute(self.s,'originals_remove',word,drain_mask=0xfffb)
        self.assertEqual(word,1)
        rv,unchanged=execute(self.s,'originals_cookie_read',cookie)
        self.assertEqual((rv,unchanged),(2,2))

    def test_raw_prefix_and_bad_proof_cannot_mutate_case4(self):
        fields = dict(read_release=1, dequeued=0, is_pktgen=0, handoff_valid=0,
                      validity_flags=0, role=self.c['ROLE_ARM'], connection_diff=0)
        table = sem.parse_const_table(self.s, 'tbl_case4_validated_input', self.c)
        self.assertEqual(table.apply(fields), 'proof_bypass')
        for flags in (0, 1, 5, 7, 11):
            self.assertEqual(table.apply(dict(fields, handoff_valid=1, validity_flags=flags)), 'proof_bypass')
        self.assertEqual(table.apply(dict(fields, handoff_valid=1, validity_flags=15)), 'proof_accept')
        self.assertEqual(table.apply(dict(fields, handoff_valid=1, validity_flags=15, connection_diff=1)), 'proof_bypass')


if __name__ == '__main__':
    unittest.main()

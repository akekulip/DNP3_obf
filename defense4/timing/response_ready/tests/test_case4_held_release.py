"""Release rechecks remain necessary when a blocker reservoir is lost."""
import unittest

from test_p4_release import SOURCE, sem, table_effect


class HeldRelease(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text()
        self.c = sem.extract_consts(self.source)

    def action(self, **kw):
        self.assertTrue('table tbl_case4_held_release' in self.source,
                        'held packets lack a deadline recheck')
        values = {'role': self.c['ROLE_ACK'], 'owner': 0,
                  'owner_valid': 1, 'txn_active': 2,
                  'age': 0, 'age_resp': 0xffffffff,
                  'ready_age': 0xffffff00}
        values.update(kw)
        return sem.parse_const_table(self.source, 'tbl_case4_held_release', self.c).apply(values)

    def test_lost_ack_reservoir_does_not_release_before_deadline(self):
        self.assertEqual(self.action(age=0xffffff00), 'finish_held_ack_wait')
        self.assertEqual(self.action(), 'finish_held_commit')

    def test_ack_requires_response_or_explicit_expiry(self):
        self.assertEqual(self.action(txn_active=1), 'finish_held_ack_wait')
        self.assertEqual(self.action(txn_active=1, ready_age=0), 'finish_held_native')

    def test_lost_response_reservoir_preserves_full_gap(self):
        self.assertEqual(self.action(role=self.c['ROLE_RESP'], age_resp=0xffffffff),
                         'finish_held_resp_wait')
        self.assertEqual(self.action(role=self.c['ROLE_RESP'], age_resp=0xffffff00),
                         'finish_held_resp_wait')
        self.assertEqual(self.action(role=self.c['ROLE_RESP'], age_resp=0),
                         'finish_held_resp_commit')

    def test_only_commit_pass_retires_response_owner(self):
        args = {'read_release': 1, 'sess': 0, 'dequeued': 1,
                'role': self.c['ROLE_RESP'], 'budget_zero': 0,
                'mode': self.c['MODE_D4_DUAL'], 'token_slot': 0,
                'expiry_enabled': 1}
        self.assertEqual(table_effect(self.source, 'tbl_owner_admission',
                                      dict(args, held_valid=1)), 'owner_observe')
        self.assertEqual(table_effect(self.source, 'tbl_owner_admission',
                                      dict(args, held_valid=2)), 'owner_release')

    def test_stale_commit_cannot_forward(self):
        self.assertEqual(table_effect(self.source, 'tbl_owner_valid',
                         {'read_release': 1, 'held_valid': 2, 'owner': 3,
                          'role': self.c['ROLE_RESP']}), 'owner_reject')

    def test_retired_owner_flushes_native_without_rearming_gap(self):
        self.assertEqual(self.action(owner=0x80000000), 'finish_held_native')


if __name__ == '__main__':
    unittest.main()

"""Source-bound app-sequence gates; not a packet-level or silicon proof."""
import unittest

from test_p4_recovery import execute
from test_p4_release import SOURCE, sem, table_effect


class ApplicationAssociation(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text()
        self.c = sem.extract_consts(self.source)

    def test_zero_sequence_is_written_after_wrap(self):
        self.assertTrue('reg_app_seq' in self.source, 'reg_app_seq')
        _, stored = execute(self.source, 'app_seq_write', 15, app_seq=0)
        self.assertEqual(stored, 0)

    def test_every_wrong_application_sequence_is_rejected(self):
        self.assertTrue('table tbl_app_association' in self.source, 'table tbl_app_association')
        for expected in range(16):
            for actual in range(16):
                diff, unchanged = execute(self.source, 'app_seq_read', expected,
                                          app_seq=actual)
                self.assertEqual(unchanged, expected)
                action = table_effect(self.source, 'tbl_app_association', {
                    'read_release': 1, 'pkt_class': self.c['CLASS_RESP'],
                    'app_diff': diff,
                })
                self.assertEqual(action, 'app_match' if actual == expected else
                                 'app_mismatch')

    def test_busy_owner_cannot_overwrite_application_identity(self):
        self.assertTrue('table tbl_guarded_app' in self.source, 'table tbl_guarded_app')
        for owner, action in ((0, 'tracker_app_write'),
                              (0x80000001, 'tracker_app_read'),
                              (0xFFFF, 'tracker_app_read')):
            got = table_effect(self.source, 'tbl_guarded_app', {
                'read_release': 1, 'owner': owner,
                'sess': self.c['SESS_MASTER'], 'role': self.c['ROLE_ARM'],
                'dequeued': 0, 'is_pktgen': 0,
            })
            self.assertEqual(got, action)

    def test_ack_and_historical_disabled_policy_do_not_use_app_fields(self):
        self.assertTrue('table tbl_app_association' in self.source, 'table tbl_app_association')
        for enabled, cls in ((0, self.c['CLASS_RESP']),
                             (1, self.c['CLASS_ACK'])):
            self.assertEqual(table_effect(self.source, 'tbl_app_association', {
                'read_release': enabled, 'pkt_class': cls, 'app_diff': 1,
            }), 'app_match')

    def test_guard_runs_before_response_mark_and_state_decode(self):
        self.assertTrue('tbl_app_association.apply();' in self.source, 'tbl_app_association.apply();')
        apply = sem.strip_comments(self.source)
        self.assertLess(apply.index('tbl_guarded_app.apply();'),
                        apply.index('tbl_app_association.apply();'))
        self.assertLess(apply.index('tbl_app_association.apply();'),
                        apply.index('tbl_resp_authorise.apply();'))


if __name__ == '__main__':
    unittest.main()

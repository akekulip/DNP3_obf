"""Independent pulse expiry fragments, with no claim about physical queue drain."""
import unittest

from test_p4_recovery import execute
from test_p4_release import SOURCE, sem, table_effect


class IndependentExpiry(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text()
        self.c = sem.extract_consts(self.source)

    def select(self, **kw):
        self.assertTrue('table tbl_case4_expiry_decide' in self.source,
                        'missing independent expiry decision')
        fields = {'expiry_enabled': 1, 'read_release': 1,
                  'role': self.c['ROLE_EXPIRY_SCAN'],
                  'owner': 0x80000001, 'ready_age': 0,
                  'age_resp': 0xFFFFFFFF}
        fields.update(kw)
        return sem.parse_const_table(self.source, 'tbl_case4_expiry_decide', self.c).apply(fields)

    def test_both_reservoirs_absent_pulse_still_retires_owner(self):
        self.assertTrue('ROLE_EXPIRY_SCAN' in self.source,
                        'missing independent pulse role')
        self.assertEqual(self.select(), 'finish_expiry_loop')
        difference, owner = execute(self.source, 'owner_retire', 0x80000001,
                                    cookie_in=0x80000001)
        self.assertEqual((difference, owner), (0, 1))

    def test_post_ack_gap_is_not_cut_by_readiness_expiry(self):
        self.assertTrue('ROLE_EXPIRY_SCAN' in self.source,
                        'missing independent pulse role')
        self.assertEqual(self.select(age_resp=0x80000000), 'finish_expiry_drop')
        self.assertEqual(self.select(age_resp=0), 'finish_expiry_loop')

    def test_unarmed_before_deadline_disabled_or_idle_pulse_drops(self):
        self.assertTrue('ROLE_EXPIRY_SCAN' in self.source,
                        'missing independent pulse role')
        for args in ({'ready_age': 0xFFFFFF00}, {'owner': 1},
                     {'expiry_enabled': 0}, {'read_release': 0}):
            self.assertEqual(self.select(**args), 'finish_expiry_drop')

    def test_expiry_register_uses_nanoseconds_across_wrap(self):
        self.assertTrue('ready_expiry_write' in self.source,
                        'missing source-bound expiry register')
        for now in (0x10001, 0xFFFFF001):
            deadline = (now + 30_000_000 // 256 * 256) & 0xFFFFFFFF
            _, stored = execute(self.source, 'ready_expiry_write', 2,
                                now_word=now, expiry_cand=deadline)
            self.assertEqual(stored, deadline)
            for at, due in ((deadline - 256, False), (deadline, True)):
                age, stored_again = execute(self.source, 'ready_expiry_read', stored,
                                             now_word=at & 0xFFFFFFFF)
                self.assertEqual(stored_again, stored)
                self.assertEqual((age & 0x800000FF) == 0, due)

    def test_pulse_is_internal_and_carries_full_owner_cookie(self):
        self.assertTrue('finish_expiry_loop' in self.source,
                        'missing internal expiry return')
        action = sem.extract_named_block(self.source, 'finish_expiry_loop')
        self.assertTrue('hdr.expiry.cookie_word = meta.owner' in action)
        self.assertTrue('PORT_PGEN' in action)
        self.assertFalse('PORT_VISION' in action or 'PORT_RELAY' in action)

    def test_stale_scan_cannot_retire_a_newly_committed_ack_gap(self):
        self.assertTrue('owner_ack_commit' in self.source,
                        'ACK commitment cannot invalidate an in-flight readiness scan')
        _, owner = execute(self.source, 'owner_ack_commit', 0x80000001,
                           cookie_in=0x80000001)
        self.assertEqual(owner, 0xc0000001)
        _, after_stale_scan = execute(self.source, 'owner_retire', owner,
                                      cookie_in=0x80000001)
        self.assertEqual(after_stale_scan, owner)
        _, after_completion = execute(self.source, 'owner_retire', owner,
                                      cookie_in=owner)
        self.assertEqual(after_completion, 1)


if __name__ == '__main__':
    unittest.main()

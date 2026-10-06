"""Source-bound control retransmission checks; no physical actuation claim."""
import unittest

from test_p4_recovery import execute
from test_p4_release import SOURCE, sem, table_effect


class OperateRepair(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text()
        self.c = sem.extract_consts(self.source)

    def test_matching_release_marks_all_application_sequences(self):
        self.assertTrue('gen_release' in self.source, 'released-domain repair is absent')
        for gen in range(0xc0, 0xd0):
            before, after = execute(self.source, 'gen_release', gen, gen_in=gen)
            self.assertEqual((before, after), (gen, gen | 0x10))
            _, duplicate = execute(self.source, 'gen_release', after, gen_in=gen)
            self.assertEqual(duplicate, after)

    def test_stale_release_does_not_mark_other_generation(self):
        self.assertTrue('gen_release' in self.source, 'released-domain repair is absent')
        _, after = execute(self.source, 'gen_release', 0xc1, gen_in=0xc2)
        self.assertEqual(after, 0xc1)

    def test_held_duplicate_drops_but_released_repair_forwards(self):
        self.assertTrue('V_OP_REPAIR' in self.c, 'released repair verdict is absent')
        for enabled in (0, 1):
            fields = {'bor_pc': self.c['BPC_OPERATE'], 'read_release': enabled,
                      'verdict_bor': self.c['V_OP_DUP'], 'owner_valid': 1,
                      'role': self.c['ROLE_ARM'], 'pkt_class': self.c['CLASS_ARM']}
            self.assertEqual(table_effect(self.source, 'tbl_decide_fresh', fields), 'OUT_OP_DUP')
            fields['verdict_bor'] = self.c['V_OP_REPAIR']
            self.assertEqual(table_effect(self.source, 'tbl_decide_fresh', fields), 'OUT_OP_REPAIR')
        self.assertTrue('gen_stored == meta.gen_rel' in self.source)
        action = sem.extract_named_block(self.source, 'finish_path_14')
        self.assertTrue('PORT_RELAY' in action)

    def test_repair_verdict_alone_cannot_admit_unqualified_traffic(self):
        fields = {'bor_pc': self.c['BPC_OPERATE'],
                  'verdict_bor': self.c['V_OP_REPAIR'],
                  'read_release': 1, 'owner_valid': 0}
        self.assertNotEqual(table_effect(self.source, 'tbl_decide_fresh', fields), 'OUT_OP_REPAIR')

    def test_busy_owner_cannot_prepare_or_arm_control_state(self):
        self.assertTrue('tbl_case4_bor_admission' in self.source,
                        'control state is not gated by owner admission')
        _, owner = execute(self.source, 'owner_arm', 0x80000001, cookie_in=0)
        self.assertEqual(owner, 0x80000001)
        self.assertEqual(table_effect(self.source, 'tbl_case4_bor_admission',
                         {'read_release': 1, 'pkt_class': self.c['CLASS_ARM'],
                          'tracker_write': 0}), 'bor_skip_request')
        block = sem.extract_named_block(self.source, 'bor_skip_request')
        self.assertTrue('meta.bor_pc = BPC_NONE' in block)
        self.assertLess(self.source.index('tbl_case4_bor_admission.apply()'),
                        self.source.index('meta.epoch_stored = epoch_prepare.execute(0)'))


if __name__ == '__main__':
    unittest.main()

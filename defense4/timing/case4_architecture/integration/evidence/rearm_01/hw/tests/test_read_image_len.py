"""read_image_len: builds whose READ image differs from the control image (read_complete_01 policy: READ 141,
SELECT/OPERATE 61). Every older build omits it and keeps exactly its previous expectations."""
import sys
import unittest
from pathlib import Path

HW = Path(__file__).resolve().parents[1]
ARCH = HW.parents[3]
sys.path[:0] = [str(HW), str(ARCH / 'protocol' / 'hw_vepa')]
import vision_candidate as vc  # noqa: E402
import loss  # noqa: E402


class ReadImageLen(unittest.TestCase):
    def test_expect_default_is_unchanged(self):
        self.assertEqual(vc.expect(1, 58), vc.EXPECT)
        self.assertEqual(vc.expect(1, 61)['padding']['1'], {'read_resp_len': [61], 'sbo_resp_len': [61]})

    def test_expect_policy_lengths(self):
        e = vc.expect(1, 61, read_image_len=141)
        self.assertEqual(e['padding']['1'], {'read_resp_len': [141], 'sbo_resp_len': [61]})
        self.assertEqual(e['padding']['0'], {'read_resp_len': [49], 'sbo_resp_len': [37]})

    def test_growth_per_function(self):
        ex = {'exchanges': [dict(kind='READ', resp_len=141), dict(kind='SELECT', resp_len=61),
                            dict(kind='OPERATE', resp_len=61)]}
        self.assertEqual(loss._growth(ex, True, True, 61, 141), (92 + 24 + 24, 92 + 24 + 24))
        old = {'exchanges': [dict(kind='READ', resp_len=61), dict(kind='SELECT', resp_len=61)]}
        self.assertEqual(loss._growth(old, True, True, 61), (12 + 24, 12 + 24))

    def test_campaign_suffix_per_class(self):
        import campaign
        c = campaign.Campaign.__new__(campaign.Campaign)
        c.cfg = {'builds': {'b': {'image_len': 61, 'read_image_len': 141}, 'o': {'image_len': 61}}}
        self.assertEqual(c._padded_suffix({'build': 'b'}, 'read_resp_padded'), '@141')
        self.assertEqual(c._padded_suffix({'build': 'b'}, 'select_resp_padded'), '@61/141')
        self.assertEqual(c._padded_suffix({'build': 'b'}, 'master_ack_of_padded_data'), '@141')
        self.assertEqual(c._padded_suffix({'build': 'o'}, 'read_resp_padded'), '@61')
        self.assertEqual(c._padded_suffix({'build': 'o'}), '@61')


    def test_drop_occurrence_counts_only_matching_length(self):
        # m11_09 shape (one padded length): SELECT is the first padded response after the READs
        old = loss.parse_drop('select_resp_padded:1@61', 65)
        self.assertEqual((old['ip_len'], old['occurrence']), (101, 66))
        # policy build: READ 141, control 61 -> the SELECT is the 1st IP-length-101 packet, OPERATE the 2nd
        sel = loss.parse_drop('select_resp_padded:1@61/141', 65)
        op = loss.parse_drop('operate_resp_padded:1@61/141', 65)
        rd = loss.parse_drop('read_resp_padded:3@141', 65)
        self.assertEqual((sel['ip_len'], sel['occurrence']), (101, 1))
        self.assertEqual((op['ip_len'], op['occurrence']), (101, 2))
        self.assertEqual((rd['ip_len'], rd['occurrence']), (181, 3))


if __name__ == '__main__':
    unittest.main()

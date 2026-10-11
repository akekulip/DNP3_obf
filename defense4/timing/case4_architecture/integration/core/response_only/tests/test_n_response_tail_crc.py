"""make_n.py edit 9 (optional): N drops the response tail/second-block CRC checks that E repeats."""
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import make_n  # noqa: E402
import make_e  # noqa: E402
import compose  # noqa: E402


class ResponseTailCrcOption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full = make_n.generate()
        cls.lean = make_n.generate(response_tail_crc=False)

    def test_default_is_the_committed_n(self):
        self.assertEqual(self.full, (HERE.parent / 'n_response_only.p4').read_text())

    def test_three_hash_units_and_tables_removed(self):
        crc = 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly)'
        self.assertEqual(self.full.count(crc) - self.lean.count(crc), 3)
        for name in ('response_crct_t', 'rd_second_crc_t', 'rd_tail_crc_t', 'hash_response_tail'):
            self.assertIn(name, self.full)
            self.assertNotIn(name, self.lean)

    def test_request_and_head_checks_kept(self):
        for kept in ('crc_t.apply();', 'input_tail_t.apply();', 'rd_request_crc_t.apply();',
                     'if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=8w1;}',
                     'if(hdr.first.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=8w1;}',
                     'if(m.response!=8w1){if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=8w1;}}'):
            self.assertIn(kept, self.lean)

    def test_e_still_checks_every_dropped_block(self):
        e = make_e.generate()
        for check in ('hdr.rb1.crc1 != (m.in_rb1', 'hdr.rtn.crc2 != (m.in_rt', 'hdr.ctn.crc1 != (m.in_ct'):
            self.assertIn(check, e)
        # padding is granted only when no native CRC failed
        self.assertRegex(e, r'rbad1|cbadt')

    def test_compose_passes_the_option_through(self):
        src_full, meta_full = compose.generate()
        src_lean, meta_lean = compose.generate(n_response_tail_crc=False)
        self.assertNotIn('n_response_tail_crc', meta_full)
        self.assertIs(meta_lean['n_response_tail_crc'], False)
        self.assertEqual(len(re.findall(r'\brd_tail_crc_t\b', src_lean)), 0)
        self.assertGreater(len(re.findall(r'\brd_tail_crc_t\b', src_full)), 0)


if __name__ == '__main__':
    unittest.main()

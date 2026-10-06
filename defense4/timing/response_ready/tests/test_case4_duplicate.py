"""A repeated complete response must not escape while its original is held."""
import unittest
from test_p4_release import SOURCE, sem, table_effect


class DuplicateResponse(unittest.TestCase):
    def test_pending_associated_response_is_suppressed_in_case4(self):
        source = SOURCE.read_text()
        c = sem.extract_consts(source)
        self.assertTrue('OUT_RESP_DUP_SUPP' in c, 'duplicate response gate is absent')
        fields = {'expiry_enabled': 1, 'read_release': 1,
                  'pkt_class': c['CLASS_RESP'], 'verdict': c['V_RESP'],
                  'txn_active': 2, 'owner_valid': 1, 'mode': c['MODE_D4_DUAL']}
        self.assertEqual(table_effect(source, 'tbl_decide_fresh', fields), 'OUT_RESP_DUP_SUPP')
        fields['verdict'] = c['V_RESP_BYPASS']
        self.assertNotEqual(table_effect(source, 'tbl_decide_fresh', fields), 'OUT_RESP_DUP_SUPP')

    def test_data_parser_requires_ack_bit(self):
        source = SOURCE.read_text()
        block = sem._extract_block_after(source, source.index('state parse_tcp {'))
        self.assertFalse('8w0x10 &&& 8w0x27' in block)
        self.assertEqual(block.count('8w0x10 &&& 8w0x37'), 4)


if __name__ == '__main__':
    unittest.main()

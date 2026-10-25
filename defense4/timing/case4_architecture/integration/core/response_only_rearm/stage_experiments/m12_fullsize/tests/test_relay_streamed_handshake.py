"""Consume/check handshake words before depositing in a final consuming state."""
import hashlib
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen import relay_ts, relay_sbo
from m12gen.build import build
import test_n_read_shapes as shared
import test_relay_ts as ts
import test_relay_handshake_deposit as hs


class StreamedHandshake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.object(relay_sbo, 'retry_fin_phase', side_effect=lambda src: src), patch.object(relay_sbo, 'half_closed_rst', side_effect=lambda src: src), patch.object(relay_sbo, 'relay_fin_psh', side_effect=lambda src: src), \
                patch.object(relay_sbo, 'canonical_profile_keys', side_effect=lambda src: src):
            with patch.object(relay_ts, 'stream_handshake_options', side_effect=lambda src: src):
                cls.original, _ = build(**ts.FLAGS, relay_ts=True)
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_only_handshake_headers_and_parser_states_change(self):
        old, new = shared.role(self.original, 'N'), shared.role(self.selected, 'N')
        self.assertEqual(hashlib.sha256(old.encode()).hexdigest(),
                         'fa2d7cd8e505e3ab03879e2c19316847b0dff384a9090a1d6c65c598c4343beb')
        self.assertEqual(old[old.index('control Ingress('):], new[new.index('control Ingress('):])
        self.assertIn('opt12_h tso;opt4_h hs0;opt4_h hs1;opt4_h hs2;opt4_h oa;', new)
        self.assertEqual(re.findall(r'header \w+\{[^}]+\}', old), re.findall(r'header \w+\{[^}]+\}', new))
        before = dict(re.findall(r' state (\w+)\{([^\n]*)\}', old))
        after = dict(re.findall(r' state (\w+)\{([^\n]*)\}', new))
        changed = {'ts_syn', 'ts_syn_profile', 'ts_syn_echo', 'ts_syn_ws', 'ts_synack',
                   'ts_synack_profile', 'ts_synack_sack', 'ts_synack_ts'}
        self.assertEqual(set(after) - set(before), {'ts_syn_value', 'ts_synack_values'})
        for state in before.keys() - changed:
            self.assertEqual(before[state], after[state], state)

    def test_each_fixed_word_is_checked_in_its_own_extraction_state(self):
        states = dict(re.findall(r' state (\w+)\{([^\n]*)\}', shared.role(self.selected, 'N')))
        for role, kind in (('syn', 1), ('synack', 2)):
            self.assertEqual(states['ts_' + role],
                'pkt.extract(hdr.mss);tc.subtract(hdr.mss);m.packet_kind=8w%d;transition ts_%s_mss;' % (kind, role))
        for state, header, word in (('ts_syn_profile', 'hs0', '0402080a'),
                                    ('ts_syn_echo', 'hs2', '0'),
                                    ('ts_syn_ws', 'oa', '01030307'),
                                    ('ts_synack_profile', 'hs0', '01030300'),
                                    ('ts_synack_sack', 'hs1', '01010402'),
                                    ('ts_synack_ts', 'hs2', '0101080a')):
            body = states[state]
            self.assertTrue(body.startswith('pkt.extract(hdr.%s);tc.subtract(hdr.%s);' % (header, header)))
            self.assertIn('transition select(hdr.%s.v)' % header, body)
            self.assertIn(('32w0:' if word == '0' else '32w0x%s:' % word), body)
        self.assertEqual(states['ts_syn_ws'].count('tc.get()'), 1)
        self.assertEqual(states['ts_synack_values'].count('tc.get()'), 1)
        self.assertIn('tc.subtract(hdr.ob);m.tcp_sum=tc.get();transition finish_handshake;', states['ts_synack_values'])
        for state, expected_end, expected_shift in (('ts_syn_ws', 3, 4), ('ts_synack_values', 7, 8)):
            fields = re.findall(r'pkt.extract\(hdr\.(\w+)\)', states[state])
            self.assertEqual(len(fields) * 4, expected_shift)
            self.assertLess(expected_end, expected_shift)
        self.assertNotIn('hdr.', states['finish_handshake'])

    test_all286_handshake_cases = hs.HandshakeChecksumDeposit.test_all_fixed_option_bits_timestamps_and_bad_checksums_preserve_admission


if __name__ == '__main__':
    unittest.main()

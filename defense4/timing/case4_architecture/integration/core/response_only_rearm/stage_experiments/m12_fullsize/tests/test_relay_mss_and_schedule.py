"""MSS-first parser checks and exactly row11's earlier shallow checksum constant."""
import hashlib
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen import relay_ts, relay_sbo
from m12gen.build import build
import test_n_read_shapes as shared
import test_relay_ts as ts
import test_relay_handshake_deposit as hs
import test_relay_parser_checksum as ps


class MSSAndSchedule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ExitStack() as patches:
            patches.enter_context(patch.object(relay_sbo, 'retry_fin_phase', side_effect=lambda src: src))
            patches.enter_context(patch.object(relay_sbo, 'half_closed_rst', side_effect=lambda src: src))
            patches.enter_context(patch.object(relay_sbo, 'relay_fin_psh', side_effect=lambda src: src))
            patches.enter_context(patch.object(relay_sbo, 'canonical_profile_keys', side_effect=lambda src: src))
            patches.enter_context(patch.object(relay_sbo, 'relay_departure_provenance', side_effect=lambda src: src))
            for name in ('stream_read_timestamp_prefix', 'early_egress_lengths', 'stream_handshake_options',
                         'padder_crc_placement'):
                patches.enter_context(patch.object(relay_ts, name, side_effect=lambda src: src))
            with patch.object(relay_ts, 'handshake_mss_first', side_effect=lambda src: src):
                with patch.object(relay_ts, 'early_shallow_checksum', side_effect=lambda src: src):
                    cls.original, _ = build(**ts.FLAGS, relay_ts=True)
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_source_scope_contains_only_mss_order_and_row11_constant_move(self):
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(),
                         '5aeec10d5558625391934bea6496bb1c5872c6c88342566c3a83650f0a696948')
        old_n, new_n = shared.role(self.original, 'N'), shared.role(self.selected, 'N')
        for role in ('E', 'T'):
            self.assertEqual(shared.role(self.original, role), shared.role(self.selected, role))
        self.assertEqual(re.findall(r'\btable (\w+)', old_n), re.findall(r'\btable (\w+)', new_n))
        self.assertEqual(re.findall(r'\bstruct \w+\{[^}]*\}', old_n), re.findall(r'\bstruct \w+\{[^}]*\}', new_n))
        old_crc = re.search(r'action crc_head_first\(\)\{([^\n]+)\}', old_n)[1]
        new_crc = re.search(r'action crc_head_first_shallow\(\)\{([^\n]+)\}', new_n)[1]
        self.assertEqual(new_crc, old_crc + 'm.tcp_sum=16w0xffeb;')
        self.assertIn('action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;}', new_n)
        self.assertNotIn('state finish_shallow{m.tcp_sum=', new_n)
        # No checksum/profile/owner/network validation expressions are relaxed.
        for table in ('network', 'profile', 'response_profile', 'guard', 'owner_command'):
            def text(source):
                start = source.index('table ' + table + '{')
                opening = source.index('{', start)
                from p4syntax import match_brace
                return source[start:match_brace(source, opening)]
            self.assertEqual(text(old_n), text(new_n), table)

    def test_mss_is_checked_before_each_timestamp_word_suffix(self):
        states = dict(re.findall(r' state (\w+)\{([^\n]*)\}', shared.role(self.selected, 'N')))
        old_states = dict(re.findall(r' state (\w+)\{([^\n]*)\}', shared.role(self.original, 'N')))
        for role, last in (('syn', 'ts_syn_ws'), ('synack', 'ts_synack_ts')):
            extraction, mss, profile = 'ts_' + role, 'ts_' + role + '_mss', 'ts_' + role + '_profile'
            self.assertIn('m.tcp_sum=tc.get();', states[extraction])
            self.assertTrue(states[extraction].endswith('transition %s;' % mss))
            self.assertEqual(states[mss], 'transition select(hdr.mss.kind,hdr.mss.len,hdr.mss.value){'
                             '(8w2,8w4,16w1460):%s;default:accept;}' % profile)
            self.assertIn(':finish_handshake;', states[last])
            self.assertNotIn(':mss_check;', states[last])
            self.assertEqual(states[last], old_states[last].replace(':mss_check;', ':finish_handshake;'))
        for state in ('ts_syn_profile', 'ts_syn_echo', 'ts_synack_profile', 'ts_synack_sack'):
            self.assertEqual(states[state], old_states[state])
        for state in ('ts_syn_profile', 'ts_syn_echo', 'ts_syn_ws', 'ts_synack_profile',
                      'ts_synack_sack', 'ts_synack_ts', 'finish_handshake'):
            self.assertNotIn('hdr.mss.', states[state])
            self.assertNotIn('tc.get()', states[state])
        graph = {name: set(re.findall(r':(\w+);|transition (\w+);', body)) for name, body in states.items()}
        graph = {name: {a or b for a, b in edges if (a or b) in states} for name, edges in graph.items()}
        def reachable(blocked=None):
            found, pending = set(), ['start']
            while pending:
                state = pending.pop()
                if state == blocked or state in found:
                    continue
                found.add(state); pending.extend(graph[state])
            return found
        for legacy in ('mss_syn', 'mss_synack', 'mss_check'):
            self.assertNotIn(legacy, reachable())
        for role in ('syn', 'synack'):
            self.assertIn('ts_%s_profile' % role, reachable())
            self.assertNotIn('ts_%s_profile' % role, reachable('ts_%s_mss' % role))

    def test_only_packet_kind11_changes_checksum_in_all256_dispatch_cases(self):
        raw = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        old, new = shared.n_source(self.original), shared.n_source(self.selected)
        old_table, new_table = (n.controls['Ingress'].tables['crc_t'] for n in (old, new))
        self.assertEqual(old_table['keys'], new_table['keys'])
        self.assertEqual(old_table['default'], new_table['default'])
        old_rows, new_rows = old_table['entries'], new_table['entries']
        self.assertEqual(len(old_rows), len(new_rows))
        for a, b in zip(old_rows, new_rows):
            if a[1] == 'crc_head_first' and b[1] == 'crc_head_first_shallow':
                self.assertEqual(a[0], [('val', ('num', 11, 8))])
            else:
                self.assertEqual(a, b)
        for kind in range(256):
            results = []
            for n in (old, new):
                n.begin_pass(9)
                n.packet_parser(ts.packet(raw, reverse=True))
                n.env.update({'m.packet_kind': kind, 'm.tcp_sum': 0x1357})
                n.table('crc_t')
                results.append(dict(n.env))
            expected = dict(results[0])
            if kind == 11:
                expected['m.tcp_sum'] = 0xffeb
            self.assertEqual(results[1], expected, kind)

    test_all286_handshake_cases = hs.HandshakeChecksumDeposit.test_all_fixed_option_bits_timestamps_and_bad_checksums_preserve_admission
    test_all84_native_admission_cases = ps.ParserChecksumPlacement.test_valid_and_invalid_native_packets_have_identical_admission_state


if __name__ == '__main__':
    unittest.main()

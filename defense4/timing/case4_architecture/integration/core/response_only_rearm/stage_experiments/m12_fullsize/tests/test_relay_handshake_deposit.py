"""Deposit SYN checksums before zero-extract option checks, retaining admission."""
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


class HandshakeChecksumDeposit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ExitStack() as patches:
            patches.enter_context(patch.object(relay_sbo, 'relay_departure_provenance', side_effect=lambda src: src))
            for name in ('handshake_mss_first', 'early_shallow_checksum', 'stream_read_timestamp_prefix',
                         'early_egress_lengths', 'stream_handshake_options', 'padder_crc_placement'):
                patches.enter_context(patch.object(relay_ts, name, side_effect=lambda src: src))
            with patch.object(relay_ts, 'handshake_checksum_deposits', side_effect=lambda src: src):
                cls.original, _ = build(**ts.FLAGS, relay_ts=True)
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_only_handshake_deposit_position_and_terminal_target_change(self):
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(),
                         'e4d78d7efb6c30db381262724d4733d6db8fd1aadd00e4ed23ccf3bd70ab8842')
        expected = self.original
        for header in ('oa', 'ob'):
            expected = expected.replace('tc.subtract(hdr.%s);m.packet_kind=' % header,
                                        'tc.subtract(hdr.%s);m.tcp_sum=tc.get();m.packet_kind=' % header)
        expected = expected.replace('(8w2,8w4,16w1460):finish;default:accept;',
                                    '(8w2,8w4,16w1460):finish_handshake;default:accept;')
        expected = expected.replace(' state finish{',
            ' state finish_handshake{m.parsed=(bit<1>)(8w1);m.shape_valid=(bit<1>)(8w1);transition accept;}\n state finish{')
        self.assertEqual(self.selected, expected)

    def test_handshake_validation_suffix_has_no_negative_checksum_deposit(self):
        n = shared.role(self.selected, 'N')
        states = dict(re.findall(r' state (\w+)\{([^\n]*)\}', n))
        for state, last, octets in (('ts_syn', 'oa', 20), ('ts_synack', 'ob', 24)):
            body = states[state]
            self.assertIn('tc.subtract(hdr.%s);m.tcp_sum=tc.get();' % last, body)
            sizes = {'mss': 4, 'tso': 12, 'oa': 4, 'ob': 4}
            self.assertEqual(sum(sizes[hdr] for hdr in re.findall(r'pkt.extract\(hdr\.(\w+)\)', body)), octets)
        suffix = ('ts_syn_profile', 'ts_syn_echo', 'ts_syn_ws', 'ts_synack_profile',
                  'ts_synack_sack', 'ts_synack_ts', 'mss_check', 'finish_handshake')
        for state in suffix:
            self.assertNotIn('tc.get()', states[state], state)
            self.assertNotIn('pkt.extract', states[state], state)
            self.assertNotRegex(states[state], r':finish;|transition finish;')
        self.assertIn('16w1460):finish_handshake;', states['mss_check'])
        self.assertIn('m.parsed=(bit<1>)(8w1)', states['finish_handshake'])

    def test_all_fixed_option_bits_timestamps_and_bad_checksums_preserve_admission(self):
        old, new = shared.n_source(self.original), shared.n_source(self.selected)
        count = 0
        for options, flags, variable, fixed in (
                (ts.SYN_OPTIONS, 2, (8,), tuple(range(8)) + tuple(range(12, 20))),
                (ts.SYNACK_OPTIONS, 18, (16, 20), tuple(range(16)))):
            cases = []
            for value in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff):
                varied = bytearray(options)
                for offset in variable:
                    varied[offset:offset + 4] = value.to_bytes(4, 'big')
                good = ts.packet(b'', flags=flags, options=bytes(varied), reverse=flags == 18)
                bad_tcp = bytearray(good); bad_tcp[50] ^= 1
                bad_ip = bytearray(good); bad_ip[24] ^= 1
                cases.extend((('valid', good), ('bad_tcp', bytes(bad_tcp)), ('bad_ip', bytes(bad_ip))))
            for offset in fixed:
                for bit in range(8):
                    invalid = bytearray(options); invalid[offset] ^= 1 << bit
                    cases.append(('bad_option', ts.packet(b'', flags=flags, options=bytes(invalid), reverse=flags == 18)))
            for case, raw in cases:
                outputs = []
                for n, text in ((old, self.original), (new, self.selected)):
                    n.begin_pass(9)
                    accepted, cursor = n.packet_parser(raw)
                    n.run(shared._branch(text)); n.table('network')
                    # Early checksum computation may populate unused metadata
                    # on rejected options. Compare all admission predicates.
                    admission = {field: n.env.get(field) for field in
                                 ('m.parsed', 'm.shape_valid', 'm.packet_kind', 'm.network_valid',
                                  'm.ip_error', 'm.kind', 'm.profile', 'm.hcrc', 'm.bcrc')}
                    # A streaming parser may reject earlier; its emitted
                    # headers plus unparsed remainder must preserve the wire.
                    outputs.append((accepted, admission, n.deparse() + raw[cursor:]))
                self.assertEqual(outputs[0], outputs[1], (flags, case))
                self.assertEqual(new.env.get('m.network_valid'), int(case == 'valid'), (flags, case))
                if case == 'valid':
                    self.assertEqual(new.env.get('m.tcp_sum'), 0xffeb)
                    self.assertEqual(new.deparse()[16:] + raw[cursor:], raw)
                elif case == 'bad_option':
                    self.assertNotEqual(new.env.get('m.parsed'), 1)
                count += 1
        self.assertEqual(count, 286)


if __name__ == '__main__':
    unittest.main()

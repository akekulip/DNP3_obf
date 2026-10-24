"""Keep shallow READ admission identical while removing its parser constant write."""
import hashlib
import json
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


class ParserChecksumPlacement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Isolate c42's two-edit repair; the separate handshake regression
        # exercises c43's deposit relocation on top of the complete c42 source.
        with ExitStack() as patches:
            patches.enter_context(patch.object(relay_sbo, 'relay_departure_provenance', side_effect=lambda src: src))
            for name in ('handshake_checksum_deposits', 'handshake_mss_first', 'early_shallow_checksum',
                         'stream_read_timestamp_prefix', 'early_egress_lengths', 'stream_handshake_options',
                         'padder_crc_placement'):
                patches.enter_context(patch.object(relay_ts, name, side_effect=lambda src: src))
            with patch.object(relay_ts, 'defer_shallow_checksum', side_effect=lambda src: src):
                cls.original, _ = build(**ts.FLAGS, relay_ts=True)
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)

    def test_exact_two_source_edits_preserve_all_other_code(self):
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(),
                         '97025e0c2a440ae2b5ab60d42f4c30622d89115bc93d501736def99ff451afb8')
        expected = self.original.replace('state finish_shallow{m.tcp_sum=16w0xffeb;', 'state finish_shallow{')
        expected = expected.replace('action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;}',
                                    'action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;m.tcp_sum=16w0xffeb;}')
        self.assertEqual(self.selected, expected)
        parser = self.selected[self.selected.index('parser n_IgParser('):self.selected.index('control n_Ingress(')]
        self.assertNotIn('m.tcp_sum=16w0xffeb;', parser)
        self.assertEqual(parser.count('m.tcp_sum=tc.get();'), 1)
        n = shared.role(self.selected, 'N')
        self.assertLess(n.index('read_shallow_admit_t.apply();'), n.index('ports.apply();network.apply();'))
        self.assertLess(n.index('ports.apply();network.apply();'), n.index('guard.apply();'))

    def test_valid_and_invalid_native_packets_have_identical_admission_state(self):
        old, new = shared.n_source(self.original), shared.n_source(self.selected)
        master, relay = 0xc0a80a01, 0xc0a80a07
        for n in (old, new):
            for src, dst, sport, dport, port, links in (
                    (master, relay, 56857, 20000, 64, (0, 0x0100)),
                    (relay, master, 20000, 56857, 9, (0x0100, 0))):
                key = [src, dst, sport, dport]
                n.install('connection', key + [9], 'forward_flow' if port == 64 else 'reverse_flow', [port])
                n.install('read_connection', key, 'read_configure', list(links))
                n.install('data_connection', key, 'configure', [301, 1, 1, 200, 0])
        vectors = ts.HERE.parent / 'read_complete_01/vectors'
        records = []
        for variant in json.loads((vectors / 'two_read_templates_relay.json').read_text())['variants'].values():
            for cls in ('mixed', 'integrity'):
                for field, reverse, kind in (('request', False, 9), ('native', True, 11)):
                    records.append((bytes.fromhex(variant['classes'][cls][field]), reverse, 24,
                                    ts.DATA_OPTIONS, kind))
        exchanges = json.loads((vectors / 'relay_sbo_templates.json').read_text())['exchanges']
        for function in (3, 4):
            item = next(item for item in exchanges if item['function'] == function)
            records.extend(((bytes.fromhex(item['request']), False, 24, ts.DATA_OPTIONS, 5 if function == 3 else 7),
                            (bytes.fromhex(item['native']), True, 24, ts.DATA_OPTIONS, 6)))
        records.extend(((b'', False, 2, ts.SYN_OPTIONS, 1),
                        (b'', True, 18, ts.SYNACK_OPTIONS, 2)))
        for flags in (16, 17, 20, 4):
            records.append((b'', False, flags, ts.DATA_OPTIONS, 3 if flags == 16 else 4))
        count = 0
        for payload, reverse, flags, options, kind in records:
            wire = ts.packet(payload, reverse=reverse, flags=flags, options=options)
            bad_tcp = bytearray(wire); bad_tcp[50] ^= 1
            bad_ip = bytearray(wire); bad_ip[24] ^= 1
            bad_options = bytearray(options); bad_options[0] ^= 1
            options_wire = ts.packet(payload, reverse=reverse, flags=flags, options=bytes(bad_options))
            cases = [('valid', wire), ('bad_tcp', bytes(bad_tcp)), ('bad_ip', bytes(bad_ip)),
                     ('bad_options', options_wire)]
            if payload:
                corrupt = bytearray(payload); corrupt[10] ^= 1
                cases.append(('bad_dnp_crc', ts.packet(bytes(corrupt), reverse=reverse, flags=flags, options=options)))
            for case, raw in cases:
                outputs = []
                for n, text in ((old, self.original), (new, self.selected)):
                    n.begin_pass(9)
                    accepted, cursor = n.packet_parser(raw)
                    n.run(shared._branch(text))
                    n.table('ports'); n.table('network')
                    outputs.append((accepted, cursor, dict(n.env), dict(n.valid), n.deparse()))
                self.assertEqual(outputs[0], outputs[1], (kind, case))
                env = outputs[1][2]
                if case == 'valid':
                    self.assertEqual(env.get('m.packet_kind'), kind)
                    self.assertEqual(env.get('m.network_valid'), 1)
                    if payload:
                        self.assertEqual(env.get('m.profile'), 1)
                        self.assertEqual(env.get('m.bcrc'), 0x993a)
                elif case == 'bad_ip':
                    self.assertEqual(env.get('m.network_valid'), 0)
                elif case == 'bad_tcp':
                    # Existing READ responses are shallow; do not claim a new
                    # full-payload TCP checksum check for this inherited path.
                    self.assertEqual(env.get('m.network_valid'), int(kind == 11))
                elif case == 'bad_options':
                    self.assertNotEqual(env.get('m.parsed'), 1)
                elif case == 'bad_dnp_crc':
                    self.assertNotEqual(env.get('m.bcrc'), 0x993a)
                count += 1
        self.assertEqual(count, 84)


if __name__ == '__main__':
    unittest.main()

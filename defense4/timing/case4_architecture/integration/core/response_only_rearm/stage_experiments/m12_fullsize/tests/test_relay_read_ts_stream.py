"""Stream only N's READ timestamp prefix without losing IP/DNP3 correlation."""
import hashlib
import json
import re
import struct
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


class ReadTimestampStream(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ExitStack() as patches:
            patches.enter_context(patch.object(relay_sbo, 'relay_departure_provenance', side_effect=lambda src: src))
            for name in ('early_egress_lengths', 'stream_handshake_options', 'padder_crc_placement'):
                patches.enter_context(patch.object(relay_ts, name, side_effect=lambda src: src))
            with patch.object(relay_ts, 'stream_read_timestamp_prefix', side_effect=lambda src: src):
                cls.original, _ = build(**ts.FLAGS, relay_ts=True)
            cls.selected, _ = build(**ts.FLAGS, relay_ts=True)
        cls.templates = json.loads((ts.HERE.parent / 'read_complete_01/vectors/two_read_templates_relay.json').read_text())

    def test_scope_is_two_read_entries_and_exact_even_sized_headers(self):
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(),
                         '10e1b0e3fd97660bd10ac0ea00e49d1e29c6880e9a93f49bf953034b18dd6ed7')
        old, new = shared.role(self.original, 'N'), shared.role(self.selected, 'N')
        for role in ('E', 'T'):
            self.assertEqual(shared.role(self.original, role), shared.role(self.selected, role))
        self.assertEqual(old[old.index('control Ingress('):], new[new.index('control Ingress('):])
        self.assertEqual(re.search(r'struct meta_t\{[^}]*\}', old)[0], re.search(r'struct meta_t\{[^}]*\}', new)[0])
        old_states = dict(re.findall(r' state (\w+)\{([^\n]*)\}', old))
        states = dict(re.findall(r' state (\w+)\{([^\n]*)\}', new))
        roots = {'rx_tcp_ts': 'rx_dl', 'rx_response_tcp_ts': 'rx_response_dl'}
        self.assertEqual(set(states) - set(old_states), {root + suffix for root in roots for suffix in ('_kind', '_body')})
        for state in old_states.keys() - roots.keys():
            self.assertEqual(states[state], old_states[state], state)
        self.assertIn('header ts_word_h{bit<16> v;}', new)
        self.assertIn('header ts_body_h{bit<32> value;bit<32> echo;}', new)
        self.assertIn('opt4_h ob;ts_word_h rts0;ts_word_h rts1;ts_body_h rts;dl_h dl;', new)
        for root, destination in roots.items():
            self.assertEqual(states[root], 'pkt.extract(hdr.rts0);tc.subtract(hdr.rts0);transition select(hdr.rts0.v){'
                             '16w0x0101:%s_kind;default:accept;}' % root)
            self.assertEqual(states[root + '_kind'], 'pkt.extract(hdr.rts1);tc.subtract(hdr.rts1);transition select(hdr.rts1.v){'
                             '16w0x080a:%s_body;default:accept;}' % root)
            self.assertEqual(states[root + '_body'], 'pkt.extract(hdr.rts);tc.subtract(hdr.rts);transition %s;' % destination)

    def test_timestamp_values_prefix_corruptions_and_checksum_behavior_match_c44(self):
        old, new = shared.n_source(self.original), shared.n_source(self.selected)
        count = 0
        for variant in self.templates['variants'].values():
            for cls in ('mixed', 'integrity'):
                for field, reverse, kind in (('request', False, 9), ('native', True, 11)):
                    payload = bytes.fromhex(variant['classes'][cls][field])
                    cases = []
                    for value, echo in ((0, 0), (1, 0xffffffff), (0x7fffffff, 0x80000000),
                                        (0xffffffff, 1), (0xaabbccdd, 0x12345678)):
                        options = bytes.fromhex('0101080a') + struct.pack('!II', value, echo)
                        good = ts.packet(payload, reverse=reverse, options=options)
                        bad_tcp = bytearray(good); bad_tcp[50] ^= 1
                        cases.extend((('valid', good), ('bad_tcp', bytes(bad_tcp))))
                    for bit in range(32):
                        options = bytearray(ts.DATA_OPTIONS); options[bit // 8] ^= 1 << (bit % 8)
                        cases.append(('bad_prefix', ts.packet(payload, reverse=reverse, options=bytes(options))))
                    bad_ip = bytearray(ts.packet(payload, reverse=reverse)); bad_ip[24] ^= 1
                    cases.append(('bad_ip', bytes(bad_ip)))
                    for case, raw in cases:
                        outputs = []
                        for n, text in ((old, self.original), (new, self.selected)):
                            n.begin_pass(9)
                            accepted, cursor = n.packet_parser(raw)
                            n.run(shared._branch(text)); n.table('network')
                            admission = {field: n.env.get(field) for field in
                                ('m.parsed', 'm.shape_valid', 'm.packet_kind', 'm.network_valid', 'm.ip_error',
                                 'm.kind', 'm.profile', 'm.hcrc', 'm.bcrc', 'm.crc1', 'm.tcrc')}
                            outputs.append((accepted, admission, n.deparse()[16:] + raw[cursor:]))
                        self.assertEqual(outputs[0], outputs[1], (cls, field, case))
                        self.assertEqual(outputs[1][2], raw)
                        expected = case == 'valid' or (case == 'bad_tcp' and reverse)
                        self.assertEqual(new.env.get('m.network_valid'), int(expected), (cls, field, case))
                        if case == 'bad_prefix':
                            self.assertNotEqual(new.env.get('m.parsed'), 1)
                        else:
                            self.assertEqual(new.env.get('m.packet_kind'), kind)
                            # Source header words reconstruct identical12 bytes:
                            # 2+2+8 keeps all checksum words at even parity.
                            parsed = struct.pack('!HHII', new.env['hdr.rts0.v'], new.env['hdr.rts1.v'],
                                                 new.env['hdr.rts.value'], new.env['hdr.rts.echo'])
                            self.assertEqual(parsed, raw[54:66])
                            if expected:
                                self.assertEqual(new.env.get('m.tcp_sum'), 0xffeb)
                        count += 1
        self.assertEqual(count, 344)

    def test_all_ip_and_link_length_cross_mismatches_are_rejected(self):
        data = next(iter(self.templates['variants'].values()))['classes']
        profiles = {77: bytes.fromhex(data['mixed']['request']), 79: bytes.fromhex(data['integrity']['request']),
                    143: bytes.fromhex(data['mixed']['native']), 186: bytes.fromhex(data['integrity']['native'])}
        n = shared.n_source(self.selected)
        for ip_length, original in profiles.items():
            for dl_length in (18, 20, 76, 115):
                payload = bytearray(original); payload[2] = dl_length
                payload[8:10] = struct.pack('<H', relay_sbo.crc(payload[:8]))
                raw = ts.packet(bytes(payload), reverse=ip_length > 100)
                self.assertEqual(int.from_bytes(raw[16:18], 'big'), ip_length)
                n.begin_pass(9); n.packet_parser(raw)
                n.run(shared._branch(self.selected)); n.table('network')
                valid = dl_length == original[2]
                self.assertEqual(n.env.get('m.parsed'), int(valid), (ip_length, dl_length))
                self.assertEqual(n.env.get('m.network_valid'), int(valid), (ip_length, dl_length))


if __name__ == '__main__':
    unittest.main()

"""Native SEL-751 timestamp TCP options across N, E and pipe1 READ padding."""
import sys
from pathlib import Path
import struct
import unittest
import json
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import test_n_read_shapes as shared

FLAGS = dict(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True,
             ack_retry=True, read_handshake=True, headroom=True, relay=True, relay_sbo=True)
DATA_OPTIONS = bytes.fromhex('0101080aaabbccdd12345678')
SYN_OPTIONS = bytes.fromhex('020405b40402080aaabbccdd0000000001030307')
SYNACK_OPTIONS = bytes.fromhex('020405b401030300010104020101080aaabbccdd12345678')


def packet(raw, reverse=False, flags=24, options=DATA_OPTIONS):
    src, dst = (bytes([192, 168, 10, 7]), bytes([192, 168, 10, 1])) if reverse else (bytes([192, 168, 10, 1]), bytes([192, 168, 10, 7]))
    sport, dport = (20000, 56857) if reverse else (56857, 20000)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, 900, 146, ((20 + len(options)) // 4) << 4, flags, 4096, 0, 0) + options
    tcp = tcp[:16] + struct.pack('!H', shared._sum(src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(raw)) + tcp + raw)) + tcp[18:]
    ip = struct.pack('!BBHHHBB', 0x45, 0, 20 + len(tcp) + len(raw), 0, 0x4000, 64, 6) + b'\0\0' + src + dst
    ip = ip[:10] + struct.pack('!H', shared._sum(ip)) + ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800') + ip + tcp + raw


class NativeTimestamp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from m12gen.build import build
        cls.text, _ = build(**FLAGS, relay_ts=True)

    def test_manifest_ip_lengths_include_options_only_for_ts_profile(self):
        flags = ['--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--two-read', '--reduce',
                 '--ack-retry', '--read-handshake', '--headroom', '--relay', '--relay-sbo']
        for ts in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run([sys.executable, str(HERE / 'make_m12.py'), tmp] + flags + (['--relay-ts'] if ts else []),
                               check=True, capture_output=True)
                doc = json.loads((Path(tmp) / 'response_only.inputs.json').read_text())
                self.assertEqual(doc['read_shapes']['mixed']['native_ip_len'], 143 if ts else 131)
                self.assertEqual(doc['read_shapes']['mixed']['request_ip_len'], 77 if ts else 65)
                self.assertEqual(doc['read_shapes']['full']['native_ip_len'], 186 if ts else 174)
                self.assertEqual(doc['read_shapes']['full']['request_ip_len'], 79 if ts else 67)

    def test_parser_select_keys_stay_within32bits(self):
        import test_two_read_pad as read
        parsers = [shared.n_source(self.text), shared.interp.ESource(shared.role(self.text, 'E')),
                   read.interp.ESource(read.padder_source(self.text))]
        for parser in parsers:
            parser.begin_pass(9)
            for name, (statements, transition) in parser.pstates.items():
                if transition[0] != 'goto':
                    width = sum(parser.ev(field)[1] for field in transition[1])
                    self.assertLessEqual(width, 32, name)

    def test_every_fixed_option_bit_rejected_and_timestamp_values_preserved(self):
        n = shared.n_source(self.text)
        e = shared.interp.ESource(shared.role(self.text, 'E'))
        for options, flags, variable, fixed in (
                (SYN_OPTIONS, 2, (8,), tuple(range(8)) + tuple(range(12, 20))),
                (SYNACK_OPTIONS, 18, (16, 20), tuple(range(16)))):
            for value in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff):
                good = bytearray(options)
                for offset in variable:
                    good[offset:offset + 4] = value.to_bytes(4, 'big')
                raw = packet(b'', flags=flags, options=bytes(good), reverse=flags == 18)
                n.begin_pass(9); n.packet_parser(raw)
                self.assertEqual(n.env.get('m.parsed'), 1)
                self.assertEqual(n.deparse()[16:], raw)
                e.begin_pass(0); e.env['eg.egress_port'] = 9
                e.packet_parser(bytes(16) + raw)
                self.assertEqual(e.env.get('m.tcp_odd'), 0)
                self.assertEqual(e.deparse(), bytes(16) + raw)
            for offset in fixed:
                for bit in range(8):
                    bad = bytearray(options); bad[offset] ^= 1 << bit
                    raw = packet(b'', flags=flags, options=bytes(bad), reverse=flags == 18)
                    n.begin_pass(9); n.packet_parser(raw)
                    self.assertNotEqual(n.env.get('m.parsed'), 1, (flags, offset, bit))
                    e.begin_pass(0); e.env['eg.egress_port'] = 9
                    e.packet_parser(bytes(16) + raw)
                    self.assertEqual(e.env.get('m.tcp_odd'), 1, (flags, offset, bit))

    def test_normalizer_accepts_actual_options_and_rejects_clean_control(self):
        from m12gen import relay_sbo as r
        n = shared.n_source(self.text)
        request = bytes.fromhex('056424c4000001004a59cbcb030c011702010101c800000000008136000000030101c8000000000000000015ee')
        response = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        for raw, reverse, kind in ((request, False, 5), (response, True, 6)):
            n.begin_pass(9)
            accepted, cursor = n.packet_parser(packet(raw, reverse))
            self.assertTrue(accepted)
            self.assertEqual(n.env.get('m.packet_kind'), kind)
            self.assertEqual(n.env.get('m.parsed'), 1)
            self.assertEqual(n.env.get('m.tcp_sum'), 0xffeb)
            self.assertEqual(n.deparse()[16:], packet(raw, reverse))
            n.begin_pass(9)
            n.packet_parser(packet(raw, reverse, options=b''))
            self.assertNotEqual(n.env.get('m.parsed'), 1)

    def test_normalizer_preserves_both_syn_option_layouts(self):
        n = shared.n_source(self.text)
        for options, flags, kind in ((SYN_OPTIONS, 2, 1), (SYNACK_OPTIONS, 18, 2)):
            n.begin_pass(9)
            raw = packet(b'', flags=flags, options=options, reverse=kind == 2)
            accepted, cursor = n.packet_parser(raw)
            self.assertTrue(accepted)
            self.assertEqual(n.env.get('m.packet_kind'), kind)
            self.assertEqual(n.env.get('m.tcp_sum'), 0xffeb)
            self.assertEqual(n.deparse()[16:], raw)
            for offset in (0, 1, 4, 5):
                damaged = bytearray(options); damaged[offset] ^= 1
                n.begin_pass(9)
                n.packet_parser(packet(b'', flags=flags, options=bytes(damaged), reverse=kind == 2))
                self.assertNotEqual(n.env.get('m.parsed'), 1)

    def test_actual_two_read_requests_and_responses(self):
        templates = json.loads((HERE.parent / 'read_complete_01/vectors/two_read_templates_relay.json').read_text())
        n = shared.n_source(self.text)
        for variant in templates['variants'].values():
            for cls in ('mixed', 'integrity'):
                for field, reverse, kind in (('request', False, 9), ('native', True, 11)):
                    raw = bytes.fromhex(variant['classes'][cls][field])
                    n.begin_pass(9)
                    accepted, cursor = n.packet_parser(packet(raw, reverse=reverse))
                    self.assertTrue(accepted)
                    self.assertEqual(n.env.get('m.packet_kind'), kind)
                    self.assertEqual(n.env.get('m.parsed'), 1)
                    self.assertEqual(n.deparse()[16:] + packet(raw, reverse)[cursor:], packet(raw, reverse))

    def test_pipe1_read_padding_preserves_options_and_native_application(self):
        import test_two_read_pad as read
        derive = read._module('ts_relay_derive', HERE.parent / 'read_complete_01/vectors/derive_two_read_relay.py')
        constants = json.loads((HERE.parent / 'read_complete_01/vectors/constants_two_read_relay.json').read_text())['shapes']
        templates = json.loads((HERE.parent / 'read_complete_01/vectors/two_read_templates_relay.json').read_text())
        e = read.interp.ESource(read.padder_source(self.text))
        key = [int.from_bytes(bytes([192, 168, 10, 7]), 'big'), int.from_bytes(bytes([192, 168, 10, 1]), 'big'), 20000, 56857]
        e.install('p1_conn', key, 'p1_pad_ok', [])
        for cls, shape, iplen in (('mixed', 'mixed_g1v2_g30v1_91', 193), ('integrity', 'integrity_134', 210)):
            for variant in templates['variants'].values():
                native = bytes.fromhex(variant['classes'][cls]['native'])
                tev = bytearray(16); tev[12] = 11
                out = e.inject(180, bytes(tev) + packet(native, reverse=True))
                self.assertEqual(out[70:82], DATA_OPTIONS)
                self.assertEqual(out[82:], derive.derive.construct(native, constants[shape]))
                self.assertEqual(int.from_bytes(out[32:34], 'big'), iplen)
                mapper = shared.interp.ESource(shared.role(self.text, 'E'))
                mapper.begin_pass(0); mapper.env['eg.egress_port'] = 9
                accepted, cursor = mapper.packet_parser(out)
                self.assertTrue(accepted)
                mapper.table('leff_t'); mapper.table('read_profile')
                self.assertEqual(mapper.env['m.leff'], len(native))
                self.assertEqual(mapper.env['m.read_shape'], 1)

    def test_mapper_preserves_timestamps_and_maps_native_lengths(self):
        from m12gen import relay_sbo as r
        e = shared.interp.ESource(shared.role(self.text, 'E'))
        native = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        raw = bytes(16) + packet(native, reverse=True)
        e.begin_pass(0); e.env['eg.egress_port'] = 9
        accepted, cursor = e.packet_parser(raw)
        self.assertTrue(accepted)
        self.assertEqual(e.deparse(), raw)
        for table in ('leff_t', 'ctl_profile', 'in_dl_t', 'in_cb0_t', 'in_ct_t', 'status_crc_t', 'crc_ctl_tail2_t', 'ctl_pad_t'):
            e.table(table)
        out = e.deparse()
        self.assertEqual(e.env['m.leff'], 49)
        self.assertEqual(out[70:82], DATA_OPTIONS)
        self.assertEqual(out[82:], r.encode(native))
        self.assertEqual(int.from_bytes(out[32:34], 'big'), 112)
        for options, flags in ((SYN_OPTIONS, 2), (SYNACK_OPTIONS, 18)):
            raw = bytes(16) + packet(b'', flags=flags, options=options, reverse=flags == 18)
            e.begin_pass(0); e.env['eg.egress_port'] = 9
            accepted, cursor = e.packet_parser(raw)
            self.assertTrue(accepted)
            e.table('shape_t'); e.table('leff_t')
            self.assertEqual(e.env['m.leff'], 0)
            self.assertEqual(e.deparse(), raw)

    def test_control_checksum_field_list_matches_full_packet_with_ts(self):
        """Independent checksum algebra; compiled extern execution remains required."""
        e = shared.interp.ESource(shared.role(self.text, 'E'))
        native = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        old = packet(native, reverse=True)
        e.begin_pass(0); e.env['eg.egress_port'] = 9
        e.packet_parser(bytes(16) + old)
        for table in ('ctl_profile', 'in_dl_t', 'in_cb0_t', 'in_ct_t', 'status_crc_t', 'crc_ctl_tail2_t', 'ctl_pad_t'):
            e.table(table)
        e.env['hdr.tcp.seq'] += 123
        e.env['hdr.tcp.ack'] += 456
        e.env['hdr.tcp.window'] = 8192
        tcp = old[34:]
        pseudo = old[26:34] + struct.pack('!BBH', 0, 6, len(tcp))
        # The parser removes oldseq,oldACK,window,checksum and parsedoption/payload
        # bytes. Ports,offset/flags,urgent and the oldpseudoheader remain.
        residual = (~shared._sum(pseudo + tcp[:4] + tcp[12:14] + tcp[18:20])) & 0xffff
        fields = re.search(r'tcp_ctl.update\(\{([^}]+)\}', self.text)[1].split(',')
        bits, width = 0, 0
        for field in fields:
            field = field.strip()
            if field == '8w0':
                value, size = 0, 8
            elif field == 'm.r_residual':
                value, size = residual, 16
            else:
                value, size = e.env.get(field, 0), e.width[field]
            bits = (bits << size) | value
            width += size
        generated = shared._sum(bits.to_bytes(width // 8, 'big'))
        out = e.deparse()[16:]
        wire_tcp = out[34:]
        wire_tcp = wire_tcp[:16] + b'\0\0' + wire_tcp[18:]
        expected = shared._sum(out[26:34] + struct.pack('!BBH', 0, 6, len(wire_tcp)) + wire_tcp)
        self.assertEqual(generated, expected)

    def test_constant_crob_pair_storage_removed_but_dynamic_start_retained(self):
        text = shared.role(self.text, 'N')
        self.assertNotIn('pair_real_object_real_on', text)
        self.assertNotIn('compare_real_object', text)
        self.assertIn('Register<bit<32>,bit<1>>(1,0) pair_real_off_native_start;', text)
        self.assertIn('v!=m.compare_native_start', text)
        declarations = re.findall(r'RegisterAction<bit<32>,bit<1>,bit<32>>\(pair_real_off_native_start\) (\w+)=\{void apply\(inout ([^,]+) v,', text)
        self.assertEqual(sorted(declarations), [('read_real_off', 'bit<32>'), ('write_real_off', 'bit<32>')])
        for authority in ('real_links_t.apply()', 'real_tcp_dst_t.apply()', 'native_end_t.apply()', 'application_t.apply()'):
            self.assertIn(authority, text)

    def test_all_dynamic_sbo_association_coordinates_still_match(self):
        n = shared.n_source(self.text)
        client, server = 0xc0a80a01, 0xc0a80a07
        n.begin_pass(9)
        n.env.update({'m.stage': 1, 'm.kind': 5, 'm.work_phase': 1, 'm.epoch_diff': 0,
                      'hdr.expected_cell.expected_cell': 0x90005, 'hdr.dl.dst': 0, 'hdr.dl.src': 0x0100,
                      'hdr.ip.src': client, 'hdr.ip.dst': server, 'hdr.tcp.sport': 56857, 'hdr.tcp.dport': 20000,
                      'hdr.tcp.seq': 900, 'hdr.tcp.ack': 146, 'hdr.first.w0': 0xc0c0030c})
        n.action('compare_select_inputs')
        tables = ('real_links_t', 'real_tcp_dst_t', 'real_off_t', 'native_end_t', 'application_t')
        for table in tables:
            n.table(table)
        response = {'m.stage': 0, 'm.kind': 6, 'm.work_phase': 4, 'm.epoch_diff': 0,
                    'm.response': 1, 'm.matched': 0, 'hdr.dl.dst': 0x0100, 'hdr.dl.src': 0,
                    'hdr.ip.src': server, 'hdr.ip.dst': client, 'hdr.tcp.sport': 20000, 'hdr.tcp.dport': 56857,
                    'hdr.tcp.seq': 146, 'hdr.tcp.ack': 945, 'hdr.first.w0': 0xc0c08180}
        for field in (None, 'hdr.dl.dst', 'hdr.dl.src', 'hdr.ip.src', 'hdr.ip.dst', 'hdr.tcp.sport',
                      'hdr.tcp.dport', 'hdr.tcp.seq', 'hdr.tcp.ack', 'hdr.first.w0'):
            n.begin_pass(9)
            n.env.update(response)
            if field:
                n.env[field] ^= 0x10000 if field == 'hdr.first.w0' else 1
            n.action('compare_response_inputs')
            for table in tables:
                n.table(table)
            n.table('object_match')
            self.assertEqual(n.env['m.matched'], int(field is None), field)

    def test_reverse_window_uses_negotiated_scale7_units(self):
        e = shared.interp.ESource(shared.role(self.text, 'E'))
        for native, image in ((49, 60), (91, 141), (134, 158)):
            for window in (0, 1, 2, 127, 255, 4096, 65535):
                for distance in range(1, image + 1):
                    e.begin_pass(0)
                    e.env.update({'m.s_end': native, 'm.r': (-distance) & 0xffffffff,
                                  'm.p': 0x12345678, 'hdr.tcp.window': window})
                    e.action('reverse_window_base')
                    e.action('rev_withhold_open')
                    e.table('window_t')
                    capacity = window << 7
                    expected = 0 if capacity < distance else min(65535, (native + capacity - distance) >> 7)
                    self.assertEqual(e.env['hdr.tcp.window'], expected, (native, window, distance))
                    self.assertEqual(e.env['hdr.tcp.ack'], 0x12345678)


if __name__ == '__main__':
    unittest.main()

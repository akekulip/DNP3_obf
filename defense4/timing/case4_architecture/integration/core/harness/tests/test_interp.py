"""Unit tests for the constructs interp_ext adds. Expectations come from independent code."""
import unittest

import support
import rrc
import vectors
from interp_ext import ExtSource
from driver import Pipeline


def source():
    return ExtSource(vectors.source_text(), include_dir=vectors.SOURCE_PATH.parent)


class Constructs(unittest.TestCase):
    def test_intrinsic_ingress_port_is_an_env_input(self):
        src = source()
        src.begin_pass(7)
        self.assertEqual(src.expr('ig.ingress_port'), 7)
        self.assertEqual(src.expr('RETURN_PORT'), 68)

    def test_parser_selects_envelope_only_on_return_port(self):
        raw = bytes.fromhex('00000011 00000001 00050001 0103 0000'.replace(' ', '')) + vectors.packet(16, 5, 6)
        src = source()
        src.begin_pass(68)
        self.assertEqual(src.packet_parser(raw), (True, len(raw) - 0))
        self.assertTrue(src.valid['envelope'] and src.valid['event'])
        self.assertEqual(src.env['hdr.envelope.epoch'], 0x11)
        src.begin_pass(1)
        src.packet_parser(vectors.packet(16, 5, 6))
        self.assertFalse(src.valid.get('envelope', False))

    def test_range_and_ternary_keys(self):
        src = source()
        src.env.update({'m.parsed': 1, 'm.kind': 3, 'hdr.tcp.flags': 16, 'm.ip_error': 0,
                        'm.tcp_sum': 0xffeb, 'hdr.ip.ttl': 64, 'hdr.tcp.reserved': 0, 'hdr.tcp.urgent': 0})
        src.table('network')
        self.assertEqual(src.env['m.network_valid'], 1)
        for key, bad in (('hdr.ip.ttl', 0), ('m.tcp_sum', 0xffea), ('m.ip_error', 1), ('hdr.tcp.flags', 2)):
            src.env.update({'m.network_valid': 0, 'm.tcp_sum': 0xffeb, 'm.ip_error': 0,
                            'hdr.ip.ttl': 64, 'hdr.tcp.flags': 16})
            src.env[key] = bad
            src.table('network')
            self.assertEqual(src.env['m.network_valid'], 0, key)
        src.env.update({'m.network_valid': 0, 'hdr.tcp.flags': 16, 'm.ip_error': 0, 'm.tcp_sum': 0xffeb, 'hdr.ip.ttl': 255})
        src.table('network')
        self.assertEqual(src.env['m.network_valid'], 1)   # range upper bound inclusive

    def test_ternary_mask_entry_matches_on_masked_bits(self):
        src = source()
        src.env.update({'m.kind': 5, 'm.sequence_valid': 1, 'm.matched': 0, 'm.observed': 0x50007})
        src.table('first_event')
        self.assertEqual(src.env['hdr.event.event'], 0x0105)

    def test_slice_assignment_and_concatenation(self):
        src = source()
        src.env['hdr.event.event'] = 0x0105
        src.action('abort_work')
        self.assertEqual(src.env['hdr.event.event'], 0x01ff)
        src.env.update({'hdr.expected_cell.expected_cell': 0x00050001, 'm.observed': 0})
        src.action('close_pending')
        self.assertEqual(src.env['m.desired'], 0x00060001)
        src.action('publish_select')
        self.assertEqual(src.env['m.desired'], 0x00090001)

    def test_fixed_width_wraparound_and_signed_compare(self):
        src = source()
        src.env.update({'hdr.tcp.seq': 5, 'm.client': 7})
        src.action('diff_forward')
        self.assertEqual(src.env['m.client_diff'], (5 - 7) & 0xffffffff)
        src.cells[('', 'counter')][0] = 0xffffffff
        self.assertEqual(src.execute('allocate', 0), 0)           # (int<32>)v != -1 guard
        self.assertEqual(src.cells[('', 'counter')][0], 0xffffffff)
        src.cells[('', 'counter')][0] = 3
        self.assertEqual(src.execute('allocate', 0), 4)

    def test_crc_hash_matches_independent_dnp3_crc(self):
        src = source()
        fields = {'magic': (0x0564, 2), 'len': (26, 1), 'ctrl': (0xc4, 1), 'dst': (0x0a00, 2), 'src': (0x0100, 2)}
        data = b''
        for name, (value, size) in fields.items():
            src.env['hdr.dl.' + name] = value
            data += value.to_bytes(size, 'big')
        src.table('input_head_t')
        self.assertEqual(src.env['m.hcrc'], rrc.dnp3_crc(data))

    def test_hash_over_slices_matches_dnp3_crc_of_the_block(self):
        select = vectors.native_select()
        body = select[10:26]                      # first 16-byte data block
        src = source()
        src.begin_pass(1)
        src.packet_parser(vectors.packet(24, 1, 2, payload=select))
        src.table('input_body_t')
        self.assertEqual(src.env['m.bcrc'], rrc.dnp3_crc(body))
        self.assertEqual(src.env['hdr.first.crc'], int.from_bytes(select[26:28], 'big'))   # field holds wire bytes; P4 swaps the hash

    def test_parser_checksums_accept_valid_and_flag_corrupt(self):
        good = vectors.packet(16, 136, 958)
        src = source()
        src.begin_pass(1)
        src.packet_parser(good)
        self.assertEqual((src.env['m.ip_error'], src.env['m.tcp_sum']), (0, 0xffeb))
        for index in (24, 50):
            bad = bytearray(good)
            bad[index] ^= 1
            src.begin_pass(1)
            src.packet_parser(bytes(bad))
            self.assertNotEqual((src.env['m.ip_error'], src.env['m.tcp_sum']), (0, 0xffeb), index)

    def test_register_action_pairs_store_then_compare(self):
        src = source()
        src.env.update({'m.compare_real_links': 5, 'm.compare_real_tcp_src': 9})
        src.action('store_real_links')
        self.assertEqual(src.cells[('', 'pair_real_links_real_tcp_src')][0], {'first': 5, 'second': 9})
        src.action('compare_real_links')
        self.assertEqual(src.env['m.diff_real_links'], 0)
        src.env['m.compare_real_tcp_src'] = 8
        src.action('compare_real_links')
        self.assertEqual(src.env['m.diff_real_links'], 1)

    def test_sub_control_work_record_claim_return_and_unavailable(self):
        src = source()
        def apply(op, generation, expected):
            src.env.update({'m.work_op': op, 'm.generation': generation, 'm.expected_work_phase': expected,
                            'm.work_phase': 99})
            src.frame.ctrl.insts  # instance exists on Ingress
            src.run('work.apply(m.work_op,m.generation,m.expected_work_phase,m.work_phase);')
            return src.env['m.work_phase'], dict(src.cells[('work', 'work')][0])
        self.assertEqual(apply(1, 0, 0), (0, {'generation': 0, 'phase': 4}))      # generation 0 unavailable
        self.assertEqual(apply(1, 7, 0), (4, {'generation': 7, 'phase': 1}))      # claim from free
        self.assertEqual(apply(1, 8, 0), (1, {'generation': 7, 'phase': 1}))      # busy: no claim
        self.assertEqual(apply(2, 7, 1), (1, {'generation': 7, 'phase': 2}))      # advance
        self.assertEqual(apply(2, 6, 2), (0, {'generation': 7, 'phase': 2}))      # wrong generation
        self.assertEqual(apply(3, 7, 2), (2, {'generation': 7, 'phase': 2}))      # inspect, no change

    def test_deparser_emits_valid_headers_in_headers_t_order(self):
        src = source()
        for name in ('event', 'envelope', 'expected_cell', 'work_generation'):
            src.valid[name] = True
        src.env.update({'hdr.envelope.epoch': 1, 'hdr.work_generation.generation': 2,
                        'hdr.expected_cell.expected_cell': 3, 'hdr.event.event': 0x0105})
        self.assertEqual(src.deparse(), bytes.fromhex('00000001 00000002 00000003 0105 0000'.replace(' ', '')))

    def test_unsupported_names_still_raise(self):
        src = source()
        with self.assertRaises(ValueError):
            src.expr('ig.no_such_field')

    def test_agrees_with_frozen_fragment_interpreter_on_a_table_it_supports(self):
        import re
        from source_eval import Source as Frozen
        text = vectors.source_text()
        text = re.sub(r'#include "work_record.p4"', '', text)
        text = re.sub(r'\br\b', 'rv', text).replace('RETURN_PORT', '9w68').replace(',_):', ',8w0&&&8w0):')
        text = re.sub(r'(8w\d+):(\w+\(\);)', r'(\1):\2', text)
        for kind, owner in ((2, 0x30001), (3, 0x50001), (4, 0x70001), (5, 0x50001), (6, 0x90001)):
            values = {'m.kind': kind, 'm.sequence_valid': 1, 'm.matched': 1 if kind == 6 else 0, 'm.observed': owner,
                      'hdr.event.event': 0x1ff, 'm.generation': 3, 'm.epoch': 4}
            old = Frozen(text, dict(values))
            old.table('first_event')
            new = source()
            new.env.update(values)
            new.table('first_event')
            self.assertEqual(new.env['hdr.event.event'], old.env['hdr.event.event'], (kind, owner))


if __name__ == '__main__':
    unittest.main()

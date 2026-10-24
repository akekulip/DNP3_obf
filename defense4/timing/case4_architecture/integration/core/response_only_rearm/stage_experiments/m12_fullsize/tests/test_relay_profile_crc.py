"""Bounded fixed-profile CRC lookups retain the original native predicates."""
import re
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_n_read_shapes as shared
from m12gen import relay_sbo as r
from m12gen.build import build


class RelayProfileCRC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True,
                            reduce=True, ack_retry=True, read_handshake=True,
                            headroom=True, relay=True, relay_sbo=True, relay_ts=True)

    def test_large_tail_hashes_are_replaced_by_bounded_tables(self):
        for name in ('hash_tail', 'hash_response_tail', 'hash_in_ct', 'hash_ctl_tail2'):
            self.assertIsNone(re.search(r'\b' + name + r'\b', self.text), name)
        self.assertIn('table in_ct_t{key={hdr.ctn.status:exact;}', self.text)
        self.assertIn('table crc_ctl_tail2_t{key={hdr.cb0.tpctrl:exact;}', self.text)
        self.assertNotIn('ctl_sequences_t', self.text)
        guard = self.text[self.text.index('table guard{'):self.text.index('\n apply{')]
        for terms, action in re.findall(r'\(([^()]*)\):([^;]+);', guard):
            fields = terms.split(',')
            if fields[1] in ('8w5', '8w6') and action.startswith(('go_new', 'go_retry', 'go_ret_work')):
                self.assertEqual(fields[6], '8w1', (terms, action))

    def test_all_sequence_status_crc_contributions_match_complete_block(self):
        status_rows = {int(s): (int(native), int(delta)) for s, native, delta in re.findall(
            r'8w(\d+):tail_status_crc\(16w(\d+),16w(\d+)\);', self.text)}
        sequence_rows = {int(s): (int(tp), int(base)) for s, tp, base in re.findall(
            r'8w(\d+):tail_sequence_crc\(8w(\d+),16w(\d+)\);', self.text)}
        self.assertEqual(len(status_rows), 256)
        self.assertEqual(len(sequence_rows), 64)
        for seq in range(64):
            tp, baseline = sequence_rows[0xc0 | seq]
            self.assertEqual(tp, 0x80 | ((seq + 1) & 63))
            for status in range(256):
                native, delta = status_rows[status]
                body = bytes(4) + bytes([status, 3, 1, 1]) + bytes.fromhex('c800000000000000')
                self.assertEqual(native, r.crc(body))
                self.assertEqual(baseline ^ delta, r.crc(bytes([tp]) + body[:-1]))

    def test_native_lookup_predicates_accept_only_original_crc(self):
        n = shared.n_source(self.text)
        # Request tail is15 bytes: off16,status,index2,code2,count2,on2,off2,status2.
        request = bytes(3) + bytes([3, 1, 1]) + bytes.fromhex('c800000000000000') + bytes(1)
        self.assertEqual(len(request), 15)
        expected = int.from_bytes(struct.pack('<H', r.crc(request)), 'big')
        request_table = self.text[self.text.index('table input_tail_t{'):].split('\n', 1)[0]
        self.assertIn('const default_action=tail_crc_bad();', request_table)
        self.assertEqual(re.findall(r'16w0x([0-9a-f]+):input_tail\(\);', request_table), ['%04x' % expected])
        response_table = self.text[self.text.index('table response_crct_t{'):].split('\n', 1)[0]
        self.assertIn('const default_action=tail_crc_bad();', response_table)
        exact = [(int(status), int(checksum, 16)) for status, checksum in re.findall(
            r'\(8w(\d+),16w0x([0-9a-f]+)\):response_crct\(\);', response_table)]
        self.assertEqual(len(exact), 256)
        for checksum in [expected] + [expected ^ (1 << bit) for bit in range(16)]:
            n.begin_pass(9)
            n.env['hdr.tail.crc'] = checksum
            n.table('input_tail_t')
            self.assertEqual(n.env['m.tcrc'] == 0x993a, checksum == expected)
        for status in range(256):
            body = bytes(4) + bytes([status, 3, 1, 1]) + bytes.fromhex('c800000000000000')
            expected = int.from_bytes(struct.pack('<H', r.crc(body)), 'big')
            self.assertEqual([checksum for value, checksum in exact if value == status], [expected])
            for checksum in [expected] + [expected ^ (1 << bit) for bit in range(16)]:
                n.begin_pass(9)
                n.env.update({'hdr.rtail.status': status, 'hdr.rtail.crc': checksum})
                n.table('response_crct_t')
                self.assertEqual(n.env['m.tcrc'] == 0x993a, checksum == expected)

    def test_egress_profile_checks_every_fixed_crob_field_independently(self):
        e = shared.interp.ESource(shared.role(self.text, 'E'))
        fields = {'hdr.dl.start': 0x0564, 'hdr.dl.len': 38,
                  'hdr.cb0.tpctrl': 0xc0, 'hdr.cb0.appctrl': 0xc0,
                  'hdr.cb0.func': 0x81, 'hdr.cb0.g_group': 12, 'hdr.cb0.g_var': 1,
                  'hdr.cb0.g_qual': 0x17, 'hdr.cb0.g_count': 2,
                  'hdr.cb0.index': 1, 'hdr.cb0.crob_code': 1, 'hdr.cb0.crob_count': 1,
                  'hdr.cb0.on_hi': 0xc8000000, 'hdr.ctn.off': 0,
                  'hdr.ctn.index2': 3, 'hdr.ctn.code2': 1, 'hdr.ctn.count2': 1,
                  'hdr.ctn.on2': 0xc8000000, 'hdr.ctn.off2': 0}
        mutations = [(None, 0)]
        for field in fields:
            width = 32 if field.endswith(('on_hi', '.off', '.on2', '.off2')) else 16 if field == 'hdr.dl.start' else 8
            bits = (6, 7) if field == 'hdr.cb0.tpctrl' else range(4, 8) if field == 'hdr.cb0.appctrl' else range(width)
            mutations.extend((field, 1 << bit) for bit in bits)
        for field, difference in mutations:
            e.begin_pass(0)
            e.env.update(fields)
            e.env['m.ctl_shape'] = 0
            if field:
                e.env[field] ^= difference
            e.table('ctl_profile')
            self.assertEqual(e.env['m.ctl_shape'], 0 if field else 1, field)

    def test_normalizer_fixed_byte_checks_still_guard_crc_lookup(self):
        n = shared.n_source(self.text)
        common = {'hdr.dl.magic': (0x0564, 0xffff), 'hdr.first.w2': (0x0101c800, 0xffffffff),
                  'hdr.first.w3': (0, 0xffffffff)}
        request = dict(common, **{'hdr.dl.len': (36, 255), 'hdr.dl.ctrl': (0xc4, 255),
            'hdr.first.w0': (0xc0c0030c, 0xc0f0ffff), 'hdr.first.w1': (0x01170201, 0xffffffff),
            'hdr.tail.off': (0, 65535), 'hdr.tail.status': (0, 255),
            'hdr.tail.index2': (3, 255), 'hdr.tail.code2': (1, 255), 'hdr.tail.count2': (1, 255),
            'hdr.tail.on2': (0xc8000000, 0xffffffff), 'hdr.tail.off2': (0, 0xffffffff),
            'hdr.tail.status2': (0, 255)})
        response = dict(common, **{'hdr.dl.len': (38, 255), 'hdr.dl.ctrl': (0x44, 255),
            'hdr.first.w0': (0xc0c08100, 0xc0f0ff00), 'hdr.first.w1': (0x000c0117, 0x00ffffff),
            'hdr.first.w2': (0x02010101, 0xffffffff), 'hdr.first.w3': (0xc8000000, 0xffffffff),
            'hdr.rtail.off': (0, 0xffffffff), 'hdr.rtail.index2': (3, 255),
            'hdr.rtail.code2': (1, 255), 'hdr.rtail.count2': (1, 255),
            'hdr.rtail.on2': (0xc8000000, 0xffffffff), 'hdr.rtail.off2': (0, 0xffffffff)})
        for table, fields in (('profile', request), ('response_profile', response)):
            mutations = [(None, 0)] + [(field, 1 << bit) for field, (_, mask) in fields.items()
                                       for bit in range(32) if mask & (1 << bit)]
            for field, difference in mutations:
                n.begin_pass(9)
                n.env.update({name: value for name, (value, _) in fields.items()})
                n.env['m.profile'] = 0
                if field:
                    n.env[field] ^= difference
                n.table(table)
                self.assertEqual(n.env['m.profile'], 0 if field else 1, (table, field, difference))

    def test_generated_egress_preserves_application_with_status1_and_status2(self):
        text, _ = build(c3='cimg', shapes='passthrough', two_read_build=True,
                        reduce=True, ack_retry=True, read_handshake=True,
                        headroom=True, relay=True, relay_sbo=True)
        e = shared.interp.ESource(shared.role(text, 'E'))
        raw = bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        header, original = r.deframe(raw)
        for seq in (0, 1, 31, 62, 63):
            for status in range(256):
                user = bytearray(original)
                user[0] = 0xc0 | seq
                user[20] = status
                user[-1] = 255 - status
                native = r.frame(header, bytes(user))
                record = dict(src=(bytes([10, 0, 0, 2]), 20000), dst=(bytes([10, 0, 0, 1]), 56857),
                              payload=native, seq=900, ack=146, flags=24)
                e.begin_pass(0)
                e.env['eg.egress_port'] = 9
                accepted, _ = e.packet_parser(bytes(16) + shared.frame(record))
                self.assertTrue(accepted)
                for table in ('ctl_profile', 'in_dl_t', 'in_cb0_t', 'in_ct_t',
                              'status_crc_t', 'crc_ctl_tail2_t', 'ctl_pad_t'):
                    e.table(table)
                self.assertEqual(e.env['m.ctl_shape'], 1)
                self.assertEqual(e.env['m.in_ct'], r.crc(native[28:44]))
                self.assertEqual(e.deparse()[70:], r.encode(native), (seq, status))


if __name__ == '__main__':
    unittest.main()

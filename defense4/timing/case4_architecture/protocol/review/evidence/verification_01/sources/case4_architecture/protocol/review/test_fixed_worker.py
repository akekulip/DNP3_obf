"""Frozen root fixed-worker byte differential; supplied parser results, no model."""
from pathlib import Path
import sys
import unittest

ARCH = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ARCH / 'protocol/assembly'), str(ARCH / 'protocol'), str(ARCH / 'tests')]
from assembly_eval import Source as RangeSource
from source_control import Source as CheckedSource
from source_eval import block


class Source(RangeSource, CheckedSource):
    pass


class FixedWorkerReview(unittest.TestCase):
    SOURCE = ARCH / 'integration/assembly_passes/evidence/fixed_worker_0_04/source/fixed_worker_0.p4'

    def setUp(self):
        self.text = self.SOURCE.read_text()
        self.payload = bytes((position * 17 + 3) & 255 for position in range(35))

    def execute(self, offset, data, expected, **overrides):
        fields = {'p.parser_err': 0, 'm.private': 1, 'm.parsed': 1, 'm.ip_error': 0,
                  'm.tcp_sum': 0xffeb, 'm.length': len(data), 'm.full_length': len(data),
                  'hdr.ip.ttl': 64, 'hdr.ref.epoch': 1, 'hdr.ref.generation': 7,
                  'hdr.ref.event': 3, 'hdr.ref.reserved': 0, 'hdr.fragment.reserved': 0,
                  'hdr.fragment.offset': offset, 'hdr.fragment.length': len(data),
                  'hdr.fragment.hops': 1}
        for position, value in enumerate(data):
            fields['hdr.b%d.data' % position] = value
        for bank, word in enumerate(expected):
            fields['hdr.expected.mask%d' % bank] = word >> 24
            fields['hdr.candidate.mask%d' % bank] = 0xa5
            for byte in range(3):
                fields['hdr.expected.data%d_%d' % (bank, byte)] = (word >> (16 - 8 * byte)) & 255
                fields['hdr.candidate.data%d_%d' % (bank, byte)] = bank * 3 + byte
        fields.update(overrides)
        source = Source(self.text, fields)
        source.run(block(block(self.text, 'control Ingress('), 'apply{'))
        return source

    def output_word(self, source, bank):
        result = source.env['hdr.candidate.mask%d' % bank] << 24
        for byte in range(3):
            result |= source.env['hdr.candidate.data%d_%d' % (bank, byte)] << (16 - 8 * byte)
        return result

    def expected_words(self, offset, data, old):
        result = list(old)
        for position, value in enumerate(data, offset):
            bank, byte = divmod(position, 3)
            if bank >= 4:
                continue
            shift = 16 - 8 * byte
            result[bank] = (result[bank] & ~(255 << shift)) | (value << shift) | (1 << (24 + byte))
        return result

    def test_every_offset_length_duplicate_and_inactive_byte_preservation(self):
        for offset in range(35):
            for length in range(1, 36 - offset):
                data = self.payload[offset:offset + length]
                expected = [0] * 12
                wanted = self.expected_words(offset, data, expected)
                for old in (expected, wanted):
                    source = self.execute(offset, data, old)
                    self.assertEqual(source.env['hdr.ref.event'], 7)
                    self.assertEqual(source.registers, {})
                    self.assertEqual([self.output_word(source, bank) for bank in range(4)], wanted[:4])
                    for bank in range(4, 12):
                        self.assertEqual(self.output_word(source, bank),
                            (0xa5 << 24) | ((bank * 3) << 16) | ((bank * 3 + 1) << 8) | (bank * 3 + 2))

    def test_byte_widths_conflicts_and_invalid_presence_return_fault(self):
        source = self.execute(1, b'\x08', [(2 << 24) | (7 << 8)] + [0] * 11)
        self.assertEqual(source.env['hdr.ref.event'], 6)
        self.assertEqual(source.env['hdr.expected.data0_1'], 7)
        self.assertEqual(source.registers, {})
        for key in ('hdr.expected.mask0', 'hdr.candidate.mask0', 'm.byte_diff0_0',
                    'hdr.expected.data0_0', 'hdr.candidate.data0_0'):
            self.assertEqual(source.width[key], 8)
        for key in ('hdr.tcp.seq', 'hdr.tcp.ack', 'hdr.ref.epoch', 'hdr.ref.generation'):
            self.assertEqual(source.width[key], 32)
        invalid = self.execute(0, self.payload, [8 << 24] + [0] * 11)
        self.assertEqual(invalid.env['hdr.ref.event'], 6)
        self.assertEqual(invalid.registers, {})

    def test_actual_guard_rejects_parser_error_out_of_range_and_hop16(self):
        for offset, data, overrides in ((35, b'a', {}), (34, b'ab', {}),
            (0, b'a', {'p.parser_err': 1}), (0, b'a', {'hdr.fragment.hops': 16}),
            (0, b'a', {'hdr.ref.generation': 0}), (0, b'a', {'hdr.fragment.reserved': 1})):
            source = self.execute(offset, data, [0] * 12, **overrides)
            self.assertEqual(source.env['md.drop_ctl'], 1)
            self.assertEqual(source.registers, {})
            self.assertEqual(source.env['hdr.candidate.mask0'], 0xa5)


if __name__ == '__main__':
    unittest.main()

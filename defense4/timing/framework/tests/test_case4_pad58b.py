"""Software wire evidence only; these tests do not establish endpoint acceptance.

Covers the Option B' (whitelisted-qualifier replacement) padding codec,
`case4_pad58b.py`. Does not touch or re-test `case4_pad58.py`'s own
qualifier-0x27 construction (now dead per `SELECTED_PATTERN.md`'s 2026-10-08
update); `test_case4_pad58.py` remains its suite, unmodified.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'size'))
import rrc
try:
    import case4_padding as pad
    import case4_pad58b as pad58b
except ImportError:
    pad = pad58b = None


def tcp_payload_len(frame):
    return len(frame)


class ReadPad58B(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(pad58b, 'strict Case 4 pad58b codec is missing')
        # transport(0xc7) + app-ctrl(0xc5) + func RESPONSE(0x81) + IIN(0x80,0x00)
        # + G10V2 qualifier-0x00 range-0..22 header (23 points) + 23 data bytes.
        self.data = bytes(range(1, 24))
        self.assertEqual(len(self.data), 23)
        self.user = bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + pad58b.HEADER_READ23 + self.data
        self.assertEqual(len(self.user), 33)
        self.frame = pad.build_frame(bytes.fromhex('056419c40a000100'), self.user)
        self.assertEqual(len(self.frame), 49)

    def test_native_fields_preserved_only_filler_appended(self):
        image, delta = pad58b.pad_read_response(self.frame)
        head, user = pad.decode_frame(image)
        self.assertEqual(user[:33], self.user)
        self.assertEqual(user[33:], pad58b.READ_FILLER)
        self.assertEqual(head[3:8], self.frame[3:8])
        self.assertEqual(delta, len(image) - len(self.frame))

    def test_filler_is_three_all_objects_headers_no_point_data(self):
        # Three ALL_OBJECTS (qualifier 0x06) headers, 3B each, no count field
        # and no point data at all: 3+3+3 = 9B. (The earlier count=0 design
        # was wrong -- NumParser::ParseCount rejects count=0 outright; see
        # module docstring.)
        self.assertEqual(pad58b.READ_FILLER[0:3], bytes([0x29, 0x01, 0x06]))
        self.assertEqual(pad58b.READ_FILLER[3:6], bytes([0x29, 0x02, 0x06]))
        self.assertEqual(pad58b.READ_FILLER[6:9], bytes([0x29, 0x03, 0x06]))
        self.assertEqual(len(pad58b.READ_FILLER), 9)

    def test_padded_image_is_exactly_58_tcp_payload_bytes(self):
        image, _ = pad58b.pad_read_response(self.frame)
        self.assertEqual(tcp_payload_len(image), 58)

    def test_padded_image_crc_and_length_are_valid(self):
        image, _ = pad58b.pad_read_response(self.frame)
        self.assertTrue(rrc.dnp3_frame_ok(image))
        self.assertEqual(image[2], len(pad.decode_frame(image)[1]) + 5)

    def test_round_trip_is_byte_exact(self):
        image, delta = pad58b.pad_read_response(self.frame)
        self.assertGreater(delta, 0)
        self.assertEqual(pad58b.unpad_read_response(image), self.frame)

    def test_invalid_or_unsupported_frame_unchanged(self):
        unsupported = [b'', self.frame[:-1], self.frame + self.frame,
                       bytes([0]) + self.frame[1:]]
        for changed in (self.user[:2] + b'\x01' + self.user[3:],
                        self.user[:5] + b'\x17' + self.user[6:],
                        bytes([0x47]) + self.user[1:],
                        self.user[:2] + b'\x04' + self.user[3:]):
            unsupported.append(pad.build_frame(self.frame[:8], changed))
        bad = bytearray(self.frame)
        bad[-1] ^= 1
        unsupported.append(bytes(bad))
        for f in unsupported:
            self.assertEqual(pad58b.pad_read_response(f), (f, 0))

    def test_unpad_rejects_a_foreign_image(self):
        with self.assertRaises(ValueError):
            pad58b.unpad_read_response(self.frame)
        with self.assertRaises(ValueError):
            # a control-shaped padded image is not a READ image
            pad58b.unpad_read_response(pad.build_frame(self.frame[:8], bytes(42)))
        with self.assertRaises(ValueError):
            # two correct ALL_OBJECTS headers followed by garbage instead of the third
            corrupted = self.user + pad58b.GROUP41_VAR1_ALL_OBJECTS + pad58b.GROUP41_VAR2_ALL_OBJECTS + bytes(3)
            pad58b.unpad_read_response(pad.build_frame(self.frame[:8], corrupted))


class ControlPad58B(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(pad58b, 'strict Case 4 pad58b codec is missing')
        self.points = (pad58b.AnalogFloatPoint(301, 10.0, 0),
                       pad58b.AnalogFloatPoint(302, 20.0, 0))
        # index(2) + CROB body: control code(1), count(1), on-time(4), off-time(4), status(1) = 11
        index_body = bytes.fromhex('0100') + bytes.fromhex('0301341200007856000000')
        self.assertEqual(len(index_body), 13)
        self.user = bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + pad58b.HEADER_CROB28 + index_body
        self.assertEqual(len(self.user), 23)
        self.frame = pad.build_frame(bytes.fromhex('056419c40a000100'), self.user)
        self.assertEqual(len(self.frame), 37)

    def test_filler_object_is_exactly_19_bytes_with_real_points(self):
        obj = pad58b._analog_float_object(self.points)
        self.assertEqual(len(obj), 19)
        self.assertEqual(obj[:5], bytes([0x29, 0x03, 0x28, 0x02, 0x00]))  # G41V3, qual 0x28, count=2

    def test_native_fields_preserved_only_filler_appended(self):
        image, delta = pad58b.pad_control_response(self.frame, self.points)
        head, user = pad.decode_frame(image)
        self.assertEqual(user[:23], self.user)
        expected_trailing = pad58b._analog_float_object(self.points)
        self.assertEqual(user[23:], expected_trailing)
        self.assertEqual(len(expected_trailing), 19)
        self.assertEqual(head[3:8], self.frame[3:8])
        self.assertEqual(delta, len(image) - len(self.frame))

    def test_padded_image_is_exactly_58_tcp_payload_bytes(self):
        image, _ = pad58b.pad_control_response(self.frame, self.points)
        self.assertEqual(tcp_payload_len(image), 58)

    def test_padded_image_crc_and_length_are_valid(self):
        image, _ = pad58b.pad_control_response(self.frame, self.points)
        self.assertTrue(rrc.dnp3_frame_ok(image))
        self.assertEqual(image[2], len(pad.decode_frame(image)[1]) + 5)

    def test_round_trip_is_byte_exact(self):
        image, delta = pad58b.pad_control_response(self.frame, self.points)
        self.assertGreater(delta, 0)
        self.assertEqual(pad58b.unpad_control_response(image), self.frame)

    def test_wrong_point_count_raises_rather_than_silently_adjusting(self):
        with self.assertRaises(ValueError):
            pad58b.pad_control_response(self.frame, self.points[:1])
        with self.assertRaises(ValueError):
            pad58b.pad_control_response(self.frame, self.points + self.points)

    def test_invalid_or_unsupported_frame_unchanged(self):
        unsupported = [b'', self.frame[:-1], self.frame + self.frame,
                       bytes([0]) + self.frame[1:]]
        for changed in (self.user[:2] + b'\x01' + self.user[3:],
                        self.user[:5] + b'\x17' + self.user[6:],
                        bytes([0x47]) + self.user[1:],
                        self.user[:-1] + b'\x01'):
            unsupported.append(pad.build_frame(self.frame[:8], changed))
        bad = bytearray(self.frame)
        bad[-1] ^= 1
        unsupported.append(bytes(bad))
        for f in unsupported:
            self.assertEqual(pad58b.pad_control_response(f, self.points), (f, 0))

    def test_unpad_rejects_a_foreign_image(self):
        with self.assertRaises(ValueError):
            pad58b.unpad_control_response(self.frame)
        read_frame = pad.build_frame(self.frame[:8],
                                      bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + pad58b.HEADER_READ23 + bytes(23))
        read_image, _ = pad58b.pad_read_response(read_frame)
        with self.assertRaises(ValueError):
            pad58b.unpad_control_response(read_image)

    def test_analog_float_object_rejects_empty_or_too_many_points(self):
        with self.assertRaises(ValueError):
            pad58b._analog_float_object(())
        with self.assertRaises(ValueError):
            pad58b._analog_float_object((pad58b.AnalogFloatPoint(0, 0.0, 0),) * 0x10000)

    def test_analog_float_point_validates_field_widths(self):
        with self.assertRaises(ValueError):
            pad58b.AnalogFloatPoint(0x10000, 0.0, 0)
        with self.assertRaises(ValueError):
            pad58b.AnalogFloatPoint(0, 0.0, 0x100)


class MutationProof(unittest.TestCase):
    """Proves the test suite can fail: flips one byte of the expected trailing
    object and confirms the equality assertion a correct test makes would
    reject it, then restores the correct value. Mirrors the discipline used
    for `test_case4_pad58.py`.
    """
    def test_a_corrupted_filler_byte_is_detected(self):
        points = (pad58b.AnalogFloatPoint(301, 10.0, 0), pad58b.AnalogFloatPoint(302, 20.0, 0))
        user = bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + pad58b.HEADER_CROB28 + bytes(13)
        frame = pad.build_frame(bytes.fromhex('056419c40a000100'), user)
        image, _ = pad58b.pad_control_response(frame, points)
        _, padded_user = pad.decode_frame(image)
        correct_trailing = pad58b._analog_float_object(points)
        self.assertEqual(padded_user[23:], correct_trailing)
        corrupted_trailing = bytearray(correct_trailing)
        corrupted_trailing[0] ^= 1
        with self.assertRaises(AssertionError):
            self.assertEqual(padded_user[23:], bytes(corrupted_trailing))


if __name__ == '__main__':
    unittest.main()

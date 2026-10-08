"""Software wire evidence only; these tests do not establish endpoint acceptance.

Covers the Option B (uniform 58-byte TCP-payload target) padding codec,
`case4_pad58.py`. Does not touch or re-test `case4_padding.py`'s own
separate-header 57-byte construction; `test_case4_padding.py` remains its
suite, unmodified.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'size'))
import rrc
try:
    import case4_padding as pad
    import case4_pad58 as pad58
except ImportError:
    pad = pad58 = None


def tcp_payload_len(frame):
    return len(frame)


class ReadPad58(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(pad58, 'strict Case 4 pad58 codec is missing')
        self.point = pad58.AnalogPoint(301, 1234, 0x02)
        # transport(0xc7) + app-ctrl(0xc5) + func RESPONSE(0x81) + IIN(0x80,0x00)
        # + G10V2 qualifier-0x00 range-0..22 header (23 points) + 23 data bytes.
        self.data = bytes(range(1, 24))
        self.assertEqual(len(self.data), 23)
        self.user = bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + pad58.HEADER_READ23 + self.data
        self.assertEqual(len(self.user), 33)
        self.frame = pad.build_frame(bytes.fromhex('056419c40a000100'), self.user)
        self.assertEqual(len(self.frame), 49)

    def test_native_fields_preserved_only_filler_appended(self):
        image, delta = pad58.pad_read_response(self.frame, (self.point,))
        head, user = pad.decode_frame(image)
        self.assertEqual(user[:33], self.user)
        self.assertEqual(user[33:], bytes([0x29, 0x02, 0x27, 1]) + self.point.packed)
        self.assertEqual(head[3:8], self.frame[3:8])
        self.assertEqual(delta, len(image) - len(self.frame))

    def test_padded_image_is_exactly_58_tcp_payload_bytes(self):
        image, _ = pad58.pad_read_response(self.frame, (self.point,))
        self.assertEqual(tcp_payload_len(image), 58)

    def test_padded_image_crc_and_length_are_valid(self):
        image, _ = pad58.pad_read_response(self.frame, (self.point,))
        self.assertTrue(rrc.dnp3_frame_ok(image))
        self.assertEqual(image[2], len(pad.decode_frame(image)[1]) + 5)

    def test_round_trip_is_byte_exact(self):
        image, delta = pad58.pad_read_response(self.frame, (self.point,))
        self.assertGreater(delta, 0)
        self.assertEqual(pad58.unpad_read_response(image), self.frame)

    def test_wrong_point_count_raises_rather_than_silently_adjusting(self):
        with self.assertRaises(ValueError):
            pad58.pad_read_response(self.frame, ())
        with self.assertRaises(ValueError):
            pad58.pad_read_response(self.frame, (self.point, self.point))

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
            self.assertEqual(pad58.pad_read_response(f, (self.point,)), (f, 0))

    def test_unpad_rejects_a_foreign_image(self):
        with self.assertRaises(ValueError):
            pad58.unpad_read_response(self.frame)
        with self.assertRaises(ValueError):
            # a control-shaped padded image is not a READ image
            pad58.unpad_read_response(pad.build_frame(self.frame[:8], bytes(42)))

    def test_analog_point_validates_field_widths(self):
        with self.assertRaises(ValueError):
            pad58.AnalogPoint(0x10000, 0, 0)
        with self.assertRaises(ValueError):
            pad58.AnalogPoint(0, 0x10000, 0)
        with self.assertRaises(ValueError):
            pad58.AnalogPoint(0, 0, 0x100)


class ControlPad58(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(pad58, 'strict Case 4 pad58 codec is missing')
        self.points = (pad58.AnalogPoint(301, 10, 0),
                       pad58.AnalogPoint(302, 20, 0),
                       pad58.AnalogPoint(303, 30, 0))
        # index(2) + CROB body: control code(1), count(1), on-time(4), off-time(4), status(1) = 11
        index_body = bytes.fromhex('0100') + bytes.fromhex('0301341200007856000000')
        self.assertEqual(len(index_body), 13)
        self.user = bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + pad58.HEADER_CROB28 + index_body
        self.assertEqual(len(self.user), 23)
        self.frame = pad.build_frame(bytes.fromhex('056419c40a000100'), self.user)
        self.assertEqual(len(self.frame), 37)

    def test_existing_separate_header_construction_lands_at_57_not_58(self):
        """Confirms the arithmetic gap this module exists to close.

        Reproduces `case4_padding`'s own "echo with decoy header" shape
        (`CASE4_SOFTWARE_EVIDENCE.md`: native control response 23 user bytes
        + one separate 18-byte G12V1 header = 41 user bytes -> 57 TCP-payload
        bytes), without calling `expand_control` itself (it only accepts
        21-byte request frames, not this 23-byte response).
        """
        import struct
        decoy_index, decoy_body = 201, bytes.fromhex('0101640000006400000000')
        trailing = bytes.fromhex('0c01280100') + struct.pack('<H', decoy_index) + decoy_body
        self.assertEqual(len(trailing), 18)
        legacy = pad.build_frame(self.frame[:8], self.user + trailing)
        self.assertEqual(len(legacy), 57)

    def test_native_fields_preserved_only_filler_appended(self):
        image, delta = pad58.pad_control_response(self.frame, self.points)
        head, user = pad.decode_frame(image)
        self.assertEqual(user[:23], self.user)
        expected_trailing = bytes([0x29, 0x02, 0x27, 3]) + b''.join(p.packed for p in self.points)
        self.assertEqual(user[23:], expected_trailing)
        self.assertEqual(head[3:8], self.frame[3:8])
        self.assertEqual(delta, len(image) - len(self.frame))

    def test_padded_image_is_exactly_58_tcp_payload_bytes(self):
        image, _ = pad58.pad_control_response(self.frame, self.points)
        self.assertEqual(tcp_payload_len(image), 58)

    def test_padded_image_crc_and_length_are_valid(self):
        image, _ = pad58.pad_control_response(self.frame, self.points)
        self.assertTrue(rrc.dnp3_frame_ok(image))
        self.assertEqual(image[2], len(pad.decode_frame(image)[1]) + 5)

    def test_round_trip_is_byte_exact(self):
        image, delta = pad58.pad_control_response(self.frame, self.points)
        self.assertGreater(delta, 0)
        self.assertEqual(pad58.unpad_control_response(image), self.frame)

    def test_wrong_point_count_raises_rather_than_silently_adjusting(self):
        with self.assertRaises(ValueError):
            pad58.pad_control_response(self.frame, self.points[:2])
        with self.assertRaises(ValueError):
            pad58.pad_control_response(self.frame, self.points + self.points)

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
            self.assertEqual(pad58.pad_control_response(f, self.points), (f, 0))

    def test_unpad_rejects_a_foreign_image(self):
        with self.assertRaises(ValueError):
            pad58.unpad_control_response(self.frame)
        read_point = pad58.AnalogPoint(1, 1, 1)
        read_user = bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + pad58.HEADER_READ23 + bytes(23)
        read_frame = pad.build_frame(self.frame[:8], read_user)
        read_image, _ = pad58.pad_read_response(read_frame, (read_point,))
        with self.assertRaises(ValueError):
            pad58.unpad_control_response(read_image)

    def test_analog_object_rejects_empty_or_too_many_points(self):
        with self.assertRaises(ValueError):
            pad58._analog_object(())
        with self.assertRaises(ValueError):
            pad58._analog_object((pad58.AnalogPoint(0, 0, 0),) * 256)


class MutationProof(unittest.TestCase):
    """Proves the test suite can fail: flips one byte of the expected trailing
    object and confirms the equality assertion a correct test makes would
    reject it, then restores the correct value. Mirrors the discipline used
    for `test_case4_qualifier_rewrite.py`.
    """
    def test_a_corrupted_filler_byte_is_detected(self):
        point = pad58.AnalogPoint(301, 1234, 0x02)
        user = bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + pad58.HEADER_READ23 + bytes(range(1, 24))
        frame = pad.build_frame(bytes.fromhex('056419c40a000100'), user)
        image, _ = pad58.pad_read_response(frame, (point,))
        _, padded_user = pad.decode_frame(image)
        correct_trailing = bytes([0x29, 0x02, 0x27, 1]) + point.packed
        self.assertEqual(padded_user[33:], correct_trailing)
        corrupted_trailing = bytearray(correct_trailing)
        corrupted_trailing[0] ^= 1
        with self.assertRaises(AssertionError):
            self.assertEqual(padded_user[33:], bytes(corrupted_trailing))


if __name__ == '__main__':
    unittest.main()

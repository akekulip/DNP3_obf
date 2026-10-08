"""Software wire evidence only; these tests do not establish endpoint acceptance."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'size'))
import rrc
try:
    import case4_padding as pad
    import case4_qualifier_rewrite as qr
except ImportError:
    pad = qr = None


class QualifierRewrite(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(qr, 'strict Case 4 qualifier-rewrite codec is missing')
        self.decoy = pad.Decoy(201, bytes.fromhex('0101640000006400000000'))
        self.native = bytes.fromhex('c5030c01280100010041783412007856341200')
        # Native CROB count and timing fields deliberately differ from defaults.
        self.native = self.native[:10] + bytes.fromhex('03783412007856341200')
        self.assertEqual(len(self.native), 20)
        self.frame = pad.build_frame(bytes.fromhex('056419c40a000100'), bytes([0xc7]) + self.native)

    def test_native_fields_preserved_in_place_rewrite(self):
        out, delta = qr.rewrite_qualifier(self.frame, self.decoy)
        head, user = pad.decode_frame(out)
        self.assertEqual(user[:3], bytes([0xc7, 0xc5, 3]))
        self.assertEqual(user[3:19], bytes.fromhex('0c011702') + bytes([1]) + self.native[9:])
        self.assertEqual(user[19:], bytes([201]) + self.decoy.body)
        self.assertEqual(head[3:8], self.frame[3:8])
        self.assertEqual((len(out), delta, len(user) - 3), (45, 10, 28))
        self.assertTrue(rrc.dnp3_frame_ok(out))

    def test_response_echo_of_the_rewritten_request_reaches_exactly_49_bytes(self):
        """Ties the codec to SELECTED_PATTERN.md's 45B request -> 49B response claim.

        The outstation echo keeps the same qualifier-0x17/count-2 object content
        and replaces only ctrl/func with response framing plus a 2-byte IIN.
        """
        image, _ = qr.rewrite_qualifier(self.frame, self.decoy)
        self.assertEqual(len(image), 45)
        _, user = pad.decode_frame(image)
        echo = pad.build_frame(self.frame[:8], bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + user[3:])
        self.assertEqual(len(echo), 49)
        self.assertTrue(rrc.dnp3_frame_ok(echo))

    def test_select_operate_same_object_set(self):
        op = pad.build_frame(self.frame[:8], bytes([0xc8, 0xc6, 4]) + self.native[2:])
        sel = pad.decode_frame(qr.rewrite_qualifier(self.frame, self.decoy)[0])[1]
        operate = pad.decode_frame(qr.rewrite_qualifier(op, self.decoy)[0])[1]
        self.assertEqual(sel[3:], operate[3:])
        self.assertEqual(operate[:3], bytes([0xc8, 0xc6, 4]))

    def test_round_trip_is_byte_exact(self):
        image, delta = qr.rewrite_qualifier(self.frame, self.decoy)
        self.assertGreater(delta, 0)
        self.assertEqual(qr.collapse_qualifier(image), self.frame)

    def test_index_at_or_above_256_refuses_rather_than_truncates(self):
        for index in (0x100, 0xffff):
            user = bytes([0xc7, 0xc5, 3]) + bytes.fromhex('0c0128') + bytes.fromhex('0100')
            user += index.to_bytes(2, 'little') + self.native[9:]
            wide = pad.build_frame(self.frame[:8], user)
            self.assertEqual(qr.rewrite_qualifier(wide, self.decoy), (wide, 0))

    def test_decoy_index_at_or_above_256_refuses(self):
        wide_decoy = pad.Decoy(0x100, self.decoy.body)
        self.assertEqual(qr.rewrite_qualifier(self.frame, wide_decoy), (self.frame, 0))

    def test_decoy_collision_refuses_rewrite_and_status_must_be_zero(self):
        self.assertEqual(qr.rewrite_qualifier(self.frame, pad.Decoy(1, self.decoy.body)), (self.frame, 0))
        with self.assertRaises(ValueError):
            pad.Decoy(201, self.decoy.body[:-1] + b'\x01')

    def test_invalid_or_unsupported_unchanged(self):
        user = bytes([0xc7]) + self.native
        unsupported = [b'', self.frame[:-1], self.frame + self.frame,
                       bytes([0]) + self.frame[1:]]
        for changed in (user[:2] + b'\x01' + user[3:], user[:5] + b'\x17' + user[6:],
                        bytes([0x47]) + user[1:], user[:6] + b'\x02\x00' + user[8:]):
            unsupported.append(pad.build_frame(self.frame[:8], changed))
        bad = bytearray(self.frame); bad[-1] ^= 1; unsupported.append(bytes(bad))
        for f in unsupported:
            self.assertEqual(qr.rewrite_qualifier(f, self.decoy), (f, 0))

    def test_collapse_rejects_a_foreign_image(self):
        separate_header_image, _ = pad.expand_control(self.frame, self.decoy)
        with self.assertRaises(ValueError):
            qr.collapse_qualifier(separate_header_image)
        with self.assertRaises(ValueError):
            qr.collapse_qualifier(self.frame)


if __name__ == '__main__':
    unittest.main()

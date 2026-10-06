"""Software wire evidence only; these tests do not establish endpoint acceptance."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'size'))
import rrc
try:
    import case4_padding as pad
except ImportError:
    pad = None


class Padding(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(pad, 'strict Case 4 padding codec is missing')
        self.decoy = pad.Decoy(201, bytes.fromhex('0101640000006400000000'))
        self.native = bytes.fromhex('c5030c01280100010041783412007856341200')
        # Native CROB count and timing fields deliberately differ from defaults.
        self.native = self.native[:10] + bytes.fromhex('03783412007856341200')
        self.assertEqual(len(self.native), 20)
        self.frame = pad.build_frame(bytes.fromhex('056419c40a000100'), bytes([0xc7]) + self.native)

    def test_native_fields_sequence_addresses_preserved_separate_header(self):
        out, delta = pad.expand_control(self.frame, self.decoy)
        head, user = pad.decode_frame(out)
        self.assertEqual(user[:21], bytes([0xc7]) + self.native)
        self.assertEqual(user[21:], bytes.fromhex('0c01280100c900') + self.decoy.body)
        self.assertEqual(head[3:8], self.frame[3:8])
        self.assertEqual((len(out), delta, len(user) - 1), (55, 20, 38))
        self.assertTrue(rrc.dnp3_frame_ok(out))
        response = pad.build_frame(head, bytes([0xc7, 0xc5, 0x81, 0x80, 0]) + user[3:])
        self.assertEqual((len(response), len(pad.decode_frame(response)[1]) - 1), (57, 40))

    def test_select_operate_same_object_set(self):
        op = pad.build_frame(self.frame[:8], bytes([0xc8, 0xc6, 4]) + self.native[2:])
        sel = pad.decode_frame(pad.expand_control(self.frame, self.decoy)[0])[1]
        operate = pad.decode_frame(pad.expand_control(op, self.decoy)[0])[1]
        self.assertEqual(sel[3:], operate[3:])
        self.assertEqual(operate[:3], bytes([0xc8, 0xc6, 4]))

    def test_invalid_or_unsupported_unchanged(self):
        user = bytes([0xc7]) + self.native
        unsupported = [b'', self.frame[:-1], self.frame + self.frame,
                       bytes([0]) + self.frame[1:]]
        for changed in (user[:2] + b'\x01' + user[3:], user[:5] + b'\x17' + user[6:],
                        bytes([0x47]) + user[1:], user[:6] + b'\x02\x00' + user[8:]):
            unsupported.append(pad.build_frame(self.frame[:8], changed))
        bad = bytearray(self.frame); bad[-1] ^= 1; unsupported.append(bytes(bad))
        for f in unsupported:
            self.assertEqual(pad.expand_control(f, self.decoy), (f, 0))

    def test_decoy_collision_refuses_padding_and_status_must_be_zero(self):
        self.assertEqual(pad.expand_control(self.frame, pad.Decoy(1, self.decoy.body)), (self.frame, 0))
        with self.assertRaises(ValueError):
            pad.Decoy(201, self.decoy.body[:-1] + b'\x01')


if __name__ == '__main__':
    unittest.main()

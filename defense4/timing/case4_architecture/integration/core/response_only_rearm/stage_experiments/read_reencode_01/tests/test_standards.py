"""Gate 1 of the 2026-10-12 directive: standards regression and the READ re-encoding candidate.

The retained candidate56r capture is the input: its 20 native READ responses are re-encoded and must
decode to the identical ordered points; the deployed READ filler must be rejected (qualifier 0x06 in
a response); the deployed SELECT/OPERATE echo must fail Rule 8.
"""
import random
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import capture  # noqa: E402
import dnp3_std as std  # noqa: E402
import reencode  # noqa: E402

RUN = (HERE.parents[3] / 'evidence/campaign_hw_vepa/candidate56r_single_loss_03/separate_ack/combined'
       / 'candidate56r_single_loss_03_separate_ack_combined_t0')
OUT_SHA = '2f92bf16e1596aad6b5c23dec1001dabead9c7856acedd7551e8a3815a7dbf51'
MASTER, OUTSTATION = 59440, 20000

NATIVE_VEC = bytes.fromhex('0564264401000a005e03c0c08190000a020000168101810181010aab81018101810181018101'
                           '810181018101cc96811d6f')
ENCODED_VEC = bytes.fromhex('05642f4401000a00652cc0c08190000a02010000030081018101082c0a020104001600810181'
                            '018101810181a43101810181018101810181a41e')


def directed(path, src_port, dst_port):
    for (src, dst), data in capture.streams(path).items():
        if src[1] == src_port and dst[1] == dst_port:
            return capture.frames(data)
    raise AssertionError('no %d->%d stream' % (src_port, dst_port))


def native_read(statuses, seq=0):
    """A native G10V2 0-22 READ response with the given 23 status octets."""
    user = bytes([0xC0 | seq, 0xC0 | seq, 0x81, 0x00, 0x00]) + reencode.NATIVE_HEADER + bytes(statuses)
    return std.frame(bytes([0x05, 0x64, 5 + len(user), 0x44, 0x01, 0x00, 0x0a, 0x00]), user)


class Vectors(unittest.TestCase):
    def test_directive_vectors(self):
        self.assertEqual(len(NATIVE_VEC), 49)
        self.assertEqual(reencode.reencode_frame(NATIVE_VEC), ENCODED_VEC)
        self.assertEqual(len(ENCODED_VEC), 58)
        self.assertTrue(reencode.semantically_equal(NATIVE_VEC, ENCODED_VEC))

    def test_first_block_alignment(self):
        _, user = std.deframe(ENCODED_VEC)
        self.assertEqual(user[:16], user[:5] + reencode.HEADER_A + user[12:16])
        self.assertEqual(user[16:23], reencode.HEADER_B)
        self.assertEqual(std.frame_length(len(user)), 58)

    def test_crc_polynomial_forms(self):
        # 0x3D65 normal == 0xA6BC reflected; Annex E check value for "123456789" is 0xEA82.
        self.assertEqual(std.crc(b'123456789'), 0xEA82)
        self.assertEqual(int('{:016b}'.format(0x3D65)[::-1], 2), 0xA6BC)


class VariedStatuses(unittest.TestCase):
    """All-0x81 statuses cannot reveal a misplaced or duplicated octet; distinct ones can."""

    def test_distinct_and_random_patterns(self):
        rng = random.Random(1815)
        patterns = [list(range(1, 24)), [0x01, 0x81, 0x02, 0x80] * 5 + [0x41, 0xC1, 0x21]]
        patterns += [[rng.choice((0x01, 0x81, 0x02, 0x82, 0x41, 0xC1, 0x21, 0xA1)) for _ in range(23)]
                     for _ in range(500)]
        for st in patterns:
            nat = native_read(st, seq=rng.randrange(16))
            enc = reencode.reencode_frame(nat)
            self.assertEqual(len(enc), 58)
            self.assertTrue(reencode.semantically_equal(nat, enc))
            _, pts = std.check_read_response(std.deframe(enc)[1])
            self.assertEqual([d[0] for *_x, d in pts], st)
            self.assertEqual([i for _g, _v, i, _d in pts], list(range(23)))

    def test_misplaced_octet_detected(self):
        nat = native_read(list(range(1, 24)))
        _, u = std.deframe(reencode.reencode_frame(nat))
        swapped = bytearray(u)
        swapped[15], swapped[23] = swapped[23], swapped[15]      # P3 <-> P4 across the two ranges
        bad = std.frame(bytes([0x05, 0x64, 5 + len(u), 0x44, 1, 0, 0x0a, 0]), bytes(swapped))
        with self.assertRaisesRegex(std.StdError, 'differs'):
            reencode.semantically_equal(nat, bad)


class Rejections(unittest.TestCase):
    def _user(self, objects):
        return bytes([0xC0, 0xC0, 0x81, 0, 0]) + objects

    def test_qualifier_06_rejected_in_response(self):
        with self.assertRaisesRegex(std.StdError, 'not permitted in a response'):
            std.check_read_response(self._user(bytes.fromhex('290106')))

    def test_g10v2_response_only_start_stop(self):
        # Table 12-6 / 14-2: G10V2 responses use 00 or 01; 17/28 are event-object qualifiers.
        for q in (0x17, 0x28, 0x06, 0x07):
            with self.assertRaisesRegex(std.StdError, 'not permitted in a response'):
                std.check_read_response(self._user(bytes([0x0a, 0x02, q, 0x01, 0x00, 0x81])))
        _, pts = std.check_read_response(self._user(bytes.fromhex('0a0200000081')))
        self.assertEqual(pts, [(10, 2, 0, b'\x81')])

    def test_duplicated_index_rejected(self):
        objs = bytes.fromhex('0a0201000003 00'.replace(' ', '')) + b'\x81' * 4
        objs += bytes.fromhex('0a020103001600') + b'\x81' * 20       # 3..22 repeats index 3
        with self.assertRaisesRegex(std.StdError, 'duplicated'):
            std.check_read_response(self._user(objs))

    def test_missing_index_rejected(self):
        objs = bytes.fromhex('0a020100000300') + b'\x81' * 4 + bytes.fromhex('0a020105001600') + b'\x81' * 18
        _, pts = std.check_read_response(self._user(objs))
        self.assertNotEqual([i for _g, _v, i, _d in pts], list(range(23)))
        nat = native_read([0x81] * 23)
        _, npts = std.check_read_response(std.deframe(nat)[1])
        with self.assertRaisesRegex(std.StdError, 'differs'):
            std.check_read_response(self._user(objs), expect=npts)

    def test_malformed_ranges_rejected(self):
        for objs, why in ((bytes.fromhex('0a020100000300') + b'\x81' * 3, 'overruns'),
                          (bytes.fromhex('0a020100000300') + b'\x81' * 5, 'truncated object header'),
                          (bytes.fromhex('0a0201030000 00'.replace(' ', '')), 'stop 0 < start 3'),
                          (bytes.fromhex('0a0201'), 'truncated start/stop'),
                          (bytes.fromhex('0a0207'), 'not permitted')):
            with self.assertRaisesRegex(std.StdError, why):
                std.check_read_response(self._user(objs))

    def test_bad_crc_rejected(self):
        b = bytearray(ENCODED_VEC)
        b[30] ^= 1
        with self.assertRaisesRegex(std.StdError, 'CRC'):
            std.deframe(bytes(b))

    def test_ineligible_shapes_stay_native(self):
        nat = native_read([0x81] * 23)
        h, u = std.deframe(nat)
        for mutated in (u[:2] + b'\x82' + u[3:],             # unsolicited response
                        bytes([0x40]) + u[1:],               # transport not FIR
                        u[:5] + bytes.fromhex('0a0200 0015'.replace(' ', '')) + u[10:-1],  # 22 points
                        u[:5] + bytes.fromhex('010200 0016'.replace(' ', '')) + u[10:]):   # other group
            self.assertIsNone(reencode.reencode_user(mutated))


@unittest.skipUnless((RUN / 'out.pcap').exists(), 'retained candidate56r capture absent')
class RetainedCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import hashlib
        assert hashlib.sha256((RUN / 'out.pcap').read_bytes()).hexdigest() == OUT_SHA
        cls.native_rsp = directed(RUN / 'out.pcap', OUTSTATION, MASTER)
        cls.native_req = directed(RUN / 'out.pcap', MASTER, OUTSTATION)
        cls.wire_rsp = directed(RUN / 'in.pcap', OUTSTATION, MASTER)

    def test_shape(self):
        self.assertEqual([len(f) for f in self.native_rsp], [49] * 20 + [37, 37])
        self.assertEqual([len(f) for f in self.wire_rsp], [58] * 22)

    def test_all_native_reads_reencode_to_58(self):
        for nat in self.native_rsp[:20]:
            enc = reencode.reencode_frame(nat)
            self.assertEqual(len(enc), 58)
            self.assertTrue(reencode.semantically_equal(nat, enc))
        self.assertEqual(reencode.reencode_frame(self.native_rsp[0]), ENCODED_VEC)

    def test_deployed_read_filler_rejected(self):
        for wire in self.wire_rsp[:20]:
            _, u = std.deframe(wire)
            self.assertEqual(u[-9:], bytes.fromhex('290106290206290306'))
            with self.assertRaisesRegex(std.StdError, '0x06 not permitted in a response'):
                std.check_read_response(u)

    def test_native_controls_satisfy_rule8(self):
        for req, rsp in zip(self.native_req[20:22], self.native_rsp[20:22]):
            self.assertTrue(std.check_control_echo(std.deframe(req)[1], std.deframe(rsp)[1]))

    def test_deployed_control_padding_fails_rule8(self):
        for req, rsp in zip(self.native_req[20:22], self.wire_rsp[20:22]):
            q, r = std.deframe(req)[1], std.deframe(rsp)[1]
            self.assertEqual(len(std.request(q)['objects']), 18)
            self.assertEqual(len(std.response(r)['objects']), 37)
            self.assertEqual(std.response(r)['objects'][18:],
                             bytes.fromhex('290328 0200 2d0100002041 00 2e010000a041 00'.replace(' ', '')))
            with self.assertRaisesRegex(std.StdError, 'request 18 octets, response 37 octets'):
                std.check_control_echo(q, r)

    def test_no_filler_choice_satisfies_rule8(self):
        """For any nonempty F, R || F != R: equality fails on length before any group is consulted."""
        req = std.deframe(self.native_req[20])[1]
        rsp = std.deframe(self.native_rsp[20])[1]
        rng = random.Random(8)
        for n in range(1, 40):
            fill = bytes(rng.randrange(256) for _ in range(n))
            with self.assertRaises(std.StdError):
                std.check_control_echo(req, rsp + fill)


if __name__ == '__main__':
    unittest.main()

"""Offline proof of the 61-octet encodings (gate 1 of the bounded experiment).

READ: 61 octets, legal response qualifiers, every octet consumed, the native ordered points, H unchanged.
SELECT/OPERATE: three transport segments of 61 octets in total; transport reassembly (Clause 8) reproduces every native
application octet and the Rule 8 exact comparison passes against the real request; FIR/FIN, sequence wrap, link lengths
and every CRC are checked; malformed series are rejected.
"""
import random
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(HERE), str(HERE.parent / 'read_reencode_01'), str(HERE.parent / 'read_reencode_01/tests')]
import dnp3_std as std  # noqa: E402
import encode61 as e  # noqa: E402
from test_standards import RUN, directed, native_read  # noqa: E402

MASTER, OUTSTATION = 59440, 20000
SELECT_RSP = bytes.fromhex('05641c4401000a00')


def frame_for(user, ctrl=0x44):
    return std.frame(bytes([0x05, 0x64, 5 + len(user), ctrl, 0x01, 0x00, 0x0a, 0x00]), user)


def ctl_user(seq, app_seq=3, fc=0x81, index=1, code=0x01):
    app = bytes([0xC0 | app_seq, fc, 0x00, 0x00]) + bytes.fromhex('0c01280100') + bytes([index, 0]) + \
        bytes([code, 0x01, 0x64, 0, 0, 0, 0x64, 0, 0, 0, 0])
    assert len(app) == 22
    return bytes([0xC0 | seq]) + app


class Read61(unittest.TestCase):
    def test_varied_statuses(self):
        rng = random.Random(61)
        pats = [list(range(1, 24))] + [[rng.choice((0x01, 0x81, 0x02, 0x82, 0x41, 0xC1, 0x21, 0xA1))
                                        for _ in range(23)] for _ in range(500)]
        for st in pats:
            nat = native_read(st, seq=rng.randrange(16))
            enc = e.read61(nat)
            self.assertEqual(len(enc), e.SIZE)
            nh, nu = std.deframe(nat)
            eh, eu = std.deframe(enc)
            self.assertEqual(eu[:5], nu[:5])
            _, npts = std.check_read_response(nu)
            _, epts = std.check_read_response(eu, expect=npts)
            self.assertEqual([d[0] for *_x, d in epts], st)
            self.assertEqual([q for q in (eu[7], eu[18], eu[27])], [0x00, 0x00, 0x01])      # qualifiers in place

    def test_block_layout(self):
        _, u = std.deframe(e.read61(native_read(list(range(1, 24)))))
        self.assertEqual(u[5:10], e.READ_HDR_A)
        self.assertEqual(u[16:21], e.READ_HDR_B)
        self.assertEqual(u[25:32], e.READ_HDR_C)
        self.assertEqual(list(u[32:45]), list(range(11, 24)))                    # block 3 = P10..P22

    def test_misplaced_octet_detected(self):
        nat = native_read(list(range(1, 24)))
        h, u = std.deframe(e.read61(nat))
        bad = bytearray(u)
        bad[15], bad[21] = bad[21], bad[15]                                         # P5 <-> P6 across ranges
        _, npts = std.check_read_response(std.deframe(nat)[1])
        with self.assertRaises(std.StdError):
            std.check_read_response(bytes(bad), expect=npts)


class Ctl61(unittest.TestCase):
    def test_every_sequence_including_wrap(self):
        for seq in range(64):
            nat = frame_for(ctl_user(seq))
            out = e.ctl61(nat)
            self.assertEqual(len(out), e.SIZE)
            frames = e.split_frames(out)
            self.assertEqual([len(f) for f in frames], [28, 19, 14])
            self.assertEqual([f[2] for f in frames], [0x15, 0x0c, 0x07])           # link LEN = 5 + user octets
            ths = [std.deframe(f)[1][0] for f in frames]
            self.assertEqual(ths, [0x40 | seq, (seq + 1) & 0x3F, 0x80 | ((seq + 2) & 0x3F)])
            frags, events = std.reassemble(frames)
            self.assertEqual(events, [])
            self.assertEqual(len(frags), 1)
            self.assertEqual(frags[0][0], std.deframe(nat)[1][1:])                 # every application octet
            for f in frames:                                                       # every CRC re-verified
                std.deframe(f)

    def test_rule8_exact_on_reassembled_fragment(self):
        req_user = bytes([0xC3, 0xC3, 0x03]) + ctl_user(0)[5:]                      # request objects = response objects
        frags, _ = std.reassemble(e.split_frames(e.ctl61(frame_for(ctl_user(5)))))
        self.assertTrue(std.check_control_echo(req_user, std.fragment_user(frags[0][0])))

    def test_malformed_series_rejected(self):
        frames = e.split_frames(e.ctl61(frame_for(ctl_user(62))))
        cases = {
            'reordered': [frames[0], frames[2], frames[1]],
            'missing middle': [frames[0], frames[2]],
            'missing first': frames[1:],
            'no FIN': frames[:2],
        }
        for name, fs in cases.items():
            frags, events = std.reassemble(fs)
            self.assertEqual(frags, [], name)
            self.assertTrue(events, name)
        frags, events = std.reassemble([frames[0], frames[1], frames[1], frames[2]])   # identical repeat discarded
        self.assertEqual(len(frags), 1)
        self.assertEqual(events, ['octet-identical repeat: discarded'])

    def test_bad_crc_in_any_segment_rejected(self):
        out = bytearray(e.ctl61(frame_for(ctl_user(7))))
        for pos in (5, 20, 30, 50, 58):
            bad = bytearray(out)
            bad[pos] ^= 1
            with self.assertRaises(std.StdError):
                [std.deframe(f) for f in e.split_frames(bytes(bad))]

    def test_ineligible_shapes_stay_native(self):
        u = ctl_user(1)
        for mut in (u[:2] + b'\x82' + u[3:], bytes([0x40 | 1]) + u[1:],
                    u[:5] + b'\x0c\x01\x17' + u[8:], u[:-1] + b'\x01'):
            self.assertIsNone(e.ctl61(frame_for(mut)))
        self.assertIsNone(e.encode(frame_for(bytes([0xC0, 0xC0, 0x81, 0, 0]))))

    def test_app_con_shapes_are_ineligible(self):
        read = bytearray(std.deframe(native_read([0x81] * 23))[1])
        read[1] |= 0x20
        self.assertIsNone(e.read61(frame_for(bytes(read))))
        control = bytearray(ctl_user(1))
        control[1] |= 0x20
        self.assertIsNone(e.ctl61(frame_for(bytes(control))))


@unittest.skipUnless((RUN / 'out.pcap').exists(), 'retained candidate56r capture absent')
class RetainedCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsp = directed(RUN / 'out.pcap', OUTSTATION, MASTER)
        cls.req = directed(RUN / 'out.pcap', MASTER, OUTSTATION)

    def test_all_reads_61(self):
        for nat in self.rsp[:20]:
            enc = e.read61(nat)
            self.assertEqual(len(enc), 61)
            _, npts = std.check_read_response(std.deframe(nat)[1])
            std.check_read_response(std.deframe(enc)[1], expect=npts)

    def test_real_select_operate_61_and_rule8(self):
        for req, rsp in zip(self.req[20:22], self.rsp[20:22]):
            out = e.ctl61(rsp)
            self.assertEqual(len(out), 61)
            frags, events = std.reassemble(e.split_frames(out))
            self.assertEqual((len(frags), events), (1, []))
            self.assertEqual(frags[0][0], std.deframe(rsp)[1][1:])
            self.assertTrue(std.check_control_echo(std.deframe(req)[1], std.fragment_user(frags[0][0])))


if __name__ == '__main__':
    unittest.main()


@unittest.skipUnless((RUN / 'out.pcap').exists(), 'retained candidate56r capture absent')
class CaptureCheck61(unittest.TestCase):
    """check_capture.py reassembles transport series: a synthetic run whose master side carries every response in its
    61-octet form is conformant, with 3 segments per control response."""

    def test_synthetic_61_run_is_conformant(self):
        import tempfile
        sys.path.insert(0, str(HERE.parents[5] / 'case4_architecture/protocol/hw_vepa/tests'))
        import check_capture
        from test_check_capture import synthetic
        with tempfile.TemporaryDirectory() as tmp:
            run = synthetic(tmp, lambda i, f: e.encode(f) or f)
            res = check_capture.check(run)
        self.assertEqual(res['failures'], [])
        self.assertEqual([v['wire_len'] for v in res['verdicts']], [61] * 22)
        self.assertEqual([v['segments'] for v in res['verdicts']], [1] * 20 + [3, 3])
        self.assertEqual([v['kind'] for v in res['verdicts'][-2:]], ['SELECT', 'OPERATE'])

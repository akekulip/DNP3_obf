"""profile_check.py: candidate61 profile-exact verdict per response attempt.

Synthetic runs are built from the native frames of the retained candidate61_fourarm_smoke_03 combined trial.
The audit's two legal-but-different 61-octet layouts must pass the general standards check (check_capture) and
fail the profile check; every response attempt, retransmissions included, is held to the exact image."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(HERE), str(HERE.parents[5] / 'case4_architecture/protocol/hw_vepa/tests')]
import capture  # noqa: E402
import check_capture  # noqa: E402
import dnp3_std as std  # noqa: E402
import pcaptk as tk  # noqa: E402
import profile_check  # noqa: E402

SMOKE = HERE.parent / ('seg61_02/evidence/hw_campaigns/candidate61_fourarm_smoke_03/separate_ack/combined/'
                       'candidate61_fourarm_smoke_03_separate_ack_combined_t0')
M, O, MP, OP = '192.168.10.61', '192.168.10.62', 59440, 20000
PADDED = {'READ': [61], 'SELECT': [61], 'OPERATE': [61]}
NATIVE = {'READ': [49], 'SELECT': [37], 'OPERATE': [37]}


def natives():
    port = json.load(open(SMOKE / 'standards.json'))['observed']['checker_result']['master_port']
    streams = capture.streams(SMOKE / 'out.pcap', include_incarnation=True)
    req = next(v for k, v in streams.items() if k[0][1] == port and k[1][1] == OP)
    rsp = next(v for k, v in streams.items() if k[0][1] == OP and k[1][1] == port)
    return capture.frames(req), capture.frames(rsp)


def build(tmp, transform, lengths=PADDED):
    """out.pcap: handshake + native exchange. in.pcap: the same requests; each native response i becomes the
    list of TCP payloads transform(i, kind, native_frame) returns (several = retransmissions or a split)."""
    reqs, rsps = natives()
    kinds = ['READ'] * (len(rsps) - 2) + ['SELECT', 'OPERATE']
    for side, conv in (('out.pcap', lambda i, k, f: [f]), ('in.pcap', transform)):
        c0, s0 = 1000, 5000
        recs = [(0, tk.frame(M, O, MP, OP, c0, 0, tk.SYN)),
                (50, tk.frame(O, M, OP, MP, s0, c0 + 1, tk.SYN | tk.ACK)),
                (90, tk.frame(M, O, MP, OP, c0 + 1, s0 + 1, tk.ACK))]
        sseq, rseq, t = c0 + 1, s0 + 1, 100
        for i, (q, r) in enumerate(zip(reqs, rsps)):
            recs.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            sseq += len(q)
            extent = len(profile_check.expected_image(kinds[i], r, lengths[kinds[i]][0]))
            for n, seg in enumerate(conv(i, kinds[i], r)):
                off = seg[0] if isinstance(seg, tuple) else 0
                payload = seg[1] if isinstance(seg, tuple) else seg
                recs.append((t + 100 + n, tk.frame(O, M, OP, MP, rseq + off, sseq, tk.PSH | tk.ACK, payload)))
                extent = off + len(payload) if n == 0 else max(extent, off + len(payload))
            rseq += extent if side == 'in.pcap' else len(r)
            t += 1000
        tk.write_pcap(str(Path(tmp) / side), recs)
    return tmp


def exact(i, kind, f, lengths=PADDED):
    return [profile_check.expected_image(kind, f, lengths[kind][0])]


def alt_read(f):
    """Audit mutation: q0x01 0-3, q0x00 4-8, q0x00 9-22 (legal, 61 octets, same points)."""
    header8, user = std.deframe(f)
    flags, body = user[10:33], bytearray(user[:5])
    for q, a, b in ((0x01, 0, 3), (0x00, 4, 8), (0x00, 9, 22)):
        body += b'\x0a\x02' + bytes([q]) + (bytes([a, b]) if q == 0 else struct.pack('<HH', a, b)) + flags[a:b + 1]
    h = bytearray(header8)
    h[2] = 5 + len(body)
    return std.frame(bytes(h), bytes(body))


def alt_control(f, split=(6, 15, 1)):
    """Audit mutation: 6/15/1 application partition, frames 19/28/14 (legal, 61 octets)."""
    header8, user = std.deframe(f)
    seq, app, out, p = user[0] & 0x3F, user[1:], b'', 0
    for i, n in enumerate(split):
        th = (0x40 if i == 0 else 0) | (0x80 if i == len(split) - 1 else 0) | ((seq + i) & 0x3F)
        seg = bytes([th]) + app[p:p + n]
        h = bytearray(header8)
        h[2] = 5 + len(seg)
        out += std.frame(bytes(h), seg)
        p += n
    return out


def reframe(image, mutate_user):
    """Apply mutate_user to the first frame's user octets and recompute every CRC (a valid-CRC change)."""
    frames = capture.frames(image)
    header8, user = std.deframe(frames[0])
    return std.frame(header8, mutate_user(bytearray(user))) + b''.join(frames[1:])


@unittest.skipUnless((SMOKE / 'out.pcap').exists(), 'retained candidate61 smoke capture absent')
class ProfileCheck(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name

    def run_both(self, transform, lengths=PADDED):
        run = build(self.tmp, transform, lengths)
        try:
            general = check_capture.check(run, OP, MP, {k: v[0] for k, v in lengths.items()}, require_handshake=True)
        except (ValueError, SystemExit) as error:           # the campaign wraps these as failures the same way
            general = {'conformant': False, 'failures': [str(error)]}
        profile = profile_check.check(run, MP, lengths, OP)
        return general, profile

    def test_retained_smoke_arms_pass_profile(self):
        for arm in ('off', 'timing_only', 'size_only', 'combined'):
            d = SMOKE.parent.parent / arm / ('candidate61_fourarm_smoke_03_separate_ack_%s_t0' % arm)
            art = json.load(open(d / 'standards.json'))
            res = profile_check.check(d, art['observed']['checker_result']['master_port'], art['expected']['lengths'])
            self.assertTrue(res['conformant'], (arm, res['failures']))
            self.assertEqual(res['responses'], 22)
            self.assertEqual(res['attempts'], 22)

    def test_exact_images_pass_both(self):
        general, profile = self.run_both(exact)
        self.assertTrue(general['conformant'], general['failures'])
        self.assertTrue(profile['conformant'], profile['failures'])
        self.assertEqual(profile['counts'], {'READ': 20, 'SELECT': 1, 'OPERATE': 1})

    def test_native_arm_requires_unchanged_native_images(self):
        general, profile = self.run_both(lambda i, k, f: [f], NATIVE)
        self.assertTrue(profile['conformant'], profile['failures'])
        _, padded_on_native_arm = self.run_both(exact, NATIVE)
        self.assertFalse(padded_on_native_arm['conformant'])

    def test_audit_alternate_read_layout_is_legal_but_not_the_profile(self):
        general, profile = self.run_both(lambda i, k, f: [alt_read(f)] if k == 'READ' else exact(i, k, f))
        self.assertTrue(general['conformant'], general['failures'])
        self.assertFalse(profile['conformant'])
        self.assertEqual(sum(1 for v in profile['verdicts'] if not v['ok']), 20)

    def test_audit_6_15_1_control_partition_is_legal_but_not_the_profile(self):
        general, profile = self.run_both(lambda i, k, f: [alt_control(f)] if k != 'READ' else exact(i, k, f))
        self.assertTrue(general['conformant'], general['failures'])
        self.assertFalse(profile['conformant'])
        self.assertEqual(sorted(v['kind'] for v in profile['verdicts'] if not v['ok']), ['OPERATE', 'SELECT'])

    def test_wrong_length_bad_crc_and_changed_content_fail(self):
        cases = {
            'native length on padded arm': lambda i, k, f: [f] if i == 3 else exact(i, k, f),
            'bad CRC': lambda i, k, f: [exact(i, k, f)[0][:-1] + bytes([exact(i, k, f)[0][-1] ^ 1])]
            if i == 3 else exact(i, k, f),
            'changed point flag': lambda i, k, f: [reframe(exact(i, k, f)[0], lambda u: u[:10] + bytes([u[10] ^ 0x80]) + u[11:])]
            if i == 3 else exact(i, k, f),
            'changed control echo': lambda i, k, f: [reframe(exact(i, k, f)[0], lambda u: u[:-1] + bytes([u[-1] ^ 1]))]
            if k == 'SELECT' else exact(i, k, f),
        }
        for name, transform in cases.items():
            _, profile = self.run_both(transform)
            self.assertFalse(profile['conformant'], name)

    def test_missing_response_fails(self):
        _, profile = self.run_both(lambda i, k, f: [] if k == 'OPERATE' else exact(i, k, f))
        self.assertFalse(profile['conformant'])
        self.assertTrue(any('no attempt reached the master' in f for f in profile['failures']), profile['failures'])

    def test_identical_retransmission_passes_and_is_counted(self):
        _, profile = self.run_both(lambda i, k, f: exact(i, k, f) * 2 if i == 5 else exact(i, k, f))
        self.assertTrue(profile['conformant'], profile['failures'])
        self.assertEqual(profile['retransmissions'], 1)
        self.assertEqual(profile['attempts'], 23)

    def test_split_retransmission_after_good_first_attempt_fails_profile_not_stream(self):
        def split_retx(i, k, f):
            img = exact(i, k, f)[0]
            return [img, (0, img[:30]), (30, img[30:])] if k == 'SELECT' else [img]
        general, profile = self.run_both(split_retx)
        self.assertTrue(general['conformant'], general['failures'])   # the reassembled stream is unchanged
        self.assertFalse(profile['conformant'])
        self.assertEqual(sum(1 for v in profile['verdicts'] if not v['ok']), 2)

    def test_response_split_across_two_segments_fails(self):
        def split(i, k, f):
            img = exact(i, k, f)[0]
            return [(0, img[:28]), (28, img[28:])] if k == 'OPERATE' else [img]
        _, profile = self.run_both(split)
        self.assertFalse(profile['conformant'])

    def test_two_responses_coalesced_into_one_segment_fail(self):
        held = {}
        def coalesce(i, k, f):
            img = exact(i, k, f)[0]
            if i == 3:
                held['img'] = img
                return []
            if i == 4:
                return [(-len(held['img']), held['img'] + img)]
            return [img]
        _, profile = self.run_both(coalesce)
        self.assertFalse(profile['conformant'])
        self.assertTrue(any('no attempt reached the master' in f for f in profile['failures']), profile['failures'])

    def test_missing_capture_fails_closed(self):
        res = profile_check.check(self.tmp, MP, PADDED, OP)
        self.assertFalse(res['conformant'])
        self.assertTrue(res['failures'][0].startswith('capture unreadable'))


if __name__ == '__main__':
    unittest.main()

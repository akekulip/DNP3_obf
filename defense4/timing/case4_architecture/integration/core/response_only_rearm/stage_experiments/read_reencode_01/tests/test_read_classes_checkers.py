"""Per-class READ checking in profile_check.py and check_capture.py (READ-class schedule endpoint).

Requests, native responses and reference images are real bytes (protocol/hw_vepa/tests/fixtures/
read_class_vectors.json: the loopback captures and general_read_padding.pad_read under the frozen policy). With a
per-class declaration every READ is classified from its request bytes and held to its class: padded classes to
the policy construction, at-target classes unchanged, multi-frame and multi-segment responses compared as the
reassembled aggregate. Without it both checkers behave exactly as before."""
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
HW_TESTS = HERE.parents[4] / 'protocol/hw_vepa/tests'
sys.path[:0] = [str(HERE), str(HW_TESTS)]
import check_capture  # noqa: E402
import dnp3_std as std  # noqa: E402
import profile_check  # noqa: E402
import read_class_fixture as fx  # noqa: E402


def natives(v):
    return [bytes.fromhex(s) for s in v['native_segments']]


class Construction(unittest.TestCase):
    def test_policy_image_equals_the_reference_encoder_for_every_class(self):
        for v in fx.vectors():
            native = bytes.fromhex(v['native'])
            got = profile_check.policy_image(fx.link_frames(native), v['expected_len'])
            self.assertEqual(got.hex(), v['expected'], (v['db'], v['class'], v['slot']))

    def test_policy_image_equals_the_read141_reference_vectors(self):
        import json
        rows = json.loads((HERE.parent / 'read_complete_01/vectors/read141_vectors.json').read_text())['vectors']
        for row in rows:
            native = bytes.fromhex(row['native'])
            self.assertEqual(profile_check.policy_image([native], 141).hex(), row['expected'])

    def test_unreachable_target_is_refused(self):
        v = fx.by_class('large')['class0'][0]
        with self.assertRaises(std.StdError):
            profile_check.policy_image(fx.link_frames(bytes.fromhex(v['native'])), 380)


class Runs(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name

    def check(self, db, transform=None, padded=True, declared=None):
        fx.build_run(self.tmp, db, transform)
        classes = declared if declared is not None else fx.read_classes_expectation(db, padded)
        images = sorted({e['image'] for e in classes.values()})
        lengths = {'READ': images}
        profile = profile_check.check(self.tmp, fx.MP, lengths, fx.OP, read_classes=classes)
        general = check_capture.check(self.tmp, fx.OP, fx.MP, {}, require_handshake=True, read_classes=classes)
        return profile, general

    def assert_both(self, ok, profile, general, what=''):
        self.assertEqual(profile['conformant'], ok, (what, profile['failures']))
        self.assertEqual(general['conformant'], ok, (what, general['failures']))

    def test_exact_policy_images_pass(self):
        for db in ('base', 'large'):
            profile, general = self.check(db)
            self.assert_both(True, profile, general, db)
            self.assertEqual(profile['counts'], {'READ': 8})
            self.assertEqual(profile['class_counts'], {'range': 2, 'analog': 2, 'class0': 2, 'integrity': 2})
            self.assertEqual([v['read_class'] for v in general['verdicts']], [c for _k, c, _v in fx.schedule(db)])
            self.assertEqual([v['wire_len'] for v in general['verdicts'] if v['read_class'] == 'class0'],
                             [401, 401] if db == 'large' else [247, 247])

    def test_native_arm_requires_every_class_unchanged(self):
        profile, general = self.check('large', lambda k, c, v: natives(v), padded=False)
        self.assert_both(True, profile, general)
        profile, general = self.check('large', padded=False)          # padded images on a native arm
        self.assert_both(False, profile, general)

    def test_padded_segmented_class_may_arrive_in_one_segment(self):
        one = lambda k, c, v: [bytes.fromhex(v['expected'])] if c == 'class0' else fx.expected_segments(v)
        profile, general = self.check('large', one)
        self.assert_both(True, profile, general)

    def test_native_image_where_padding_is_declared_fails(self):
        for db, cls in (('base', 'range'), ('large', 'class0'), ('large', 'integrity')):
            profile, general = self.check(db, lambda k, c, v: natives(v) if c == cls else fx.expected_segments(v))
            self.assert_both(False, profile, general, (db, cls))

    def test_padded_image_for_an_at_target_class_fails(self):
        def pad_analog(k, c, v):
            if c != 'analog':
                return fx.expected_segments(v)
            return [profile_check.policy_image(fx.link_frames(bytes.fromhex(v['native'])), 247)]
        profile, general = self.check('base', pad_analog)
        self.assert_both(False, profile, general)

    def test_wrong_class_length_fails(self):
        def range247(k, c, v):
            if c != 'range':
                return fx.expected_segments(v)
            return [profile_check.policy_image(fx.link_frames(bytes.fromhex(v['native'])), 247)]
        profile, general = self.check('base', range247)
        self.assert_both(False, profile, general)

    def test_changed_synthetic_or_native_octet_fails(self):
        for which in (0, 1):
            def mutate(k, c, v, which=which):
                segs = fx.expected_segments(v)
                if c != 'class0':
                    return segs
                frames = fx.link_frames(b''.join(segs))
                header, user = std.deframe(frames[which])
                user = bytearray(user)
                user[-1] ^= 0x01
                frames[which] = std.frame(header, bytes(user))
                return [frames[0] + frames[1]] + frames[2:]
            profile, general = self.check('large', mutate)
            self.assert_both(False, profile, general, which)

    def test_unsupported_class_present_in_the_schedule_fails(self):
        declared = fx.read_classes_expectation('large')
        del declared['class0']
        profile, general = self.check('large', declared=declared)
        self.assert_both(False, profile, general)
        self.assertTrue(any('class0' in f for f in profile['failures']), profile['failures'])

    def test_legacy_call_without_classes_is_unchanged(self):
        fx.build_run(self.tmp, 'base', lambda k, c, v: natives(v))
        res = check_capture.check(self.tmp, fx.OP, fx.MP, {}, require_handshake=True)
        self.assertNotIn('read_class', res['verdicts'][0])
        self.assertFalse(res['conformant'])          # legacy READ path knows only G10V2 responses
        self.assertTrue(any('non-Group 10 Var 2' in f for f in res['failures']), res['failures'])


if __name__ == '__main__':
    unittest.main()

"""Hardware checkers for a read_complete_01 policy build: READ image 141 beside the 61-octet control image.

rc01_hw_b08_20261021_01_reference (2026-10-21): standards.expected_lengths, the packet-boundary requirement and
profile_check all assumed READ = 61 on any candidate61 build, so a correctly padded READ (141) could never pass.
"""
import importlib.util
import json
import os
import sys
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import capture_boundary  # noqa: E402
import standards  # noqa: E402

STAGE = HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments'
REENCODE = STAGE / 'read_reencode_01'
VECTORS = STAGE / 'read_complete_01/vectors/read141_vectors.json'


def profile_check():
    spec = importlib.util.spec_from_file_location('dnp3_profile_check_test', REENCODE / 'profile_check.py')
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(REENCODE))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(REENCODE))
    return module


def config(read_image_len=141):
    build = {'profile': 'candidate61', 'image_len': 61}
    if read_image_len is not None:
        build['read_image_len'] = read_image_len
    return {'builds': {'b': build}}


def arm(name, padding):
    return {'name': name, 'build': 'b', 'padding': padding, 'T': 0}


class ExpectedLengths(unittest.TestCase):
    def test_size_arms_expect_the_build_read_image(self):
        for name in ('size_only', 'combined'):
            self.assertEqual(standards.expected_lengths(config(), arm(name, 1)),
                             {'READ': [141], 'SELECT': [61], 'OPERATE': [61]})

    def test_size_off_arms_stay_native(self):
        for name in ('off', 'timing_only'):
            self.assertEqual(standards.expected_lengths(config(), arm(name, 0)),
                             {'READ': [49], 'SELECT': [37], 'OPERATE': [37]})

    def test_a_build_without_read_image_len_is_unchanged(self):
        self.assertEqual(standards.expected_lengths(config(None), arm('size_only', 1)),
                         {'READ': [61], 'SELECT': [61], 'OPERATE': [61]})


class BoundaryRequirement(unittest.TestCase):
    def requirement(self, lengths):
        context = {'config': config(), 'arm': arm('size_only', 1)}
        expected = {'expected': {'lengths': lengths, 'counts': {'READ': 65, 'SELECT': 64, 'OPERATE': 64}}}
        return standards.boundary_segment_requirement(context, expected)

    def test_every_transformed_kind_counts_at_its_own_length(self):
        self.assertEqual(self.requirement({'READ': [141], 'SELECT': [61], 'OPERATE': [61]}), ((61, 141), 193))

    def test_one_transformed_length_keeps_the_integer_form(self):
        self.assertEqual(self.requirement({'READ': [61], 'SELECT': [61], 'OPERATE': [61]}), (61, 193))

    def test_native_lengths_need_no_boundary(self):
        self.assertEqual(self.requirement({'READ': [49], 'SELECT': [37], 'OPERATE': [37]}), (None, 0))

    def test_checker_verdicts_are_bound_at_every_required_length(self):
        verdicts = [{'index': i, 'kind': k, 'wire_len': n, 'app_seq': i} for i, (k, n) in
                    enumerate([('READ', 141), ('SELECT', 61), ('READ', 49)])]
        with unittest.mock.patch.object(capture_boundary, '_verdict_app_seq', lambda v: v['app_seq']):
            got, failures = capture_boundary._checker_expectations({'verdicts': verdicts}, (61, 141))
        self.assertEqual(failures, [])
        self.assertEqual([g['index'] for g in got], [0, 1])


class ProfileRead141(unittest.TestCase):
    def test_the_independent_construction_equals_the_reference_encoder(self):
        pc = profile_check()
        rows = json.loads(VECTORS.read_text())['vectors']
        self.assertEqual(len(rows), 64)
        for row in rows:
            native, want = bytes.fromhex(row['native']), bytes.fromhex(row['expected'])
            self.assertEqual(pc.expected_image('READ', native, 141), want)

    def test_an_unsupported_read_target_is_refused(self):
        pc = profile_check()
        native = bytes.fromhex(json.loads(VECTORS.read_text())['vectors'][0]['native'])
        with self.assertRaises(pc.std.StdError):
            pc.expected_image('READ', native, 150)


class ClrtPairing(unittest.TestCase):
    def test_a_padded_141_read_pairs_with_its_native(self):
        import clrt_check
        rows = json.loads(VECTORS.read_text())['vectors']
        for row in rows:
            native, padded = bytes.fromhex(row['native']), bytes.fromhex(row['expected'])
            self.assertTrue(clrt_check._response_content_matches(native, padded))

    def test_a_changed_point_or_synthetic_octet_does_not_pair(self):
        import clrt_check
        std = profile_check().std
        row = json.loads(VECTORS.read_text())['vectors'][0]
        native, padded = bytes.fromhex(row['native']), bytes.fromhex(row['expected'])
        frames = [padded[:92], padded[92:]]
        for which, offset in ((0, 30), (1, 15)):          # a synthetic flag octet; a native point octet
            header, user = std.deframe(frames[which])
            user = bytearray(user)
            user[offset] ^= 0x01
            changed = list(frames)
            changed[which] = std.frame(header, bytes(user))
            self.assertFalse(clrt_check._response_content_matches(native, b''.join(changed)))


if __name__ == '__main__':
    unittest.main()

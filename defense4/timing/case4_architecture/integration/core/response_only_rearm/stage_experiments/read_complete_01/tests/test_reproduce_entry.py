"""The active reproduction entry point must identify the retained relay source exactly."""
import json
import os
from pathlib import Path
import subprocess
import unittest


HERE = Path(__file__).resolve().parents[1]


class ReproduceEntry(unittest.TestCase):
    def info(self, candidate):
        return subprocess.run(['bash', str(HERE / 'reproduce.sh'), '--candidate-info'],
                              env=dict(os.environ, CANDIDATE=candidate),
                              capture_output=True, text=True, timeout=10)

    def test_c30_uses_retained_sdk9132_directory_and_relay_flags(self):
        result = self.info('c30')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        info = json.loads(result.stdout)
        self.assertTrue(info['build'].endswith('/m12p_c30_sdk9132'))
        self.assertEqual(info['source_sha256'],
                         'b006752236a7d1cccab461a010b2b68a3ea7b5629b1097c926ebacd348126de2')
        self.assertEqual(info['generator_args'], ['--policy', '--c3', 'cimg', '--shapes', 'passthrough',
                         '--two-read', '--reduce', '--ack-retry', '--read-handshake', '--headroom', '--relay'])
        self.assertEqual(info['evidence_tier'], 'relay READ reference; legacy software SBO')

    def test_historical_candidate_identity_is_preserved(self):
        result = self.info('c25')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        info = json.loads(result.stdout)
        self.assertTrue(info['build'].endswith('/m12p_c25'))
        self.assertEqual(info['source_sha256'],
                         '61f9af0fa141a1b4d0a93938893119909e792c1e98e1665156e0011969aadc07')

    def test_c48_identifies_integrated_timestamp_relay_source(self):
        result = self.info('c48')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        info = json.loads(result.stdout)
        self.assertTrue(info['build'].endswith('/m12p_c48_sdk9132'))
        self.assertEqual(info['source_sha256'],
                         '902a84bf1714d15788b707b7c23b86c4abe8f66a4ba8395d1d52f0377a2eae66')
        self.assertEqual(info['generator_args'], ['--policy', '--c3', 'cimg', '--shapes', 'passthrough',
                         '--two-read', '--reduce', '--ack-retry', '--read-handshake', '--headroom',
                         '--relay', '--relay-sbo', '--relay-ts'])
        self.assertEqual(info['evidence_tier'], 'integrated SEL-751 timestamp profile; qualification requires recorded gates')

    def test_unknown_candidate_fails_before_reproduction(self):
        result = self.info('not_a_candidate')
        self.assertEqual(result.returncode, 2)
        self.assertIn('unknown CANDIDATE', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

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

    def test_profile_and_fin_successors_identify_exact_source(self):
        identities = {
            'c49': '995386583fc373e9a770b22e50194b49c246afc0e1c5789ccd099d9ae0b31bc2',
            'c50': '1c4138ede50aaea8a662f0fba4db6b6dac2916cad46679b5d16599d34f67f43b',
            'c51': '3fe7087971f165942f8af1c94cceab5d0bef163d5d83708957d03fc270065598',
        }
        for candidate, source in identities.items():
            with self.subTest(candidate=candidate):
                result = self.info(candidate)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                info = json.loads(result.stdout)
                self.assertTrue(info['build'].endswith('/m12p_%s_sdk9132' % candidate))
                self.assertEqual(info['source_sha256'], source)
                self.assertEqual(info['generator_args'], json.loads(self.info('c48').stdout)['generator_args'])

    def test_unknown_candidate_fails_before_reproduction(self):
        result = self.info('not_a_candidate')
        self.assertEqual(result.returncode, 2)
        self.assertIn('unknown CANDIDATE', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

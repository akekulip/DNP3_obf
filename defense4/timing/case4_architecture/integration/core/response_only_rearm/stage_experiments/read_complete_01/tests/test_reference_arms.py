"""--reference-arms writes one reference config that runs only the named arms (rc01_hw_c52_20261024_24 stopped after
off and timing_only). It must equal the full reference config except for the arm filter and the block metadata,
so the two blocks together keep the 4 x 193 = 772-exchange denominator under one candidate."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('make_sel751_configs', HERE / 'hw' / 'make_sel751_configs.py')
make = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make)
BUILD = HERE.parent / 'ctl_timing_01/evidence/m12p_c52_sdk9132'


def generate(*extra):
    out = Path(tempfile.mkdtemp())
    make.main(['--build', str(BUILD), '--output', str(out)] + list(extra))
    return out


class ReferenceArms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full = json.loads((generate() / 'rc01_m12p_c52_sdk9132_sel751_reference.json').read_text())
        out = generate('--tag', 'ref2', '--reference-arms', 'size_only', 'combined')
        cls.written = sorted(p.name for p in out.iterdir())
        cls.rest = json.loads((out / cls.written[0]).read_text())

    def test_writes_only_the_reference_rest_config(self):
        self.assertEqual(self.written, ['rc01_m12p_c52_sdk9132_sel751_ref2_reference_rest.json'])

    def test_runs_only_the_named_arms_with_their_share_of_the_denominator(self):
        block = self.rest['evaluation']['campaign_block']
        self.assertEqual([a['name'] for a in self.rest['arms']], ['size_only', 'combined'])
        self.assertEqual(self.rest['evaluation']['arm_order'], ['size_only', 'combined'])
        self.assertEqual(block['arms'], ['size_only', 'combined'])
        self.assertEqual(block['expected_exchanges'], 386)
        self.assertEqual(block['arguments'], ['--arms', 'size_only,combined', '--fixtures', 'physical_relay'])
        self.assertEqual(block['id'], 'rc01_m12p_c52_sdk9132_sel751_ref2_reference_rest')

    def test_everything_else_equals_the_full_reference(self):
        full, rest = json.loads(json.dumps(self.full)), json.loads(json.dumps(self.rest))
        full['arms'] = [a for a in full['arms'] if a['name'] in ('size_only', 'combined')]
        for cfg in (full, rest):
            cfg['evaluation'].pop('arm_order')
            cfg['evaluation'].pop('campaign_block')
            cfg.pop('reference_split', None)
        self.assertEqual(full, rest)
        self.assertEqual(self.full['evaluation']['campaign_block']['expected_exchanges'], 772)

    def test_records_the_split(self):
        self.assertEqual(self.rest['reference_split']['arms'], ['size_only', 'combined'])
        self.assertEqual(self.rest['reference_split']['full_reference_arms'], ['off', 'timing_only', 'size_only', 'combined'])

    def test_refuses_unknown_or_repeated_arms(self):
        for arms in (['size_only', 'bogus'], ['combined', 'combined'], []):
            with self.assertRaises((ValueError, SystemExit)):
                generate('--tag', 'x', '--reference-arms', *arms)


if __name__ == '__main__':
    unittest.main()

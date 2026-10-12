"""Reuse independent actual-source regressions against the T outcome-elision program."""
import importlib.util
import re
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent.parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


combined = module('t_outcome_elide_experiment', HERE / 'generate.py')
lifetime = module('combined_lifetime_tests', HERE.parent / 't_sealed_lifetime/tests/test_lifetime.py')
residue = module('combined_residue_tests', HERE.parent / 'n_crc_residue/test_residue_source.py')
rearm = module('combined_rearm_tests', combined.CANDIDATE / 'tests/test_rearm.py')
# Only this process's test-module reference changes. All source files are frozen.
lifetime.experiment = combined


class Identity(unittest.TestCase):
    def test_expected_source_identity_and_counter_elision(self):
        source = combined.full_source()
        prior = (HERE.parent / 'combined_nt_01/evidence/full_01/response_only.p4').read_text()
        self.assertEqual(combined.segment(source, 'N'), combined.segment(prior, 'N'))
        self.assertEqual(combined.segment(source, 'E'), combined.segment(prior, 'E'))
        self.assertIsNone(re.search(r'\btable\s+outcome_count\b', combined.segment(source, 'T')))
        self.assertNotIn('Register<bit<32>, bit<4>>(16, 0) outcomes', combined.segment(source, 'T'))


class Lifetime(lifetime.SealedLifetime):
    pass


class FullComposite(lifetime.FullComposite):
    pass


def patch_roles(test):
    for component, name in ((lifetime.make_n, 'N'), (lifetime.make_e, 'E'), (lifetime.make_t, 'T')):
        replacement = patch.object(component, 'generate', lambda role=name: combined.source_role(role))
        replacement.start()
        test.addCleanup(replacement.stop)


class Lifecycle(rearm.ProtectedRearm):
    def setUp(self):
        patch_roles(self)


class Residue(residue.ResidueParity):
    def setUp(self):
        patch_roles(self)

    def fresh(self, **kw):
        pipeline = lifetime.SourcePipeline(**kw)
        self.addCleanup(pipeline.close)
        return pipeline.handshake()


if __name__ == '__main__':
    unittest.main()

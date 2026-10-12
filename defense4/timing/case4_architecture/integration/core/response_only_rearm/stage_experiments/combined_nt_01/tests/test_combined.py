"""Reuse independent actual-source regressions against the combined program."""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent.parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


combined = module('combined_nt_experiment', HERE / 'generate.py')
lifetime = module('combined_lifetime_tests', HERE.parent / 't_sealed_lifetime/tests/test_lifetime.py')
residue = module('combined_residue_tests', HERE.parent / 'n_crc_residue/test_residue_source.py')
rearm = module('combined_rearm_tests', combined.CANDIDATE / 'tests/test_rearm.py')
# Only this process's test-module reference changes. All source files are frozen.
lifetime.experiment = combined


class Identity(unittest.TestCase):
    def test_each_role_and_all_surrounding_source_are_exact(self):
        source = combined.full_source()
        base, n, t = (combined.checked(name) for name in ('baseline', 'N', 'T'))
        self.assertEqual(combined.segment(source, 'N'), combined.segment(n, 'N'))
        self.assertEqual(combined.segment(source, 'E'), combined.segment(base, 'E'))
        self.assertEqual(combined.segment(source, 'T'), combined.segment(t, 'T'))
        self.assertEqual(source.replace(combined.segment(n, 'N'), combined.segment(base, 'N'), 1)
                         .replace(combined.segment(t, 'T'), combined.segment(base, 'T'), 1), base)


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

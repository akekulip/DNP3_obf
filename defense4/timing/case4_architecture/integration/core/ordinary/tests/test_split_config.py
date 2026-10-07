"""Disjoint compiled programs on one model device, no altered artifact paths."""
import copy
import unittest
import test_model_config
from pathlib import Path


class SplitConfiguration(unittest.TestCase):
    def test_three_programs_scopes_zero_one_three_preserve_artifacts(self):
        here=Path(__file__).resolve().parents[1]
        self.assertTrue((here/'split_model_config.py').exists(),'three-role scoped model configuration missing')
        import split_model_config as cfg
        helper=test_model_config.ModelConfiguration()
        configs=[helper.config(name) for name in ('nf','m3','e3')]
        before=copy.deepcopy(configs);got=cfg.combine(*configs)
        self.assertEqual(configs,before);self.assertEqual(len(got['p4_devices']),1)
        self.assertEqual(got['p4_devices'][0]['device-id'],0)
        for program,scope in zip(got['p4_devices'][0]['p4_programs'],([0],[1],[3])):
            pipe=program['p4_pipelines'][0];self.assertEqual(pipe['pipe_scope'],scope)
            self.assertEqual(pipe['context'],'retained-context');self.assertEqual(pipe['config'],'retained-bin')
        with self.assertRaises(ValueError):cfg.combine(configs[0],configs[1],configs[1])
        configs[2]['p4_devices'][0]['device-id']=1
        with self.assertRaises(ValueError):cfg.combine(*configs)


if __name__=='__main__':unittest.main()

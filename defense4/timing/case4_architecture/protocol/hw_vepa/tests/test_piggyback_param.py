"""The ctl_timing piggyback bound pb: optional everywhere, required to be a real bound when given, and passed
from the configuration to the installer; bfrt name checking refuses any build/params mismatch."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / 'integration/core/response_only/hw'))
import campaign as cp  # noqa: E402
import t_config as tc  # noqa: E402

CONFIG = HERE.parent / 'campaign.json'


class InstallerParams(unittest.TestCase):
    def test_pb_is_sent_only_when_given(self):
        values = dict(tc.T_PARAM_DEFAULTS)
        self.assertNotIn('pb', [k for k, _ in tc.params_op(values)['data']])
        self.assertIn(('pb', 5000000), tc.params_op(dict(values, pb=5000000))['data'])

    def test_pb_must_lie_between_op_j_and_readiness(self):
        values = dict(tc.T_PARAM_DEFAULTS)
        self.assertEqual(tc.check_params(values), [])
        self.assertEqual(tc.check_params(dict(values, pb=5000000)), [])
        for bad in (0, values['op_j'], values['op_j'] - 1, values['readiness'], values['readiness'] + 1, 1 << 31):
            with self.subTest(pb=bad):
                self.assertTrue(tc.check_params(dict(values, pb=bad)))


class CampaignParams(unittest.TestCase):
    def load(self, pb):
        cfg = json.load(open(CONFIG))
        if pb is not None:
            cfg['timing_params_ns']['pb'] = pb
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'c.json'
            path.write_text(json.dumps(cfg))
            return cp.load_config(str(path))

    def test_config_pb_validation(self):
        self.assertNotIn('pb', self.load(None)['timing_params_ns'])
        self.assertEqual(self.load(5000000)['timing_params_ns']['pb'], 5000000)
        for bad in (0, -1, True, 10 ** 12, 2000000):                 # 2 ms is below op_j (2.4 ms)
            with self.subTest(pb=bad), self.assertRaises(ValueError):
                self.load(bad)

    def test_installer_command_carries_pb_only_when_configured(self):
        for pb, want in ((None, False), (5000000, True)):
            c = cp.Campaign.__new__(cp.Campaign)
            c.cfg = self.load(pb)
            c.R = '/r'
            c.bound = {name: {} for name in c.cfg['builds']}
            c.installer_has = lambda flag: False
            build = next(iter(c.cfg['builds']))
            cmd = c.installer_cmd(build, 1, '/out', 59000)
            self.assertEqual('--t-pb 5000000' in cmd, want, cmd)


class InstallerRefusesMismatch(unittest.TestCase):
    """bfrt name checking refuses an m3 install without pb and a pb sent to candidate61 (fail closed)."""
    ROOT = HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments'
    SCHEMA = Path('/home/philip/bf-sde-9.13.1/install/share/bf_rt_shared')

    def tables(self, rel):
        path = self.ROOT / rel / 'compile_switch_9132/out/bfrt.json'
        if not path.is_file() or not self.SCHEMA.is_dir():
            self.skipTest('compiler build tree or SDE schemas absent')
        import check_names
        return check_names.load(path, str(self.SCHEMA))

    def test_name_check_refuses_pb_mismatch_both_ways(self):
        import check_names
        m3, c61 = self.tables('ctl_timing_01/evidence/m3_01'), self.tables('seg61_02/evidence/full_04')
        values = dict(tc.T_PARAM_DEFAULTS)
        self.assertTrue(check_names.check([tc.params_op(values)], m3))                     # pb missing on m3
        self.assertEqual(check_names.check([tc.params_op(dict(values, pb=4000000))], m3), [])
        self.assertTrue(check_names.check([tc.params_op(dict(values, pb=4000000))], c61))  # pb on candidate61
        self.assertEqual(check_names.check([tc.params_op(values)], c61), [])

    def test_config_requires_pb_for_piggyback_bound_builds(self):
        cfg = json.load(open(CONFIG))
        next(iter(cfg['builds'].values()))['piggyback_bound'] = True
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'c.json'
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, 'requires timing_params_ns.pb'):
                cp.load_config(str(path))


if __name__ == '__main__':
    unittest.main()

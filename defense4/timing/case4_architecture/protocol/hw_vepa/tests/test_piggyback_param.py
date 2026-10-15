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

    def test_pb_must_be_a_real_bound_below_readiness(self):
        values = dict(tc.T_PARAM_DEFAULTS)
        self.assertEqual(tc.check_params(values), [])
        self.assertEqual(tc.check_params(dict(values, pb=5000000)), [])
        for bad in (0, values['readiness'], values['readiness'] + 1, 1 << 31):
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
        for bad in (0, -1, True, 10 ** 12):
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


if __name__ == '__main__':
    unittest.main()

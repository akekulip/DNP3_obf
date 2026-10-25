"""--loss-identity writes the verified-targeting loss blocks on unchanged c52 (c52 timing diagnosis, plan Step 2):
the full 7-preset core_full set and a one-preset repeat of the invalid t0 (request_full n=3), every entry targeted by
transaction identity. Everything else equals the c52 loss_full config, so the 7-preset denominator is unchanged."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('make_sel751_configs', HERE / 'hw' / 'make_sel751_configs.py')
make = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make)
sys.path.insert(0, str(HERE.parents[4] / 'protocol' / 'hw_vepa'))
import campaign  # noqa: E402
BUILD = HERE.parent / 'ctl_timing_01/evidence/m12p_c52_sdk9132'
PREFIX = 'rc01_m12p_c52_sdk9132_sel751_'


def generate(*extra):
    out = Path(tempfile.mkdtemp())
    make.main(['--build', str(BUILD), '--output', str(out)] + list(extra))
    return out


class LossIdentityConfigs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = json.loads((generate() / (PREFIX + 'loss_full_950.json')).read_text())
        out = generate('--tag', 'idt', '--loss-identity')
        cls.names = sorted(p.name for p in out.iterdir())
        cls.cfg = {p.name: json.loads(p.read_text()) for p in out.iterdir()}

    def test_writes_the_repeat_and_the_full_set_only(self):
        self.assertEqual(self.names, [PREFIX + 'idt_loss_full_950.json', PREFIX + 'idt_loss_t0_repeat_950.json'])

    def test_every_entry_targets_identity_and_the_full_set_keeps_seven_presets(self):
        full = self.cfg[PREFIX + 'idt_loss_full_950.json']
        base = self.base['loss']['presets']['core_full']
        presets = full['loss']['presets']['core_full']
        self.assertEqual(len(presets), 7)
        self.assertEqual([dict(e, target='identity') for e in base], presets)
        repeat = self.cfg[PREFIX + 'idt_loss_t0_repeat_950.json']
        self.assertEqual(repeat['loss']['presets'], {'t0_repeat': [{'class': 'request_full', 'n': 3,
                                                                       'target': 'identity'}]})
        self.assertEqual(repeat['evaluation']['campaign_block']['arguments'][-2:], ['--loss', 't0_repeat'])
        self.assertEqual(full['evaluation']['campaign_block']['arguments'][-2:], ['--loss', 'core_full'])

    def test_nothing_else_differs_from_the_c52_loss_full_config(self):
        for name, cfg in self.cfg.items():
            a, b = json.loads(json.dumps(self.base)), json.loads(json.dumps(cfg))
            for c in (a, b):
                c['loss'].pop('presets')
                c['evaluation'].pop('campaign_block')
                c.pop('loss_identity', None)
            self.assertEqual(a, b, name)
            self.assertEqual(cfg['timing_params_ns'], self.base['timing_params_ns'])

    def test_configs_validate_with_the_identity_targets(self):
        for name, cfg in self.cfg.items():
            campaign.validate_profile(cfg)
            for entries in cfg['loss']['presets'].values():
                for e in entries:
                    self.assertTrue(campaign.drop_text(e).endswith(':identity'), name)


if __name__ == '__main__':
    unittest.main()

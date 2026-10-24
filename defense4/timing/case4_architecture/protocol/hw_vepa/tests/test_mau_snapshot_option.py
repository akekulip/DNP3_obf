"""The opt-in diagnostic MAU snapshot: validated spec, passed (quoted) to every counter snapshot only when configured."""
import copy
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402

CONFIGS = HERE.parents[2] / ('integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/config')
SMOKE = CONFIGS / 'rc01_m12p_c51_sdk9132_sel751_smoke.json'
SMOKE_MAU = CONFIGS / 'rc01_m12p_c51_sdk9132_sel751_smoke_mau.json'


class FakeCampaign:
    snapshot = cp.Campaign.snapshot

    def __init__(self, cfg):
        self.cfg, self.R, self.commands = cfg, '/remote', []

    def hw_env(self, cmd):
        return cmd

    def switch_cmd(self, tool, args):
        return '%s %s' % (tool, args)

    def step(self, where, label, check=True, cmd=None):
        self.commands.append(cmd)
        return cmd


class MauSnapshotOption(unittest.TestCase):
    def test_diagnostic_config_validates_and_only_adds_the_spec(self):
        smoke, mau = json.loads(SMOKE.read_text()), json.loads(SMOKE_MAU.read_text())
        cp.validate_profile(mau)
        self.assertEqual(mau.pop('diagnostic_mau_snapshot'), 'start=0,end=10,m.packet_kind=9/0xff,m.lap=1/1,m.stage=0/3')
        for cfg in (smoke, mau):
            cfg['_notes'] = cfg['_notes'][:2]
            cfg['evaluation']['campaign_block'].pop('id')
            cfg['evaluation']['campaign_block'].pop('phase')
        self.assertEqual(smoke, mau)

    def test_malformed_or_unsafe_specs_are_refused(self):
        base = json.loads(SMOKE_MAU.read_text())
        for spec in ('', 'start=0,end=10', 'start=0,end=10,m.packet_kind=9', 'start=0,end=10,m.x=1/1;reboot',
                     "start=0,end=10,m.x=1/1 'q'", 'start=0,end=100,m.x=1/1', ['start=0'],
                     'start=0,end=12,m.x=1/1', 'start=5,end=2,m.x=1/1', 'start=0,end=10,start=5/5',
                     'start=0,end=10,m.x=1/1,m.x=0/1', 'start=0,end=10,m.x=2/1'):
            cfg = copy.deepcopy(base)
            cfg['diagnostic_mau_snapshot'] = spec
            with self.assertRaises(ValueError, msg=spec):
                cp.validate_profile(cfg)

    def test_snapshot_command_carries_the_quoted_spec_only_when_configured(self):
        smoke, mau = FakeCampaign(json.loads(SMOKE.read_text())), FakeCampaign(json.loads(SMOKE_MAU.read_text()))
        plain = smoke.snapshot('/out', 'x_before')
        diag = mau.snapshot('/out', 'x_before')
        self.assertNotIn('--mau-snapshot', plain)
        self.assertTrue(diag.endswith(" --mau-snapshot 'start=0,end=10,m.packet_kind=9/0xff,m.lap=1/1,m.stage=0/3'")
                        or diag.endswith(' --mau-snapshot start=0,end=10,m.packet_kind=9/0xff,m.lap=1/1,m.stage=0/3'))
        self.assertEqual(diag.replace(diag[diag.index(' --mau-snapshot'):], ''), plain)


if __name__ == '__main__':
    unittest.main()

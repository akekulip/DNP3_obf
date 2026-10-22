"""Host diagnostic: RX interrupt coalescing off for one campaign, baseline recorded and restored (Philip,
2026-10-22). Only RX moderation is touched; restore verifies by read-back and keeps the baseline on any mismatch."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import capture_observation as co  # noqa: E402

TEMPLATE = ('Coalesce parameters for enp59s0f0np0:\nAdaptive RX: %s  TX: on\nstats-block-usecs:\tn/a\n\n'
            'rx-usecs:\t%d\nrx-frames:\tn/a\n\ntx-usecs:\t50\n')


class FakeNic:
    def __init__(self, adaptive='on', usecs=50, refuse=False):
        self.adaptive, self.usecs, self.refuse, self.calls = adaptive, usecs, refuse, []

    def __call__(self, cmd):
        self.calls.append(cmd)
        if cmd[:2] == ['ethtool', '-c']:
            return SimpleNamespace(returncode=0, stdout=TEMPLATE % (self.adaptive, self.usecs), stderr='')
        if cmd[:2] == ['ethtool', '-C']:
            if self.refuse:
                return SimpleNamespace(returncode=1, stdout='', stderr='Operation not supported')
            args = dict(zip(cmd[3::2], cmd[4::2]))
            if args.get('adaptive-rx') == 'on' and 'rx-usecs' in args:   # the i40e rejection seen on Vision
                return SimpleNamespace(returncode=1, stdout='', stderr='netlink error: Invalid argument')
            self.adaptive = args.get('adaptive-rx', self.adaptive)
            self.usecs = int(args.get('rx-usecs', self.usecs))
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        raise AssertionError(cmd)


class RxCoalesceDiagnostic(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'rx_coalesce_baseline.json'

    def tearDown(self):
        self.temp.cleanup()

    def test_apply_records_baseline_and_reads_back(self):
        nic = FakeNic()
        baseline, effective = co.rx_coalesce_diagnostic(self.path, run=nic)
        self.assertEqual((baseline['adaptive_rx'], baseline['rx_usecs']), ('on', 50))
        self.assertEqual((effective['adaptive_rx'], effective['rx_usecs']), ('off', 0))
        self.assertTrue(self.path.exists())
        # only RX moderation is written
        writes = [c for c in nic.calls if c[:2] == ['ethtool', '-C']]
        self.assertEqual(writes, [['ethtool', '-C', 'enp59s0f0np0', 'adaptive-rx', 'off', 'rx-usecs', '0']])

    def test_existing_baseline_is_never_overwritten(self):
        self.path.write_text(json.dumps({'interface': 'enp59s0f0np0', 'adaptive_rx': 'on', 'rx_usecs': 50}))
        baseline, _ = co.rx_coalesce_diagnostic(self.path, run=FakeNic(adaptive='off', usecs=0))
        self.assertEqual((baseline['adaptive_rx'], baseline['rx_usecs']), ('on', 50))

    def test_ineffective_setting_raises(self):
        with self.assertRaisesRegex(RuntimeError, 'not effective'):
            co.rx_coalesce_diagnostic(self.path, run=FakeNic(refuse=True))

    def test_restore_reapplies_verifies_and_removes_baseline(self):
        nic = FakeNic()
        co.rx_coalesce_diagnostic(self.path, run=nic)
        self.assertEqual(co.restore_rx_coalesce(self.path, run=nic), [])
        self.assertEqual((nic.adaptive, nic.usecs), ('on', 50))
        self.assertFalse(self.path.exists())

    def test_restore_mismatch_keeps_baseline_and_reports(self):
        nic = FakeNic()
        co.rx_coalesce_diagnostic(self.path, run=nic)
        nic.refuse = True
        errors = co.restore_rx_coalesce(self.path, run=nic)
        self.assertTrue(errors)
        self.assertTrue(self.path.exists())

    def test_restore_without_diagnostic_is_a_noop(self):
        nic = FakeNic()
        self.assertEqual(co.restore_rx_coalesce(self.path, run=nic), [])
        self.assertEqual(nic.calls, [])


class CampaignSetupCommand(unittest.TestCase):
    def setup_command(self, cfg):
        import campaign as cp
        steps = []
        stub = type('S', (), {'V': '/v', 'cfg': cfg, 'vision_touched': False,
                              'step': lambda self, where, what, cmd, **k: steps.append(cmd)})()
        cp.Campaign.vision_setup(stub)
        return steps[0]

    def test_flag_only_with_the_diagnostic(self):
        self.assertEqual(self.setup_command({}), 'sudo python3 /v/vision_run.py setup')
        self.assertEqual(self.setup_command({'host_diagnostic': {'rx_coalescing': 'off'}}),
                         'sudo python3 /v/vision_run.py setup --rx-coalesce-diag')
        with self.assertRaises(ValueError):
            self.setup_command({'host_diagnostic': {'rx_coalescing': 'on'}})

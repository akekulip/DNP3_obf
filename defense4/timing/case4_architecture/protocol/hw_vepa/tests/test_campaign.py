"""campaign.py loads one config, validates it, expands the four arms over their builds, and renders a
complete runbook that ties the hw/ composite installer to the endpoint runner, verification and
restoration. Offline only; the hardware `run` path is not exercised."""
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402

CONFIG = HERE.parent / 'campaign.json'


class ConfigValidation(unittest.TestCase):
    def setUp(self):
        self.cfg = json.load(open(CONFIG))

    def _write(self, cfg):
        fd, path = tempfile.mkstemp(suffix='.json')
        os.write(fd, json.dumps(cfg).encode())
        os.close(fd)
        return path

    def test_shipped_config_is_valid(self):
        cfg = cp.load_config(str(CONFIG))
        self.assertEqual(len(cfg['arms']), 4)
        self.assertEqual(len({a['build'] for a in cfg['arms']}), 1)   # one build; padding is a policy row

    def test_timing_order_is_enforced(self):
        bad = copy.deepcopy(self.cfg)
        bad['timing_params_ns']['readiness'] = bad['timing_params_ns']['da']   # da < readiness violated
        with self.assertRaises(ValueError):
            cp.load_config(self._write(bad))

    def test_arm_referencing_unknown_build_is_rejected(self):
        bad = copy.deepcopy(self.cfg)
        bad['arms'][0]['build'] = 'does_not_exist'
        with self.assertRaises(ValueError):
            cp.load_config(self._write(bad))

    def test_missing_section_is_rejected(self):
        bad = copy.deepcopy(self.cfg)
        del bad['trials']
        with self.assertRaises(ValueError):
            cp.load_config(self._write(bad))

    def test_fixture_delay_past_readiness_warns(self):
        cfg = cp.load_config(str(CONFIG))
        cfg['fixture']['delay_ms'] = 999
        self.assertTrue(any('readiness deadline' in w for w in cp.warnings(cfg)))

    def test_shipped_config_does_not_trip_the_readiness_trap(self):
        cfg = cp.load_config(str(CONFIG))
        self.assertFalse(any('readiness deadline' in w for w in cp.warnings(cfg)))


class PlanContent(unittest.TestCase):
    def setUp(self):
        self.cfg = cp.load_config(str(CONFIG))
        self.steps = cp.plan(self.cfg)
        self.text = cp.render(self.steps)

    def test_installs_each_build_once(self):
        applies = [s for s in self.steps if 'bringup_composite.py' in s[2] and '--apply' in s[2]]
        self.assertEqual(len(applies), 1)                       # one per build, not one per arm
        for s in applies:
            self.assertIn('--expect bfrt.json=', s[2])
            self.assertIn('--enable-pktgen', s[2])

    def test_sets_T_once_per_arm_with_the_right_bit(self):
        sets = [s[2] for s in self.steps if 'set_enabled.py' in s[2]]
        self.assertEqual(len(sets), 4)
        self.assertEqual(sum('--enabled 1' in c for c in sets), 2)
        self.assertEqual(sum('--enabled 0' in c for c in sets), 2)

    def test_each_trial_runs_endpoint_then_both_extractors(self):
        runs = [s for s in self.steps if 'vision_run.py run' in s[2]]
        self.assertEqual(len(runs), 4 * self.cfg['trials']['trials_per_arm'])
        self.assertTrue(all('--reads %d' % self.cfg['trials']['reads_per_trial'] in s[2] for s in runs))
        self.assertEqual(len([s for s in self.steps if 'wire_check.py' in s[2]]), len(runs))
        self.assertEqual(len([s for s in self.steps if 'clrt_check.py' in s[2]]), len(runs))

    def test_ties_in_snapshots_and_restoration(self):
        self.assertIn('snapshot_counters.py', self.text)
        self.assertIn('bringup_teardown.py', self.text)
        self.assertIn('restore_ports.py', self.text)
        self.assertIn('run.py deploy', self.text)
        self.assertIn('run.py restore', self.text)

    def test_timing_parameters_from_config_appear_in_the_install(self):
        comp = next(s[2] for s in self.steps if 'bringup_composite.py' in s[2])
        self.assertIn('--t-readiness %d' % self.cfg['timing_params_ns']['readiness'], comp)
        self.assertIn('--k %d' % self.cfg['service']['k'], comp)


class RunGating(unittest.TestCase):
    def test_run_without_apply_refuses(self):
        with self.assertRaises(SystemExit):
            cp.main(['run', '--config', str(CONFIG)])

    def test_run_without_authorization_refuses(self):
        os.environ.pop('DEFENSE4_HW_AUTHORIZED', None)
        with self.assertRaises(SystemExit):
            cp.main(['run', '--config', str(CONFIG), '--apply'])

    def test_run_refuses_on_unbound_identity_even_when_authorized(self):
        os.environ['DEFENSE4_HW_AUTHORIZED'] = '1'
        try:
            with self.assertRaises(SystemExit) as e:
                cp.main(['run', '--config', str(CONFIG), '--apply'])
            self.assertIn('not pinned', str(e.exception))
        finally:
            os.environ.pop('DEFENSE4_HW_AUTHORIZED', None)


if __name__ == '__main__':
    unittest.main()

"""campaign.py loads one config, validates it, expands the four arms over their builds, and renders a
complete runbook that ties the hw/ composite installer to the endpoint runner, verification and
restoration. Offline only; the hardware `run` path is not exercised."""
import contextlib
import copy
import io
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
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = os.path.join(td.name, 'cfg.json')
        open(path, 'w').write(json.dumps(cfg))
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
    """`plan` is the orchestration over a DryRunner, so these read the exact commands `run` would emit."""
    def setUp(self):
        self.cfg = cp.load_config(str(CONFIG))
        self.dry = cp.DryRunner()
        with contextlib.redirect_stdout(io.StringIO()):
            cp.Campaign(self.cfg, self.dry, 'c1', installer_flags=lambda f: True).execute()
        self.cmds = [c for _w, c in self.dry.calls if not c.startswith('sha256sum')]   # the verification line names every file
        self.text = '\n'.join(self.cmds)

    def test_every_trial_has_its_own_install(self):
        applies = [c for c in self.cmds if 'bringup_composite.py' in c and '--apply' in c]
        self.assertEqual(len(applies), 4 * self.cfg['trials']['trials_per_arm'] * len(self.cfg['fixture']['modes']))
        for c in applies:
            self.assertIn('--expect bfrt.json=', c)
            self.assertIn('--enable-pktgen', c)

    def test_sets_T_once_per_bring_up_with_the_right_bit(self):
        sets = [c for c in self.cmds if 'set_enabled.py' in c]
        n = 2 * self.cfg['trials']['trials_per_arm'] * len(self.cfg['fixture']['modes'])   # two arms T=1, two T=0
        self.assertEqual(len(sets), 2 * n)
        self.assertEqual(sum('--enabled 1' in c for c in sets), n)
        self.assertEqual(sum('--enabled 0' in c for c in sets), n)

    def test_each_trial_runs_endpoint_then_both_extractors(self):
        runs = [c for c in self.cmds if 'vision_run.py run' in c]
        self.assertEqual(len(runs), 4 * self.cfg['trials']['trials_per_arm'] * len(self.cfg['fixture']['modes']))
        self.assertTrue(all('--reads %d' % self.cfg['trials']['reads_per_trial'] in c for c in runs))
        self.assertEqual(len([c for c in self.cmds if c.startswith(cp.runner.PY + ' ') and 'wire_check.py' in c]), len(runs))
        self.assertEqual(len([c for c in self.cmds if c.startswith(cp.runner.PY + ' ') and 'clrt_check.py' in c]), len(runs))

    def test_ties_in_snapshots_and_restoration(self):
        for s in ('snapshot_counters.py', 'bringup_teardown.py', 'restore_ports.py', 'vision_run.py setup',
                  'vision_run.py restore', 'switch_swap.sh'):
            self.assertIn(s, self.text)

    def test_timing_parameters_and_k_from_config_appear_in_the_install(self):
        comp = next(c for c in self.cmds if 'bringup_composite.py' in c)
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
        cfg = json.load(open(CONFIG))
        cfg['endpoint']['binary_sha256'] = None
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = os.path.join(td.name, 'cfg.json')
        open(path, 'w').write(json.dumps(cfg))
        os.environ['DEFENSE4_HW_AUTHORIZED'] = '1'
        try:
            with self.assertRaises(SystemExit) as e:
                cp.main(['run', '--config', path, '--apply'])
            self.assertIn('not pinned', str(e.exception))
        finally:
            os.environ.pop('DEFENSE4_HW_AUTHORIZED', None)


if __name__ == '__main__':
    unittest.main()

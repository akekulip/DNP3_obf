"""Nothing the campaign needs lives in an ad hoc scratch path: the `deploy` step puts every tool in the configured aux
directory (hash-verified) and every emitted command refers to it; tests and tooling keep no scratch-path fixtures."""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402
from test_campaign_run import FakeRunner  # noqa: E402
from test_campaign_bindings import H64  # noqa: E402

SCRATCH = '/' + 'tmp'                      # spelled so this file does not trip its own scan
CONFIG = HERE.parent / 'campaign.json'


class NoScratchPaths(unittest.TestCase):
    def test_tooling_sources_reference_no_scratch_path(self):
        bad = []
        for p in HERE.parent.iterdir():
            if p.suffix in ('.py', '.sh', '.json', '.md'):
                if SCRATCH in p.read_text():
                    bad.append(p.name)
        self.assertEqual(bad, [])

    def test_tests_reference_no_scratch_path_and_clean_up_after_themselves(self):
        bad = []
        for p in HERE.glob('test_*.py'):
            t = p.read_text()
            if p.name != Path(__file__).name and (SCRATCH in t or 'mkdtemp(' in t or 'mkstemp(' in t):
                bad.append(p.name)
        self.assertEqual(bad, [], 'use tempfile.TemporaryDirectory + addCleanup, never a leaked mkdtemp/mkstemp')

    def test_every_emitted_command_stays_inside_the_configured_dirs(self):
        cfg = cp.load_config(str(CONFIG))
        dry = cp.DryRunner()
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            cp.Campaign(cfg, dry, 'c1', arms=['combined'], installer_flags=lambda f: True).execute()
        allowed = (cfg['hosts']['switch_remote_dir'], cfg['builds']['sbo_admission_01']['sde'],
                   cfg['production']['launch_script'], cfg['hosts']['switch_remote_dir'] + '/')
        for where, cmd in dry.calls:
            self.assertNotIn(SCRATCH, cmd)
            if where != 'switch':
                continue
            for tok in re.findall(r'(?<![\w=-])/[\w./-]+\.(?:py|sh)\b', cmd):
                self.assertTrue(tok.startswith(allowed), '%s runs %s outside the configured dirs' % (cmd[:80], tok))


class DeployStep(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.cfg = cp.load_config(str(CONFIG))
        self.cfg['evidence_dir'] = str(Path(td.name) / 'ev')
        self.cfg['endpoint'].update(binary_sha256=H64, lib_sha256=H64)      # what the fake Vision reports

    def deploy(self, runner):
        return cp.Campaign(self.cfg, runner, 'c1', arms=['combined'], installer_flags=lambda f: True).deploy_only()

    def test_deploy_copies_every_tool_to_aux_and_verifies_its_hash(self):
        r = FakeRunner()
        r.deployed = {}
        self.assertEqual(self.deploy(r), 0)
        aux = self.cfg['hosts']['switch_remote_dir'] + '/aux'
        verify = [c for w, c in r.calls if w == 'switch' and c.startswith('sha256sum') and aux in c]
        self.assertEqual(len(verify), 1)
        for name in ('switch_swap.sh', 'launch_composite.sh', 'observe_program.py', 'switch_slot.py',
                     'response_path_cp.py', 'restore_ports.py', 'live_snapshot.py'):
            self.assertIn('%s/%s' % (aux, name), verify[0], name)

    def test_deploy_changes_nothing_but_files(self):
        r = FakeRunner()
        self.deploy(r)
        for needle in ('bringup_composite.py', 'switch_swap.sh ', 'restore_ports.py ', 'vision_run.py setup',
                       'set_enabled.py', 'observe_program.py'):
            self.assertFalse([c for w, c in r.calls if c.startswith(('bash', 'python3', 'sudo')) and needle in c],
                             needle)

    def test_a_tool_whose_deployed_hash_differs_fails_deploy(self):
        class Corrupt(FakeRunner):
            def run(self, where, cmd, **kw):
                res = super().run(where, cmd, **kw)
                if where == 'switch' and cmd.startswith('sha256sum'):
                    return cp.Result(0, '\n'.join('%s  %s' % ('0' * 64, p) for p in cmd.split()[1:]), '')
                return res
        self.assertEqual(self.deploy(Corrupt()), 1)

    @pytest.mark.build_tree
    def test_run_deploys_before_it_observes_the_switch(self):
        r = FakeRunner()
        cp.Campaign(self.cfg, r, 'c1', arms=['combined'], installer_flags=lambda f: True).execute()
        verify = [i for i, (w, c) in enumerate(r.calls) if w == 'switch' and c.startswith('sha256sum')]
        self.assertTrue(verify)
        self.assertLess(verify[0], r.runs('observe_program.py')[0])

    def test_deploy_mode_is_a_cli_mode_and_plans_without_running(self):
        import subprocess
        out = subprocess.run([sys.executable, str(HERE.parent / 'campaign.py'), 'deploy', '--dry-run'],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('switch_swap.sh', out.stdout)


if __name__ == '__main__':
    unittest.main()

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
        allowed = (cfg['hosts']['switch_remote_dir'], cfg['builds'][cfg['arms'][0]['build']]['sde'],
                   cfg['production']['launch_script'], cfg['hosts']['switch_remote_dir'] + '/')
        for where, cmd in dry.calls:
            self.assertNotIn(SCRATCH, cmd)
            if where != 'switch':
                continue
            for tok in re.findall(r'(?<![\w=-])/[\w./-]+\.(?:py|sh)\b', cmd):
                self.assertTrue(tok.startswith(allowed), '%s runs %s outside the configured dirs' % (cmd[:80], tok))


class ImportClosure(unittest.TestCase):
    """Every local module a script the campaign runs on the switch imports (transitively) must be deployed at its
    repo-relative path. Computed from the scripts' own import statements, not from a list kept in step by hand."""
    ARCH = HERE.parents[2]
    RO = ARCH / 'integration' / 'core' / 'response_only'
    HW = RO / 'hw'
    FW = ARCH.parent / 'framework' / 'control'
    SEARCH = [HW, RO, ARCH / 'protocol', HERE.parent, FW]          # the dirs the scripts put on sys.path
    HW_SCRIPTS = ['bringup_composite.py', 'bringup_teardown.py', 'snapshot_counters.py', 'set_enabled.py',
                  'make_conf.py']
    AUX_SCRIPTS = [HERE.parent / 'observe_program.py', HERE.parent / 'switch_slot.py', FW / 'live_snapshot.py',
                   FW / 'restore_ports.py']

    def local_imports(self, path):
        import ast
        mods = set()
        for node in ast.walk(ast.parse(Path(path).read_text())):
            if isinstance(node, ast.Import):
                mods.update(a.name.split('.')[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                mods.add(node.module.split('.')[0])
        found = []
        for m in sorted(mods):
            for d in self.SEARCH:
                if (d / (m + '.py')).is_file():
                    found.append(d / (m + '.py'))
                    break
        return found

    def closure(self, scripts):
        seen, todo = {}, [Path(s) for s in scripts]
        while todo:
            cur = todo.pop()
            for mod in self.local_imports(cur):
                if mod not in seen:
                    seen[mod] = cur
                    todo.append(mod)
        return seen

    def test_closure_finds_the_known_guard_import(self):
        found = {p.name for p in self.closure([self.HW / s for s in self.HW_SCRIPTS])}
        self.assertIn('check_mirror_select.py', found)                  # bringup_composite imports it inside a function
        self.assertTrue({'cp.py', 'port_map.py', 'response_path_cp.py', 'rows.py', 't_config.py'} <= found)

    def test_every_local_module_the_installer_scripts_import_is_deployed_at_its_repo_path(self):
        deployed = {Path(p).resolve() for p in cp.installer_sources() + cp.installer_hw_files()}
        missing = [str(p.relative_to(self.ARCH)) + '  (imported by %s)' % by.name
                   for p, by in sorted(self.closure([self.HW / s for s in self.HW_SCRIPTS]).items())
                   if p.resolve() not in deployed]
        self.assertEqual(missing, [], 'not deployed to <switch>/src: %s' % missing)

    def test_every_local_module_the_aux_scripts_import_is_deployed_into_aux(self):
        aux = {Path(p).resolve() for p, _n in cp.switch_tools()}
        missing = [p.name for p in self.closure(self.AUX_SCRIPTS) if p.resolve() not in aux]
        self.assertEqual(missing, [])

    def test_the_rsync_command_carries_the_deployed_files(self):
        dry = cp.DryRunner()
        import contextlib
        import io
        cfg = cp.load_config(str(CONFIG))
        with contextlib.redirect_stdout(io.StringIO()):
            cp.Campaign(cfg, dry, 'c1', arms=['combined'], installer_flags=lambda f: True).execute()
        rs = [c for _w, c in dry.calls if c.startswith('rsync -aR')][0]
        self.assertIn('integration/core/response_only/check_mirror_select.py', rs)
        self.assertIn('integration/core/response_only/hw', rs)


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

    def test_the_hash_verification_covers_the_installer_sources_including_the_mirror_guard(self):
        r = FakeRunner()
        self.deploy(r)
        verify = [c for w, c in r.calls if w == 'switch' and c.startswith('sha256sum')][0]
        src = self.cfg['hosts']['switch_remote_dir'] + '/src/integration/core/response_only'
        for name in ('check_mirror_select.py', 'cp.py', 'port_map.py', 'hw/bringup_composite.py', 'hw/t_config.py'):
            self.assertIn('%s/%s' % (src, name), verify, name)
        self.assertIn(self.cfg['hosts']['switch_remote_dir'] + '/src/protocol/response_path_cp.py', verify)

    def test_a_corrupted_mirror_guard_on_the_switch_fails_deploy(self):
        class Corrupt(FakeRunner):
            def run(self, where, cmd, **kw):
                res = super().run(where, cmd, **kw)
                if where == 'switch' and cmd.startswith('sha256sum'):
                    lines = [l.replace(l.split()[0], '0' * 64) if 'check_mirror_select' in l else l
                             for l in res.out.splitlines()]
                    return cp.Result(0, '\n'.join(lines), '')
                return res
        self.assertEqual(self.deploy(Corrupt()), 1)

    def test_vision_gets_loss_py_beside_vision_run_and_both_are_hash_verified(self):
        r = FakeRunner()
        self.deploy(r)
        scp = [c for w, c in r.calls if c.startswith('scp') and 'vision_run.py' in c][0]
        self.assertIn('loss.py', scp)
        verify = [c for w, c in r.calls if w == 'vision' and c.startswith('sha256sum') and 'vision_run.py' in c][0]
        self.assertIn('/loss.py', verify)

    def test_a_corrupted_loss_py_on_vision_fails_deploy(self):
        class Corrupt(FakeRunner):
            def run(self, where, cmd, **kw):
                res = super().run(where, cmd, **kw)
                if where == 'vision' and cmd.startswith('sha256sum') and 'loss.py' in cmd:
                    return cp.Result(0, res.out.replace(res.out.splitlines()[-1].split()[0], '0' * 64), '')
                return res
        self.assertEqual(self.deploy(Corrupt()), 1)

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

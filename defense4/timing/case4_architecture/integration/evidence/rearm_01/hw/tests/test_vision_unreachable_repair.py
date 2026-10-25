"""vision_unreachable_repair.py and its reconcile acceptance (offline; no switch, no Vision, no systemd)."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW))
sys.path.insert(0, str(HW / 'tests'))
import evaluation_campaign as ec  # noqa: E402
import vision_unreachable_repair as vur  # noqa: E402
from test_reconcile import ReconcileTests, sha  # noqa: E402

BLOCK = HW.parents[2] / ('core/response_only_rearm/stage_experiments/read_complete_01/evidence/hw_blocks/'
                         'rc01_hw_c51_20261024_05_persistence_graceful_950')
REAL_RUN = json.loads((BLOCK / 'campaign_run.json').read_text())
REAL_OUT = (BLOCK / 'run_block_run.out').read_text(errors='replace')
HOST = 'decps@10.10.54.166'


class BoundFailure(unittest.TestCase):
    def test_the_real_block05_failure_binds(self):
        failure, problems = vur.bound_failure(REAL_RUN, REAL_OUT, HOST)
        self.assertEqual(problems, [])
        self.assertEqual([s['step'] for s in failure['steps']], vur.STEPS)

    def test_other_configured_host_refused(self):
        self.assertTrue(vur.bound_failure(REAL_RUN, REAL_OUT, 'decps@10.10.54.19')[1])

    def test_a_switch_restore_failure_is_refused(self):
        run = copy.deepcopy(REAL_RUN)
        run['restore'][0].update(ok=False, rc=1)
        self.assertTrue(vur.bound_failure(run, REAL_OUT, HOST)[1])

    def test_a_vision_failure_that_executed_is_refused(self):
        run = copy.deepcopy(REAL_RUN)
        next(s for s in run['restore'] if s['step'] == ec.VISION_RESTORE_STEP)['rc'] = 1
        self.assertTrue(vur.bound_failure(run, REAL_OUT, HOST)[1])

    def test_non_connect_failure_detail_is_refused(self):
        out = REAL_OUT.replace('No route to host', 'Permission denied (publickey)', 1)
        self.assertTrue(vur.bound_failure(REAL_RUN, out, HOST)[1])

    def test_extra_or_missing_failure_line_is_refused(self):
        lines = [l for l in REAL_OUT.splitlines() if l.startswith('RESTORE STEP FAILED')]
        self.assertTrue(vur.bound_failure(REAL_RUN, REAL_OUT.replace(lines[1], ''), HOST)[1])
        self.assertTrue(vur.bound_failure(REAL_RUN, REAL_OUT + '\n' + lines[0], HOST)[1])


class Result(SimpleNamespace):
    pass


CONFIG = {'hosts': {'vision': HOST, 'vision_run_dir': '/home/decps/run'},
          'production': {'ping': {'count': 2, 'src': '192.168.10.1', 'dst': '192.168.10.7'}}}


class ApplyRepair(unittest.TestCase):
    def runner(self, identity='vision\n%s\n' % ec.VISION_DATA_MAC, rcs=(0, 0)):
        calls = []

        def run(host, command):
            calls.append((host, command))
            if command.startswith('hostname'):
                return Result(returncode=0, stdout=identity, stderr='')
            return Result(returncode=rcs[len(calls) - 2], stdout='ok', stderr='')
        return run, calls

    def test_identity_then_the_runner_commands(self):
        run, calls = self.runner()
        out = vur.apply_repair('decps@10.10.54.19', CONFIG, run=run)
        self.assertTrue(out['ok'])
        self.assertEqual([c for _h, c in calls[1:]],
                         ['sudo -n /usr/bin/python3 /home/decps/run/vision_run.py restore --endpoint-profile sel751',
                          'ping -c 2 -I 192.168.10.1 192.168.10.7'])

    def test_wrong_host_runs_nothing(self):
        run, calls = self.runner(identity='hulk\n%s\n' % ec.VISION_DATA_MAC)
        self.assertFalse(vur.apply_repair('decps@x', CONFIG, run=run)['ok'])
        self.assertEqual(len(calls), 1)
        run, calls = self.runner(identity='vision\naa:bb:cc:dd:ee:ff\n')
        self.assertFalse(vur.apply_repair('decps@x', CONFIG, run=run)['ok'])
        self.assertEqual(len(calls), 1)

    def test_a_raising_runner_is_a_failed_repair_in_main_path(self):
        def boom(host, command):
            raise OSError('ssh missing')
        with self.assertRaises(OSError):            # main() records this as a failed repair (ok False), never a pass
            vur.apply_repair('decps@x', CONFIG, run=boom)

    def test_failed_restore_or_ping_is_not_ok(self):
        for rcs in ((1, 0), (0, 1)):
            run, _calls = self.runner(rcs=rcs)
            self.assertFalse(vur.apply_repair('decps@x', CONFIG, run=run)['ok'])


class Remap(unittest.TestCase):
    def test_host_must_be_user_at_host(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp, 'cfg.json')
            config.write_text(json.dumps(CONFIG))
            for host in ('-oProxyCommand=x', '10.10.54.19', 'a@b;c', ''):
                with self.assertRaises(ec.Refused, msg=host):
                    ec.remap_vision_host(config, Path(temp), host)

    def test_only_vision_host_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp, 'cfg.json')
            config.write_text(json.dumps(CONFIG))
            out = Path(temp, 'out')
            out.mkdir()
            derived, record = ec.remap_vision_host(config, out, 'decps@10.10.54.19')
            got = json.loads(Path(derived).read_text())
            want = copy.deepcopy(CONFIG)
            want['hosts']['vision'] = 'decps@10.10.54.19'
            self.assertEqual(got, want)
            self.assertEqual((record['vision_from'], record['vision_to']), (HOST, 'decps@10.10.54.19'))
            with self.assertRaises(FileExistsError):
                ec.remap_vision_host(config, out, 'decps@10.10.54.19')


class UnreachableReconcileTests(ReconcileTests):
    """Regular reconcile of a block whose Vision restore and ping never reached Vision (fixture testbed)."""

    def setUp(self):
        super().setUp()
        run_root = self.root / 'run0'
        (run_root / 'campaign_run.json').write_text(json.dumps({'restore': [
            {'step': 'cold-swap', 'rc': 0, 'ok': True},
            {'step': ec.VISION_RESTORE_STEP, 'rc': 255, 'ok': False}, {'step': ec.PING_STEP, 'rc': 255, 'ok': False}]}))
        files = {p.name: {'sha256': sha(p), 'size': p.stat().st_size} for p in run_root.iterdir()
                 if p.name != 'artifact_manifest.json'}
        (run_root / 'artifact_manifest.json').write_text(json.dumps({'files': files}))
        steps = self.campaign / 'steps' / 'block0'
        terminal = json.loads((steps / 'terminal.json').read_text())
        terminal['artifact_manifest']['sha256'] = sha(run_root / 'artifact_manifest.json')
        (steps / 'terminal.json').write_text(json.dumps(terminal))
        own = json.loads(self.ownership.read_text())
        own['terminal_sha256'] = sha(steps / 'terminal.json')
        self.ownership.write_text(json.dumps(own))
        self.original = {p: p.read_bytes() for p in run_root.iterdir()}
        self.repair_dir = steps / 'vision_unreachable_repair_20261025T010000Z'

    def write_repair(self, **change):
        steps = self.campaign / 'steps' / 'block0'
        repair = {'ok': True, 'vision_host': None,
                  'bound_sha256': {'terminal': sha(steps / 'terminal.json'),
                                   'campaign_run.json': sha(self.root / 'run0' / 'campaign_run.json')},
                  'failed_restoration': {'steps': [{'step': ec.VISION_RESTORE_STEP}, {'step': ec.PING_STEP}]},
                  'identity': {'hostname': 'vision', 'data_mac': ec.VISION_DATA_MAC},
                  'restore': {'rc': 0}, 'ping': {'rc': 0}}
        repair.update(change)
        self.repair_dir.mkdir(exist_ok=True)
        (self.repair_dir / 'repair.json').write_text(json.dumps(repair))

    def fresh(self, failures, vision_rc=0, ping_rc=0):
        code = ('import json,sys; from pathlib import Path; Path(%r).joinpath("restore_verify.json").write_text('
                'json.dumps({"ok": False, "failures": %r, "checks": {"vision_state": {"rc": %d}, "ping": {"rc": %d}}}));'
                ' sys.exit(1)')
        return lambda config, out: [sys.executable, '-c', code % (str(out), list(failures), vision_rc, ping_rc)]

    ONLY = [ec.UNREACHABLE_ONLY_FAILURE]

    def test_bound_repair_with_only_the_historical_steps_clears(self):
        self.write_repair()
        record = Path(self.run_reconcile(verifier=self.fresh(self.ONLY)))
        self.assertIs(json.loads(self.ownership.read_text())['unsafe_restoration'], False)
        data = json.loads(record.read_text())
        self.assertEqual(data['vision_unreachable_repair']['problems'], [])
        self.assertIn('never reached Vision', data['result'])
        self.assert_original_untouched()

    def test_without_repair_record_refused(self):
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(verifier=self.fresh(self.ONLY))
        self.assert_flag_set()

    def test_any_other_fresh_failure_refused(self):
        self.write_repair()
        for i, verifier in enumerate((self.fresh(self.ONLY + ['switch runs other']), self.fresh(self.ONLY, vision_rc=255),
                                      self.fresh(self.ONLY, ping_rc=1))):
            with self.subTest(i=i):
                with self.assertRaises(self.c.Refused):
                    self.run_reconcile(verifier=verifier, now=2000 + i)
                self.assert_flag_set()

    def test_failed_unbound_or_wrong_host_repair_refused(self):
        for i, change in enumerate(({'ok': False}, {'bound_sha256': {'terminal': 'x', 'campaign_run.json': 'y'}},
                                    {'identity': {'hostname': 'hulk', 'data_mac': ec.VISION_DATA_MAC}},
                                    {'vision_host': 'decps@elsewhere'}, {'restore': {'rc': 1}})):
            with self.subTest(change=change):
                self.write_repair(**change)
                with self.assertRaises(self.c.Refused):
                    self.run_reconcile(verifier=self.fresh(self.ONLY), now=3000 + i)
                self.assert_flag_set()

    def test_record_without_vision_host_uses_the_config_host(self):
        self.write_repair(vision_host='decps@configured')
        with self.assertRaises(self.c.Refused):                 # fixture block: config host is None, record differs
            self.run_reconcile(verifier=self.fresh(self.ONLY))
        self.assert_flag_set()

    def test_a_vision_record_never_lets_a_nic_repair_record_decide(self):
        self.write_repair(ok=False)
        nic = self.campaign / 'steps' / 'block0' / 'nic_repair_20261025T000000Z'
        nic.mkdir()
        (nic / 'repair.json').write_text(json.dumps({'ok': True}))
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(verifier=self.fresh(self.ONLY))
        data = json.loads(sorted(self.root.glob('reconcile_block0_*/reconciliation_refused.json'))[-1].read_text())
        self.assertIn('vision_unreachable_repair', data)
        self.assertNotIn('nic_repair', data)
        self.assert_flag_set()

    def test_vision_host_needs_a_hardware_block(self):
        self.write_repair()
        with self.assertRaises(self.c.Refused):
            self.c.reconcile(self.campaign, 'block0', root=self.testbed, units=lambda: [],
                             verifier=self.fresh(self.ONLY), now=1000, vision_host='decps@10.10.54.19')
        self.assert_flag_set()


if __name__ == '__main__':
    unittest.main()

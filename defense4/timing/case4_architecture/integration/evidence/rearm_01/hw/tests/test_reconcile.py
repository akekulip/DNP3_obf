"""Offline tests for evaluation_campaign.reconcile (fixture state; no switch, no systemd)."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'evaluation_campaign.py'


def load_module():
    spec = importlib.util.spec_from_file_location('evaluation_campaign_reconcile', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def writer(ok, rc=0, failures=()):
    """A stand-in for restore_verify.py: writes its record into the run root and exits rc."""
    def build(config, out):
        code = ('import json,sys; from pathlib import Path; '
                'Path(%r).joinpath("restore_verify.json").write_text(json.dumps({"ok": %r, "failures": %r})); '
                'sys.exit(%d)' % (str(out), ok, list(failures), rc))
        return [sys.executable, '-c', code]
    return build


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.c = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        run_root = self.root / 'run0'
        manifest = {'campaign_id': 'reconcile-test', 'evidence_kind': 'supervision_fixture',
                    'steps': [{'id': 'block0', 'kind': 'block', 'argv': [sys.executable, '-c', 'pass'],
                               'run_root': str(run_root)}]}
        (self.root / 'input.json').write_text(json.dumps(manifest))
        self.campaign = Path(self.c.initialize(self.root / 'input.json'))
        run_root.mkdir()
        (run_root / 'campaign_run.json').write_text('{"restore": []}')
        (run_root / 'block0_prerun.json').write_text('{"tables": {}}')
        (run_root / 'restore_verify.json').write_text(json.dumps({'ok': False, 'failures': ['counter tables']}))
        files = {p.name: {'sha256': sha(p), 'size': p.stat().st_size} for p in run_root.iterdir()}
        (run_root / 'artifact_manifest.json').write_text(json.dumps({'files': files}))
        steps = self.campaign / 'steps' / 'block0'
        steps.mkdir(parents=True, exist_ok=True)
        terminal = {'id': 'block0', 'status': 'failed', 'reason': 'unsafe_restoration',
                    'restoration': {'path': str(run_root / 'restore_verify.json'), 'ok': False,
                                    'sha256': sha(run_root / 'restore_verify.json')},
                    'artifact_manifest': {'path': str(run_root / 'artifact_manifest.json'),
                                          'sha256': sha(run_root / 'artifact_manifest.json')}}
        (steps / 'terminal.json').write_text(json.dumps(terminal))
        self.testbed = self.root / 'testbed'
        self.testbed.mkdir()
        self.ownership = self.testbed / 'ownership.json'
        self.ownership.write_text(json.dumps({'active': False, 'unsafe_restoration': True,
                                              'campaign_dir': str(self.campaign), 'step_id': 'block0',
                                              'terminal_sha256': sha(steps / 'terminal.json')}))
        self.original = {p: p.read_bytes() for p in run_root.iterdir()}

    def tearDown(self):
        self.temp.cleanup()

    def run_reconcile(self, verifier=None, units=lambda: [], now=1000):
        return self.c.reconcile(self.campaign, 'block0', root=self.testbed, units=units,
                                verifier=verifier or writer(True), now=now)

    def assert_flag_set(self):
        self.assertIs(json.loads(self.ownership.read_text())['unsafe_restoration'], True)

    def assert_original_untouched(self):
        for path, raw in self.original.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_fresh_pass_clears_flag_with_immutable_record(self):
        record = self.run_reconcile()
        own = json.loads(self.ownership.read_text())
        self.assertIs(own['unsafe_restoration'], False)
        self.assertIs(own['active'], False)
        self.assertEqual(own['reconciliation_sha256'], sha(record))
        data = json.loads(Path(record).read_text())
        self.assertEqual(data['rc'], 0)
        self.assertEqual(data['bound_sha256']['terminal'], own['previous_terminal_sha256'])
        self.assertIn('original_restore_verify', data['bound_sha256'])
        self.assert_original_untouched()

    def test_fresh_failure_leaves_flag_set(self):
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(verifier=writer(False, rc=1, failures=['tables differ']))
        self.assert_flag_set()
        refused = list(self.root.glob('reconcile_block0_*/reconciliation_refused.json'))
        self.assertEqual(len(refused), 1)
        self.assertFalse(list(self.root.glob('reconcile_block0_*/reconciliation.json')))
        self.assert_original_untouched()

    def test_ok_record_with_nonzero_exit_or_failures_is_not_a_pass(self):
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(verifier=writer(True, rc=1), now=1001)
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(verifier=writer(True, failures=['x']), now=1002)
        self.assert_flag_set()

    def test_missing_fresh_record_leaves_flag_set(self):
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(verifier=lambda config, out: [sys.executable, '-c', 'pass'])
        self.assert_flag_set()

    def test_active_owner_refused(self):
        own = json.loads(self.ownership.read_text())
        own['active'] = True
        self.ownership.write_text(json.dumps(own))
        with self.assertRaises(self.c.Refused):
            self.run_reconcile()
        self.assertIs(json.loads(self.ownership.read_text())['active'], True)
        self.assert_flag_set()

    def test_running_evaluation_unit_refused(self):
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(units=lambda: ['dnp3-eval-x-step-y.service'])
        self.assert_flag_set()

    def test_held_testbed_lock_refused(self):
        import fcntl
        with open(self.testbed / 'active.lock', 'a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            with self.assertRaises(self.c.Refused):
                self.run_reconcile()
        self.assert_flag_set()

    def test_ownership_naming_another_step_refused(self):
        own = json.loads(self.ownership.read_text())
        own['step_id'] = 'other'
        self.ownership.write_text(json.dumps(own))
        with self.assertRaises(self.c.Refused):
            self.run_reconcile()
        self.assert_flag_set()

    def test_changed_terminal_record_refused(self):
        terminal = self.campaign / 'steps' / 'block0' / 'terminal.json'
        terminal.write_text(terminal.read_text() + ' ')
        with self.assertRaises(self.c.Refused):
            self.run_reconcile()
        self.assert_flag_set()

    def test_changed_restore_input_refused(self):
        (self.root / 'run0' / 'block0_prerun.json').write_text('{"tables": {"changed": 1}}')
        with self.assertRaises(self.c.Refused):
            self.run_reconcile()
        self.assert_flag_set()

    def test_changed_original_failure_record_refused(self):
        (self.root / 'run0' / 'restore_verify.json').write_text(json.dumps({'ok': True}))
        with self.assertRaises(self.c.Refused):
            self.run_reconcile()
        self.assert_flag_set()

    def test_no_unsafe_flag_means_nothing_to_reconcile(self):
        own = json.loads(self.ownership.read_text())
        own['unsafe_restoration'] = False
        self.ownership.write_text(json.dumps(own))
        with self.assertRaises(self.c.Refused):
            self.run_reconcile()

    def test_reconcile_directory_is_never_reused(self):
        self.run_reconcile(now=2000)
        own = json.loads(self.ownership.read_text())
        own['unsafe_restoration'] = True
        self.ownership.write_text(json.dumps(own))
        with self.assertRaises(FileExistsError):
            self.run_reconcile(now=2000)


    def test_rule_history_is_recorded(self):
        data = json.loads(Path(self.run_reconcile(now=3000)).read_text())
        tool = data['restore_verify_tool']
        self.assertIn('$PORT_STAT', tool['volatile_tables'])
        self.assertIn('$COUNTER_SPEC_PKTS', tool['stripped_statistics'])
        self.assertTrue(tool['last_commit'])


class UnitListingTests(unittest.TestCase):
    def test_running_queued_and_reserved_are_busy_but_exited_is_not(self):
        from unittest import mock
        c = load_module()
        listing = ('dnp3-eval-a-step-x.service loaded active exited desc\n'
                   'dnp3-eval-a-step-y.service loaded active running desc\n'
                   'dnp3-eval-a-step-z.service loaded activating start desc\n'
                   'dnp3-eval-a-step-w.service loaded failed failed desc\n')
        jobs = '7 dnp3-eval-a-step-q.service start waiting\n'
        outputs = iter([mock.Mock(returncode=0, stdout=listing, stderr=''), mock.Mock(returncode=0, stdout=jobs, stderr='')])
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(c.subprocess, 'run', side_effect=lambda *a, **k: next(outputs)):
            c.HERE = Path(temp)
            (Path(temp) / 'run_reservations').mkdir()
            (Path(temp) / 'run_reservations' / 'r1').write_text('x')
            busy = c.running_eval_units()
        self.assertIn('dnp3-eval-a-step-y.service', busy)
        self.assertIn('dnp3-eval-a-step-z.service', busy)
        self.assertNotIn('dnp3-eval-a-step-x.service', busy)
        self.assertNotIn('dnp3-eval-a-step-w.service', busy)
        self.assertTrue(any(b.startswith('job:') for b in busy))
        self.assertIn('reservation: r1', busy)


if __name__ == '__main__':
    unittest.main()

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


TRACEBACK_LOG = ('freeze check: OK 0 changed, 0 missing\n'
                 'Traceback (most recent call last):\n'
                 '  File "campaign.py", line 142, in load_config\n'
                 '    validate_profile(cfg)\n'
                 'ValueError: evaluation.purpose must be qualification\n')
WRAPPER = str(MODULE.parent / 'run_block_frozen.sh')
HOSTS = {'switch': 'sw', 'vision': 'vi', 'switch_remote_dir': '/r', 'vision_run_dir': '/v'}
PRODUCTION = {'program': 'prod', 'relay_slot': True, 'ping': {'count': 3, 'src': 'a', 'dst': 'b'}}


def block_log(*lines):
    return ''.join('2026-10-21T04:4%d:00-04:00 %s\n' % (i, line) for i, line in enumerate(lines))


def busy_after(calls):
    """units(): idle for the first `calls` listings, then a running evaluation unit."""
    seen = []
    def units():
        seen.append(1)
        return [] if len(seen) <= calls else ['dnp3-eval-late.service']
    return units


class NoContactReconcileTests(unittest.TestCase):
    """A block that failed before any hardware contact: no run root, a traceback in command.log."""

    def setUp(self):
        self.c = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.blocks = self.root / 'blocks'
        self.blocks.mkdir()
        self.run_root = self.blocks / 'block0'  # never created: the block failed before entry
        self.step_config = self.root / 'step_config.json'
        self.step_config.write_text(json.dumps({'evidence_dir': str(self.blocks), 'hosts': HOSTS,
                                                'production': PRODUCTION}))
        manifest = {'campaign_id': 'nocontact-test', 'evidence_kind': 'supervision_fixture',
                    'steps': [{'id': 'block0', 'kind': 'block', 'run_root': str(self.run_root),
                               'argv': ['/bin/bash', WRAPPER, str(self.root / 'freeze.json'), 'candidate_campaign',
                                        str(self.step_config), 'block0']}]}
        (self.root / 'input.json').write_text(json.dumps(manifest))
        self.campaign = Path(self.c.initialize(self.root / 'input.json'))
        self.steps = self.campaign / 'steps' / 'block0'
        self.steps.mkdir(parents=True, exist_ok=True)
        self.log = self.steps / 'command.log'
        self.log.write_text(TRACEBACK_LOG)
        self.terminal = {'id': 'block0', 'kind': 'block', 'status': 'failed', 'reason': 'unsafe_restoration', 'rc': 1,
                         'artifact_manifest': None,
                         'restoration': {'path': str(self.run_root / 'restore_verify.json'), 'ok': False,
                                         'error': 'No such file or directory'}}
        self.testbed = self.root / 'testbed'
        self.testbed.mkdir()
        self.ownership = self.testbed / 'ownership.json'
        self.write_terminal()
        self.make_baseline()
        self.c.RUN_BLOCK_LOG = self.root / 'run_block.log'
        self.c.RUN_BLOCK_LOG.write_text(block_log('START candidate_campaign older', 'END older block_rc=0 restore_verify_rc=0',
                                                  'START candidate_campaign base',
                                                  'END base block_rc=1 restore_verify_rc=0'))
        self.original = {p: p.read_bytes() for p in list(self.baseline.iterdir()) + list(self.steps.iterdir())
                         if p.is_file()}

    def write_terminal(self):
        terminal = self.steps / 'terminal.json'
        terminal.write_text(json.dumps(self.terminal))
        self.ownership.write_text(json.dumps({'active': False, 'unsafe_restoration': True,
                                              'campaign_dir': str(self.campaign), 'step_id': 'block0',
                                              'terminal_sha256': sha(terminal)}))

    def make_baseline(self):
        """A prior block that passed restoration, bound to its campaign's terminal record."""
        self.baseline = self.blocks / 'base'
        self.baseline.mkdir()
        self.config = self.root / 'baseline_config.json'
        self.config.write_text(json.dumps({'evidence_dir': str(self.blocks), 'hosts': HOSTS, 'production': PRODUCTION,
                                           'other': 'differs from the step config'}))
        (self.baseline / 'campaign_run.json').write_text('{"restore": [{"step": "x", "ok": true}]}')
        (self.baseline / 'base_prerun.json').write_text('{"tables": {"t": 1}}')
        (self.baseline / 'restore_verify.json').write_text(json.dumps({'ok': True, 'failures': []}))
        (self.baseline / 'freeze_check.json').write_text(json.dumps({'config': str(self.config),
                                                                     'config_sha256': sha(self.config)}))
        manifest = {'campaign_id': 'basecamp', 'evidence_kind': 'supervision_fixture',
                    'steps': [{'id': 'base', 'kind': 'block', 'run_root': str(self.baseline),
                               'argv': ['/bin/bash', WRAPPER, str(self.root / 'freeze.json'), 'candidate_campaign',
                                        str(self.config), 'base']}]}
        (self.root / 'base_input.json').write_text(json.dumps(manifest))
        self.base_campaign = Path(self.c.initialize(self.root / 'base_input.json'))
        self.base_terminal = self.base_campaign / 'steps' / 'base' / 'terminal.json'
        self.base_terminal.parent.mkdir(parents=True, exist_ok=True)
        self.write_baseline_manifest()

    def write_baseline_manifest(self, restoration_ok=True):
        files = {p.name: {'sha256': sha(p), 'size': p.stat().st_size} for p in self.baseline.iterdir()
                 if p.name != 'artifact_manifest.json'}
        (self.baseline / 'artifact_manifest.json').write_text(json.dumps({'files': files}))
        rv = self.baseline / 'restore_verify.json'
        self.base_terminal.write_text(json.dumps({
            'id': 'base', 'kind': 'block', 'status': 'failed', 'reason': 'block_failed',
            'manifest_sha256': sha(self.base_campaign / 'manifest.json'),
            'restoration': {'path': str(rv), 'ok': restoration_ok, 'sha256': sha(rv)},
            'artifact_manifest': {'path': str(self.baseline / 'artifact_manifest.json'),
                                  'sha256': sha(self.baseline / 'artifact_manifest.json')}}))

    def tearDown(self):
        self.temp.cleanup()

    def run_reconcile(self, verifier=None, units=lambda: [], now=1000, baseline='default', terminal='default'):
        return self.c.reconcile(self.campaign, 'block0', root=self.testbed, units=units,
                                verifier=verifier or writer(True), now=now,
                                baseline_run_root=self.baseline if baseline == 'default' else baseline,
                                baseline_terminal=self.base_terminal if terminal == 'default' else terminal)

    def assert_flag_set(self):
        self.assertIs(json.loads(self.ownership.read_text())['unsafe_restoration'], True)

    def refusals(self):
        return list(self.steps.glob('reconcile_*/reconciliation_refused.json'))

    def assert_refused_with_record(self, problem=None, **kwargs):
        with self.assertRaises(self.c.Refused) as caught:
            self.run_reconcile(**kwargs)
        self.assert_flag_set()
        self.assertEqual(len(self.refusals()), 1)
        self.assertFalse(list(self.steps.glob('reconcile_*/reconciliation.json')))
        self.assertIs(json.loads(self.refusals()[0].read_text())['flag_left_set'], True)
        if problem:
            self.assertIn(problem, str(caught.exception))
        return caught.exception

    def test_pass_clears_flag_with_bound_immutable_record(self):
        record = Path(self.run_reconcile())
        self.assertEqual(record.parent.parent, self.steps)
        own = json.loads(self.ownership.read_text())
        self.assertIs(own['unsafe_restoration'], False)
        self.assertIs(own['active'], False)
        self.assertEqual(own['reconciliation_sha256'], sha(record))
        self.assertEqual(own['previous_terminal_sha256'], sha(self.steps / 'terminal.json'))
        data = json.loads(record.read_text())
        bound = data['bound_sha256']
        self.assertEqual(data['mode'], 'no_hardware_contact')
        self.assertEqual(bound['terminal'], sha(self.steps / 'terminal.json'))
        self.assertEqual(bound['command_log'], sha(self.log))
        self.assertEqual(bound['fresh_restore_verify'], sha(record.parent / 'restore_verify.json'))
        self.assertEqual(bound['baseline']['restore_verify.json'], sha(self.baseline / 'restore_verify.json'))
        self.assertEqual(bound['baseline']['config'], sha(self.config))
        self.assertEqual(bound['baseline']['terminal'], sha(self.base_terminal))
        self.assertEqual(bound['baseline']['artifact_manifest.json'], sha(self.baseline / 'artifact_manifest.json'))
        self.assertEqual(bound['run_block_log'], sha(self.c.RUN_BLOCK_LOG))
        for name in ('campaign_run.json', 'base_prerun.json'):
            self.assertEqual(sha(record.parent / name), sha(self.baseline / name))
            self.assertEqual(bound['baseline'][name], sha(self.baseline / name))
        evidence = data['no_contact_evidence']
        self.assertEqual(evidence['classification'], 'no_hardware_contact')
        self.assertIs(evidence['primary']['terminal_artifact_manifest_null'], True)
        self.assertEqual(evidence['primary']['run_block_log_entries'], [])
        self.assertEqual(data['config'], str(self.config))
        self.assertEqual(data['rc'], 0)
        tool = data['restore_verify_tool']
        self.assertIn('$PORT_STAT', tool['volatile_tables'])
        self.assertIn('$COUNTER_SPEC_PKTS', tool['stripped_statistics'])
        self.assertTrue(tool['rule_note'])
        self.assertIn('campaign_run.json', data['fresh_checks_note'])
        self.assertIn('2-5', data['fresh_checks_note'])
        for path, raw in self.original.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_docstring_names_record_location(self):
        self.assertIn('steps/<step>/reconcile_<ts>/', self.c.reconcile_no_contact.__doc__)

    def test_repo_root_resolves_like_guarded_block(self):
        target = MODULE.parent / 'restore_verify.py'
        self.assertTrue((self.c.REPO / '.git').exists())
        self.assertEqual(self.c.REPO / target.relative_to(self.c.REPO), target)
        self.assertEqual(self.c.ARCH.name, 'case4_architecture')

    def test_freeze_refusal_passes_with_bound_exit_status(self):
        self.log.write_text(FREEZE_LOG)
        self.terminal['rc'] = 3
        self.write_terminal()
        self.c.FREEZE_CHECKS = self.root / 'no_freeze_checks'
        before = {p: p.read_bytes() for p in (self.log, self.steps / 'terminal.json')}
        record = Path(self.run_reconcile())
        for path, raw in before.items():                       # the original failure record is preserved
            self.assertEqual(path.read_bytes(), raw, path.name)
        self.assertIs(json.loads(self.ownership.read_text())['unsafe_restoration'], False)
        self.assertEqual(json.loads(record.read_text())['no_contact_evidence']['corroborating']['ending'],
                         'freeze_refused')

    def test_freeze_refusal_with_other_exit_status_refused(self):
        self.log.write_text(FREEZE_LOG)
        self.terminal['rc'] = 1
        self.write_terminal()
        self.c.FREEZE_CHECKS = self.root / 'no_freeze_checks'
        self.assert_refused_with_record('terminal exit status')

    def test_freeze_refusal_fresh_verifier_failure_leaves_flag_set(self):
        self.log.write_text(FREEZE_LOG)
        self.terminal['rc'] = 3
        self.write_terminal()
        self.c.FREEZE_CHECKS = self.root / 'no_freeze_checks'
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(verifier=writer(False))
        self.assert_flag_set()

    # --- no-contact proof -------------------------------------------------------------------------------------
    def test_hardware_marker_in_command_log_refused(self):
        self.log.write_text('[switch] make remote directories -> rc 0\n' + TRACEBACK_LOG)
        self.assert_refused_with_record('hardware marker')

    def test_ssh_in_command_log_refused(self):
        self.log.write_text('              $ ssh -o BatchMode=yes switch true\n' + TRACEBACK_LOG)
        self.assert_refused_with_record('hardware marker')

    def test_log_not_ending_in_traceback_or_refusal_refused(self):
        self.log.write_text('freeze check: OK 0 changed, 0 missing\n')
        self.assert_refused_with_record('does not end')

    def test_missing_command_log_refused(self):
        self.log.unlink()
        self.assert_refused_with_record('command.log unreadable')

    def test_existing_empty_run_root_refused(self):
        self.run_root.mkdir()
        self.assert_refused_with_record('run root exists')

    def test_dangling_symlink_run_root_refused(self):
        self.run_root.symlink_to(self.root / 'nowhere')
        self.assert_refused_with_record('run root exists')

    def test_terminal_with_artifact_manifest_refused(self):
        self.terminal['artifact_manifest'] = {'path': '/x/artifact_manifest.json', 'sha256': '0' * 64}
        self.write_terminal()
        self.assert_refused_with_record('artifact_manifest')

    def test_run_block_log_start_for_this_run_refused(self):
        self.c.RUN_BLOCK_LOG.write_text(self.c.RUN_BLOCK_LOG.read_text() +
                                        block_log('START candidate_campaign block0',
                                                  'REFUSED block0 block_rc=1 (no hardware entry)'))
        self.assert_refused_with_record('run_block.log')

    def test_terminal_restoration_not_this_run_root_refused(self):
        self.terminal['restoration']['path'] = str(self.root / 'elsewhere' / 'restore_verify.json')
        self.write_terminal()
        self.assert_refused_with_record('restoration')

    def test_terminal_restoration_ok_refused(self):
        self.terminal['restoration']['ok'] = True
        self.write_terminal()
        self.assert_refused_with_record('restoration')

    def test_run_root_not_derived_from_config_refused(self):
        self.step_config.write_text(json.dumps({'evidence_dir': str(self.root / 'other'), 'hosts': HOSTS,
                                                'production': PRODUCTION}))
        self.assert_refused_with_record('run root')

    def test_run_root_with_hardware_evidence_must_use_existing_path(self):
        self.run_root.mkdir()
        (self.run_root / 'campaign_run.json').write_text('{"restore": []}')
        with self.assertRaises(self.c.Refused):
            self.run_reconcile()
        self.assert_flag_set()
        self.assertFalse(list(self.steps.glob('reconcile_*')))

    # --- baseline binding ---------------------------------------------------------------------------------------
    def test_missing_baseline_refused(self):
        self.assert_refused_with_record('baseline', baseline=None)

    def test_missing_baseline_terminal_refused(self):
        self.assert_refused_with_record('baseline', terminal=None)

    def test_baseline_not_bound_to_terminal_refused(self):
        terminal = json.loads(self.base_terminal.read_text())
        terminal['artifact_manifest']['sha256'] = '0' * 64
        self.base_terminal.write_text(json.dumps(terminal))
        self.assert_refused_with_record('baseline')

    def test_baseline_terminal_restoration_not_ok_refused(self):
        self.write_baseline_manifest(restoration_ok=False)
        self.assert_refused_with_record('baseline')

    def test_stale_baseline_later_start_refused(self):
        self.c.RUN_BLOCK_LOG.write_text(self.c.RUN_BLOCK_LOG.read_text() +
                                        block_log('START candidate_campaign later'))
        self.assert_refused_with_record('baseline')

    def test_baseline_end_without_verified_restore_refused(self):
        self.c.RUN_BLOCK_LOG.write_text(block_log('START candidate_campaign base',
                                                  'END base block_rc=0 restore_verify_rc=1'))
        self.assert_refused_with_record('baseline')

    def test_config_hosts_or_production_mismatch_refused(self):
        self.step_config.write_text(json.dumps({'evidence_dir': str(self.blocks), 'hosts': HOSTS,
                                                'production': dict(PRODUCTION, program='other')}))
        self.assert_refused_with_record('hosts/production')

    def test_baseline_restore_not_ok_refused_without_running_verifier(self):
        (self.baseline / 'restore_verify.json').write_text(json.dumps({'ok': False, 'failures': ['tables differ']}))
        self.write_baseline_manifest()
        self.assert_refused_with_record('baseline')
        self.assertFalse((self.refusals()[0].parent / 'restore_verify.json').exists())

    def test_baseline_with_failures_refused(self):
        (self.baseline / 'restore_verify.json').write_text(json.dumps({'ok': True, 'failures': ['x']}))
        self.write_baseline_manifest()
        self.assert_refused_with_record('baseline')

    def test_baseline_input_changed_after_retention_refused(self):
        (self.baseline / 'base_prerun.json').write_text('{"tables": {"t": 2}}')
        self.assert_refused_with_record('baseline')

    def test_baseline_config_changed_refused(self):
        self.config.write_text(json.dumps({'evidence_dir': str(self.blocks), 'hosts': HOSTS, 'production': PRODUCTION}))
        self.assert_refused_with_record('baseline')

    # --- fresh check and post-verify recheck --------------------------------------------------------------------
    def test_fresh_verifier_failure_leaves_flag_set(self):
        self.assert_refused_with_record('fresh', verifier=writer(False, rc=1, failures=['tables differ']))

    def test_fresh_ok_with_nonzero_exit_refused(self):
        self.assert_refused_with_record('fresh', verifier=writer(True, rc=1))

    def test_unit_started_during_verify_refused(self):
        self.assert_refused_with_record('after the fresh check', units=busy_after(1))

    def test_ownership_changed_during_verify_refused(self):
        def verifier(config, out):
            code = ('import json; from pathlib import Path; '
                    'Path(%r).joinpath("restore_verify.json").write_text(json.dumps({"ok": True, "failures": []})); '
                    'p = Path(%r); p.write_text(p.read_text() + " ")' % (str(out), str(self.ownership)))
            return [sys.executable, '-c', code]
        self.assert_refused_with_record('after the fresh check', verifier=verifier)

    def test_shared_guards_still_apply(self):
        own = json.loads(self.ownership.read_text())
        own['step_id'] = 'other'
        self.ownership.write_text(json.dumps(own))
        with self.assertRaises(self.c.Refused):
            self.run_reconcile()
        self.assert_flag_set()
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(units=lambda: ['dnp3-eval-x.service'], now=1001)
        terminal = self.steps / 'terminal.json'
        own['step_id'] = 'block0'
        self.ownership.write_text(json.dumps(own))
        terminal.write_text(terminal.read_text() + ' ')
        with self.assertRaises(self.c.Refused):
            self.run_reconcile(now=1002)
        self.assert_flag_set()
        self.assertEqual(len(self.refusals()), 3)

    def test_record_is_never_overwritten(self):
        record = Path(self.run_reconcile(now=2000))
        raw = record.read_bytes()
        own = json.loads(self.ownership.read_text())
        own['unsafe_restoration'] = True
        self.ownership.write_text(json.dumps(own))
        with self.assertRaises(FileExistsError):
            self.run_reconcile(now=2000)
        self.assertEqual(record.read_bytes(), raw)


class EvidenceClassificationTests(unittest.TestCase):
    TERMINAL = {'artifact_manifest': None}

    def setUp(self):
        self.c = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / 'command.log'
        self.runlog = self.root / 'run_block.log'
        self.runlog.write_text(block_log('START candidate_campaign other', 'END other block_rc=0 restore_verify_rc=0'))

    def tearDown(self):
        self.temp.cleanup()

    def classify(self, run_root=None, terminal=None):
        return self.c.classify_step_evidence(run_root or self.root / 'run0', self.log,
                                             self.TERMINAL if terminal is None else terminal,
                                             'run0', self.runlog)

    def test_traceback_without_run_root_is_no_contact(self):
        self.log.write_text(TRACEBACK_LOG)
        self.assertEqual(self.classify()['classification'], 'no_hardware_contact')

    def test_wrapper_refusal_is_no_contact(self):
        self.log.write_text('REFUSED (nothing entered): retained run path already exists\n')
        self.assertEqual(self.classify()['classification'], 'no_hardware_contact')

    def test_any_hardware_evidence_file_is_hardware_run(self):
        for name in ('campaign_run.json', 'x_prerun.json', 'run_block_plan.out', 'run_block_run.out',
                     'restore_verify.json', 'restore_verify_postrun.json', 'freeze_check.json'):
            with tempfile.TemporaryDirectory() as temp:
                (Path(temp) / name).write_text('{}')
                self.log.write_text(TRACEBACK_LOG)
                self.assertEqual(self.classify(run_root=Path(temp))['classification'], 'hardware_run', name)

    def test_existing_root_or_symlink_is_ambiguous(self):
        self.log.write_text(TRACEBACK_LOG)
        (self.root / 'empty').mkdir()
        self.assertEqual(self.classify(run_root=self.root / 'empty')['classification'], 'ambiguous')
        (self.root / 'dangling').symlink_to(self.root / 'nowhere')
        self.assertEqual(self.classify(run_root=self.root / 'dangling')['classification'], 'ambiguous')

    def test_terminal_artifact_manifest_or_start_entry_is_ambiguous(self):
        self.log.write_text(TRACEBACK_LOG)
        self.assertEqual(self.classify(terminal={'artifact_manifest': {'path': 'x'}})['classification'], 'ambiguous')
        self.assertEqual(self.classify(terminal={})['classification'], 'ambiguous')
        self.runlog.write_text(self.runlog.read_text() + block_log('START candidate_campaign run0'))
        self.assertEqual(self.classify()['classification'], 'ambiguous')

    def test_markers_are_ambiguous(self):
        for line in ('[local      ] deploy', '[vision] verify', '[restore:switch] x', 'rsync -a a b',
                     'scp -q a b', 'launch bf_switchd', 'DEFENSE4_HW_AUTHORIZED=1',
                     'block command failed; checking for hardware entry: x'):
            self.log.write_text(line + '\n' + TRACEBACK_LOG)
            self.assertEqual(self.classify()['classification'], 'ambiguous', line)

    def test_traceback_must_be_last(self):
        self.log.write_text(TRACEBACK_LOG + 'more output\n')
        self.assertEqual(self.classify()['classification'], 'ambiguous')


FREEZE_LOG = ('freeze check: FAILED 1 changed, 0 missing\n'
              '  changed defense4/timing/case4_architecture/protocol/hw_vepa/vision_run.py\n'
              '  DIAGNOSTIC EXCEPTION (does not qualify): matched control; not a qualification\n')


class FreezeRefusalClassificationTests(unittest.TestCase):
    """guarded_block's pre-hardware freeze refusal (rc 3, freeze_gate's failure report only) is no-contact; every
    weaker or contradicting form stays ambiguous (rc01_hw_c25_20261022_03, 2026-10-22)."""

    def setUp(self):
        self.c = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / 'command.log'
        self.log.write_text(FREEZE_LOG)
        self.runlog = self.root / 'run_block.log'
        self.runlog.write_text(block_log('START candidate_campaign other', 'END other block_rc=0 restore_verify_rc=0'))
        self.checks = self.root / 'freeze_checks'
        self.checks.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def classify(self, rc=3, run_root=None, terminal=None):
        t = {'artifact_manifest': None, 'rc': rc} if terminal is None else terminal
        return self.c.classify_step_evidence(run_root or self.root / 'run0', self.log, t, 'run0', self.runlog,
                                             freeze_checks=self.checks)

    def test_exact_freeze_refusal_is_no_contact(self):
        r = self.classify()
        self.assertEqual(r['classification'], 'no_hardware_contact', r['reasons'])
        self.assertEqual(r['corroborating']['ending'], 'freeze_refused')
        self.assertEqual(r['corroborating']['terminal_rc'], 3)

    def test_other_exit_status_is_ambiguous(self):
        for rc in (1, 2, 0, None, '3', True):
            self.assertEqual(self.classify(rc=rc)['classification'], 'ambiguous', rc)

    def test_retained_freeze_record_is_ambiguous(self):
        (self.checks / 'run0.json').write_text('{}')
        self.assertEqual(self.classify()['classification'], 'ambiguous')

    def test_passing_freeze_check_is_not_a_refusal(self):
        self.log.write_text('freeze check: OK 0 changed, 0 missing\n')
        self.assertEqual(self.classify()['classification'], 'ambiguous')

    def test_any_line_after_the_report_is_ambiguous(self):
        for extra in ('plan output\n', 'block started\n', '[switch] x -> rc 0\n',
                      '              $ ssh switch true\n', '  plan step indented\n'):
            self.log.write_text(FREEZE_LOG + extra)
            self.assertEqual(self.classify()['classification'], 'ambiguous', extra)

    def test_listing_without_header_or_header_not_first_is_ambiguous(self):
        self.log.write_text(FREEZE_LOG.split('\n', 1)[1])
        self.assertEqual(self.classify()['classification'], 'ambiguous')
        self.log.write_text('something else\n' + FREEZE_LOG)
        self.assertEqual(self.classify()['classification'], 'ambiguous')

    def test_primary_conditions_still_required(self):
        (self.root / 'exists').mkdir()
        self.assertEqual(self.classify(run_root=self.root / 'exists')['classification'], 'ambiguous')
        self.assertEqual(self.classify(terminal={'artifact_manifest': {'path': 'x'}, 'rc': 3})['classification'],
                         'ambiguous')
        self.runlog.write_text(self.runlog.read_text() + block_log('START candidate_campaign run0'))
        self.assertEqual(self.classify()['classification'], 'ambiguous')

    def test_default_freeze_checks_is_guarded_blocks_directory(self):
        self.assertEqual(self.c.FREEZE_CHECKS, self.c.HERE / 'freeze_checks')
        self.assertIn("HW / 'freeze_checks' / (run_id + '.json')", (self.c.HERE / 'guarded_block.py').read_text())

    def test_marker_inside_a_listing_line_is_ambiguous(self):
        self.log.write_text('freeze check: FAILED 0 changed, 1 missing\n  missing a regenerate: ssh host make\n')
        r = self.classify()
        self.assertEqual(r['classification'], 'ambiguous')
        self.assertTrue(r['corroborating']['markers'])

    def test_listing_lines_must_have_their_exact_form(self):
        for line in ('  changed a; plan: deployed pipeline', '  changed', '\tchanged a', '  deployed x'):
            self.log.write_text('freeze check: FAILED 1 changed, 0 missing\n' + line + '\n')
            self.assertEqual(self.classify()['classification'], 'ambiguous', line)

    def test_hardware_evidence_file_is_hardware_run(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'freeze_check.json').write_text('{}')
            self.assertEqual(self.classify(run_root=Path(temp))['classification'], 'hardware_run')


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


class WrapperLocationTest(unittest.TestCase):
    def test_a_wrapper_from_another_checkout_is_refused(self):
        step = {'id': 's', 'argv': ['/bin/bash', '/elsewhere/checkout/run_block_frozen.sh', 'F', 'T', 'C', 'R']}
        with self.assertRaises(ValueError):
            load_module().frozen_argv(step)
        step['argv'][1] = WRAPPER
        self.assertEqual(load_module().frozen_argv(step), ('C', 'R'))


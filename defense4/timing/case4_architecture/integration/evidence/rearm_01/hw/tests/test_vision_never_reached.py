"""vision_never_reached and its reconcile route (offline; no switch, no Vision, no systemd).

The retained relay_event_clear_20261025_02 block failed at its first Vision command because its config named the old
Vision address (.166) after only pre-contact switch/local steps; reconcile may then remap Vision only on this proof.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW))
import evaluation_campaign as ec  # noqa: E402

BLOCK = HW.parents[2] / ('core/response_only_rearm/stage_experiments/read_complete_01/evidence/'
                         'relay_event_clear_20261025/relay_event_clear_20261025_02')
HOST = 'decps@10.10.54.166'


class NeverReached(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ('campaign_run.json', 'run_block_run.out'):
            shutil.copy(BLOCK / name, self.root / name)

    def tearDown(self):
        self.temp.cleanup()

    def edit_out(self, old, new):
        path = self.root / 'run_block_run.out'
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def edit_run(self, **change):
        path = self.root / 'campaign_run.json'
        record = json.loads(path.read_text())
        record.update(change)
        path.write_text(json.dumps(record))

    def test_the_real_block_binds(self):
        proof, problems = ec.vision_never_reached(self.root, HOST)
        self.assertEqual(problems, [])
        self.assertEqual(proof['pre_contact_steps'], 13)

    def test_other_configured_host_refused(self):
        self.assertTrue(ec.vision_never_reached(self.root, 'decps@10.10.54.19')[1])

    def test_a_state_changing_switch_step_refused(self):
        self.edit_out('[switch] verify production conf_sha256 -> rc 0',
                      '[switch] cold-swap bf_switchd to the candidate -> rc 0')
        self.assertTrue(ec.vision_never_reached(self.root, HOST)[1])

    def test_a_failed_pre_contact_step_refused(self):
        self.edit_out('[switch] verify production conf_sha256 -> rc 0', '[switch] verify production conf_sha256 -> rc 1')
        self.assertTrue(ec.vision_never_reached(self.root, HOST)[1])

    def test_a_vision_step_that_ran_refused(self):
        self.edit_out('[vision] make relay helper directories -> rc 255', '[vision] make relay helper directories -> rc 0')
        self.assertTrue(ec.vision_never_reached(self.root, HOST)[1])

    def test_a_second_vision_step_refused(self):
        self.edit_out('[vision] make relay helper directories -> rc 255',
                      '[vision] make relay helper directories -> rc 0\n[vision] deploy relay helper x -> rc 255')
        self.assertTrue(ec.vision_never_reached(self.root, HOST)[1])

    def test_non_connect_failure_refused(self):
        record = json.loads((self.root / 'campaign_run.json').read_text())
        self.edit_run(failure=record['failure'].replace('No route to host', 'Permission denied (publickey)'))
        self.assertTrue(ec.vision_never_reached(self.root, HOST)[1])

    def test_runner_work_refused(self):
        for change in ({'restore': [{'step': 'cold-swap', 'ok': True}]}, {'arms': [{'arm': 'off'}]},
                       {'bringups': [1]}, {'collections': [1]}, {'ok': True}, {'candidate_loaded': True},
                       {'state_touched': {'switch': True, 'vision': False}}):
            with self.subTest(change=change):
                self.setUp()
                self.edit_run(**change)
                self.assertTrue(ec.vision_never_reached(self.root, HOST)[1])

    def test_missing_runner_record_refused(self):
        (self.root / 'campaign_run.json').unlink()
        self.assertTrue(ec.vision_never_reached(self.root, HOST)[1])


import copy  # noqa: E402
sys.path.insert(0, str(HW / 'tests'))
import test_reconcile as tr  # noqa: E402
writer, block_log, sha, HOSTS = tr.writer, tr.block_log, tr.sha, tr.HOSTS

REAL_OUT = (BLOCK / 'run_block_run.out').read_text()
REAL_RUN = json.loads((BLOCK / 'campaign_run.json').read_text())
VISION_OK = {'rc': 0, 'hostname': 'vision', 'data_mac': ec.VISION_DATA_MAC}


class NeverReachedReconcileTests(unittest.TestCase):
    """reconcile() end to end on a hardware-kind fixture: the never-reached proof routes to the no-contact path
    against a named baseline; only hosts.vision may differ, to --vision-host, re-proven to be Vision."""
    write_terminal = tr.NoContactReconcileTests.write_terminal
    make_baseline = tr.NoContactReconcileTests.make_baseline
    write_baseline_manifest = tr.NoContactReconcileTests.write_baseline_manifest
    tearDown = tr.NoContactReconcileTests.tearDown
    assert_flag_set = tr.NoContactReconcileTests.assert_flag_set

    def setUp(self):
        tr.NoContactReconcileTests.setUp(self)
        # the same fixture as a hardware campaign whose step names the old Vision host
        step_cfg = json.loads(self.step_config.read_text())
        step_cfg['hosts'] = dict(HOSTS, vision='decps@10.10.54.166')
        self.step_config.write_text(json.dumps(step_cfg))
        base_cfg = json.loads(self.config.read_text())
        base_cfg['hosts'] = dict(HOSTS, vision='decps@10.10.54.19')
        self.config.write_text(json.dumps(base_cfg))
        (self.baseline / 'freeze_check.json').write_text(json.dumps({'config': str(self.config),
                                                                     'config_sha256': sha(self.config)}))
        self.write_baseline_manifest()
        manifest = json.loads((self.root / 'input.json').read_text())
        manifest.update(campaign_id='neverreached-test', evidence_kind='hardware')
        (self.root / 'input_hw.json').write_text(json.dumps(manifest))
        self.campaign = Path(self.c.initialize(self.root / 'input_hw.json'))
        self.steps = self.campaign / 'steps' / 'block0'
        self.steps.mkdir(parents=True, exist_ok=True)
        self.run_root.mkdir()
        self.write_root(REAL_OUT, REAL_RUN)
        self.c.RUN_BLOCK_LOG.write_text(block_log('START candidate_campaign base',
                                                  'END base block_rc=1 restore_verify_rc=0',
                                                  'START candidate_relay_native block0',
                                                  'END block0 block_rc=2 restore_verify_rc=1'))

    def write_root(self, out, run):
        (self.run_root / 'run_block_run.out').write_text(out)
        (self.run_root / 'campaign_run.json').write_text(json.dumps(run))
        (self.run_root / 'block0_prerun.json').write_text('{}')
        (self.run_root / 'freeze_check.json').write_text('{}')
        (self.run_root / 'restore_verify.json').write_text(json.dumps({'ok': False, 'failures': ['x']}))
        files = {q.name: {'sha256': sha(q)} for q in self.run_root.iterdir() if q.name != 'artifact_manifest.json'}
        (self.run_root / 'artifact_manifest.json').write_text(json.dumps({'files': files}))
        self.terminal.update(rc=2, artifact_manifest={'path': str(self.run_root / 'artifact_manifest.json'),
                                                      'sha256': sha(self.run_root / 'artifact_manifest.json')},
                             restoration={'path': str(self.run_root / 'restore_verify.json'), 'ok': False,
                                          'sha256': sha(self.run_root / 'restore_verify.json')})
        self.write_terminal()

    def reconcile(self, host='decps@10.10.54.19', identity=lambda h: VISION_OK, verifier=None, now=1000):
        return self.c.reconcile(self.campaign, 'block0', root=self.testbed, units=lambda: [],
                                verifier=verifier or writer(True), now=now, baseline_run_root=self.baseline,
                                baseline_terminal=self.base_terminal, vision_host=host, identity=identity)

    def test_pass_clears_flag_against_the_baseline(self):
        record = Path(self.reconcile())
        data = json.loads(record.read_text())
        self.assertEqual(data['mode'], 'vision_never_reached')
        self.assertEqual(data['no_contact_evidence']['classification'], 'vision_never_reached')
        self.assertEqual(data['config'], str(self.config))              # the baseline that stands for the testbed
        remapped = json.loads(Path(data['check_config']).read_text())     # the fresh check: this block's config
        self.assertEqual(remapped['hosts']['vision'], 'decps@10.10.54.19')
        self.assertEqual(data['vision_remap']['vision_from'], 'decps@10.10.54.166')
        self.assertIs(json.loads(self.ownership.read_text())['unsafe_restoration'], False)
        self.assertEqual(sha(record.parent / 'campaign_run.json'), sha(self.baseline / 'campaign_run.json'))

    def test_failed_fresh_check_keeps_flag(self):
        with self.assertRaises(self.c.Refused):
            self.reconcile(verifier=writer(False, rc=1, failures=['Vision receive offloads differ']))
        self.assert_flag_set()

    def test_remap_must_be_vision_and_the_baseline_host(self):
        for i, kwargs in enumerate(({'identity': lambda h: dict(VISION_OK, hostname='hulk')},
                                    {'identity': lambda h: dict(VISION_OK, rc=255)},
                                    {'host': 'decps@10.10.54.77'})):
            with self.subTest(kwargs=list(kwargs)):
                with self.assertRaises(self.c.Refused):
                    self.reconcile(now=2000 + i, **kwargs)
                self.assert_flag_set()

    def test_any_other_host_difference_refused(self):
        step_cfg = json.loads(self.step_config.read_text())
        step_cfg['hosts']['switch'] = 'other'
        self.step_config.write_text(json.dumps(step_cfg))
        with self.assertRaises(self.c.Refused):
            self.reconcile()
        self.assert_flag_set()

    def test_production_identity_pins_allowed_other_keys_refused(self):
        step_cfg = json.loads(self.step_config.read_text())
        step_cfg['production'] = dict(step_cfg['production'], conf_sha256='a' * 64, _note='prose')
        self.step_config.write_text(json.dumps(step_cfg))
        self.assertTrue(Path(self.reconcile()).is_file())
        own = json.loads(self.ownership.read_text())
        own.update(unsafe_restoration=True, terminal_sha256=sha(self.steps / 'terminal.json'))
        self.ownership.write_text(json.dumps(own))
        step_cfg['production']['program'] = 'other'
        self.step_config.write_text(json.dumps(step_cfg))
        with self.assertRaises(self.c.Refused):
            self.reconcile(now=7000)
        step_cfg['production'] = dict(json.loads(self.config.read_text())['production'], extra=1)
        self.step_config.write_text(json.dumps(step_cfg))
        with self.assertRaises(self.c.Refused):
            self.reconcile(now=7001)
        self.assert_flag_set()

    def test_invalid_vision_host_never_reaches_ssh(self):
        called = []
        with self.assertRaises(self.c.Refused):
            self.reconcile(host='-oProxyCommand=x', identity=lambda h: called.append(h) or VISION_OK)
        self.assertEqual(called, [])
        self.assert_flag_set()

    def test_changed_run_output_refused(self):
        self.write_root(REAL_OUT, REAL_RUN)
        (self.run_root / 'run_block_run.out').write_text(REAL_OUT.replace('rc 0', 'rc 0 ', 1))
        with self.assertRaises(self.c.Refused):
            self.reconcile()
        self.assert_flag_set()

    def test_a_block_that_ran_further_is_not_routed_here(self):
        run = copy.deepcopy(REAL_RUN)
        run['restore'] = [{'step': 'cold-swap', 'ok': True, 'rc': 0}]
        self.write_root(REAL_OUT, run)
        with self.assertRaises(self.c.Refused):
            self.reconcile()
        self.assert_flag_set()


if __name__ == '__main__':
    unittest.main()

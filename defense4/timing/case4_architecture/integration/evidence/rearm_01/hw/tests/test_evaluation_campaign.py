"""Offline supervision tests; all commands are harmless local Python fixtures."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / 'evaluation_campaign.py'


def load_module():
    spec = importlib.util.spec_from_file_location('evaluation_campaign', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeSystemd:
    """Only the user-manager boundary is replaced; commands and persistence are real."""
    def __init__(self):
        self.units = {}
        self.launched = []

    def launch(self, unit, argv, cwd):
        if unit in self.units:
            raise RuntimeError('duplicate unit')
        self.units[unit] = 'active'
        self.launched.append((unit, argv, cwd))

    def state(self, unit):
        return self.units.get(unit, 'absent')


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.c = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manager = FakeSystemd()

    def tearDown(self):
        self.temp.cleanup()

    def manifest(self, blocks=2, hook=None, restore=True, rc=0, postcheck=None):
        steps = []
        if hook is not None:
            steps.append({'id': 'prepare', 'kind': 'hook', 'argv': hook})
        for index in range(blocks):
            run_root = self.root / ('run%d' % index)
            count = self.root / ('count%d' % index)
            code = ('from pathlib import Path; import json; '
                    'p=Path(%r); p.mkdir(); '
                    'Path(%r).write_text("executed"); ' % (str(run_root), str(count)))
            if restore is not None:
                code += '(p/"restore_verify.json").write_text(json.dumps({"ok":%r})); ' % restore
            code += 'raise SystemExit(%d)' % rc
            step = {'id': 'block%d' % index, 'kind': 'block',
                    'argv': [sys.executable, '-c', code], 'run_root': str(run_root)}
            if postcheck:
                step['postcheck_argv'] = postcheck
            steps.append(step)
        path = self.root / 'input.json'
        path.write_text(json.dumps({'campaign_id': 'fixture-test',
                                    'evidence_kind': 'supervision_fixture', 'steps': steps}))
        return self.c.initialize(path)

    def advance(self, campaign, now=100):
        return self.c.advance(campaign, self.manager, now=now)

    def run_active(self, campaign):
        state = self.c.read_state(campaign)
        step_id = state['active_step']
        with mock.patch.object(self.c.time, 'time', return_value=100):
            self.c.run_step(campaign, step_id)
        self.manager.units[state['active_unit']] = 'inactive'

    def test_manifest_is_immutable_and_campaign_never_overwritten(self):
        campaign = self.manifest()
        with self.assertRaises((FileExistsError, self.c.Refused)):
            self.c.initialize(self.root / 'input.json')
        (campaign / 'manifest.json').chmod(0o644)
        (campaign / 'manifest.json').write_text('{}')
        with self.assertRaises(self.c.Refused):
            self.c.status(campaign)

    def test_delayed_service_refuses_actual_entry_after_deadline(self):
        campaign = self.manifest()
        self.advance(campaign)
        with mock.patch.object(self.c.time, 'time', return_value=90000):
            self.c.run_step(campaign, 'block0')
        report = self.c.status(campaign)
        self.assertEqual(report['blocks'][0]['status'], 'unexecuted')
        self.assertEqual(report['blocks'][0]['reason'], 'deadline_expired')
        self.assertFalse((self.root / 'count0').exists())
        self.assertEqual(self.advance(campaign), 'stopped')

    def test_distinct_campaigns_share_active_testbed_guard(self):
        campaign = self.manifest()
        _, manifest, _ = self.c.load(campaign)
        with self.c.testbed_guard(campaign, manifest, manifest['steps'][0]):
            with self.assertRaises(self.c.Refused):
                with self.c.testbed_guard(campaign, dict(manifest, campaign_id='other'), manifest['steps'][1]):
                    self.fail('second owner entered')

    def test_duplicate_start_refused_after_launcher_disconnect(self):
        campaign = self.manifest()
        self.c.launch_controller(campaign, self.manager)
        with self.assertRaises(self.c.Refused):
            self.c.launch_controller(campaign, self.manager)
        self.assertEqual(len(self.manager.launched), 1)
        self.assertTrue(self.c.read_state(campaign)['started'])

    def test_controller_loss_does_not_relaunch_active_block(self):
        campaign = self.manifest()
        self.advance(campaign)
        self.assertEqual(self.advance(campaign), 'waiting')
        self.assertEqual(len(self.manager.launched), 1)
        self.run_active(campaign)
        self.advance(campaign, now=200)
        self.assertTrue((self.root / 'count0').exists())
        self.assertEqual(len(self.manager.launched), 2)
        self.assertEqual(self.c.read_state(campaign)['deadline'], 86500)

    def test_terminal_record_is_durable_without_controller(self):
        campaign = self.manifest()
        self.advance(campaign)
        self.run_active(campaign)
        record = json.loads((campaign / 'steps/block0/terminal.json').read_text())
        self.assertEqual(record['status'], 'completed')
        self.assertEqual(len(record['restoration']['sha256']), 64)
        self.assertEqual(self.c.read_state(campaign)['steps']['block0']['status'], 'running')
        self.advance(campaign)
        self.assertEqual(self.c.read_state(campaign)['steps']['block0']['status'], 'completed')

    def test_block_artifacts_and_partial_coverage_report_are_persisted(self):
        campaign = self.manifest(rc=7)
        self.advance(campaign)
        self.run_active(campaign)
        hashes = json.loads((self.root / 'run0/artifact_manifest.json').read_text())
        self.assertEqual(hashes['evidence_kind'], 'supervision_fixture')
        self.assertEqual(hashes['files']['restore_verify.json']['sha256'],
                         self.c.digest((self.root / 'run0/restore_verify.json').read_bytes()))
        self.assertEqual(self.advance(campaign), 'stopped')
        report = json.loads((campaign / 'campaign_report.json').read_text())
        self.assertEqual(report['result'], 'INCOMPLETE')
        self.assertEqual(report['failed'], ['block0'])
        self.assertEqual(report['unexecuted'], ['block1'])
        self.assertEqual(report['completed'], [])

    def test_expiry_does_not_kill_active_and_prevents_next_block(self):
        campaign = self.manifest()
        self.advance(campaign)
        self.assertEqual(self.advance(campaign, now=90000), 'waiting')
        self.run_active(campaign)
        self.assertEqual(self.advance(campaign, now=90000), 'stopped')
        report = self.c.status(campaign)
        self.assertEqual(report['result'], 'INCOMPLETE')
        self.assertEqual([b['status'] for b in report['blocks']], ['completed', 'unexecuted'])
        self.assertEqual(len(self.manager.launched), 1)

    def test_missing_or_false_restore_is_terminal_unsafe(self):
        for value in (False, None):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    old = self.root
                    self.root = Path(directory)
                    self.manager = FakeSystemd()
                    campaign = self.manifest(restore=value)
                    self.advance(campaign)
                    self.run_active(campaign)
                    self.assertEqual(self.advance(campaign), 'stopped')
                    self.assertEqual(self.c.status(campaign)['blocks'][0]['status'], 'failed')
                    self.assertEqual(self.c.read_state(campaign)['stop_reason'], 'unsafe_restoration')
                    self.assertFalse((self.root / 'count1').exists())
                    self.root = old

    def test_block_executes_only_once_even_if_internal_entrypoint_reinvoked(self):
        campaign = self.manifest()
        self.advance(campaign)
        self.run_active(campaign)
        with self.assertRaises(self.c.Refused):
            self.c.run_step(campaign, 'block0')
        self.assertEqual((self.root / 'count0').read_text(), 'executed')

    def test_missing_terminal_record_refuses_replay(self):
        campaign = self.manifest()
        self.advance(campaign)
        unit = self.c.read_state(campaign)['active_unit']
        self.manager.units[unit] = 'inactive'
        with self.assertRaises(self.c.Refused):
            self.advance(campaign)
        self.assertEqual(len(self.manager.launched), 1)

    def test_failed_block_stops_whole_sequence_after_restore(self):
        campaign = self.manifest(rc=7)
        self.advance(campaign)
        self.run_active(campaign)
        self.assertEqual(self.advance(campaign), 'stopped')
        self.assertEqual(self.c.read_state(campaign)['steps']['block0']['rc'], 7)
        self.assertFalse((self.root / 'count1').exists())

    def test_hook_failure_stops_before_hardware_deadline(self):
        campaign = self.manifest(hook=[sys.executable, '-c', 'raise SystemExit(9)'])
        self.advance(campaign)
        self.run_active(campaign)
        self.assertEqual(self.advance(campaign), 'stopped')
        self.assertIsNone(self.c.read_state(campaign)['deadline'])
        self.assertFalse((self.root / 'count0').exists())

    def test_postcheck_failure_follows_verified_restore_and_stops(self):
        campaign = self.manifest(postcheck=[sys.executable, '-c', 'raise SystemExit(6)'])
        self.advance(campaign)
        self.run_active(campaign)
        self.assertEqual(self.advance(campaign), 'stopped')
        state = self.c.read_state(campaign)
        self.assertEqual(state['steps']['block0']['postcheck_rc'], 6)
        self.assertTrue(state['steps']['block0']['restoration']['ok'])

    def test_stop_after_current_preserves_active_restore(self):
        campaign = self.manifest()
        self.advance(campaign)
        self.c.stop_after_current(campaign)
        self.assertEqual(self.advance(campaign), 'waiting')
        self.run_active(campaign)
        self.assertEqual(self.advance(campaign), 'stopped')
        self.assertEqual(len(self.manager.launched), 1)

    def test_completed_fixture_explicitly_excluded_from_hardware_evidence(self):
        campaign = self.manifest(blocks=1)
        self.advance(campaign)
        self.run_active(campaign)
        self.assertEqual(self.advance(campaign), 'complete')
        report = self.c.status(campaign)
        self.assertEqual(report['result'], 'COMPLETE')
        self.assertTrue(report['excluded_from_main_evidence'])

    def test_unsafe_ids_and_duplicate_argv_rejected(self):
        campaign = self.manifest()
        path = self.root / 'input.json'
        data = json.loads(path.read_text())
        for identifier in ('../bad', 'bad name', '-bad'):
            data['campaign_id'] = identifier
            path.write_text(json.dumps(data))
            with self.assertRaises(self.c.Refused):
                self.c.initialize(path)
        data['campaign_id'] = 'other'
        data['steps'][1]['argv'] = data['steps'][0]['argv']
        path.write_text(json.dumps(data))
        with self.assertRaises(self.c.Refused):
            self.c.initialize(path)

    def test_resume_preserves_deadline_and_refuses_live_controller(self):
        campaign = self.manifest()
        first = self.c.launch_controller(campaign, self.manager)
        self.advance(campaign, now=100)
        with self.assertRaises(self.c.Refused):
            self.c.launch_controller(campaign, self.manager, resume=True)
        self.manager.units[first] = 'failed'
        second = self.c.launch_controller(campaign, self.manager, resume=True)
        self.assertNotEqual(first, second)
        self.assertEqual(self.c.read_state(campaign)['deadline'], 86500)
        self.assertEqual(self.advance(campaign, now=300), 'waiting')
        self.assertEqual(len([unit for unit, _, _ in self.manager.launched if '-step-' in unit]), 1)

    def test_resume_refuses_missing_terminal_before_launching_controller(self):
        campaign = self.manifest()
        controller = self.c.launch_controller(campaign, self.manager)
        self.advance(campaign)
        active_unit = self.c.read_state(campaign)['active_unit']
        self.manager.units[controller] = 'failed'
        self.manager.units[active_unit] = 'inactive'
        with self.assertRaises(self.c.Refused):
            self.c.launch_controller(campaign, self.manager, resume=True)
        self.assertEqual(len(self.manager.launched), 2)

    def test_uncertain_dispatch_is_never_replayed(self):
        campaign = self.manifest()
        original = self.manager.launch
        def uncertain(unit, argv, cwd):
            original(unit, argv, cwd)
            raise self.c.Refused('connection lost after dispatch')
        self.manager.launch = uncertain
        with self.assertRaises(self.c.Refused):
            self.advance(campaign, now=100)
        self.manager.launch = original
        self.assertEqual(self.advance(campaign, now=500), 'waiting')
        self.assertEqual(self.c.read_state(campaign)['deadline'], 86500)
        self.assertEqual(len(self.manager.launched), 1)

    def test_restore_evidence_mutation_refuses_next_block(self):
        campaign = self.manifest()
        self.advance(campaign)
        self.run_active(campaign)
        (self.root / 'run0/restore_verify.json').write_text('{"ok": true, "changed": true}')
        with self.assertRaises(self.c.Refused):
            self.advance(campaign)
        self.assertFalse((self.root / 'count1').exists())

    def test_offline_hook_after_final_restored_block_may_finish_after_deadline(self):
        campaign = self.manifest(blocks=1)
        # Reinitialize a distinct identity with a final harmless export hook.
        source = self.root / 'input.json'
        data = json.loads(source.read_text())
        data['campaign_id'] = 'fixture-export'
        exported = self.root / 'exported'
        data['steps'].append({'id': 'export', 'kind': 'hook', 'argv':
                             [sys.executable, '-c', 'from pathlib import Path; Path(%r).touch()' % str(exported)]})
        source.write_text(json.dumps(data))
        campaign = self.c.initialize(source)
        self.advance(campaign, now=100)
        self.run_active(campaign)
        self.assertEqual(self.advance(campaign, now=90000), 'launched')
        self.run_active(campaign)
        self.assertEqual(self.advance(campaign, now=90001), 'complete')
        self.assertTrue(exported.exists())

    def test_hardware_manifest_refuses_bypass_of_frozen_wrapper(self):
        self.manifest()
        source = self.root / 'input.json'
        data = json.loads(source.read_text())
        data.update(campaign_id='unsafe-hardware', evidence_kind='hardware')
        source.write_text(json.dumps(data))
        with self.assertRaises(self.c.Refused):
            self.c.initialize(source)

    def test_systemd_launcher_is_detached_and_no_deadline_kill(self):
        manager = self.c.Systemd()
        command = manager.launch_command('dnp3-fixture-abc.service', ['/bin/true'], self.root)
        self.assertIn('--no-block', command)
        self.assertIn('--user', command)
        self.assertIn('--property=Restart=no', command)
        self.assertFalse(any('RuntimeMaxSec' in part or 'BindsTo' in part for part in command))


if __name__ == '__main__':
    unittest.main()

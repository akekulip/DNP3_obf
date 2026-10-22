"""nic_repair.py's bound-failure parsing and evaluation_campaign.nic_repair_acceptance (offline; no hosts).

The repair path (Philip, 2026-10-22): a block whose ONLY failed runner restore step is the Vision restore, failed as
an RX-coalescing restore, repaired by the exact restore function with the ACTUAL NIC settings verified; reconcile
then accepts a fresh check whose only failure is that historical runner step, with the NIC itself verified."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW))
import nic_repair as nr  # noqa: E402

spec = importlib.util.spec_from_file_location('evaluation_campaign_repair', HW / 'evaluation_campaign.py')
ec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ec)

STEP = nr.VISION_STEP
LINE = ('RESTORE STEP FAILED: %s (rc 1) rx coalescing restore failed: ethtool -C restore rc 1: netlink error: Invalid '
        'argument; RX coalescing is adaptive off rx-usecs 0, baseline adaptive on rx-usecs 50' % STEP)
BASE = {'interface': 'enp59s0f0np0', 'adaptive_rx': 'on', 'rx_usecs': 50}
RUNNER = {'restore': [{'step': 'cold-swap', 'ok': True}, {'step': STEP, 'rc': 1, 'ok': False},
                      {'step': 'ping through the restored switch path', 'ok': True}]}


class BoundFailure(unittest.TestCase):
    def test_the_real_failure_binds_the_saved_settings(self):
        settings, failure, problems = nr.bound_failure(RUNNER, 'x\n' + LINE + '\ny\n', BASE)
        self.assertEqual(problems, [])
        self.assertEqual(settings, {'adaptive_rx': 'on', 'rx_usecs': 50})
        self.assertEqual(failure['line'], LINE)

    def test_an_additional_failed_step_is_refused(self):
        runner = {'restore': RUNNER['restore'] + [{'step': 'replay the pre-run $PORT snapshot', 'ok': False}]}
        self.assertTrue(nr.bound_failure(runner, LINE, BASE)[2])

    def test_a_non_rx_or_mixed_failure_is_refused(self):
        for line in (LINE.replace('rx coalescing restore failed', 'receive offload restore failed'),
                     LINE + '; receive offload restore failed: x',
                     LINE.replace(STEP, 'replay the pre-run $PORT snapshot')):
            self.assertTrue(nr.bound_failure(RUNNER, line, BASE)[2], line)

    def test_two_failure_lines_or_none_are_refused(self):
        self.assertTrue(nr.bound_failure(RUNNER, LINE + '\n' + LINE, BASE)[2])
        self.assertTrue(nr.bound_failure(RUNNER, 'nothing failed', BASE)[2])

    def test_saved_settings_must_equal_the_independent_baseline(self):
        self.assertTrue(nr.bound_failure(RUNNER, LINE.replace('rx-usecs 50', 'rx-usecs 0'), BASE)[2])
        self.assertTrue(nr.bound_failure(RUNNER, LINE.replace('baseline adaptive on', 'baseline adaptive off'), BASE)[2])

    def test_missing_saved_settings_is_refused(self):
        self.assertTrue(nr.bound_failure(RUNNER, LINE.split('; RX')[0], BASE)[2])


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.records = Path(self.temp.name)
        self.fresh = {'ok': False, 'failures': [ec.REPAIRED_ONLY_FAILURE],
                      'checks': {'vision_rx_coalescing': {'rc': 0, 'failures': []}}}
        self.repair = {'ok': True, 'bound_sha256': {'terminal': 'T', 'campaign_run.json': 'C'},
                       'saved_settings': {'adaptive_rx': 'on', 'rx_usecs': 50},
                       'actual_settings': {'adaptive_rx': 'on', 'rx_usecs': 50},
                       'restore_function': {'source_sha256': ec.REVIEWED_RESTORE_RX_COALESCE_SHA256,
                                            'deployed': {'commit': 'abc', 'sha256': dict(ec.REVIEWED_DEPLOYED_SHA256)}},
                       'staged_sha256': dict(ec.REVIEWED_DEPLOYED_SHA256),
                       'failed_restoration': {'steps': [{'step': STEP, 'ok': False}], 'line': LINE}}

    def tearDown(self):
        self.temp.cleanup()

    def accept(self):
        d = self.records / 'nic_repair_20261022T220000Z'
        d.mkdir(exist_ok=True)
        (d / 'repair.json').write_text(json.dumps(self.repair))
        return ec.nic_repair_acceptance(self.records, 'T', 'C', self.fresh, BASE)

    def test_bound_repair_is_accepted(self):
        binding, problems = self.accept()
        self.assertEqual(problems, [])
        self.assertEqual(binding['restore_function_sha256'], ec.REVIEWED_RESTORE_RX_COALESCE_SHA256)

    def test_any_other_fresh_failure_is_refused(self):
        self.fresh['failures'] = [ec.REPAIRED_ONLY_FAILURE, 'switch runs other']
        self.assertTrue(self.accept()[1])
        self.fresh['failures'] = ['switch runs other']
        self.assertTrue(self.accept()[1])

    def test_nic_not_verified_afresh_is_refused(self):
        self.fresh['checks']['vision_rx_coalescing'] = {'rc': 0, 'failures': ['adaptive off']}
        self.assertTrue(self.accept()[1])
        del self.fresh['checks']['vision_rx_coalescing']
        self.assertTrue(self.accept()[1])

    def test_no_repair_record_is_refused(self):
        self.assertTrue(ec.nic_repair_acceptance(self.records, 'T', 'C', self.fresh, BASE)[1])

    def test_unbound_or_failed_or_mismatched_repair_is_refused(self):
        for key, value in (('ok', False), ('bound_sha256', {'terminal': 'X', 'campaign_run.json': 'C'}),
                           ('bound_sha256', {'terminal': 'T', 'campaign_run.json': 'X'}),
                           ('actual_settings', {'adaptive_rx': 'off', 'rx_usecs': 0}),
                           ('saved_settings', {'adaptive_rx': 'on', 'rx_usecs': 0}),
                           ('restore_function', {'source_sha256': 'other', 'deployed': {'commit': 'abc', 'sha256': dict(ec.REVIEWED_DEPLOYED_SHA256)}}),
                           ('restore_function', {}),
                           ('staged_sha256', {'capture_observation.py': 'Y'}),
                           ('failed_restoration', {'steps': [{'step': 'other'}]})):
            saved = self.repair[key]
            self.repair[key] = value
            self.assertTrue(self.accept()[1], key)
            self.repair[key] = saved


class AcceptanceLatestAndMalformed(Acceptance):
    def test_later_failed_record_wins_over_earlier_ok(self):
        self.accept()                                    # nic_repair_20261022T220000Z ok
        d = self.records / 'nic_repair_20261022T230000Z'
        d.mkdir()
        (d / 'repair.json').write_text(json.dumps(dict(self.repair, ok=False)))
        self.assertTrue(ec.nic_repair_acceptance(self.records, 'T', 'C', self.fresh, BASE)[1])

    def test_malformed_record_is_a_problem_not_a_crash(self):
        d = self.records / 'nic_repair_20261022T230000Z'
        d.mkdir()
        (d / 'repair.json').write_text('[1, 2')
        self.assertTrue(ec.nic_repair_acceptance(self.records, 'T', 'C', self.fresh, BASE)[1])

    def test_cpu_latency_failure_in_the_line_is_refused(self):
        self.assertTrue(nr.bound_failure(RUNNER, LINE + '; cpu latency restore failed: helper running', BASE)[2])


class FunctionPin(unittest.TestCase):
    def test_committed_restore_function_is_the_reviewed_one(self):
        files, provenance = nr.committed_files()
        self.assertEqual(nr.function_source_sha(files), ec.REVIEWED_RESTORE_RX_COALESCE_SHA256)
        self.assertEqual(set(provenance['blobs']), {'capture_observation.py', 'wire_check.py'})
        self.assertEqual(provenance['sha256'], ec.REVIEWED_DEPLOYED_SHA256)      # HEAD still deploys the reviewed blobs


class Result:
    def __init__(self, stdout='', rc=0):
        self.stdout, self.stderr, self.returncode = stdout, '', rc


class ApplyRepair(unittest.TestCase):
    """apply_repair with a scripted remote host."""
    SETTINGS = {'adaptive_rx': 'on', 'rx_usecs': 50}
    ETH = 'Coalesce parameters for x:\nAdaptive RX: %s  TX: on\nrx-usecs:\t%d\n'

    def host(self, before=('on', 50), after=('on', 50), staged=None, mk='decps 700 /tmp/nic_repair.abc',
             apply_out=None):
        provenance = {'sha256': {'capture_observation.py': 'X', 'wire_check.py': 'W'}}
        reads = iter([self.ETH % before, self.ETH % after])

        def run(host, cmd):
            if cmd.startswith('ethtool -c'):
                return Result(next(reads))
            if 'mktemp' in cmd:
                return Result(mk.replace(' ', '\n'))
            if cmd == 'id -un':
                return Result('decps\n')
            if cmd.startswith('sudo -n python3 -I -c'):
                return Result(apply_out if apply_out is not None else
                              json.dumps({'errors': [], 'staged_sha256': staged or provenance['sha256']}) + '\n')
            raise AssertionError(cmd)
        return nr.apply_repair('vision', 'enp59s0f0np0', self.SETTINGS, {}, provenance, run=run,
                               upload=lambda h, d, f: {})

    def test_reapply_verified_by_readback(self):
        out = self.host()
        self.assertTrue(out['ok'])
        self.assertTrue(out['already_at_baseline_before'])

    def test_snippet_skips_writes_when_already_at_the_bound_settings(self):
        seen = []

        def run(host, cmd):
            seen.append(cmd)
            if cmd.startswith('ethtool -c'):
                return Result(self.ETH % ('on', 50))
            if 'mktemp' in cmd:
                return Result('decps\n700\n/tmp/nic_repair.abc')
            if cmd == 'id -un':
                return Result('decps\n')
            return Result(json.dumps({'errors': [], 'staged_sha256': {'capture_observation.py': 'X', 'wire_check.py': 'W'},
                                      'action': 'none: already at the bound settings (no ethtool -C written)'}))
        out = nr.apply_repair('vision', 'enp59s0f0np0', self.SETTINGS, {},
                              {'sha256': {'capture_observation.py': 'X', 'wire_check.py': 'W'}}, run=run,
                              upload=lambda h, d, f: {})
        self.assertTrue(out['ok'])
        self.assertTrue(out['action'].startswith('none'))
        snippet = next(c for c in seen if c.startswith('sudo -n python3 -I -c'))
        self.assertIn('snapshot_rx_coalesce', snippet)
        self.assertIn('restore_rx_coalesce', snippet)

    def test_repair_from_a_modified_nic(self):
        out = self.host(before=('off', 0))
        self.assertTrue(out['ok'])
        self.assertFalse(out['already_at_baseline_before'])

    def test_readback_mismatch_is_not_ok(self):
        self.assertFalse(self.host(after=('off', 0))['ok'])

    def test_staged_hash_mismatch_is_not_ok(self):
        self.assertFalse(self.host(staged={'capture_observation.py': 'Z', 'wire_check.py': 'W'})['ok'])

    def test_unreadable_or_non_dict_output_is_not_ok(self):
        for out in ('garbage', '[1, 2]', '{"errors": "x"}', ''):
            self.assertFalse(self.host(apply_out=out)['ok'], out)

    def test_staging_dir_not_private_refuses(self):
        for mk in ('root 700 /tmp/nic_repair.abc', 'decps 755 /tmp/nic_repair.abc', ''):
            out = self.host(mk=mk)
            self.assertFalse(out['ok'])
            self.assertIsNone(out['remote_dir'])

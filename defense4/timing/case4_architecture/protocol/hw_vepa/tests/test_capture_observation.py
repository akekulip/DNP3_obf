import json
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import capture_observation as co  # noqa: E402
import pcaptk as tk  # noqa: E402


class FakeProcess:
    def __init__(self, argv, stderr_text='2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n'):
        self.argv = list(argv)
        self.returncode = None
        self.stderr_text = stderr_text

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9

    def communicate(self, timeout=None):
        return '', self.stderr_text


class CaptureObservation(unittest.TestCase):
    def test_default_calibration_sender_runs_in_outstation_namespace(self):
        from unittest.mock import patch
        root = Path(self.tmpdir())
        expected = {'payloads': ['41', '42'], 'frames': ['aa', 'bb'],
                    'send_command': ['ip', 'netns', 'exec', 'ns_vepa_b', 'python3',
                                     'capture_observation.py', 'send-calibration']}
        calls = []
        def run(argv):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(co, 'calibration_expected', return_value=expected), \
                patch.object(co, 'send_calibration_frames', side_effect=AssertionError('wrong namespace')):
            co.run_calibration(root, run=run, popen=lambda argv, **kw: FakeProcess(argv), sleep=lambda _: None)
        self.assertIn(expected['send_command'], calls)

    def test_restore_mismatch_fails_even_when_main_succeeds(self):
        snapshots = iter(['generic-receive-offload: on\nlarge-receive-offload: off [fixed]\n',
                          'generic-receive-offload: off\nlarge-receive-offload: off [fixed]\n',
                          'generic-receive-offload: off\nlarge-receive-offload: off [fixed]\n'])
        def run(argv):
            if argv[:2] == ['ethtool', '-k']:
                return SimpleNamespace(returncode=0, stdout=next(snapshots), stderr='')
            self.assertNotIn('lro', argv)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        root = Path(self.tmpdir())
        with self.assertRaisesRegex(RuntimeError, 'restore'):
            with co.offload_capture_context(root, run=run):
                pass
        self.assertFalse(json.loads((root/'capture_offloads.json').read_text())['restore_ok'])

    def test_parse_ethtool_features_normalizes_receive_aggregation_names(self):
        raw = '\n'.join([
            'Features for enp59s0f0np0:',
            'generic-receive-offload: on',
            'large-receive-offload: off [fixed]',
            'rx-gro-hw: off',
            'rx-gro-list: on',
            'tx-checksumming: on',
        ])
        features = co.parse_ethtool_features(raw)
        self.assertTrue(features['gro'])
        self.assertFalse(features['lro'])
        self.assertFalse(features['rx-gro-hw'])
        self.assertTrue(features['rx-gro-list'])
        self.assertTrue(features['tx-checksumming'])

    def test_offload_context_disables_receive_aggregation_and_restores_original_values_after_failure(self):
        states = [
            'generic-receive-offload: on\nlarge-receive-offload: off\nrx-gro-hw: off\nrx-gro-list: on\n',
            'generic-receive-offload: off\nlarge-receive-offload: off\nrx-gro-hw: off\nrx-gro-list: off\n',
            'generic-receive-offload: on\nlarge-receive-offload: off\nrx-gro-hw: off\nrx-gro-list: on\n',
        ]
        commands = []

        def run(argv, **kw):
            commands.append(list(argv))
            if argv[:2] == ['ethtool', '-k']:
                return SimpleNamespace(returncode=0, stdout=states.pop(0), stderr='')
            if argv[:2] == ['ethtool', '-K']:
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            raise AssertionError(argv)

        with self.assertRaisesRegex(RuntimeError, 'inside block'):
            with co.offload_capture_context(Path(self.tmpdir()) / 'evidence', 'enp59s0f0np0', run=run):
                raise RuntimeError('inside block')
        evidence = json.loads((Path(self.tmpdir_path) / 'evidence' / 'capture_offloads.json').read_text())
        self.assertTrue(evidence['restore_ok'])
        self.assertTrue(evidence['before']['features']['gro'])
        self.assertFalse(evidence['during']['features']['gro'])
        self.assertTrue(evidence['after']['features']['gro'])
        self.assertIn(['ethtool', '-K', 'enp59s0f0np0', 'gro', 'off'], commands)
        self.assertIn(['ethtool', '-K', 'enp59s0f0np0', 'rx-gro-list', 'off'], commands)
        self.assertIn(['ethtool', '-K', 'enp59s0f0np0', 'gro', 'on'], commands)
        self.assertIn(['ethtool', '-K', 'enp59s0f0np0', 'rx-gro-list', 'on'], commands)

    def _ethtool(self, states, commands, fail_set=False):
        def run(argv, **kw):
            commands.append(list(argv))
            if argv[:2] == ['ethtool', '-k']:
                return SimpleNamespace(returncode=0, stdout=states.pop(0), stderr='')
            if argv[:2] == ['ethtool', '-K']:
                return SimpleNamespace(returncode=1 if fail_set else 0, stdout='', stderr='set failed' if fail_set else '')
            raise AssertionError(argv)
        return run

    def test_campaign_baseline_is_recorded_once_and_restore_reapplies_and_verifies_it(self):
        on = 'generic-receive-offload: on\nlarge-receive-offload: off\nrx-gro-hw: off\nrx-gro-list: off\n'
        off = 'generic-receive-offload: off\nlarge-receive-offload: off\nrx-gro-hw: off\nrx-gro-list: off\n'
        path = Path(self.tmpdir()) / 'offload_baseline.json'
        commands = []
        co.record_offload_baseline(path, 'enp59s0f0np0', run=self._ethtool([on], commands))
        # a later setup (e.g. after an interrupted campaign left GRO off) must not overwrite the baseline
        co.record_offload_baseline(path, 'enp59s0f0np0', run=self._ethtool([off], commands))
        self.assertTrue(json.loads(path.read_text())['features']['gro'])
        commands.clear()
        errors = co.restore_offload_baseline(path, 'enp59s0f0np0', run=self._ethtool([off, on], commands))
        self.assertEqual(errors, [])
        self.assertIn(['ethtool', '-K', 'enp59s0f0np0', 'gro', 'on'], commands)
        self.assertFalse(path.exists())

    def test_restore_sets_only_keys_that_differ_so_fixed_features_are_never_written(self):
        base = 'generic-receive-offload: on\nlarge-receive-offload: off [fixed]\nrx-gro-hw: off [fixed]\n'
        now = 'generic-receive-offload: off\nlarge-receive-offload: off [fixed]\nrx-gro-hw: off [fixed]\n'
        path = Path(self.tmpdir()) / 'offload_baseline.json'
        co.record_offload_baseline(path, 'enp59s0f0np0', run=self._ethtool([base], []))
        commands = []
        self.assertEqual(co.restore_offload_baseline(path, 'enp59s0f0np0',
                                                     run=self._ethtool([now, base], commands)), [])
        self.assertEqual([c for c in commands if c[:2] == ['ethtool', '-K']],
                         [['ethtool', '-K', 'enp59s0f0np0', 'gro', 'on']])

    def test_restore_reports_mismatch_and_keeps_the_baseline(self):
        on = 'generic-receive-offload: on\nlarge-receive-offload: off\n'
        off = 'generic-receive-offload: off\nlarge-receive-offload: off\n'
        path = Path(self.tmpdir()) / 'offload_baseline.json'
        co.record_offload_baseline(path, 'enp59s0f0np0', run=self._ethtool([on], []))
        errors = co.restore_offload_baseline(path, 'enp59s0f0np0', run=self._ethtool([off, off], [], fail_set=True))
        self.assertTrue(any('gro' in e for e in errors), errors)
        self.assertTrue(path.exists())

    def test_restore_without_a_recorded_baseline_is_an_error(self):
        errors = co.restore_offload_baseline(Path(self.tmpdir()) / 'none.json', 'enp59s0f0np0',
                                             run=self._ethtool([], []))
        self.assertTrue(errors)

    def tmpdir(self):
        import tempfile
        if not hasattr(self, '_tmp'):
            self._tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self._tmp.cleanup)
            self.tmpdir_path = self._tmp.name
        return self.tmpdir_path

    def _write_calibration(self, root, *, merged=False):
        payload_a = bytes([0x11]) * 256
        payload_b = bytes([0x22]) * 256
        frame_a = tk.frame('192.168.10.62', '192.168.10.61', 20001, 61998, 100, 200, tk.ACK, payload_a)
        frame_b = tk.frame('192.168.10.62', '192.168.10.61', 20001, 61998, 356, 200, tk.ACK, payload_b)
        tk.write_pcap(str(root / 'calibration_out.pcap'), [(100, frame_a), (101, frame_b)])
        if merged:
            merged_payload = payload_a + payload_b
            merged_frame = tk.frame('192.168.10.62', '192.168.10.61', 20001, 61998, 100, 200, tk.ACK, merged_payload)
            tk.write_pcap(str(root / 'calibration_in.pcap'), [(100, merged_frame)])
        else:
            tk.write_pcap(str(root / 'calibration_in.pcap'), [(100, frame_a), (101, frame_b)])
        expected = {
            'interface': 'enp59s0f0np0',
            'source_namespace': 'ns_vepa_b',
            'send_command': ['ip', 'netns', 'exec', 'ns_vepa_b', 'python3', 'capture_observation.py', 'send-calibration'],
            'tuple': {'src': '192.168.10.62', 'dst': '192.168.10.61', 'sport': 20001, 'dport': 61998},
            'direction': 'in',
            'payloads': [payload_a.hex(), payload_b.hex()],
            'frames': [frame_a.hex(), frame_b.hex()],
        }
        (root / 'calibration_expected.json').write_text(json.dumps(expected))
        (root / 'calibration_result.json').write_text(json.dumps({
            'capture_commands': {
                'in': ['tcpdump', '-i', 'enp59s0f0np0', '-Q', 'in', '-w', str(root / 'calibration_in.pcap')],
                'out': ['tcpdump', '-i', 'enp59s0f0np0', '-Q', 'out', '-w', str(root / 'calibration_out.pcap')],
            },
            'tcpdump': {
                'in': {'captured': 2, 'received': 2, 'dropped_kernel': 0, 'dropped_interface': 0},
                'out': {'captured': 2, 'received': 2, 'dropped_kernel': 0, 'dropped_interface': 0},
            },
        }))

    def test_calibration_validation_rejects_merged_or_missing_boundary_proof(self):
        root = Path(self.tmpdir()) / 'calibration'
        root.mkdir()
        self._write_calibration(root, merged=False)
        self.assertEqual(co.validate_calibration_files(root), [])
        self._write_calibration(root, merged=True)
        failures = co.validate_calibration_files(root)
        self.assertTrue(any('payload count' in failure or 'does not match' in failure for failure in failures))
        (root / 'calibration_expected.json').unlink()
        self.assertTrue(any('missing' in failure for failure in co.validate_calibration_files(root)))

    def test_qualified_capture_runs_calibration_before_main_and_restores_after(self):
        root = Path(self.tmpdir()) / 'qualified'
        snapshots = iter([
            'generic-receive-offload: on\nlarge-receive-offload: off\nrx-gro-hw: off\n',
            'generic-receive-offload: off\nlarge-receive-offload: off\nrx-gro-hw: off\n',
            'generic-receive-offload: on\nlarge-receive-offload: off\nrx-gro-hw: off\n',
        ])
        events = []

        def run(argv, **kw):
            events.append(('run', list(argv)))
            if argv[:2] == ['ethtool', '-k']:
                return SimpleNamespace(returncode=0, stdout=next(snapshots), stderr='')
            if argv[:4] == ['ip', 'netns', 'exec', 'ns_vepa_b']:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'address': '02:00:00:00:00:02'}]), stderr='')
            if argv[:4] == ['ip', 'netns', 'exec', 'ns_vepa_a']:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'address': '02:00:00:00:00:01'}]), stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        def popen(argv, **kw):
            events.append(('popen', list(argv)))
            Path(argv[argv.index('-w') + 1]).write_bytes(b'\xd4\xc3\xb2\xa1' + b'\0' * 20)
            return FakeProcess(argv)

        def send(expected):
            events.append(('send', expected['tuple']['sport']))

        def main():
            events.append(('main', None))
            return {'ok': True}

        result = co.run_with_qualified_capture(root, main, interface='enp59s0f0np0',
                                               run=run, popen=popen, send_calibration=send, sleep=lambda _: None)
        self.assertTrue(result['ok'])
        self.assertEqual([kind for kind, _ in events].count('main'), 1)
        self.assertLess(events.index(('send', 20001)), events.index(('main', None)))
        self.assertTrue((root / 'capture_offloads.json').is_file())
        self.assertTrue((root / 'calibration_expected.json').is_file())
        self.assertTrue((root / 'calibration_result.json').is_file())


    def test_calibration_capture_is_immediate_and_bounded_captures_exit_on_their_own(self):
        """smoke_02 combined: tcpdump reported received 4 / captured 0 after a fixed 1 s then terminate.
        Calibration captures must use --immediate-mode and be allowed to finish their -c count."""
        root = Path(self.tmpdir()) / 'cal'
        root.mkdir()
        procs = []

        class SelfExiting(FakeProcess):
            def __init__(self, argv):
                super().__init__(argv)
                self.polls = 0
                self.terminated = False

            def poll(self):
                self.polls += 1
                if self.polls >= 3 and self.returncode is None:
                    self.returncode = 0
                return self.returncode

            def terminate(self):
                self.terminated = True
                super().terminate()

        def run(argv, **kw):
            if argv[:4] == ['ip', 'netns', 'exec', 'ns_vepa_b']:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'address': '02:00:00:00:00:02'}]), stderr='')
            if argv[:4] == ['ip', 'netns', 'exec', 'ns_vepa_a']:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'address': '02:00:00:00:00:01'}]), stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        def popen(argv, **kw):
            proc = SelfExiting(argv)
            procs.append(proc)
            return proc

        co.run_calibration(root, 'enp59s0f0np0', run=run, popen=popen,
                           send_calibration=lambda expected: None, sleep=lambda _: None)
        self.assertEqual(len(procs), 2)
        for proc in procs:
            self.assertIn('--immediate-mode', proc.argv)
            self.assertFalse(proc.terminated, proc.argv)


    def test_calibration_sends_once_both_captures_are_active_without_fixed_one_second_sleeps(self):
        """candidate61_stale_tokens_950_01: two fixed 1 s sleeps delayed the next connection past the old tokens.
        Readiness is the pcap header tcpdump writes once the capture is active; exit is the -c count."""
        root = Path(self.tmpdir()) / 'cal_ready'
        root.mkdir()
        events, procs = [], []

        class Proc(FakeProcess):
            def __init__(self, argv):
                super().__init__(argv)
                self.path = Path(argv[argv.index('-w') + 1])
                self.sent = False

            def poll(self):
                if self.sent and self.returncode is None:
                    self.returncode = 0
                return self.returncode

        def run(argv, **kw):
            if argv[:4] == ['ip', 'netns', 'exec', 'ns_vepa_b']:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'address': '02:00:00:00:00:02'}]), stderr='')
            if argv[:4] == ['ip', 'netns', 'exec', 'ns_vepa_a']:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{'address': '02:00:00:00:00:01'}]), stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        def popen(argv, **kw):
            proc = Proc(argv)
            procs.append(proc)
            return proc

        def sleep(seconds):
            events.append(('sleep', seconds))
            if len([e for e in events if e[0] == 'sleep']) == 3:     # captures become active after a few polls
                for proc in procs:
                    proc.path.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\0' * 20)

        def send(expected):
            events.append(('send', all(p.path.is_file() and p.path.stat().st_size >= 24 for p in procs)))
            for proc in procs:
                proc.sent = True

        co.run_calibration(root, 'enp59s0f0np0', run=run, popen=popen, send_calibration=send, sleep=sleep)
        sends = [e for e in events if e[0] == 'send']
        self.assertEqual(sends, [('send', True)])
        self.assertFalse([e for e in events if e == ('sleep', 1.0)], events)


if __name__ == '__main__':
    unittest.main()

"""vision_run's pure helpers: tcpdump drop-statistics parsing and the checked sysctl readback. The
subprocess/root orchestration itself needs the Vision host and is not exercised here."""
import sys
import types
import unittest
import tempfile
import subprocess
import threading
from unittest.mock import patch
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import vision_run as vr  # noqa: E402


class TcpdumpStats(unittest.TestCase):
    def test_full_summary(self):
        s = vr.parse_tcpdump_stats('10 packets captured\n12 packets received by filter\n'
                                   '2 packets dropped by kernel\n1 packet dropped by interface\n')
        self.assertEqual(s, {'captured': 10, 'received': 12, 'dropped_kernel': 2, 'dropped_interface': 1})

    def test_partial_summary_keeps_what_is_present(self):
        s = vr.parse_tcpdump_stats('0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n')
        self.assertEqual(s, {'captured': 0, 'received': 0, 'dropped_kernel': 0})

    def test_no_summary_is_empty(self):
        self.assertEqual(vr.parse_tcpdump_stats('tcpdump: listening on enp59s0f0np0\n'), {})


class SysctlReadback(unittest.TestCase):
    def _patch(self, written, readback):
        calls = {}

        def fake_nsx(ns, *cmd, **kw):
            if cmd[:2] == ('sysctl', '-w'):
                calls['written'] = cmd[2]
                return types.SimpleNamespace(stdout='', returncode=0)
            if cmd[:2] == ('sysctl', '-n'):
                return types.SimpleNamespace(stdout=readback + '\n', returncode=0)
            raise AssertionError(cmd)

        self._orig = vr.nsx
        vr.nsx = fake_nsx
        self.addCleanup(lambda: setattr(vr, 'nsx', self._orig))
        return calls

    def test_match_returns_the_value(self):
        self._patch('1', '1')
        self.assertEqual(vr.set_sysctl_checked('ns_vepa_a', 'net.ipv4.tcp_sack', '1'), '1')

    def test_port_range_tab_rendering_still_matches(self):
        # the kernel renders a port range tab-separated; a whitespace-token compare must accept it
        self._patch('40000 40000', '40000\t40000')
        self.assertEqual(vr.set_sysctl_checked('ns_vepa_a', 'net.ipv4.ip_local_port_range', '40000 40000'),
                         '40000\t40000')

    def test_mismatch_raises(self):
        self._patch('1', '0')
        with self.assertRaises(RuntimeError):
            vr.set_sysctl_checked('ns_vepa_a', 'net.ipv4.tcp_sack', '1')


class EndpointEvidence(unittest.TestCase):
    def test_timeout_keeps_partial_bytes_stdout_stderr_and_status(self):
        error = subprocess.TimeoutExpired(['master'], 1, output=b'{"partial":', stderr=b'timed out detail\n')
        with tempfile.TemporaryDirectory() as directory, patch.object(vr, 'nsx', side_effect=error):
            result = vr._run_master_evidence(directory, 40000, ['master'], 1)
            self.assertTrue(result['master_timeout'])
            self.assertIsNone(result['master_rc'])
            self.assertEqual(Path(directory, 'master.json').read_text(), '{"partial":')
            self.assertEqual(Path(directory, 'master.stderr').read_text(), 'timed out detail\n')
            self.assertEqual(result['endpoint_collection']['status'], 'timeout')
            self.assertEqual(result['tcp_rto']['status'], 'unavailable')

    def test_rto_readback_keeps_clock_source_units_and_unavailable_errors(self):
        with patch.object(vr, 'nsx', return_value=types.SimpleNamespace(
                returncode=0, stdout=' cubic rto:204 rtt:1.3/0.6\n', stderr='')) as invoke:
            record = vr.tcp_rto_readback(40000)
        self.assertEqual(record['rto_ms'], [204.0])
        self.assertEqual(record['units'], 'ms')
        self.assertEqual(record['status'], 'ok')
        self.assertIsInstance(record['observed_at_epoch_ns'], int)
        self.assertIn('ss', invoke.call_args.args)
        with patch.object(vr, 'nsx', side_effect=FileNotFoundError('ss absent')):
            self.assertEqual(vr.tcp_rto_readback(40000)['status'], 'error')

    def test_rto_sample_is_taken_during_active_master(self):
        sampled = threading.Event()
        endpoints = set()

        def invoke(namespace, *command, **kwargs):
            if command[0] == 'ss':
                endpoints.add(namespace)
                if endpoints == {vr.NS_M, vr.NS_O}:
                    sampled.set()
                return types.SimpleNamespace(returncode=0, stdout=' cubic rto:208\n', stderr='')
            self.assertTrue(sampled.wait(timeout=2))
            return types.SimpleNamespace(returncode=0, stdout='{}', stderr='')

        with tempfile.TemporaryDirectory() as directory, patch.object(vr, 'nsx', side_effect=invoke):
            result = vr._run_master_evidence(directory, 40000, ['master'], 3)
        self.assertEqual(result['tcp_rto']['status'], 'ok')
        self.assertEqual(result['tcp_rto']['samples'][0]['rto_ms'], [208.0])
        self.assertEqual({r['endpoint'] for r in result['tcp_rto']['samples']}, {'master', 'outstation'})
        self.assertEqual(set(result['tcp_rto']['endpoints']), {'master', 'outstation'})
        self.assertTrue(all(value['status'] == 'ok' for value in result['tcp_rto']['endpoints'].values()))

    def test_outstation_rto_independent_failure_is_not_hidden_by_master_success(self):
        with patch.object(vr, 'nsx', return_value=types.SimpleNamespace(
                returncode=1, stdout='', stderr='outstation probe failed')) as invoke:
            record = vr.tcp_rto_readback(40000, endpoint='outstation')
        self.assertEqual(record['endpoint'], 'outstation')
        self.assertEqual(record['namespace'], vr.NS_O)
        self.assertEqual(record['status'], 'error')
        self.assertEqual(record['units'], 'ms')
        self.assertEqual(invoke.call_args.args[0], vr.NS_O)
        self.assertIn('sport = :20000', ' '.join(record['command']))
        self.assertIn('dport = :40000', ' '.join(record['command']))

    def test_master_positive_rto_cannot_qualify_failed_outstation(self):
        sampled = threading.Event()

        def invoke(namespace, *command, **kwargs):
            if command[0] == 'ss':
                if namespace == vr.NS_O:
                    sampled.set()
                    return types.SimpleNamespace(returncode=1, stdout='', stderr='probe failed')
                return types.SimpleNamespace(returncode=0, stdout=' cubic rto:208\n', stderr='')
            self.assertTrue(sampled.wait(timeout=2))
            return types.SimpleNamespace(returncode=0, stdout='{}', stderr='')

        with tempfile.TemporaryDirectory() as directory, patch.object(vr, 'nsx', side_effect=invoke):
            result = vr._run_master_evidence(directory, 40000, ['master'], 3)
        self.assertEqual(result['tcp_rto']['status'], 'unavailable')
        self.assertEqual(result['tcp_rto']['endpoints']['master']['status'], 'ok')
        self.assertEqual(result['tcp_rto']['endpoints']['outstation']['status'], 'error')


if __name__ == '__main__':
    unittest.main()


class CaseaNetem(unittest.TestCase):
    def run_casea(self, *args):
        calls = []
        ok = types.SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(vr, 'nsx', side_effect=lambda ns, *cmd, **kw: calls.append(cmd) or ok):
            vr.casea(True, *args)
        return [c for c in calls if 'netem' in c][0]

    def test_without_jitter_the_netem_command_is_unchanged(self):
        self.assertEqual(self.run_casea(5)[-5:], ('netem', 'delay', '5ms', 'limit', '1000'))

    def test_jitter_and_distribution_are_passed_to_netem(self):
        self.assertEqual(self.run_casea(2, 2, 'paretonormal')[-8:],
                         ('netem', 'delay', '2ms', '2ms', 'distribution', 'paretonormal', 'limit', '1000'))

    def test_jitter_without_a_distribution_is_refused(self):
        with self.assertRaises(SystemExit):
            self.run_casea(2, 2, None)

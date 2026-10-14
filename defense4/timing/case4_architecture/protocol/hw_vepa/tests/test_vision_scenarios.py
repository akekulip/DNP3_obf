"""vision_run.run_connection / run_reconnect with the process boundary faked (tcpdump, outstation and master
processes, ip netns exec, ss, sleeps): nothing here touches a namespace, a NIC or root."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import vision_run as vr  # noqa: E402


class FakePopen:
    """tcpdump (creates its -w file, exits on terminate) and the outstation (prints READY, then its JSON)."""
    log = []

    def __init__(self, argv, **kw):
        FakePopen.log.append(list(argv))
        self.argv, self.returncode = argv, None
        if 'tcpdump' in argv[0]:
            Path(argv[argv.index('-w') + 1]).write_bytes(b'\xd4\xc3\xb2\xa1' + b'\0' * 20)
            self.stdout = None
        else:
            self.stdout = io.StringIO('READY\n')

    def poll(self):
        return None

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        return 0

    def communicate(self, timeout=None):
        if 'tcpdump' in self.argv[0]:
            return None, '4 packets captured\n4 packets received by filter\n0 packets dropped by kernel\n'
        return '{"select_real":1,"select_decoy":0,"operate_real":1,"operate_decoy":0}\n', ''


class Base(unittest.TestCase):
    master_rcs = None

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.runs = td.name
        FakePopen.log = []
        self.master_calls = []
        self.busy_polls = 0
        orig = {k: getattr(vr, k) for k in ('RUNS', 'nsx', 'sh', 'state', 'set_sysctl_checked')}
        orig_popen, orig_sleep = subprocess.Popen, vr.time.sleep
        vr.RUNS = self.runs
        vr.state = lambda: 'state'
        vr.set_sysctl_checked = lambda ns, k, v: v
        vr.sh = lambda *cmd, **kw: SimpleNamespace(returncode=0, stdout='a\nb\nc\nd\n', stderr='')
        vr.nsx = self.fake_nsx
        subprocess.Popen = FakePopen
        vr.time.sleep = lambda s: None

        def undo():
            for k, v in orig.items():
                setattr(vr, k, v)
            subprocess.Popen = orig_popen
            vr.time.sleep = orig_sleep
        self.addCleanup(undo)

    def fake_nsx(self, ns, *cmd, **kw):
        if cmd[0] == 'ss':
            self.busy_polls += 1
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        if vr.BIN in cmd and 'master' in cmd:
            self.master_calls.append(cmd)
            rcs = self.master_rcs or {}
            rc = rcs.get(len(self.master_calls), 0)
            if rc == 'timeout':
                raise subprocess.TimeoutExpired(cmd, 1)
            return SimpleNamespace(returncode=rc, stdout='{"success": %s}' % ('true' if rc == 0 else 'false'), stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    def reconnect(self, label='lbl', port=54500, **kw):
        return vr.run_reconnect(label, port, kw.get('reconnect_port', port + 1), 5, 8, 0, 0, 0)


class SingleRun(Base):
    def test_default_capture_arguments_remain_buffered_and_are_recorded(self):
        dest = os.path.join(self.runs, 'default_capture')
        result = vr.run_connection(dest, 'default_capture', 54500, 1, 8, 0, 0, 0)
        expected = {direction: ['tcpdump', '-i', vr.PARENT, '-Q', direction, '-s0', '-U', '-n',
                     '-w', os.path.join(dest, direction + '.pcap'),
                     'tcp and host %s and host %s' % (vr.IP_M, vr.IP_O)] for direction in ('out', 'in')}
        self.assertEqual([call for call in FakePopen.log if call[0] == 'tcpdump'], list(expected.values()))
        self.assertIs(result['capture_immediate'], False)
        self.assertEqual(result['capture_commands'], expected)

    def test_immediate_capture_adds_only_the_flag_to_both_directions(self):
        dest = os.path.join(self.runs, 'immediate_capture')
        result = vr.run_connection(dest, 'immediate_capture', 54500, 1, 8, 0, 0, 0, capture_immediate=True)
        expected = {direction: ['tcpdump', '--immediate-mode', '-i', vr.PARENT, '-Q', direction, '-s0', '-U', '-n',
                     '-w', os.path.join(dest, direction + '.pcap'),
                     'tcp and host %s and host %s' % (vr.IP_M, vr.IP_O)] for direction in ('out', 'in')}
        self.assertEqual([call for call in FakePopen.log if call[0] == 'tcpdump'], list(expected.values()))
        retained = json.loads(Path(dest, 'result.json').read_text())
        self.assertIs(retained['capture_immediate'], True)
        self.assertEqual(retained['capture_commands'], expected)

    def test_capture_immediate_requires_boolean_before_state_or_process_calls(self):
        for value in ('true', 1, None):
            dest = os.path.join(self.runs, 'invalid_capture')
            with self.assertRaisesRegex(ValueError, 'capture_immediate'):
                vr.run_connection(dest, 'invalid_capture', 54500, 1, 8, 0, 0, 0, capture_immediate=value)
            self.assertFalse(os.path.exists(dest))
        self.assertEqual(FakePopen.log, [])

    def test_qualified_capture_wraps_main_run_without_changing_default_capture_arguments(self):
        wrapped = []

        def qualify(run_dir, main, **kwargs):
            wrapped.append((run_dir, kwargs))
            return main()

        dest = os.path.join(self.runs, 'qualified_capture')
        with patch.object(vr.capture_observation, 'run_with_qualified_capture', side_effect=qualify):
            result = vr.run_connection(dest, 'qualified_capture', 54500, 1, 8, 0, 0, 0, qualify_capture=True)
        self.assertTrue(result['ok'])
        self.assertEqual([row[0] for row in wrapped], [dest])
        self.assertEqual(wrapped[0][1]['interface'], vr.PARENT)
        retained = json.loads(Path(dest, 'result.json').read_text())
        self.assertTrue(retained['qualify_capture'])

    def test_controls_reach_endpoint_environment_and_extend_timeout(self):
        res = vr.run_connection(os.path.join(self.runs, 'controls'), 'controls', 54500, 5, 8, 0, 0, 0,
                                read_pause_ms=5000, run_sbo=False, close_grace_ms=5000)
        self.assertTrue(res['ok'])
        call = self.master_calls[0]
        for value in ('CASE4_READ_PAUSE_MS=5000', 'CASE4_RUN_SBO=0', 'CASE4_CLOSE_GRACE_MS=5000'):
            self.assertIn(value, call)
        self.assertEqual(res['endpoint_controls'], {'read_pause_ms': 5000, 'run_sbo': False, 'close_grace_ms': 5000})

    def test_a_normal_run_still_writes_its_evidence_and_result(self):
        res = vr.run_connection(os.path.join(self.runs, 'one'), 'one', 54500, 5, 8, 0, 0, 0)
        self.assertTrue(res['ok'])
        for f in ('out.pcap', 'in.pcap', 'master.json', 'outstation.json', 'result.json', 'state.txt'):
            self.assertTrue(os.path.exists(os.path.join(self.runs, 'one', f)), f)

    def test_source_port_wait_records_poll_count_elapsed_and_result(self):
        original = vr.nsx
        busy = iter(['ESTAB 0 0 192.168.10.61:54500 peer\n', '', ''])
        def nsx(ns, *cmd, **kw):
            if cmd[0] == 'ss':
                return SimpleNamespace(returncode=0, stdout=next(busy), stderr='')
            return original(ns, *cmd, **kw)
        vr.nsx = nsx
        res = vr.run_connection(os.path.join(self.runs, 'wait'), 'wait', 54500, 5, 8, 0, 0, 0)
        self.assertEqual(res['source_port_wait']['polls'], 2)
        self.assertEqual(res['source_port_wait']['result'], 'free')
        self.assertEqual(res['source_port_wait']['port'], 54500)
        self.assertGreaterEqual(res['source_port_wait']['elapsed_s'], 0)

    def test_busy_port_timeout_is_retained_before_any_endpoint_starts(self):
        vr.nsx = lambda ns, *cmd, **kw: SimpleNamespace(returncode=0, stdout='ESTAB 0 0 192.168.10.61:54500 peer\n', stderr='')
        res = self.reconnect()
        wait = res['connections']['c1']['source_port_wait']
        self.assertEqual(wait['polls'], 80)
        self.assertEqual(wait['result'], 'busy')
        self.assertFalse(res['ok'])
        self.assertEqual(FakePopen.log, [])
        retained = json.load(open(Path(self.runs) / 'lbl' / 'c1' / 'result.json'))
        self.assertEqual(retained['source_port_wait'], wait)

    def test_unreadable_source_port_probe_is_retained_and_starts_no_endpoint(self):
        vr.nsx = lambda ns, *cmd, **kw: SimpleNamespace(returncode=1, stdout='', stderr='ss probe failed')
        res = self.reconnect()
        wait = res['connections']['c1']['source_port_wait']
        self.assertEqual(wait['result'], 'probe_error')
        self.assertEqual(wait['polls'], 1)
        self.assertIn('ss probe failed', wait['error'])
        self.assertFalse(res['ok'])
        self.assertEqual(FakePopen.log, [])

    def test_a_label_is_never_reused(self):
        vr.run_connection(os.path.join(self.runs, 'one'), 'one', 54500, 5, 8, 0, 0, 0)
        with self.assertRaises(FileExistsError):
            vr.run_connection(os.path.join(self.runs, 'one'), 'one', 54500, 5, 8, 0, 0, 0)

    def test_master_timeout_is_recorded_not_raised(self):
        self.master_rcs = {1: 'timeout'}
        res = vr.run_connection(os.path.join(self.runs, 'one'), 'one', 54500, 5, 8, 0, 0, 0)
        self.assertTrue(res['master_timeout'])
        self.assertFalse(res['ok'])


class ReconnectScenario(Base):
    def test_three_connections_each_with_its_own_directory_evidence_and_label(self):
        res = self.reconnect()
        self.assertEqual(sorted(res['connections']), ['c1', 'c2', 'c3'])
        for c in ('c1', 'c2', 'c3'):
            d = Path(self.runs) / 'lbl' / c
            for f in ('out.pcap', 'in.pcap', 'master.json', 'outstation.json', 'result.json'):
                self.assertTrue((d / f).exists(), '%s/%s' % (c, f))
        self.assertEqual([res['connections'][c]['label'] for c in ('c1', 'c2', 'c3')], ['lbl_c1', 'lbl_c2', 'lbl_c3'])

    def test_ports_are_installed_new_then_installed_again(self):
        res = self.reconnect(port=54500, reconnect_port=54777)
        self.assertEqual([res['connections'][c]['master_port'] for c in ('c1', 'c2', 'c3')], [54500, 54777, 54500])
        self.assertEqual([res['connections'][c]['role'] for c in ('c1', 'c2', 'c3')],
                         ['installed', 'unknown_port', 'installed_again'])

    def test_each_connection_gets_a_fresh_outstation_and_capture_pair(self):
        self.reconnect()
        self.assertEqual(len([a for a in FakePopen.log if 'tcpdump' in a[0]]), 6)
        self.assertEqual(len([a for a in FakePopen.log if 'outstation' in a]), 3)

    def test_connection_three_failure_is_recorded_and_does_not_fail_the_scenario(self):
        self.master_rcs = {3: 1}
        res = self.reconnect()
        self.assertEqual(res['connections']['c3']['master_rc'], 1)
        self.assertTrue(res['ok'])

    def test_connection_three_timeout_is_recorded_too(self):
        self.master_rcs = {3: 'timeout'}
        res = self.reconnect()
        self.assertTrue(res['connections']['c3']['master_timeout'])
        self.assertTrue(res['ok'])

    def test_connection_one_failure_aborts_the_scenario(self):
        self.master_rcs = {1: 1}
        res = self.reconnect()
        self.assertFalse(res['ok'])
        self.assertEqual(sorted(res['connections']), ['c1'])
        self.assertEqual(len(self.master_calls), 1)

    def test_connection_two_must_complete(self):
        self.master_rcs = {2: 1}
        res = self.reconnect()
        self.assertFalse(res['ok'])
        self.assertEqual(len(self.master_calls), 2)
        self.assertFalse(res['connections']['c3']['ran'])
        self.assertFalse(res['connections']['c3']['comparable'])

    def test_scenario_json_and_state_are_written_and_the_label_is_not_reusable(self):
        self.reconnect()
        self.assertEqual(json.load(open(Path(self.runs) / 'lbl' / 'scenario.json'))['scenario'], 'reconnect')
        with self.assertRaises(FileExistsError):
            self.reconnect()

    def test_port_range_is_pinned_per_connection_and_time_wait_is_awaited_before_the_reuse(self):
        pinned = []
        vr.set_sysctl_checked = lambda ns, k, v: pinned.append(v) or v
        self.reconnect(port=54500, reconnect_port=54600)
        self.assertEqual(pinned, ['54500 54500', '54600 54600', '54500 54500'])
        self.assertGreaterEqual(self.busy_polls, 3)                 # ss polled before every connection


class Cli(unittest.TestCase):
    def test_cli_exposes_the_scenario(self):
        out = subprocess.run([sys.executable, str(HERE.parent / 'vision_run.py'), '--help'],
                             capture_output=True, text=True).stdout
        self.assertIn('--scenario', out)
        self.assertIn('--reconnect-port', out)
        self.assertIn('--qualify-capture', out)


if __name__ == '__main__':
    unittest.main()

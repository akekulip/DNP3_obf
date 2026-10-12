"""Real OpenDNP3 loopback tests; set CASE4_ENDPOINT_TEST_BINARY to a built gate.

These tests exercise endpoint pacing/close/SBO, not P4 or hardware timing.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
BINARY = os.environ.get('CASE4_ENDPOINT_TEST_BINARY')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def result(output):
    return json.loads([row for row in output.splitlines() if row.startswith('{')][-1])


@unittest.skipUnless(BINARY, 'set CASE4_ENDPOINT_TEST_BINARY to a pinned production build')
class EndpointControls(unittest.TestCase):
    def exchange(self, reads=2, **controls):
        spec = importlib.util.spec_from_file_location('control_test_proxy', HERE / 'pad58b_proxy.py')
        proxy_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proxy_module)
        env = {key: value for key, value in os.environ.items()
               if key not in ('CASE4_READ_PAUSE_MS', 'CASE4_RUN_SBO', 'CASE4_CLOSE_GRACE_MS')}
        env.update(CASE4_PAD58B_SOCKET_GATE='1', **controls)
        with tempfile.TemporaryDirectory() as temp:
            stop = Path(temp) / 'stop'
            tee = Path(temp) / 'tee.jsonl'
            outstation_port, proxy_port = free_port(), free_port()
            while proxy_port == outstation_port:
                proxy_port = free_port()
            outstation = subprocess.Popen(
                [BINARY, 'outstation', '127.0.0.1', str(outstation_port), str(stop), '15'],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            proxy = proxy_module.Proxy(proxy_port, '127.0.0.1', outstation_port, tee)
            errors = []
            closed = []
            def serve():
                try:
                    proxy.run()
                except Exception as error:
                    errors.append(error)
            def observe_close():
                proxy.stop.wait(10)
                closed.append(time.monotonic_ns())
            thread = threading.Thread(target=serve, daemon=True)
            observer = threading.Thread(target=observe_close, daemon=True)
            try:
                self.assertEqual(outstation.stdout.readline().strip(), 'READY')
                thread.start()
                observer.start()
                # A new local listener, not a connection probe that consumes its single accept.
                time.sleep(0.05)
                master = subprocess.run(
                    [BINARY, 'master', '127.0.0.1', str(proxy_port), str(stop), str(reads), '', '8', '0'],
                    env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(master.returncode, 0, master.stdout + master.stderr)
                observer.join(5)
                stop.touch()
                out, _ = outstation.communicate(timeout=5)
                thread.join(5)
                self.assertFalse(thread.is_alive(), 'proxy did not observe the endpoint close')
                self.assertFalse(errors, str(errors))
                self.assertEqual(outstation.returncode, 0, out)
                return result(master.stdout), result(out), [json.loads(row) for row in tee.read_text().splitlines()], closed[0]
            finally:
                if outstation.poll() is None:
                    outstation.terminate()
                    outstation.communicate(timeout=5)

    def test_defaults_preserve_two_reads_and_one_sbo(self):
        master, station, _, _ = self.exchange()
        self.assertEqual((master.get('read_pause_ms'), master.get('run_sbo'), master.get('close_grace_ms')), (25, True, 0))
        self.assertEqual(master['application_calls'], 1)
        self.assertEqual((station['select_real'], station['operate_real']), (1, 1))
        self.assertEqual(master['reads_completed'], 2)
        self.assertTrue(master['all_reads_match_seed'])

    def test_read_only_zero_pause_completes_every_scan_without_sbo(self):
        master, station, events, _ = self.exchange(reads=100, CASE4_READ_PAUSE_MS='0', CASE4_RUN_SBO='0')
        self.assertEqual(master['application_calls'], 0)
        self.assertEqual((station['select_real'], station['operate_real'], station['select_decoy'], station['operate_decoy']), (0, 0, 0, 0))
        self.assertEqual(master['reads_completed'], 100)
        self.assertTrue(master['all_reads_match_seed'])
        self.assertTrue(all(scan['completed'] and scan['matches_seed'] for scan in master['reads']))
        self.assertEqual(sum(event.get('kind') == 'read' for event in events), 100)
        self.assertEqual(sum(event.get('kind') == 'control' for event in events), 0)

    def test_pause_and_close_grace_delay_actual_requests_and_socket_close(self):
        master, _, events, closed_ns = self.exchange(
            CASE4_READ_PAUSE_MS='80', CASE4_RUN_SBO='0', CASE4_CLOSE_GRACE_MS='150')
        self.assertEqual((master.get('read_pause_ms'), master.get('run_sbo'), master.get('close_grace_ms')), (80, False, 150))
        replies = [event for event in events if event.get('kind') == 'read']
        requests = [event for event in events if event['direction'] == 'master_to_outstation'
                    and len(bytes.fromhex(event['frame_hex'])) > 12
                    and bytes.fromhex(event['frame_hex'])[12] == 1]
        self.assertEqual(len(requests), 2)
        self.assertGreaterEqual(requests[1]['time_ns'] - replies[0]['time_ns'], 75_000_000)
        # Last READ pause (80 ms) plus close grace (150 ms), observed outside the endpoint.
        self.assertGreaterEqual(closed_ns - replies[-1]['time_ns'], 225_000_000)

    def test_invalid_controls_fail_before_listening_with_clear_error(self):
        cases = [('CASE4_READ_PAUSE_MS', value) for value in ('', '-1', '5001', '1x', ' 1', '+1', '999999999999999999999')]
        cases += [('CASE4_CLOSE_GRACE_MS', value) for value in ('-1', '5001', '0.5')]
        cases += [('CASE4_RUN_SBO', value) for value in ('', '2', 'true', '-1')]
        with tempfile.TemporaryDirectory() as temp:
            stop = Path(temp) / 'stop'
            stop.touch()
            for key, value in cases:
                with self.subTest(key=key, value=value):
                    env = dict(os.environ, CASE4_PAD58B_SOCKET_GATE='1', **{key: value})
                    proc = subprocess.run([BINARY, 'outstation', '127.0.0.1', str(free_port()), str(stop), '1'],
                                          env=env, capture_output=True, text=True, timeout=3)
                    self.assertEqual(proc.returncode, 64, proc.stdout + proc.stderr)
                    self.assertIn(key, proc.stderr)
                    self.assertNotIn('READY', proc.stdout)

    def test_boundaries_are_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            stop = Path(temp) / 'stop'
            stop.touch()
            for value in ('0', '5000'):
                env = dict(os.environ, CASE4_PAD58B_SOCKET_GATE='1', CASE4_READ_PAUSE_MS=value,
                           CASE4_CLOSE_GRACE_MS=value, CASE4_RUN_SBO='0')
                proc = subprocess.run([BINARY, 'outstation', '127.0.0.1', str(free_port()), str(stop), '1'],
                                      env=env, capture_output=True, text=True, timeout=3)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn('READY', proc.stdout)

    def test_software_evidence_runner_accepts_read_only_workload(self):
        spec = importlib.util.spec_from_file_location('control_test_runner', HERE / 'run_sockets_pad58b.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as temp:
            run = runner.reserve_run(Path(temp) / 'run', {'scope': 'software test'})
            manifest = {'binary_path': BINARY, 'binary_sha256': runner.sha256(BINARY),
                        'opendnp3_commit': runner.PIN, 'pad58b_sha256': runner.sha256(HERE.parent / 'case4_pad58b.py')}
            ports = free_port(), free_port()
            while ports[0] == ports[1]:
                ports = free_port(), free_port()
            with patch.dict(os.environ, {'CASE4_READ_PAUSE_MS': '0', 'CASE4_RUN_SBO': '0', 'CASE4_CLOSE_GRACE_MS': '0'}):
                with run:
                    evidence = runner.launch(run, manifest, 3, *ports)
                    run.finish('passed' if evidence['passed'] else 'failed', evidence)
            self.assertTrue(evidence['passed'], evidence['failures'])


if __name__ == '__main__':
    unittest.main()

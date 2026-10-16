"""Real loopback endpoint tests, with a transparent two-socket byte-level tee.

No namespaces, P4, raw sockets or hardware. CASE4_CANDIDATE_ENDPOINT_BINARY
may select a build; the default is this isolated candidate's build output.
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

BASE = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('CASE4_CANDIDATE_ENDPOINT_BINARY', BASE / 'build/case4_socket_gate_pad58b'))
GATE = BASE.parents[4] / 'framework/size/endpoint_gate'
SPEC = importlib.util.spec_from_file_location('candidate_transparent_tee', GATE / 'pad58b_proxy.py')
PROXY = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PROXY)
PROXY.maybe_pad = lambda frame: (frame, 'passthrough')  # transport proxy without any response edits


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]


def last_json(text):
    return json.loads([line for line in text.splitlines() if line.startswith('{')][-1])


def environment(**controls):
    env = {key: value for key, value in os.environ.items() if not key.startswith('CASE4_')}
    env.update(CASE4_PAD58B_SOCKET_GATE='1', **controls)
    return env


class PreReadGrace(unittest.TestCase):
    def exchange(self, grace=None, marker=True, marker_bad=False, marker_path_override=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stop = root/'stop'; tee = root/'tee.jsonl'
            marker_path = root/'ready.json' if not marker_bad else root/'missing/ready.json'
            if marker_path_override:
                marker_path = Path(marker_path_override)
            controls = {} if grace is None else {'CASE4_PRE_READ_GRACE_MS': str(grace)}
            if marker or marker_bad:
                controls['CASE4_PRE_READ_MARKER'] = str(marker_path)
            env = environment(**controls)
            station_port, proxy_port = free_port(), free_port()
            while station_port == proxy_port:
                proxy_port = free_port()
            station = subprocess.Popen([str(BINARY), 'outstation', '127.0.0.1', str(station_port), str(stop), '15'],
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            proxy = PROXY.Proxy(proxy_port, '127.0.0.1', station_port, tee)
            errors = []
            def serve():
                try:
                    proxy.run()
                except Exception as error:
                    errors.append(str(error))
            thread = threading.Thread(target=serve, daemon=True)
            master = None
            ready, before = None, []
            try:
                self.assertEqual(station.stdout.readline().strip(), 'READY')
                thread.start(); time.sleep(0.05)
                master = subprocess.Popen([str(BINARY), 'master', '127.0.0.1', str(proxy_port), str(stop), '2', '', '8', '0'],
                                          env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                deadline = time.monotonic() + 2
                if marker and not marker_bad:
                    while not marker_path.exists() and master.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertTrue(marker_path.is_file(), 'candidate did not write readiness marker')
                    while ready is None and time.monotonic() < deadline:
                        try:
                            ready = json.loads(marker_path.read_text())
                        except (OSError, ValueError):
                            time.sleep(0.005)
                    self.assertIsNotNone(ready, 'readiness marker did not contain complete JSON')
                    if grace:
                        time.sleep(0.1)
                        before = [json.loads(line) for line in tee.read_text().splitlines()] if tee.exists() else []
                output, err = master.communicate(timeout=10)
                stop.touch(); station_out, station_err = station.communicate(timeout=5)
                thread.join(5)
                self.assertFalse(thread.is_alive(), 'transparent tee did not close')
                self.assertFalse(errors, errors)
                self.assertEqual(station.returncode, 0, station_out + station_err)
                events = [json.loads(line) for line in tee.read_text().splitlines()]
                retained = BASE/'evidence'/self._testMethodName; retained.mkdir(parents=True, exist_ok=True)
                for name, content in (('master.stdout', output), ('master.stderr', err),
                                      ('outstation.stdout', station_out), ('outstation.stderr', station_err)):
                    (retained/name).write_text(content)
                (retained/'tee.jsonl').write_text(tee.read_text())
                (retained/'observation.json').write_text(json.dumps(dict(scope='real software loopback; transparent TCP tee',
                    software_only=True, controls=controls, binary=str(BINARY), master_rc=master.returncode,
                    outstation_rc=station.returncode, marker=ready, events_during_grace=before), indent=2)+'\n')
                return master.returncode, output, err, last_json(station_out), ready, before, events
            finally:
                stop.touch()
                for process in (master, station):
                    if process and process.poll() is None:
                        process.terminate(); process.communicate(timeout=5)
                    if process:
                        for stream in (process.stdout, process.stderr):
                            if stream and not stream.closed:
                                stream.close()
                proxy.stop.set()
                if thread.ident is not None:
                    thread.join(3)

    def test_default_zero_preserves_reads_seed_and_exact_sbo(self):
        rc, output, err, station, _, _, events = self.exchange(marker=False)
        self.assertEqual(rc, 0, output + err)
        master = last_json(output)
        self.assertEqual(master.get('pre_read_grace_ms'), 0)
        self.assertGreater(master['pre_read_ready_ns'], 0)
        self.assertGreaterEqual(master['first_read_issued_ns'], master['pre_read_ready_ns'])
        self.assertLess(master['first_read_issued_ns'] - master['pre_read_ready_ns'], 100_000_000)
        self.assertEqual((master['reads_completed'], master['application_calls'], master['opens']), (2, 1, 1))
        self.assertTrue(master['success'] and master['all_reads_match_seed'])
        self.assertTrue(all(row['points_received'] == 23 and row['matches_seed'] for row in master['reads']))
        self.assertEqual([station[key] for key in ('select_real','operate_real','select_decoy','operate_decoy')], [1,1,0,0])
        self.assertEqual(sum(bytes.fromhex(row.get('frame_hex',''))[12:13] == b'\x01' for row in events
                             if row['direction'] == 'master_to_outstation'), 2)

    def test_500ms_marker_precedes_every_read_and_first_issue(self):
        rc, output, err, _, ready, before, events = self.exchange(grace=500)
        self.assertEqual(rc, 0, output + err)
        master = last_json(output)
        self.assertEqual(ready['pre_read_grace_ms'], 500)
        self.assertTrue(ready['tcp_open']); self.assertEqual(ready['opens'], 1)
        self.assertEqual(ready['first_read_issued_ns'], 0)
        self.assertEqual(master['pre_read_ready_ns'], ready['pre_read_ready_ns'])
        self.assertEqual(master['pre_read_grace_ms'], 500)
        self.assertGreaterEqual(master['first_read_issued_ns'] - ready['pre_read_ready_ns'], 500_000_000)
        self.assertFalse(any(bytes.fromhex(row.get('frame_hex',''))[12:13] == b'\x01' for row in before))
        requests = [row for row in events if row['direction'] == 'master_to_outstation'
                    and bytes.fromhex(row.get('frame_hex',''))[12:13] == b'\x01']
        self.assertEqual(len(requests), 2)
        self.assertGreaterEqual(requests[0]['time_ns'] - ready['pre_read_ready_ns'], 500_000_000)

    def test_marker_write_failure_refuses_before_any_read(self):
        rc, output, err, station, _, _, events = self.exchange(grace=500, marker_bad=True)
        self.assertEqual(rc, 74, output + err); self.assertIn('CASE4_PRE_READ_MARKER', err)
        self.assertFalse(any(bytes.fromhex(row.get('frame_hex',''))[12:13] == b'\x01' for row in events))
        self.assertEqual((station['select_real'], station['operate_real']), (0, 0))

    def test_marker_flush_failure_refuses_before_any_read(self):
        rc, output, err, station, _, _, events = self.exchange(grace=500, marker_bad=True, marker_path_override='/dev/full')
        self.assertEqual(rc, 74, output + err); self.assertIn('CASE4_PRE_READ_MARKER', err)
        self.assertFalse(any(bytes.fromhex(row.get('frame_hex',''))[12:13] == b'\x01' for row in events))
        self.assertEqual((station['select_real'], station['operate_real']), (0, 0))

    def test_strict_invalid_controls_fail_before_listening(self):
        with tempfile.TemporaryDirectory() as temp:
            stop=Path(temp)/'stop'; stop.touch()
            for value in ('', '-1', '+1', '10001', '1x', '0.5', ' 1', '999999999999999999999'):
                with self.subTest(value=value):
                    run = subprocess.run([str(BINARY), 'outstation', '127.0.0.1', str(free_port()), str(stop), '1'],
                                         env=environment(CASE4_PRE_READ_GRACE_MS=value), capture_output=True, text=True, timeout=3)
                    self.assertEqual(run.returncode, 64, run.stdout + run.stderr)
                    self.assertIn('CASE4_PRE_READ_GRACE_MS', run.stderr); self.assertNotIn('READY', run.stdout)

    def test_boundaries_accepted_and_outstation_does_not_write_master_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            stop=Path(temp)/'stop'; stop.touch(); marker=Path(temp)/'marker.json'
            for value in ('0', '10000'):
                with self.subTest(value=value):
                    run = subprocess.run([str(BINARY), 'outstation', '127.0.0.1', str(free_port()), str(stop), '1'],
                                         env=environment(CASE4_PRE_READ_GRACE_MS=value, CASE4_PRE_READ_MARKER=str(marker)),
                                         capture_output=True, text=True, timeout=3)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertIn('READY', run.stdout); self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()

"""Real loopback tests of the 20 s isolation endpoint, with a transparent two-socket byte-level tee.

Pattern of endpoint_barrier_10s/tests/test_pre_read_grace_10s.py. No namespaces, P4, raw sockets or hardware.
CASE4_CANDIDATE_ENDPOINT_BINARY may select a build; the default is this fixture's build output. Pauses stay
short (300-800 ms); the 20000 ms ceiling is tested by argument validation, not by sleeping.
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

PERMIT_GRACE_NS = 2_000_000_000
ABSENT_RC, REFUSED_RC = 75, 76
RUN = 'iso20_test_c2'


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]


def last_json(text):
    return json.loads([line for line in text.splitlines() if line.startswith('{')][-1])


def environment(**controls):
    env = {key: value for key, value in os.environ.items() if not key.startswith('CASE4_')}
    env.update(CASE4_PAD58B_SOCKET_GATE='1', **controls)
    return env


def is_read(row):
    return row['direction'] == 'master_to_outstation' and bytes.fromhex(row.get('frame_hex', ''))[12:13] == b'\x01'


def write_atomic(path, text):
    tmp = Path(str(path) + '.tmp')
    tmp.write_text(text)
    os.replace(tmp, path)


def valid_permit(ready):
    return dict(run=RUN, ready_ns=ready['pre_read_ready_ns'], opens=ready['opens'], grant=True,
                granted_ns=time.monotonic_ns())


class PreReadPermit(unittest.TestCase):
    def exchange(self, grace, permit=None, write_at_ms=None, use_permit=True):
        """permit: None (never written) or a callable(ready) -> text. write_at_ms: when to write it, measured from
        the endpoint's readiness on the shared monotonic clock (default: half way through the pause)."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stop = root / 'stop'; tee = root / 'tee.jsonl'
            marker_path, permit_path = root / 'ready.json', root / 'permit.json'
            controls = {'CASE4_PRE_READ_GRACE_MS': str(grace), 'CASE4_PRE_READ_MARKER': str(marker_path)}
            if use_permit:
                controls.update(CASE4_PRE_READ_PERMIT=str(permit_path), CASE4_PRE_READ_RUN=RUN)
            env = environment(**controls)
            station_port, proxy_port = free_port(), free_port()
            while station_port == proxy_port:
                proxy_port = free_port()
            station = subprocess.Popen([str(BINARY), 'outstation', '127.0.0.1', str(station_port), str(stop),
                                        str(max(20, grace // 1000 + 15))],   # lifetime outlasts the pause
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            proxy = PROXY.Proxy(proxy_port, '127.0.0.1', station_port, tee)
            errors = []

            def serve():
                try:
                    proxy.run()
                except Exception as error:
                    errors.append(str(error))
            thread = threading.Thread(target=serve, daemon=True)
            master, ready, written_ns = None, None, None
            try:
                self.assertEqual(station.stdout.readline().strip(), 'READY')
                thread.start(); time.sleep(0.05)
                master = subprocess.Popen([str(BINARY), 'master', '127.0.0.1', str(proxy_port), str(stop), '2', '',
                                           '8', '0'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                deadline = time.monotonic() + 5
                while ready is None and master.poll() is None and time.monotonic() < deadline:
                    try:
                        ready = json.loads(marker_path.read_text())
                    except (OSError, ValueError):
                        time.sleep(0.002)
                self.assertIsNotNone(ready, 'readiness marker did not contain complete JSON')
                if permit is not None:
                    at = ready['pre_read_ready_ns'] + (grace // 2 if write_at_ms is None else write_at_ms) * 1_000_000
                    while time.monotonic_ns() < at:
                        time.sleep(0.001)
                    written_ns = time.monotonic_ns()
                    write_atomic(permit_path, permit(ready))
                output, err = master.communicate(timeout=max(15, grace // 1000 + 15))
                stop.touch(); station_out, station_err = station.communicate(timeout=5)
                thread.join(5)
                self.assertFalse(thread.is_alive(), 'transparent tee did not close')
                self.assertFalse(errors, errors)
                self.assertEqual(station.returncode, 0, station_out + station_err)
                events = [json.loads(line) for line in tee.read_text().splitlines()] if tee.exists() else []
                retained = BASE / 'evidence' / self._testMethodName; retained.mkdir(parents=True, exist_ok=True)
                for name, content in (('master.stdout', output), ('master.stderr', err),
                                      ('outstation.stdout', station_out), ('outstation.stderr', station_err)):
                    (retained / name).write_text(content)
                (retained / 'tee.jsonl').write_text(tee.read_text() if tee.exists() else '')
                (retained / 'observation.json').write_text(json.dumps(dict(
                    scope='real software loopback; transparent TCP tee', software_only=True, controls=controls,
                    binary=str(BINARY), master_rc=master.returncode, outstation_rc=station.returncode, marker=ready,
                    permit_written_ns=written_ns), indent=2) + '\n')
                return dict(rc=master.returncode, output=output, err=err, station=last_json(station_out),
                            ready=ready, events=events, written_ns=written_ns)
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

    def assert_reads_and_exact_sbo(self, result):
        self.assertEqual(result['rc'], 0, result['output'] + result['err'])
        master = last_json(result['output'])
        self.assertEqual((master['reads_completed'], master['application_calls'], master['opens']), (2, 1, 1))
        self.assertTrue(master['success'] and master['all_reads_match_seed'])
        self.assertTrue(all(row['points_received'] == 23 and row['matches_seed'] for row in master['reads']))
        self.assertEqual([result['station'][key] for key in ('select_real', 'operate_real', 'select_decoy',
                                                             'operate_decoy')], [1, 1, 0, 0])
        self.assertEqual(sum(is_read(row) for row in result['events']), 2)
        return master

    def assert_refused_before_any_read(self, result, rc, reason):
        self.assertEqual(result['rc'], rc, result['output'] + result['err'])
        self.assertIn('CASE4_PRE_READ_PERMIT refused', result['err']); self.assertIn(reason, result['err'])
        self.assertFalse(any(is_read(row) for row in result['events']), 'a READ reached the outstation')
        self.assertEqual((result['station']['select_real'], result['station']['operate_real']), (0, 0))
        master = last_json(result['output'])
        self.assertEqual((master['success'], master['pre_read_permit_refused'], master['permit_rc'],
                          master['first_read_issued_ns'], master['reads_completed']), (False, True, rc, 0, 0))
        self.assertEqual(master['pre_read_ready_ns'], result['ready']['pre_read_ready_ns'])
        return master

    # ------------------------------------------------------------------ opt-in: unset means the 10 s parent

    def test_without_permit_behaves_like_the_parent_for_a_short_pause(self):
        result = self.exchange(400, use_permit=False)
        master = self.assert_reads_and_exact_sbo(result)
        self.assertNotIn('pre_read_permit', master)
        self.assertEqual(set(master), {'success', 'application_calls', 'opens', 'read_pause_ms', 'run_sbo',
                                       'close_grace_ms', 'pre_read_grace_ms', 'pre_read_ready_ns',
                                       'first_read_issued_ns', 'issued_ns', 'completed_ns', 'reads_requested',
                                       'reads_completed', 'all_reads_match_seed', 'reads'})
        self.assertGreaterEqual(master['first_read_issued_ns'] - master['pre_read_ready_ns'], 400_000_000)
        self.assertEqual(result['ready'], dict(pre_read_grace_ms=400, pre_read_ready_ns=master['pre_read_ready_ns'],
                                               first_read_issued_ns=0, tcp_open=True, opens=1))

    # ------------------------------------------------------------------ valid permit

    def test_valid_permit_written_during_the_pause_reads_at_the_scheduled_time(self):
        result = self.exchange(500, permit=lambda ready: json.dumps(valid_permit(ready)))
        master = self.assert_reads_and_exact_sbo(result)
        ready = result['ready']['pre_read_ready_ns']
        self.assertGreaterEqual(master['first_read_issued_ns'] - ready, 500_000_000)
        self.assertLess(master['first_read_issued_ns'] - ready, 500_000_000 + 100_000_000)
        permit = master['pre_read_permit']
        self.assertEqual(permit['run'], RUN)
        self.assertTrue(ready < permit['granted_ns'] <= permit['accepted_ns'] <= master['first_read_issued_ns'])
        first = min(row['time_ns'] for row in result['events'] if is_read(row))
        self.assertGreaterEqual(first - ready, 500_000_000)

    def test_permit_written_after_the_scheduled_time_but_before_the_deadline_is_accepted(self):
        result = self.exchange(300, permit=lambda ready: json.dumps(valid_permit(ready)), write_at_ms=1100)
        master = self.assert_reads_and_exact_sbo(result)
        self.assertGreaterEqual(master['first_read_issued_ns'], result['written_ns'])
        self.assertLess(master['first_read_issued_ns'] - result['ready']['pre_read_ready_ns'],
                        300_000_000 + PERMIT_GRACE_NS)

    # ------------------------------------------------------------------ the full 20 s capability (review W1)

    def test_full_20000_ms_pause_with_permit_late_in_the_window_reads_once_scheduled(self):
        result = self.exchange(20000, permit=lambda ready: json.dumps(valid_permit(ready)), write_at_ms=19000)
        master = self.assert_reads_and_exact_sbo(result)
        ready = result['ready']['pre_read_ready_ns']
        self.assertEqual(master['pre_read_grace_ms'], 20000)
        self.assertGreaterEqual(master['first_read_issued_ns'] - ready, 20_000_000_000)
        self.assertLess(master['first_read_issued_ns'] - ready, 20_000_000_000 + 100_000_000)
        first = min(row['time_ns'] for row in result['events'] if is_read(row))
        self.assertGreaterEqual(first - ready, 20_000_000_000)

    def test_full_20000_ms_pause_without_permit_exits_75_and_never_reads(self):
        result = self.exchange(20000)
        self.assert_refused_before_any_read(result, ABSENT_RC, 'absent')
        self.assertGreaterEqual(time.monotonic_ns() - result['ready']['pre_read_ready_ns'],
                                20_000_000_000 + PERMIT_GRACE_NS)

    # ------------------------------------------------------------------ every negative case: no READ

    def test_absent_permit_exits_75_at_the_deadline_and_never_reads(self):
        started = time.monotonic_ns()
        result = self.exchange(300)
        self.assert_refused_before_any_read(result, ABSENT_RC, 'absent')
        self.assertGreaterEqual(time.monotonic_ns() - result['ready']['pre_read_ready_ns'],
                                300_000_000 + PERMIT_GRACE_NS)
        self.assertLess(time.monotonic_ns() - started, 15_000_000_000)

    def test_late_permit_after_the_deadline_exits_75_and_never_reads(self):
        result = self.exchange(300, permit=lambda ready: json.dumps(valid_permit(ready)), write_at_ms=2600)
        self.assert_refused_before_any_read(result, ABSENT_RC, 'absent')

    def test_malformed_permit_exits_76(self):
        for name, text in (('truncated', '{"run":"%s","ready_ns":' % RUN), ('not_json', 'grant'),
                           ('trailing', None), ('duplicate', None), ('unknown_key', None), ('missing_key', None),
                           ('string_ready', None), ('escaped_run', None)):
            with self.subTest(name=name):
                def build(ready, name=name, text=text):
                    if text is not None:
                        return text
                    permit = valid_permit(ready)
                    body = json.dumps(permit)
                    if name == 'trailing':
                        return body + 'x'
                    if name == 'duplicate':
                        return body[:-1] + ', "grant": true}'
                    if name == 'unknown_key':
                        return json.dumps(dict(permit, extra=1))
                    if name == 'missing_key':
                        return json.dumps({k: v for k, v in permit.items() if k != 'granted_ns'})
                    if name == 'string_ready':
                        return json.dumps(dict(permit, ready_ns=str(permit['ready_ns'])))
                    return json.dumps(dict(permit, run=RUN + '\\u0000'))
                self.assert_refused_before_any_read(self.exchange(300, permit=build), REFUSED_RC, 'malformed')

    def test_wrong_binding_or_grant_false_exits_76(self):
        cases = (('wrong run', lambda r: dict(valid_permit(r), run='iso20_test_c3')),
                 ('wrong ready_ns', lambda r: dict(valid_permit(r), ready_ns=r['pre_read_ready_ns'] - 1)),
                 ('wrong opens or reconnect', lambda r: dict(valid_permit(r), opens=2)),
                 ('grant false', lambda r: dict(valid_permit(r), grant=False)),
                 ('granted_ns not after readiness', lambda r: dict(valid_permit(r), granted_ns=r['pre_read_ready_ns'])),
                 ('granted_ns not after readiness', lambda r: dict(valid_permit(r), granted_ns=10 ** 18)))
        for reason, build in cases:
            with self.subTest(reason=reason):
                result = self.exchange(300, permit=lambda ready, build=build: json.dumps(build(ready)))
                self.assert_refused_before_any_read(result, REFUSED_RC, reason)

    # ------------------------------------------------------------------ argument validation

    def test_grace_cap_is_20000_and_invalid_values_fail_before_listening(self):
        with tempfile.TemporaryDirectory() as temp:
            stop = Path(temp) / 'stop'; stop.touch()
            for value in ('0', '20000'):
                with self.subTest(value=value):
                    run = subprocess.run([str(BINARY), 'outstation', '127.0.0.1', str(free_port()), str(stop), '1'],
                                         env=environment(CASE4_PRE_READ_GRACE_MS=value), capture_output=True,
                                         text=True, timeout=5)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr); self.assertIn('READY', run.stdout)
            for value in ('20001', '-1', '+1', '1x', '', '999999999999999999999'):
                with self.subTest(value=value):
                    run = subprocess.run([str(BINARY), 'outstation', '127.0.0.1', str(free_port()), str(stop), '1'],
                                         env=environment(CASE4_PRE_READ_GRACE_MS=value), capture_output=True,
                                         text=True, timeout=5)
                    self.assertEqual(run.returncode, 64, run.stdout + run.stderr)
                    self.assertIn('CASE4_PRE_READ_GRACE_MS', run.stderr); self.assertNotIn('READY', run.stdout)

    def test_permit_requires_run_label_and_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            stop = Path(temp) / 'stop'; stop.touch(); marker = str(Path(temp) / 'm.json')
            permit = str(Path(temp) / 'p.json')
            for controls in (dict(CASE4_PRE_READ_PERMIT=permit, CASE4_PRE_READ_MARKER=marker),
                             dict(CASE4_PRE_READ_PERMIT=permit, CASE4_PRE_READ_RUN=RUN),
                             dict(CASE4_PRE_READ_PERMIT='', CASE4_PRE_READ_RUN=RUN, CASE4_PRE_READ_MARKER=marker),
                             dict(CASE4_PRE_READ_PERMIT=permit, CASE4_PRE_READ_RUN='bad label', CASE4_PRE_READ_MARKER=marker),
                             dict(CASE4_PRE_READ_PERMIT=permit, CASE4_PRE_READ_RUN='x' * 129, CASE4_PRE_READ_MARKER=marker)):
                for role in ('outstation', 'master'):
                    with self.subTest(role=role, controls=sorted(controls)):
                        run = subprocess.run([str(BINARY), role, '127.0.0.1', str(free_port()), str(stop), '1'],
                                             env=environment(CASE4_PRE_READ_GRACE_MS='300', **controls),
                                             capture_output=True, text=True, timeout=5)
                        self.assertEqual(run.returncode, 64, run.stdout + run.stderr)
                        self.assertIn('CASE4_PRE_READ_PERMIT', run.stderr); self.assertNotIn('READY', run.stdout)
                        self.assertFalse(Path(marker).exists())


if __name__ == '__main__':
    unittest.main()

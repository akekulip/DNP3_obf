"""Endpoint semantic gate for repeated SELECT/OPERATE on one persistent connection (software only).

Real OpenDNP3 outstation and master processes, loopback kernel TCP, and a transparent byte tee (no response
edits, no P4). The tee's decoded link frames are checked independently of the endpoints' own JSON:
  - requests: READ, then (SELECT, OPERATE, READ) x N, application sequence +1 mod 16 throughout
  - responses: transport sequence +1 mod 64 (single-frame native responses), application sequence echoes
  - every SELECT/OPERATE response echoes its request's CROB exactly, status SUCCESS, on-time 100 + cycle
  - the outstation records exactly one SELECT and one OPERATE callback per cycle, in order, same on-time
Build first with ../build_endpoint.py. CASE4_REPEAT_SBO_RETAIN=DIR keeps each test's streams under DIR.
"""
import importlib.util
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('CASE4_REPEAT_SBO_ENDPOINT_BINARY', BASE / 'build/case4_socket_gate_pad58b'))
GATE = BASE.parents[4] / 'framework/size/endpoint_gate'
SPEC = importlib.util.spec_from_file_location('repeat_sbo_transparent_tee', GATE / 'pad58b_proxy.py')
PROXY = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PROXY)
PROXY.maybe_pad = lambda frame: (frame, 'passthrough')      # transport proxy without any response edits
FUNC = {0: 'CONFIRM', 1: 'READ', 3: 'SELECT', 4: 'OPERATE'}


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]


def last_json(text):
    return json.loads([line for line in text.splitlines() if line.startswith('{')][-1])


def environment(**controls):
    env = {key: value for key, value in os.environ.items() if not key.startswith('CASE4_')}
    env.update(CASE4_PAD58B_SOCKET_GATE='1', CASE4_READ_PAUSE_MS='0', **controls)
    return env


def user_data(frame):
    """Strip the 10-octet link header and every block CRC: transport octet + application bytes."""
    length = frame[2] - 5
    out, p = b'', 10
    while length:
        k = min(16, length)
        out += frame[p:p + k]; p += k + 2; length -= k
    return out


def crob(app):
    """(on_time_ms, off_time_ms, status) of the single G12V1 q0x28 object in a request or response."""
    p = 2 if app[1] in (3, 4) else 4                         # request: ctrl+func; response: ctrl+func+IIN
    assert app[p:p + 3] == b'\x0c\x01\x28' and app[p + 3:p + 5] == b'\x01\x00', app.hex()
    obj = app[p + 7:p + 18]
    return int.from_bytes(obj[2:6], 'little'), int.from_bytes(obj[6:10], 'little'), obj[10]


@unittest.skipUnless(BINARY.is_file(), 'build the repeated-SBO endpoint first (build_endpoint.py)')
class RepeatSbo(unittest.TestCase):
    def exchange(self, reads=1, **controls):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stop = root / 'stop'; tee = root / 'tee.jsonl'
            env = environment(**controls)
            station_port, proxy_port = free_port(), free_port()
            while station_port == proxy_port:
                proxy_port = free_port()
            station = subprocess.Popen([str(BINARY), 'outstation', '127.0.0.1', str(station_port), str(stop), '60'],
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            proxy = PROXY.Proxy(proxy_port, '127.0.0.1', station_port, tee)
            errors, master = [], None
            thread = threading.Thread(target=lambda: proxy.run() if True else None, daemon=True)
            try:
                self.assertEqual(station.stdout.readline().strip(), 'READY')
                thread.start(); time.sleep(0.05)
                master = subprocess.Popen([str(BINARY), 'master', '127.0.0.1', str(proxy_port), str(stop), str(reads),
                                           '', '8', '0'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output, err = master.communicate(timeout=60)
                stop.touch(); station_out, station_err = station.communicate(timeout=5)
                thread.join(5)
                self.assertEqual(station.returncode, 0, station_out + station_err)
                rows = [json.loads(line) for line in tee.read_text().splitlines()]
                retain = os.environ.get('CASE4_REPEAT_SBO_RETAIN')
                if retain:
                    out = Path(retain) / self._testMethodName; out.mkdir(parents=True, exist_ok=True)
                    for name, content in (('master.stdout', output), ('master.stderr', err),
                                          ('outstation.stdout', station_out), ('outstation.stderr', station_err),
                                          ('tee.jsonl', tee.read_text())):
                        (out / name).write_text(content)
                return master.returncode, output, err, last_json(station_out), rows
            finally:
                stop.touch()
                for process in (master, station):
                    if process and process.poll() is None:
                        process.terminate(); process.communicate(timeout=5)
                proxy.stop.set()
                if thread.ident is not None:
                    thread.join(3)

    def test_64_cycles_on_one_connection_cross_both_sequence_wraps(self):
        cycles = 64
        rc, output, err, station, rows = self.exchange(reads=1, CASE4_SBO_CYCLES=str(cycles))
        self.assertEqual(rc, 0, output + err)
        master = last_json(output)
        self.assertTrue(master['success'])
        self.assertEqual((master['sbo_cycles'], master['application_calls'], master['opens']), (cycles, cycles, 1))
        self.assertEqual((master['reads_requested'], master['reads_completed']), (1 + cycles, 1 + cycles))
        self.assertEqual(master['actuation'], 'software_handler')
        for c, row in enumerate(master['cycles']):
            self.assertEqual((row['cycle'], row['on_time_ms'], row['callbacks'], row['ok']), (c, 100 + c, 1, True))
            self.assertEqual((row['index'], row['status'], row['points']), (1, 0, 1))
            self.assertTrue(row['read_matches_seed'])
            self.assertGreater(row['completed_ns'], row['issued_ns'])

        # independent decode of the byte streams
        requests = [user_data(bytes.fromhex(r['frame_hex'])) for r in rows if r['direction'] == 'master_to_outstation']
        responses = [user_data(bytes.fromhex(r['native_frame_hex'])) for r in rows if r['direction'] == 'outstation_to_master']
        kinds = [FUNC.get(u[2], u[2]) for u in requests]
        self.assertEqual(kinds, ['READ'] + ['SELECT', 'OPERATE', 'READ'] * cycles)
        app_seqs = [u[1] & 0x0F for u in requests]
        self.assertEqual(app_seqs, [(app_seqs[0] + i) % 16 for i in range(len(app_seqs))])
        self.assertGreaterEqual(len(app_seqs) // 16, 12)                         # many application wraps
        self.assertEqual(len(responses), len(requests))
        t_seqs = [u[0] & 0x3F for u in responses]
        self.assertTrue(all(u[0] & 0xC0 == 0xC0 for u in responses))            # native single FIR|FIN frames
        self.assertEqual(t_seqs, [(t_seqs[0] + i) % 64 for i in range(len(t_seqs))])
        self.assertGreaterEqual(len(t_seqs) // 64, 3)                            # transport wraps three times
        for req, rsp in zip(requests, responses):
            self.assertEqual(req[1] & 0x0F, rsp[1] & 0x0F)                       # response echoes the sequence
            self.assertEqual(rsp[2], 0x81)
        controls = [(req, rsp) for req, rsp in zip(requests, responses) if req[2] in (3, 4)]
        self.assertEqual(len(controls), 2 * cycles)
        for i, (req, rsp) in enumerate(controls):
            on, off, status = crob(rsp[1:])
            self.assertEqual((on, off, status), (100 + i // 2, 100, 0))
            self.assertEqual(crob(req[1:])[:2], (on, off))
            self.assertEqual(req[1 + 2:], rsp[1 + 4:])                           # exact Rule 8 echo of objects

        # outstation callbacks: append-only, one SELECT then one OPERATE per cycle
        self.assertEqual([station[k] for k in ('select_real', 'operate_real', 'select_decoy', 'operate_decoy')],
                         [cycles, cycles, 0, 0])
        self.assertEqual(station['actuation'], 'software_handler')
        self.assertEqual(station['physical_actuations'], 0)
        events = station['events']
        self.assertEqual([e['kind'] for e in events], ['SELECT', 'OPERATE'] * cycles)
        self.assertEqual([e['seq'] for e in events], list(range(2 * cycles)))
        for i, e in enumerate(events):
            self.assertEqual((e['index'], e['status'], e['on_time_ms'], e['off_time_ms']), (1, 0, 100 + i // 2, 100))
        self.assertEqual([e['ns'] for e in events], sorted(e['ns'] for e in events))

    def test_default_keeps_the_single_trailing_sbo(self):
        rc, output, err, station, rows = self.exchange(reads=2)
        self.assertEqual(rc, 0, output + err)
        master = last_json(output)
        self.assertEqual((master['sbo_cycles'], master['application_calls'], master['reads_requested'],
                          master['reads_completed']), (0, 1, 2, 2))
        kinds = [FUNC.get(user_data(bytes.fromhex(r['frame_hex']))[2]) for r in rows
                 if r['direction'] == 'master_to_outstation']
        self.assertEqual(kinds, ['READ', 'READ', 'SELECT', 'OPERATE'])
        self.assertEqual([station[k] for k in ('select_real', 'operate_real')], [1, 1])
        self.assertEqual(len(station['events']), 2)

    def test_build_matches_the_current_source(self):
        # 2026-10-14: a binary built before a source edit was deployed and failed on silicon; never again.
        import hashlib
        manifest = json.loads((BASE / 'build/build_manifest.json').read_text())
        for name, digest in manifest['source_hashes'].items():
            self.assertEqual(hashlib.sha256((BASE / 'sources' / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), manifest['binary_sha256'])

    def test_invalid_cycle_controls_fail_before_any_traffic(self):
        with tempfile.TemporaryDirectory() as temp:
            stop = Path(temp) / 'stop'; stop.touch()
            for env in (dict(CASE4_SBO_CYCLES='65'), dict(CASE4_SBO_CYCLES='-1'), dict(CASE4_SBO_CYCLES='1x'),
                        dict(CASE4_SBO_CYCLES='2', CASE4_RUN_SBO='0')):
                with self.subTest(env=env):
                    run = subprocess.run([str(BINARY), 'master', '127.0.0.1', str(free_port()), str(stop), '1'],
                                         env=environment(**env), capture_output=True, text=True, timeout=5)
                    self.assertEqual(run.returncode, 64, run.stdout + run.stderr)
                    self.assertIn('CASE4_SBO_CYCLES', run.stderr)


if __name__ == '__main__':
    unittest.main()

"""Fixed isolation sequence through mocked process boundaries; no hardware."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

HW = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('vision_isolation', HW / 'vision_isolation.py')
vi = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(vi)


class VisionIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.port = 59412
        environment = patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'})
        environment.start(); self.addCleanup(environment.stop)

    def test_default_plan_has_exact_three_same_tuple_legs_and_no_process_calls(self):
        with patch.object(vi.vc.vr, 'run_connection', side_effect=AssertionError('traffic')), \
             patch.object(vi.vc, 'preflight', side_effect=AssertionError('process')), patch('builtins.print'):
            self.assertEqual(vi.main(['test', '--master-port', str(self.port)]), 0)
            plan = vi.scenario('test', self.port, 1)
        self.assertFalse(plan['applied']); self.assertEqual(plan['reads'], 1)
        self.assertEqual([row['pre_read_grace_ms'] for row in plan['plan']], [0, 5000, 0])
        self.assertEqual([row['master_port'] for row in plan['plan']], [self.port] * 3)
        self.assertEqual(plan['close_grace_ms'], 1000); self.assertEqual(plan['close_mode'], 'rst')
        self.assertTrue(all(row['reads'] == 1 for row in plan['plan']))

    def test_authorization_identity_and_fresh_label_are_required(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'DEFENSE4_HW_AUTHORIZED'):
            vi.scenario('test', self.port, 1, apply=True)
        with patch.object(vi.vc.vr, 'IP_O', '192.168.10.7'), self.assertRaisesRegex(ValueError, 'software'):
            vi.scenario('test', self.port, 1, apply=True)
        with patch.object(vi.vc.vr, 'RUNS', str(self.root)):
            (self.root/'test').mkdir()
            with self.assertRaises(FileExistsError), patch.object(vi.vc, 'preflight') as preflight:
                vi.scenario('test', self.port, 1, apply=True)
            preflight.assert_not_called()

    def test_fixed_sequence_propagates_controls_and_retains_evidence_hashes(self):
        calls, gates = [], []
        def connect(dest, label, port, *args, **kwargs):
            dest=Path(dest); dest.mkdir()
            grace=int(os.environ['CASE4_PRE_READ_GRACE_MS'])
            calls.append(dict(port=port, args=args, kwargs=kwargs, grace=grace,
                              marker=os.environ.get('CASE4_PRE_READ_MARKER')))
            (dest/'master.json').write_text(json.dumps(dict(pre_read_grace_ms=grace,
                 pre_read_ready_ns=1_000_000_000, first_read_issued_ns=1_000_000_000 + grace*1_000_000)))
            if grace:
                Path(calls[-1]['marker']).write_text(json.dumps(dict(pre_read_grace_ms=grace,
                     pre_read_ready_ns=1_000_000_000, first_read_issued_ns=0, tcp_open=True, opens=1)))
            return dict(ok=True)
        def evaluate(*args, **kwargs):
            gates.append(kwargs); return []
        with patch.object(vi.vc.vr, 'RUNS', str(self.root)), patch.object(vi.vc, 'preflight', return_value=[]), \
             patch.object(vi.vc.vr, 'run_connection', side_effect=connect), patch.object(vi.vc, 'evaluate', side_effect=evaluate), \
             patch.object(vi.vc, 'observe', return_value={'ok': True}) as observe, \
             patch.object(vi.vc.vr, 'profile', side_effect=AssertionError('setup')), \
             patch.object(vi.vc.vr, 'casea', side_effect=AssertionError('fixture')):
            record = vi.scenario('test', self.port, 0, apply=True)
        self.assertTrue(record['ok']); self.assertEqual(observe.call_count, 3)
        self.assertEqual([row['grace'] for row in calls], [0, 5000, 0])
        self.assertTrue(all(row['port'] == self.port and row['args'][:4] == (1, 8, 0, 0) for row in calls))
        self.assertEqual([row['args'][4] for row in calls], [12345, 12346, 12347])
        self.assertTrue(all(row['kwargs'] == dict(read_pause_ms=25, run_sbo=True, close_grace_ms=1000,
                                                 capture_immediate=True) for row in calls))
        self.assertEqual([row['pre_read_grace_ms'] for row in gates], [0, 5000, 0])
        self.assertTrue(all(row['reads'] == 1 and row['rst_grace_ms'] == 1000 for row in gates))
        self.assertIsNone(calls[0]['marker']); self.assertIsNone(calls[2]['marker'])
        self.assertEqual(calls[1]['marker'], str(self.root/'test/c2/pre_read_ready.json'))
        retained=json.loads((self.root/'test/scenario.json').read_text())
        self.assertEqual(len(retained['connections'][1]['pre_read_hook']['marker_sha256']), 64)
        self.assertTrue(retained['hashes']); self.assertTrue(retained['source_sha256'])

    def test_any_gate_or_observer_failure_stops_later_legs(self):
        for failure in ('gate', 'observer'):
            with self.subTest(failure=failure):
                def connect(dest, *args, **kwargs):
                    Path(dest).mkdir(); return {'ok': True}
                with patch.object(vi.vc.vr, 'RUNS', str(self.root)), patch.object(vi.vc, 'preflight', return_value=[]), \
                     patch.object(vi.vc.vr, 'run_connection', side_effect=connect) as connection, \
                     patch.object(vi.vc, 'evaluate', return_value=['opens mismatch'] if failure=='gate' else []), \
                     patch.object(vi.vc, 'observe', return_value={'ok': failure != 'observer'}):
                    record=vi.scenario(failure, self.port, 1, apply=True)
                self.assertFalse(record['ok']); self.assertEqual(connection.call_count, 1)
                self.assertEqual(len(record['connections']), 1)

    def test_connection_exception_stops_observer_and_restores_caller_environment(self):
        stopped=threading.Event()
        def observe(dest, port, done):
            done.wait(1); stopped.set(); return dict(ok=False)
        def connect(dest, *args, **kwargs):
            Path(dest).mkdir(); raise RuntimeError('injected failure')
        previous={'CASE4_PRE_READ_GRACE_MS': '777', 'CASE4_PRE_READ_MARKER': '/caller/path'}
        with patch.dict(os.environ, previous), patch.object(vi.vc.vr, 'RUNS', str(self.root)), \
             patch.object(vi.vc, 'preflight', return_value=[]), patch.object(vi.vc, 'observe', side_effect=observe), \
             patch.object(vi.vc.vr, 'run_connection', side_effect=connect), patch.object(vi.vc, 'evaluate', return_value=[]):
            record=vi.scenario('failure', self.port, 1, apply=True)
            self.assertEqual({key: os.environ[key] for key in previous}, previous)
        self.assertFalse(record['ok']); self.assertTrue(stopped.is_set())
        self.assertIn('injected failure', record['connections'][0]['failures'])
        self.assertTrue((self.root/'failure/c1/observer.json').is_file())


if __name__ == '__main__':
    unittest.main()

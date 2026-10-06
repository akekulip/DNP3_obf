"""Independent acceptance checks for a production-socket, kernel-repair gate."""
import importlib.util
from pathlib import Path
import unittest
import json
import tempfile
from unittest.mock import patch
from types import SimpleNamespace

GATE = Path(__file__).resolve().parents[1] / 'size/endpoint_gate/socket_lab.py'

class SocketEvidence(unittest.TestCase):
    def gate(self):
        self.assertTrue(GATE.exists(), 'production socket gate missing')
        spec = importlib.util.spec_from_file_location('case4_socket_lab_test', GATE)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def fixture(self):
        return {'master': {'success': True, 'application_calls': 1, 'opens': 1},
                'outstation': {'select_real': 1, 'select_decoy': 1, 'operate_real': 1, 'operate_decoy': 1,
                               'opens': 1, 'retention_ns': 210000000},
                'phases': [{'native_size': 35, 'wire_size': 55, 'prefix_ack': 34, 'complete_ack': 35,
                            'kernel_retransmission_size': 1, 'replay_size': 21, 'response_size': 57},
                           {'native_size': 35, 'wire_size': 55, 'prefix_ack': 69, 'complete_ack': 70,
                            'kernel_retransmission_size': 1, 'replay_size': 21, 'response_size': 57}]}

    def test_requires_each_growth_tail_repaired_by_kernel(self):
        gate = self.gate(); data = self.fixture()
        self.assertTrue(gate.accept(data)['passed'])
        for index in range(2):
            for key, value in [('kernel_retransmission_size', 0), ('replay_size', 20), ('prefix_ack', 35 + 35 * index), ('response_size', 37)]:
                with self.subTest(index=index, key=key):
                    data = self.fixture(); data['phases'][index][key] = value
                    self.assertFalse(gate.accept(data)['passed'])

    def test_no_application_retry_reconnect_or_unaccepted_decoy(self):
        gate = self.gate()
        for role, key, value in [('master', 'application_calls', 2), ('master', 'opens', 2),
                                 ('master', 'success', False), ('outstation', 'operate_decoy', 0),
                                 ('outstation', 'retention_ns', 500000001)]:
            with self.subTest(role=role, key=key):
                data = self.fixture(); data[role][key] = value
                self.assertFalse(gate.accept(data)['passed'])

    def test_bridge_binds_synchronously_before_endpoint_can_connect(self):
        gate = self.gate(); actions = []
        class PacketSocket:
            def __init__(self, *args): actions.append('create')
            def bind(self, address): actions.append(('bind', address[0]))
            def close(self): actions.append('close')
        with patch.object(gate.socket, 'socket', PacketSocket):
            bridge = gate.Bridge(Path('/unused'))
            bridge.open()
            self.assertEqual(actions, ['create', ('bind', 's0'), 'create', ('bind', 's1')])

    def test_independent_capture_reconstruction_requires_complete_consistent_bytes(self):
        spec = importlib.util.spec_from_file_location('case4_socket_analysis_test', GATE.parent/'analyze_sockets.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        row = lambda seq, data: (0, True, SimpleNamespace(seq=seq, payload=data))
        # Wrap and overlap are reconstructed from captured bytes; a missing
        # inserted tail or conflicting replay can never satisfy completeness.
        rows = [row(0xfffffffe, b'abc'), row(0, b'cde')]
        self.assertEqual(module.reconstruct(rows, 0xfffffffe, 0, 5), b'abcde')
        with self.assertRaisesRegex(ValueError, 'missing'): module.reconstruct(rows[:1], 0xfffffffe, 0, 5)
        with self.assertRaisesRegex(ValueError, 'conflicting'): module.reconstruct(rows+[row(0, b'X')], 0xfffffffe, 0, 5)

    def test_interrupt_kills_private_group_before_aborted_inventory(self):
        gate=self.gate()
        from runner.evidence import reserve_run
        with tempfile.TemporaryDirectory() as temp:
            run=reserve_run(Path(temp)/'run',{'scope':'unit'})
            source=GATE;run.snapshot(source)
            manifest={'files':{'socket_lab.py':gate.sha256(source)},'binary_sha256':'not executed'}
            for name,key in [('case4_padding.py','wire_transform_sha256'),('case4_transport.py','transport_sha256'),('rrc.py','crc_model_sha256')]:
                path=GATE.parents[1]/name;run.snapshot(path);manifest[key]=gate.sha256(path)
            child=SimpleNamespace(pid=424242)
            calls=[]
            def wait():
                calls.append('wait')
                if len(calls)==1: raise KeyboardInterrupt()
                return 0
            child.wait=wait
            with patch.object(gate.subprocess,'Popen',return_value=child),patch.object(gate.os,'killpg') as kill:
                with self.assertRaises(KeyboardInterrupt):
                    with run: gate.launch(run,manifest)
                kill.assert_called_once_with(child.pid,gate.signal.SIGKILL)
            self.assertEqual(len(calls),2)
            self.assertEqual(json.loads((run.path/'completion.json').read_text())['status'],'aborted')

if __name__ == '__main__': unittest.main()

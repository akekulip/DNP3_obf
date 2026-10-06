"""Exclusive evidence reservation precedes acquisition, including failure paths."""
import concurrent.futures
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FRAMEWORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRAMEWORK))


class EvidenceReservation(unittest.TestCase):
    def api(self):
        self.assertTrue((FRAMEWORK / 'runner/evidence.py').exists(), 'exclusive evidence helper missing')
        from runner import evidence
        return evidence

    def test_existing_directory_file_and_symlink_are_never_reused(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / 'old'; directory.mkdir()
            raw = directory / 'capture'; raw.write_bytes(b'original')
            file = root / 'file'; file.write_bytes(b'original')
            link = root / 'link'; link.symlink_to(directory, target_is_directory=True)
            for path in (directory, file, link):
                with self.subTest(path=path), self.assertRaises(FileExistsError):
                    api.reserve_run(path, {'scope': 'unit'})
            self.assertEqual(raw.read_bytes(), b'original')
            self.assertEqual(file.read_bytes(), b'original')

    def test_concurrent_reservation_has_exactly_one_owner(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'run'
            def reserve(_):
                try:
                    return api.reserve_run(path, {'scope': 'unit'})
                except FileExistsError:
                    return None
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                owners = [x for x in pool.map(reserve, range(2)) if x is not None]
            self.assertEqual(len(owners), 1)

    def test_claim_is_one_shot_and_completed_runs_cannot_be_claimed(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as temp:
            run = api.reserve_run(Path(temp) / 'run', {'scope': 'unit'})
            with self.assertRaises(ValueError): api.claim_run(run.path, 'wrong')
            child = api.claim_run(run.path, run.token)
            with self.assertRaises(FileExistsError): api.claim_run(run.path, run.token)
            child.finish('passed', {'assertions': 1})
            with self.assertRaises(FileExistsError): api.claim_run(run.path, run.token)
            with self.assertRaises(FileExistsError): run.finish('passed', {})

    def test_failure_keeps_partial_files_and_hash_inventory(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as temp:
            run = api.reserve_run(Path(temp) / 'run', {'scope': 'unit'})
            with self.assertRaisesRegex(RuntimeError, 'acquisition failed'):
                with run:
                    run.write_bytes('partial.pcap', b'partial')
                    raise RuntimeError('acquisition failed')
            completion = json.loads((run.path / 'completion.json').read_text())
            self.assertEqual(completion['status'], 'failed')
            self.assertIn('partial.pcap', completion['files_sha256'])
            self.assertEqual((run.path / 'partial.pcap').read_bytes(), b'partial')
            with self.assertRaises(FileExistsError): run.write_bytes('partial.pcap', b'replaced')
            with self.assertRaises(FileExistsError): run.write_bytes('late.txt', b'invalidate inventory')

    def test_interrupt_retains_aborted_verdict(self):
        with tempfile.TemporaryDirectory() as temp:
            run=self.api().reserve_run(Path(temp)/'run',{'scope':'unit'})
            with self.assertRaises(KeyboardInterrupt):
                with run:
                    run.write_bytes('partial.log',b'partial')
                    raise KeyboardInterrupt()
            self.assertEqual(json.loads((run.path/'completion.json').read_text())['status'],'aborted')

    def test_endpoint_existing_output_refuses_before_build(self):
        path = FRAMEWORK / 'size/endpoint_gate/run.py'
        spec = importlib.util.spec_from_file_location('case4_gate_refusal', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temp, patch.object(module, 'build_gate', side_effect=AssertionError('build started')):
            with self.assertRaises(FileExistsError): module.main(['--output', temp])

    def test_socket_artifact_reuse_rejects_changed_library_before_acquisition(self):
        path = FRAMEWORK / 'size/endpoint_gate/run.py'
        spec = importlib.util.spec_from_file_location('case4_gate_artifact', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); binary=root/'binary'; binary.write_bytes(b'pinned application')
            library=root/'cpp/lib/libopendnp3.so'; library.parent.mkdir(parents=True); library.write_bytes(b'production')
            manifest=root/'manifest.json'; manifest.write_text(json.dumps(dict(opendnp3_commit=module.PIN,result=0,
                scope='production TCP sockets',binary_path=str(binary),binary_sha256=module.sha256(binary),
                production_library_sha256=module.sha256(library))))
            library.write_bytes(b'changed production')
            run=self.api().reserve_run(root/'fresh',{'scope':'unit'})
            with self.assertRaisesRegex(ValueError,'artifact changed'):
                module.reuse_socket_artifact(run,manifest)

    def test_bmv2_existing_output_refuses_before_namespace(self):
        path = FRAMEWORK / 'bmv2/lab/run_lab.py'
        spec = importlib.util.spec_from_file_location('case4_bmv2_refusal', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temp, patch.dict('os.environ', {'BMV2_LAB_INNER': ''}), patch('subprocess.call', side_effect=AssertionError('namespace started')):
            with self.assertRaises(FileExistsError): module.main(['step1', temp])

    def test_importing_endpoint_gate_has_no_build_or_write_side_effect(self):
        path = FRAMEWORK / 'size/endpoint_gate/run.py'
        spec = importlib.util.spec_from_file_location('case4_gate_run', path)
        module = importlib.util.module_from_spec(spec)
        with patch('subprocess.check_output', side_effect=AssertionError('build side effect on import')):
            spec.loader.exec_module(module)
        self.assertTrue(callable(getattr(module, 'main', None)), 'endpoint gate must have explicit entry point')


if __name__ == '__main__': unittest.main()

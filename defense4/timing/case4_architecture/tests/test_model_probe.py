"""Startup failures must retain evidence and never certify packet execution."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ModelProbe(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('case4_model_probe', ROOT/'integration/model_probe.py')
        self.probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.probe)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = self.root/'compile'
        (self.evidence/'out').mkdir(parents=True)
        (self.evidence/'out/test.conf').write_text('{}')
        (self.evidence/'manifest.json').write_text(json.dumps({
            'source_sha256':'fixture source','artifact_sha256':{'test.conf':'fixture config'}}))
        self.sde = self.root/'sde'
        self.binary = self.sde/'install/bin/tofino-model'
        self.binary.parent.mkdir(parents=True)
        self.output = self.root/'probe01'
        patcher = patch.object(self.probe.build, 'verify_evidence', return_value={
            'compiled_artifacts_verified':True})
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_retained(self, result):
        self.assertEqual(json.loads((self.output/'result.json').read_text()), result)
        self.assertFalse(result['target_model_verified'])
        self.assertFalse(result['packet_execution_attempted'])
        self.assertFalse(result['hardware_contact'])

    def test_missing_binary_retains_outcome(self):
        result = self.probe.probe(self.evidence,self.output,self.sde)
        self.assertEqual(result['exit_code'],125)
        self.assertIn('FileNotFoundError',result['error'])
        self.assert_retained(result)

    def test_failed_launch_retains_outcome(self):
        self.binary.write_text('not an executable format')
        self.binary.chmod(0o700)
        result = self.probe.probe(self.evidence,self.output,self.sde)
        self.assertEqual(result['exit_code'],125)
        self.assert_retained(result)

    def test_successful_startup_never_verifies_pipeline(self):
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        self.binary.chmod(0o700)
        result = self.probe.probe(self.evidence,self.output,self.sde)
        self.assertEqual(result['exit_code'],0)
        self.assert_retained(result)

    def test_cancellation_records_result_and_stops_process_group(self):
        self.binary.write_text('fixture model binary')
        with patch.object(self.probe.subprocess,'Popen') as spawn:
            process = spawn.return_value
            process.wait.side_effect = KeyboardInterrupt
            with patch.object(self.probe.build,'terminate_group') as terminate:
                with self.assertRaises(KeyboardInterrupt):
                    self.probe.probe(self.evidence,self.output,self.sde)
                terminate.assert_called_once_with(process)
        result = json.loads((self.output/'result.json').read_text())
        self.assertTrue(result['interrupted'])
        self.assertEqual(result['exit_code'],130)
        self.assert_retained(result)

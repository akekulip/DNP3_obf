"""Hardware map cannot silently fall back to the model composition."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent.parent


class BuildInputs(unittest.TestCase):
    def test_spaced_and_equals_flags_record_and_generate_hardware_map(self):
        expected = dict(relay_port=9, n_ack_return=48, t_in=180, hb_return=181, held_return=182)
        for equals in (False, True):
            with self.subTest(equals=equals), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'response_only.p4'
                flags = []
                for name, value in expected.items():
                    flag = '--' + name.replace('_', '-')
                    flags.extend([flag + '=' + str(value)] if equals else [flag, str(value)])
                subprocess.run([sys.executable, str(HERE / 'compose.py'), str(output)] + flags,
                               check=True, capture_output=True, text=True)
                meta = json.loads(output.with_suffix('.inputs.json').read_text())
                self.assertEqual(meta['port_map'], expected)
                self.assertEqual(meta['source_sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
                self.assertIn('t_T_IN          = 9w180', output.read_text())

    def test_unknown_flags_fail_before_source_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'response_only.p4'
            result = subprocess.run([sys.executable, str(HERE / 'compose.py'), str(output), '--relay-prt=9'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

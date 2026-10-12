#!/usr/bin/env python3
"""Generator safety checks for E window-fold evidence directories."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
GEN = HERE / 'generate.py'


class GenerateExclusive(unittest.TestCase):
    def test_refuses_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'already_there'
            out.mkdir()
            proc = subprocess.run([sys.executable, str(GEN), '--out', str(out)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('File exists', proc.stderr)
            self.assertEqual(list(out.iterdir()), [])

    def test_writes_fresh_output_directory(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'fresh'
            proc = subprocess.run([sys.executable, str(GEN), '--out', str(out)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((out / 'response_only.p4').exists())
            self.assertTrue((out / 'source_manifest.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)

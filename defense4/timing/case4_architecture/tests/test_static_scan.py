import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / 'integration/core/scan_static_entries.py'


class StaticScanTests(unittest.TestCase):
    def scan(self, nested, entries):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = root / nested / 'p0/context.json'
            context.parent.mkdir(parents=True)
            context.write_text(json.dumps({'tables': [
                {'name': 'Ingress.guard', 'size': 1,
                 'static_entries': [{} for _ in range(entries)]}]}))
            return subprocess.run([sys.executable, str(SCANNER), str(root)],
                                  capture_output=True, text=True)

    def test_named_pipeline_over_capacity_blocks_direct_output(self):
        result = self.scan('', 2)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Ingress.guard size=1 static_entries=2', result.stdout)

    def test_named_pipeline_evidence_discovery_accepts_capacity(self):
        result = self.scan('trial/out', 1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_named_pipeline_evidence_discovery_blocks_over_capacity(self):
        result = self.scan('trial/out', 2)
        self.assertEqual(result.returncode, 1)


if __name__ == '__main__':
    unittest.main()

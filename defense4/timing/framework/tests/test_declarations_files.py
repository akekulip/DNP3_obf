"""The committed experiment declarations must pass the fail-closed validator and match the retained build evidence."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "runner"))
import declaration as d  # noqa: E402


class Files(unittest.TestCase):
    def load(self, n):
        return json.loads((HERE.parent / "declarations" / (n + ".json")).read_text())

    def test_both_declarations_validate(self):
        for n in ("smoke", "main"):
            self.assertEqual(d.validate(self.load(n)), [], n)

    def test_source_hash_matches_the_tree(self):
        src = TIMING / "response_ready/src/defense4_response_ready.p4"
        for n in ("smoke", "main"):
            self.assertEqual(self.load(n)["source"]["sha256"], hashlib.sha256(src.read_bytes()).hexdigest(), n)

    def test_build_identity_matches_the_9_13_2_manifest(self):
        man = json.loads((TIMING / "response_ready/evidence/sde_9_13_2_build_03/manifest.json").read_text())
        for n in ("smoke", "main"):
            b = self.load(n)["build"]
            self.assertEqual(b["sha256"], man["artifact_sha256"]["pipe/tofino.bin"])
            self.assertEqual(b["program_source_sha256"], man["source_sha256"])

    def test_no_operate_and_restore_is_required(self):
        for n in ("smoke", "main"):
            x = self.load(n)
            self.assertNotIn("OPERATE", x["workload"]["ops"])
            self.assertTrue(x["termination"]["restore_required"])

    def test_the_refused_points_are_declared_not_silently_dropped(self):
        self.assertIn("rejected", self.load("main")["failure_outcomes"])


if __name__ == "__main__":
    unittest.main()

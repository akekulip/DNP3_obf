"""Guard against reporting intermediate placement attempts as emitted stages."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "stage_build", Path(__file__).resolve().parents[1] / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def allocation(ingress, egress=0):
    return (f"Table allocation done\n"
            f"Number of stages for ingress table allocation: {ingress}\n"
            f"Number of stages for egress table allocation: {egress}\n"
            "Critical path length through the table dependency graph: 8\n"
            "Number of tables allocated: 76\n")


class TestBuildEvidence(unittest.TestCase):
    def test_compiled_schema_and_manifest_belong_to_current_source(self):
        root = Path(__file__).resolve().parents[1]
        schema = Path(os.environ.get("DNP3_BFRT_JSON", root / "evidence/candidate/bfrt.json"))
        manifest = schema.parent / "manifest.json"
        if not manifest.exists():
            manifest = schema.parent.parent / "manifest.json"
        evidence = json.loads(manifest.read_text())
        self.assertEqual(hashlib.sha256((root / "src/defense4_timing.p4").read_bytes()).hexdigest(),
                         evidence["source_sha256"])
        self.assertEqual(hashlib.sha256(schema.read_bytes()).hexdigest(),
                         evidence["artifact_sha256"]["bfrt.json"])

    def test_uses_final_retry_even_when_it_worsens_placement(self):
        for first, final in ((9, 8), (8, 10)):
            with self.subTest(first=first, final=final):
                result = build.final_allocation(allocation(first) + allocation(final))
                self.assertEqual(result["ingress_stages"], final)

    def test_rejects_incomplete_final_retry(self):
        with self.assertRaises(ValueError):
            build.final_allocation(allocation(8) + "Table allocation done\n")

    def test_context_cross_check_includes_match_and_stateful_tables(self):
        result = build.context_stages({"tables": [
            {"direction": "ingress", "match_attributes": {
                "stage_tables": [{"stage_number": 6}]}},
            {"direction": "ingress", "stage_tables": [{"stage_number": 7}]},
        ]})
        self.assertEqual(result, {"ingress_stages": 8, "egress_stages": 0})


if __name__ == "__main__":
    unittest.main()

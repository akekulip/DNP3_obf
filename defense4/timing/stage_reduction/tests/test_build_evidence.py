"""Guard against reporting intermediate placement attempts as emitted stages."""
import importlib.util
import hashlib
import json
import os
import re
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


# The retained evidence was compiled from commit 16050715 (sha256 d2306158...). The working source is the
# comment-only cleanup of bfc00616, so its bytes differ; what must match is the code. CODE_SHA256 is the hash of
# 16050715's source with comments removed and whitespace collapsed (code_text below), computed from git history.
EVIDENCE_SOURCE_SHA256 = "d2306158f59e69c622654b0577e4518e5be7a69eb927f80c3727f07f8c553090"
CODE_SHA256 = "188c7ab29398d834710fcfc193b82d37caebd39d245baa4a7510f192f834ce2a"


def code_text(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return re.sub(r"\s+", " ", text).strip()


class TestBuildEvidence(unittest.TestCase):
    def test_compiled_schema_and_manifest_belong_to_current_source(self):
        root = Path(__file__).resolve().parents[1]
        schema = Path(os.environ.get("DNP3_BFRT_JSON", root / "evidence/candidate/bfrt.json"))
        # out/manifest.json is the compiler's own schema, not our build evidence.
        evidence = next((data for path in (
            schema.parent / "manifest.json", schema.parent.parent / "manifest.json")
            if path.exists() for data in (json.loads(path.read_text()),)
            if "source_sha256" in data and "artifact_sha256" in data), None)
        self.assertIsNotNone(evidence, f"No build evidence manifest for {schema}")
        source = (root / "src/defense4_timing.p4").read_bytes()
        if hashlib.sha256(source).hexdigest() != evidence["source_sha256"]:
            # a fresh build (DNP3_BFRT_JSON) of the current bytes passes above; the retained evidence must
            # be the 16050715 build and the current source must carry the same code
            self.assertEqual(evidence["source_sha256"], EVIDENCE_SOURCE_SHA256)
            self.assertEqual(hashlib.sha256(code_text(source.decode()).encode()).hexdigest(), CODE_SHA256,
                             "src/defense4_timing.p4 differs from the evidence build in more than comments")
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

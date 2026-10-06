#!/usr/bin/env python3
"""Targeted checks for the 2026-09-29 audit report helper."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_analysis_report as report


class ManifestInputTests(unittest.TestCase):
    def test_sweep_manifest_entries_resolve_from_campaign_root(self):
        inputs = report.manifest_inputs()

        self.assertIn(
            "defense4/timing/evidence/campaign_v2/sweep/app_jsonl/sw_D2_0_24.jsonl",
            inputs["listed_sweep_sample"],
        )
        self.assertEqual([], inputs["listed_missing"])


if __name__ == "__main__":
    unittest.main()

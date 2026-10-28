"""Regressions for relocated build records and the original protected-text fixture."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import check_lin_verbatim
import paths
import publish_manuscript as publish


class BuildRecords(unittest.TestCase):
    def test_original_protected_fixture_is_byte_exact(self):
        self.assertEqual(hashlib.sha256(check_lin_verbatim.SOURCE.read_bytes()).hexdigest(),
                         "d1f6fc89a2f59c63f811fddcc59e5946bb248105294f0a113ebe2236dc5f698b")
        self.assertEqual(len(check_lin_verbatim.protected_paragraphs()), 20)

    def test_current_build_inputs_include_all_thirteen_figures(self):
        files = publish.source_files()
        self.assertEqual(sum(p.suffix == ".pdf" for p in files), 13)
        self.assertTrue(all(paths.PAPER in p.parents for p in files))
        self.assertIn(paths.PAPER / "References.bib", files)
        self.assertIn(paths.PAPER / "IEEEtran.cls", files)
        self.assertEqual(sum(p.parent.name == "tables" for p in files), 3)

    def test_table_edit_invalidates_source_digest(self):
        with tempfile.TemporaryDirectory() as name:
            paper = Path(name)
            for folder in ("sections", "tables", "figures"):
                (paper / folder).mkdir()
            for path in ("main.tex", "References.bib", "IEEEtran.cls", "sections/s.tex",
                         "tables/t.tex"):
                (paper / path).write_text("original")
            with patch.object(publish, "PAPER", paper):
                before = publish.source_digest(publish.source_files())
                (paper / "tables/t.tex").write_text("changed")
                self.assertNotEqual(before, publish.source_digest(publish.source_files()))

    def test_an_empty_gate_report_cannot_be_recorded_as_a_pass(self):
        with tempfile.TemporaryDirectory() as name:
            build = Path(name)
            (build / "lin_check.json").write_text(json.dumps({"exit_code": 0, "checks": []}))
            with self.assertRaisesRegex(ValueError, "successful manuscript gate"):
                publish.record(build)

    def test_latest_pointer_cannot_escape_the_results_directory(self):
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            results = repo / "results" / "paper"
            results.mkdir(parents=True)
            (results / "latest.json").write_text(json.dumps({"build_directory": "elsewhere"}))
            with patch.object(paths, "REPO", repo), patch.object(paths, "RESULTS", results):
                with self.assertRaisesRegex(ValueError, "escapes results/paper"):
                    paths.latest_build()


if __name__ == "__main__":
    unittest.main()

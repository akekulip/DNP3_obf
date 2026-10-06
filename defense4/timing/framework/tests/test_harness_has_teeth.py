"""The model-vs-P4 diff must fail when the P4 is broken. Each mutant is a text edit of a copy of the source."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "defense4/timing/response_ready/src/defense4_response_ready.p4"
TARGET = "defense4.timing.framework.tests.test_model_vs_p4.Agree.test_early_response"


def mutate(text, old, new, count=1):
    assert text.count(old) >= 1, old
    return text.replace(old, new, count)


def run_with(source_text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "mutant.p4"
        p.write_text(source_text)
        env = dict(os.environ, P4_RESPONSE_READY_SOURCE=str(p))
        return subprocess.run([sys.executable, "-B", "-m", "unittest", TARGET], cwd=ROOT, env=env,
                              capture_output=True, text=True)


class Teeth(unittest.TestCase):
    def test_unmutated_source_passes(self):
        self.assertEqual(run_with(SRC.read_text()).returncode, 0)

    def test_dropping_the_deadline_test_is_caught(self):
        lines = SRC.read_text().split("\n")
        i = next(n for n, l in enumerate(lines) if "OUT_AB_DL)" in l and "8w0x9" in l and "8w0x1, 8w0x0&&&8w0x0)" in l)
        lines[i] = lines[i].replace("32w0x0&&&32w0x800000FF", "32w0x0&&&32w0x0")
        self.assertNotEqual(run_with("\n".join(lines)).returncode, 0)

    def test_wrong_response_gap_is_caught(self):
        text = mutate(SRC.read_text(), "meta.tresp_cand = meta.now_word + meta.read_gap_ticks;",
                      "meta.tresp_cand = meta.now_word + meta.seq_m;")
        self.assertNotEqual(run_with(text).returncode, 0)


if __name__ == "__main__":
    unittest.main()

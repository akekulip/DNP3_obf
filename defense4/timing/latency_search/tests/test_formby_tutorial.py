import csv
import importlib.util
from pathlib import Path

import numpy as np


MODULE_PATH = Path(__file__).resolve().parents[1] / "formby_tutorial.py"
SPEC = importlib.util.spec_from_file_location("formby_tutorial", MODULE_PATH)
tutorial = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tutorial)


def test_timing_summary_uses_heldout_samples_and_keeps_sbo_phases(tmp_path):
    source = tmp_path / "transactions.csv"
    fields = ["replicate", "arm", "policy_name", "txn_class", "ack_ms", "clrt_ms", "rt_ms"]
    with source.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(fields)
        writer.writerows([
            [39, "native", "OFF", "READ", 1, 100, 101],
            [40, "native", "OFF", "READ", 1, 1, 2],
            [41, "native", "OFF", "READ", 1, 4, 5],
            [40, "obfuscated", "policy", "SELECT", 1, 2, 3],
            [40, "obfuscated", "policy", "OPERATE", 1, 6, 7],
        ])
    stats = tutorial.timing_data(source, tmp_path)
    native = stats["native", "READ", "clrt_ms"]
    assert native["n"] == 2
    assert native["mean"] == 2.5
    assert native["variance"] == 4.5
    assert np.isclose(native["sd"], np.sqrt(4.5))
    assert stats["policy", "SBO", "clrt_ms"]["mean"] == 4
    assert stats["policy", "SBO", "clrt_ms"]["variance"] == 8
    assert stats["policy", "SELECT", "clrt_ms"]["n"] == 1
    assert stats["policy", "SELECT", "clrt_ms"]["variance"] is None
    assert (tmp_path / "tutorial_timing_statistics.csv").is_file()

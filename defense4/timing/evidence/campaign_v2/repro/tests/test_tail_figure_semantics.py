"""Regression checks for the release-tail figure's exported data."""
import csv
import json
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ROOT.parent
sys.path.insert(0, str(CAMPAIGN / "_bin"))

import make_tail_figure as tail  # noqa: E402


def test_panel_b_exports_exact_raw_integer_pcap_tails(tmp_path):
    tail.build(tmp_path)

    rows = list(csv.DictReader(open(tmp_path / "fig_release_tail_data.csv")))
    histogram = [r for r in rows if r["panel"] == "b" and r["record"] == "histogram_bin"]
    medians = [r for r in rows if r["panel"] == "b" and r["record"] == "class_median"]
    assert histogram
    assert any(r["category"] == "overflow" for r in histogram)

    # Recompute from capture timestamps without calling the tail-loading helper. In
    # particular, independently count against the exported bin edges: using the same
    # histogram helper twice would miss rounding disagreements at exact timestamp ties.
    cfg = json.loads(tail.POLICY.read_text())
    deadline_ns = int(cfg["D_A_ms"] * 1e6) // 256 * 256
    exact_tails = defaultdict(list)
    for pc in sorted(CAMPAIGN.glob("s[0-9][0-9]/raw_pcaps/*_obfuscated.pcap")):
        for e in tail.pd3.extract(pc).exchanges:
            cls = tail.pd3.FUNC_NAME[e.func]
            exact_tails[cls].append((e.t_ack_ns - e.t_req_ns - deadline_ns) / 1e6)

    observed = defaultdict(int)
    denominators = {}
    for r in histogram:
        cls = r["txn_class"]
        observed[cls] += int(r["transactions"])
        denominators[cls] = int(r["denominator"])

    expected = {cls: len(vals) for cls, vals in exact_tails.items()}

    assert dict(observed) == expected
    assert dict(denominators) == expected

    for r in histogram:
        lo = float(r["bin_lo_ms"])
        hi = float(r["bin_hi_ms"]) if r["bin_hi_ms"] else float("inf")
        assert int(r["transactions"]) == sum(lo <= x < hi for x in exact_tails[r["txn_class"]])
        if r["category"] == "overflow":
            assert lo == 0.129

    for r in medians:
        cls = r["txn_class"]
        assert float(r["tail_ms"]) == round(st.median(exact_tails[cls]), 6)

    plt.close("all")


def test_panel_a_sweep_medians_are_from_exact_raw_integer_pcap_intervals(tmp_path):
    tail.build(tmp_path)
    rows = list(csv.DictReader(open(tmp_path / "fig_release_tail_data.csv")))
    exported = {(r["point"], r["txn_class"]): r for r in rows
                if r["panel"] == "a" and r["record"] == "sweep_median"}
    points = {r["point"]: r for r in csv.DictReader(open(tail.SWEEP_POINTS))}
    assert exported
    for (point, cls), got in exported.items():
        pc = CAMPAIGN / "sweep" / "raw_pcaps" / (point + ".pcap")
        deltas = [e.t_ack_ns - e.t_req_ns for e in tail.pd3.extract(pc).exchanges
                  if tail.pd3.FUNC_NAME[e.func] == cls]
        deadline_ns = int(float(points[point]["D_A_ms"]) * 1e6) // 256 * 256
        median_ns = st.median(deltas)
        assert int(got["n"]) == len(deltas)
        assert float(got["ack_med_ms"]) == round(median_ns / 1e6, 6)
        assert float(got["tail_ms"]) == round((median_ns - deadline_ns) / 1e6, 6)
    plt.close("all")

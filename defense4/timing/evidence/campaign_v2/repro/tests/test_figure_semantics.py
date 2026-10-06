"""Regression checks for what the campaign plots actually show, independent of PDF bytes."""
import sys
import csv
import hashlib
import json
import os
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import make_ndss_figures as figures


@pytest.fixture
def rendered(monkeypatch):
    result = {}

    def capture(fig, out, stem, caption, inputs, notes, **kwargs):
        result.update(fig=fig, caption=caption, inputs=inputs, notes=notes, **kwargs)

    monkeypatch.setattr(figures.F, "save", capture)
    figures.F.use()
    yield result
    plt.close("all")


def rows_at(interval):
    return [(f"s{run:02}", arm, cls, interval + delta if arm == "obfuscated" else 2 + delta,
             20.1 + delta if arm == "obfuscated" else 0.5 + delta,
             20.1 + interval + 2 * delta if arm == "obfuscated" else 2.5 + 2 * delta)
            for run in range(1, 23) for arm in figures.ARMS for cls in figures.CLASSES
            for delta in (-0.005, 0, 0.005)]


@pytest.mark.parametrize("scheduled", [4.0, 8.0])
def test_stability_window_contains_current_policy_and_all_quartiles(rendered, scheduled):
    figures.fig_stability(rows_at(scheduled), {"scheduled_release_interval_ms": scheduled},
                          None, [])
    low, high = rendered["fig"].axes[1].get_ylim()
    assert low < scheduled < high
    for row in rendered["data_rows"]:
        if row["panel"] == "b":
            assert low <= row["q1_ms"] <= row["q3_ms"] <= high


def test_overlap_zoom_contains_current_policy_and_exports_drawn_points(rendered):
    rows = rows_at(8.0)
    figures.fig_feature_overlap(rows, {"scheduled_release_interval_ms": 8.0}, None, [])
    window = rendered["notes"]["inset_window"]
    assert window["y"][0] < 8.0 < window["y"][1]
    assert window["x"][0] < 20.1 < window["x"][1]
    points = [r for r in rendered["data_rows"] if r.get("record") == "point"]
    assert len(points) == len(rows)
    assert all("ack_ms" in r and "post_ack_ms" in r for r in points)


def test_empirical_curves_are_exact_at_ties_and_include_both_endpoints():
    x, cdf, survival = figures.empirical_curves([1, 1, 2, 4])
    np.testing.assert_array_equal(x, [1, 2, 4])
    np.testing.assert_allclose(cdf, [0.5, 0.75, 1.0])
    # Fraction strictly exceeding the displayed threshold: P(X > x).
    np.testing.assert_allclose(survival, [0.5, 0.25, 0.0])


def test_distribution_data_reconstructs_every_step_and_shows_full_support(rendered):
    rows = rows_at(8.0) + [("s01", "native", "READ", 200.0, 1.0, 201.0)]
    figures.fig_distributions(rows, None, [])
    points = [r for r in rendered["data_rows"] if r.get("series") == "Timing OFF/READ"
              and "y_ecdf" in r]
    expected = np.unique(figures.sel(rows, "native", "READ"))
    np.testing.assert_array_equal([r["x_ms"] for r in points], expected)
    assert points[-1]["y_ecdf"] == 1.0
    assert rendered["fig"].axes[0].get_xlim()[1] >= expected.max()


@pytest.fixture
def campaign_artifacts():
    location = os.environ.get("CV1_OUT")
    if not location:
        pytest.skip("set CV1_OUT to the independently rebuilt campaign")
    return Path(location)


def read_csv(path):
    with path.open() as handle:
        return list(csv.DictReader(handle))


def test_published_empirical_steps_match_direct_counts(campaign_artifacts):
    rows = read_csv(campaign_artifacts / "transactions_canonical.csv")
    curves = read_csv(campaign_artifacts / "figs/fig_distributions_data.csv")
    for arm in figures.ARMS:
        for cls in figures.CLASSES:
            v = np.array([float(r["clrt_ms"]) for r in rows
                          if r["arm"] == arm and r["txn_class"] == cls])
            points = [r for r in curves if r["panel"] == "abc"
                      and r["series"] == f"{figures.F.LBL[arm]}/{cls}"]
            assert len(points) == len(set(v))
            for point in points[::max(1, len(points) // 17)] + points[-1:]:
                assert float(point["y_ecdf"]) == pytest.approx(
                    np.count_nonzero(v <= float(point["x_ms"])) / len(v), abs=1e-12)
    survival = read_csv(campaign_artifacts / "figs/fig_policy_coverage_cost_data.csv")
    for cls in figures.READ_LANE:
        v = np.array([float(r["rt_ms"]) for r in rows
                      if r["arm"] == "native" and r["txn_class"] == cls])
        points = [r for r in survival if r["panel"] == "a" and r["series"] == cls]
        assert len(points) == len(set(v))
        for point in points[::max(1, len(points) // 17)] + points[-1:]:
            assert float(point["y_fraction_exceeding"]) == pytest.approx(
                np.count_nonzero(v > float(point["x_ms"])) / len(v), abs=1e-12)


def test_scatter_export_only_contains_real_measurements(campaign_artifacts):
    rows = read_csv(campaign_artifacts / "transactions_canonical.csv")
    measured = {(figures.F.LBL[r["arm"]], r["txn_class"], float(r["ack_ms"]),
                 float(r["clrt_ms"])) for r in rows}
    shown = read_csv(campaign_artifacts / "figs/fig_feature_overlap_data.csv")
    points = [r for r in shown if r["record"] in ("point", "zoom_point")]
    assert points
    assert all((r["arm"], r["txn_class"], float(r["ack_ms"]), float(r["post_ack_ms"]))
               in measured for r in points)


def test_pooled_classifier_input_is_hash_identified(campaign_artifacts):
    prov = json.loads((campaign_artifacts / "figs/fig_leakage.provenance.json").read_text())
    expected = hashlib.sha256((campaign_artifacts / "multiobs.json").read_bytes()).hexdigest()
    assert any(p["path"].endswith("multiobs.json") and p["sha256"] == expected
               for p in prov["inputs"])


def test_replacement_figure_uses_canonical_shift_and_per_run_variances(campaign_artifacts):
    rows = read_csv(campaign_artifacts / "transactions_canonical.csv")
    data = read_csv(campaign_artifacts / "figs/fig_replacement_evidence_data.csv")
    native = np.array([float(r["clrt_ms"]) for r in rows
                       if r["arm"] == "native" and r["txn_class"] == "READ"])
    obf = np.array([float(r["clrt_ms"]) for r in rows
                    if r["arm"] == "obfuscated" and r["txn_class"] == "READ"])
    shifted = native - np.median(native) + np.median(obf)
    for label, values in (("Timing OFF", native), ("constant shift", shifted),
                          ("Obfuscated", obf)):
        points = [r for r in data if r["panel"] == "a" and r["series"] == label]
        thresholds = np.unique(values)
        np.testing.assert_allclose([float(r["post_ack_ms"]) for r in points],
                                   thresholds, rtol=0, atol=5e-7)
        expected_cdf = np.searchsorted(np.sort(values), thresholds, side="right") / values.size
        np.testing.assert_allclose([float(r["empirical_cdf"]) for r in points],
                                   expected_cdf, rtol=0, atol=1e-12)
        assert float(points[-1]["empirical_cdf"]) == 1.0
    ratios = [r for r in data if r["record"] == "run_variance_ratio"]
    assert len(ratios) == 44
    assert {(r["run"], r["txn_class"]) for r in ratios} == {
        (r["run"], r["txn_class"]) for r in rows if r["txn_class"] in ("READ", "SELECT")}
    for sample in ratios:
        rn, cls = sample["run"], sample["txn_class"]
        nat_run = np.array([float(r["clrt_ms"]) for r in rows
                           if r["run"] == rn and r["arm"] == "native" and r["txn_class"] == cls])
        obf_run = np.array([float(r["clrt_ms"]) for r in rows
                           if r["run"] == rn and r["arm"] == "obfuscated" and r["txn_class"] == cls])
        assert float(sample["variance_ratio"]) == pytest.approx(
            float(obf_run.var(ddof=1) / nat_run.var(ddof=1)), rel=0, abs=5e-10)


def test_residual_information_figure_is_directly_from_proof_json(campaign_artifacts):
    proof = json.loads((campaign_artifacts / "proof.json").read_text())
    data = read_csv(campaign_artifacts / "figs/fig_residual_information_data.csv")
    for panel, block in (("a", "read_vs_select"), ("b", "read_arrival_split")):
        for arm in figures.ARMS:
            label = figures.F.LBL[arm]
            row = next(r for r in data if r["panel"] == panel and r["arm"] == label)
            src = proof[block][arm]["balanced_accuracy"]["ack_clrt"]
            assert float(row["mean"]) == pytest.approx(src["mean"], abs=1e-12)
            assert float(row["min"]) == pytest.approx(src["min"], abs=1e-12)
            assert float(row["max"]) == pytest.approx(src["max"], abs=1e-12)
            assert int(row["n_runs"]) == 22


def test_layout_check_rejects_legend_title_collision():
    figures.F.use()
    fig, ax = plt.subplots(figsize=(3.48, 2.3), layout="none")
    ax.plot([0, 1], [0, 1], label="READ")
    ax.set_title("Panel title")
    fig.canvas.draw()
    title_box = ax.title.get_window_extent().transformed(fig.transFigure.inverted())
    fig.legend(*ax.get_legend_handles_labels(), loc="center",
               bbox_to_anchor=((title_box.x0 + title_box.x1) / 2,
                               (title_box.y0 + title_box.y1) / 2))
    problems = []
    figures.F.check_layout(fig, "collision", problems)
    assert any("legend overlaps label" in p for p in problems)
    plt.close(fig)


def test_manual_layout_is_preserved_across_pdf_and_png_exports(tmp_path):
    figures.F.use()
    fig, ax = plt.subplots(figsize=(3.48, 2.3), constrained_layout=False)
    ax.plot([0, 1], [0, 1], label="READ")
    ax.set_title("Panel title")
    fig.legend(*ax.get_legend_handles_labels(), loc="upper center")
    fig.subplots_adjust(left=0.15, right=0.95, bottom=0.2, top=0.7)
    expected = ax.get_position().bounds
    figures.F.save(fig, tmp_path, "layout", "Caption", [], {})
    np.testing.assert_allclose(ax.get_position().bounds, expected, rtol=0, atol=1e-12)

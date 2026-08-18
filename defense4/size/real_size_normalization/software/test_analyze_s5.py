from __future__ import annotations

from defense4.size.real_size_normalization.software import analyze_s5


def _facts(cells: int, modal: int, latency: float, boundary: bool = True) -> dict:
    return {
        "observer_cells": cells,
        "observer_bytes": cells * 256,
        "modal_bin_cell_count": modal,
        "master_latency_ms": {"median_ms": latency},
        "boundary_passed": boundary,
    }


def test_s5_passes_when_outer_volume_is_j_independent() -> None:
    # identical observer volume + modal count across native delays; latency may
    # differ (schedule quantization) without failing the size property.
    runs = {0: _facts(4406, 22, 209.6), 120: _facts(4406, 22, 419.8), 300: _facts(4406, 22, 419.7)}
    result = analyze_s5.summarize_runs(runs)

    assert result["passed"]
    assert result["observer_volume_j_independent"]
    assert result["observer_volume_spread_cells"] == 0
    assert result["modal_bin_count_j_independent"]


def test_s5_fails_when_outer_volume_depends_on_j() -> None:
    # a native delay that changes the observed cell volume is a timing->size leak.
    runs = {0: _facts(4406, 22, 210.0), 300: _facts(4600, 24, 410.0)}
    result = analyze_s5.summarize_runs(runs)

    assert not result["passed"]
    assert not result["observer_volume_j_independent"]
    assert not result["modal_bin_count_j_independent"]


def test_s5_fails_when_a_boundary_run_did_not_deliver_bytes() -> None:
    runs = {0: _facts(4406, 22, 210.0), 120: _facts(4406, 22, 420.0, boundary=False)}
    result = analyze_s5.summarize_runs(runs)

    assert not result["passed"]
    assert not result["boundary_all_passed"]


def test_s5_requires_at_least_two_delays() -> None:
    runs = {0: _facts(4406, 22, 210.0)}
    assert not analyze_s5.summarize_runs(runs)["passed"]

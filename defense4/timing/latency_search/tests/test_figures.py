#!/usr/bin/env python3
"""Offline tests for latency-search figure generation."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import figures  # noqa: E402


def _stat(median):
    return {"median": median, "p95": median + 1.0, "p99": median + 2.0, "n": 5}


def _ops(read, select, operate):
    return {
        "READ": {"rt_ms": _stat(read), "ack_ms": _stat(1), "clrt_ms": _stat(read - 1)},
        "SELECT": {"rt_ms": _stat(select), "ack_ms": _stat(1), "clrt_ms": _stat(select - 1)},
        "OPERATE": {"rt_ms": _stat(operate), "ack_ms": _stat(1), "clrt_ms": _stat(operate - 1)},
    }


def _policy(name, kind, mode, da, gap, j):
    return {
        "name": name,
        "kind": kind,
        "mode": mode,
        "requested_da_ms": da,
        "requested_gap_ms": gap,
        "j_set_ms": list(j),
    }


def _write_inputs(tmp_path: Path):
    measurements = {
        "phase": "screen",
        "complete_screen": False,
        "n_blocks": 12,
        "n_exchanges": 3600,
        "policies": {
            "ref_off_20_4": {
                "policy": _policy("ref_off_20_4", "reference", "OFF", 20, 4, figures.REFERENCE_J),
                "n_blocks": 5,
                "n_exchanges": 1500,
                "operations": _ops(5.0, 6.0, 7.0),
            },
            "da5_gap1": {
                "policy": _policy("da5_gap1", "fixed", "D4", 5, 1, figures.SEARCH_J),
                "n_blocks": 5,
                "n_exchanges": 1500,
                "operations": _ops(7.0, 8.5, 9.0),
            },
            "ref_d4_20_4": {
                "policy": _policy("ref_d4_20_4", "reference", "D4", 20, 4, figures.REFERENCE_J),
                "n_blocks": 5,
                "n_exchanges": 1500,
                "operations": _ops(14.0, 15.0, 18.0),
            },
            "da10_gap2": {
                "policy": _policy("da10_gap2", "fixed", "D4", 10, 2, figures.SEARCH_J),
                "n_blocks": 5,
                "n_exchanges": 1500,
                "operations": _ops(8.0, 9.0, 10.0),
            },
        },
    }
    attacks = {
        "quick": True,
        "source_sha256": "rows-sha",
        "code_sha256": "code-sha",
        "per_policy": {
            "da5_gap1": {
                "policy": "da5_gap1",
                "quick": True,
                "complete_attack_coverage": False,
                "qualifies_for_selection": False,
                "tasks": {
                    "three_class": {
                        "chance": 1 / 3,
                        "threshold": 1 / 3 + 0.05,
                        "envelopes": {
                            "ack_response": {
                                "max_accuracy": 0.42,
                                "upper_bound": 0.49,
                                "passes_screen": False,
                                "within_tested_subset_threshold": False,
                                "n_groups": 4,
                            },
                            "all_timing": {
                                "max_accuracy": 0.46,
                                "upper_bound": 0.53,
                                "passes_screen": False,
                                "within_tested_subset_threshold": False,
                                "n_groups": 4,
                            },
                        },
                    },
                    "read_select": {
                        "chance": 0.5,
                        "threshold": 0.55,
                        "envelopes": {
                            "ack_response": {
                                "max_accuracy": 0.51,
                                "upper_bound": 0.57,
                                "passes_screen": False,
                                "within_tested_subset_threshold": False,
                                "n_groups": 4,
                            },
                            "all_timing": {
                                "max_accuracy": 0.52,
                                "upper_bound": 0.58,
                                "passes_screen": False,
                                "within_tested_subset_threshold": False,
                                "n_groups": 4,
                            },
                        },
                    },
                },
            },
            "ref_d4_20_4": {
                "policy": "ref_d4_20_4",
                "quick": True,
                "tasks": {
                    "three_class": {
                        "chance": 1 / 3,
                        "threshold": 1 / 3 + 0.05,
                        "envelopes": {
                            "ack_response": {"max_accuracy": 0.7, "upper_bound": 0.8, "passes_screen": False, "n_groups": 4},
                            "all_timing": {"max_accuracy": 0.72, "upper_bound": 0.84, "passes_screen": False, "n_groups": 4},
                        },
                    }
                },
            },
        },
    }
    measurements_path = tmp_path / "measurements.json"
    attacks_path = tmp_path / "attacks.json"
    measurements_path.write_text(json.dumps(measurements))
    attacks_path.write_text(json.dumps(attacks))
    return measurements_path, attacks_path


def test_tradeoff_rows_use_added_latency_against_per_class_off_medians(tmp_path):
    measurements_path, attacks_path = _write_inputs(tmp_path)
    rows, doc = figures.load_rows(measurements_path)
    attacks = json.loads(attacks_path.read_text())

    tradeoff = figures.build_tradeoff_rows(rows, attacks, doc)

    row = next(r for r in tradeoff if r["policy_name"] == "da5_gap1" and r["task"] == "three_class" and r["attack_family"] == "ack_response")
    assert row["worst_added_median_rt_ms"] == 2.5
    assert row["worst_added_operation"] == "SELECT"
    assert row["max_accuracy"] == 0.42
    assert row["upper_bound"] == 0.49
    assert row["j_interpretation"] == "search_small_j"
    assert row["analysis_partial"] is True
    assert row["complete_attack_coverage"] is False
    assert row["missing_attack_policy_count"] == 1
    assert "da10_gap2" in row["missing_attack_policies"]
    ref = next(r for r in tradeoff if r["policy_name"] == "ref_d4_20_4" and r["attack_family"] == "all_timing")
    assert ref["j_interpretation"] == "historical_reference_j"
    assert ref["worst_added_median_rt_ms"] == 11.0
    assert ref["worst_added_operation"] == "OPERATE"


def test_generate_with_attacks_writes_tradeoff_artifacts_and_provenance(tmp_path):
    measurements_path, attacks_path = _write_inputs(tmp_path)
    outdir = tmp_path / "figures"

    outputs = figures.generate(measurements_path, outdir, attacks_path)

    names = {p.name for p in outputs}
    assert "latency_accuracy_tradeoff.csv" in names
    assert "latency_accuracy_tradeoff.pdf" in names
    assert "latency_accuracy_tradeoff_manifest.json" in names
    csv_rows = list(csv.DictReader((outdir / "latency_accuracy_tradeoff.csv").open()))
    assert {r["task"] for r in csv_rows} == {"three_class", "read_select"}
    assert {r["latency_metric"] for r in csv_rows} == {"added_worst_operation_median_rt_vs_off_ms"}
    manifest = json.loads((outdir / "latency_accuracy_tradeoff_manifest.json").read_text())
    assert manifest["source"]["attacks_json"] == str(attacks_path)
    assert manifest["analysis"]["partial"] is True
    assert manifest["analysis"]["missing_attack_policy_count"] == 1
    assert manifest["analysis"]["extra_attack_policy_count"] == 0
    assert "caption_sha256" in manifest["text_hashes"]
    assert "limitations_sha256" in manifest["text_hashes"]
    assert (outdir / "latency_accuracy_tradeoff.caption.md").exists()
    assert (outdir / "latency_accuracy_tradeoff.method.md").exists()
    assert (outdir / "latency_accuracy_tradeoff.limitations.md").exists()
    assert (outdir / "latency_accuracy_tradeoff.provenance.json").exists()
    assert (outdir / "latency_grid.caption.md").exists()
    assert (outdir / "latency_grid.method.md").exists()
    assert (outdir / "latency_grid.limitations.md").exists()
    assert (outdir / "latency_grid.provenance.json").exists()
    assert (outdir / "FIGURES.sha256").exists()
    caption = (outdir / "latency_accuracy_tradeoff.caption.md").read_text()
    method = (outdir / "latency_accuracy_tradeoff.method.md").read_text()
    assert "Circle markers denote search-J policies" in caption
    assert "With request spacing" in method
    assert "97.5% per task" in method
    assert "same-operation" in method
    checked = figures.check_figures(outdir)
    assert "latency_accuracy_tradeoff.pdf" in checked
    assert "latency_grid.pdf" in checked


def test_check_figures_rejects_modified_output(tmp_path):
    measurements_path, attacks_path = _write_inputs(tmp_path)
    outdir = tmp_path / "figures"
    figures.generate(measurements_path, outdir, attacks_path)

    target = outdir / "latency_accuracy_tradeoff.csv"
    target.write_text(target.read_text() + "# changed\n")

    try:
        figures.check_figures(outdir)
    except ValueError as exc:
        assert "latency_accuracy_tradeoff.csv" in str(exc)
    else:
        raise AssertionError("check_figures accepted a modified artifact")


def test_tradeoff_full_only_when_attack_policy_set_exact_and_records_complete(tmp_path):
    measurements_path, attacks_path = _write_inputs(tmp_path)
    doc = json.loads(measurements_path.read_text())
    doc["complete_screen"] = True
    measurements_path.write_text(json.dumps(doc))
    attacks = json.loads(attacks_path.read_text())
    attacks["quick"] = False
    attacks["per_policy"]["da5_gap1"]["quick"] = False
    attacks["per_policy"]["da5_gap1"]["complete_attack_coverage"] = True
    attacks["per_policy"]["ref_d4_20_4"]["quick"] = False
    attacks["per_policy"]["ref_d4_20_4"]["complete_attack_coverage"] = True
    attacks["per_policy"]["da10_gap2"] = json.loads(json.dumps(attacks["per_policy"]["da5_gap1"]))
    attacks["per_policy"]["da10_gap2"]["policy"] = "da10_gap2"
    attacks_path.write_text(json.dumps(attacks))

    rows, loaded = figures.load_rows(measurements_path)
    tradeoff = figures.build_tradeoff_rows(rows, attacks, loaded)

    assert {r["policy_name"] for r in tradeoff} == {"da5_gap1", "da10_gap2", "ref_d4_20_4"}
    assert {r["analysis_partial"] for r in tradeoff} == {False}
    assert {r["complete_attack_coverage"] for r in tradeoff} == {True}
    assert {r["missing_attack_policy_count"] for r in tradeoff} == {0}


def test_cli_check_is_read_only_and_does_not_regenerate_corrupt_output(tmp_path):
    measurements_path, attacks_path = _write_inputs(tmp_path)
    outdir = tmp_path / "figures"
    figures.generate(measurements_path, outdir, attacks_path)
    target = outdir / "latency_accuracy_tradeoff.csv"
    corrupt = target.read_text() + "# corrupt sentinel\n"
    target.write_text(corrupt)

    try:
        figures.main([
            "--measurements", str(measurements_path),
            "--attacks", str(attacks_path),
            "--outdir", str(outdir),
            "--check",
        ])
    except ValueError as exc:
        assert "latency_accuracy_tradeoff.csv" in str(exc)
    else:
        raise AssertionError("--check accepted corrupt output")

    assert target.read_text() == corrupt


def test_check_figures_rejects_changed_source_inputs(tmp_path):
    measurements_path, attacks_path = _write_inputs(tmp_path)
    outdir = tmp_path / "figures"
    figures.generate(measurements_path, outdir, attacks_path)
    original_hash = figures.sha256_file(outdir / "latency_accuracy_tradeoff.csv")
    doc = json.loads(measurements_path.read_text())
    doc["n_blocks"] = 999
    measurements_path.write_text(json.dumps(doc))

    try:
        figures.check_figures(outdir, measurements_path, attacks_path)
    except ValueError as exc:
        assert "measurements input hash changed" in str(exc)
    else:
        raise AssertionError("check_figures accepted changed measurements input")

    assert figures.sha256_file(outdir / "latency_accuracy_tradeoff.csv") == original_hash


def test_latency_grid_uses_shared_scale_clean_labels_and_paper_axis_names(monkeypatch, tmp_path):
    rows = [
        {
            "available": True,
            "requested_da_ms": 5.0,
            "requested_gap_ms": 1.0,
            "median_rt_worst_ms": 6.0,
            "median_rt_operation": "READ",
            "p99_rt_worst_ms": 28.0,
            "p99_rt_operation": "OPERATE",
        },
        {
            "available": True,
            "requested_da_ms": 10.0,
            "requested_gap_ms": 2.0,
            "median_rt_worst_ms": 20.0,
            "median_rt_operation": "SELECT",
            "p99_rt_worst_ms": 24.0,
            "p99_rt_operation": "READ",
        },
    ]
    seen = {"images": [], "text": [], "xlabels": [], "ylabels": [], "colorbars": 0}
    real_imshow = figures.plt.Axes.imshow
    real_text = figures.plt.Axes.text
    real_xlabel = figures.plt.Axes.set_xlabel
    real_ylabel = figures.plt.Axes.set_ylabel
    real_colorbar = figures.plt.Figure.colorbar

    def spy_imshow(self, *args, **kwargs):
        seen["images"].append(kwargs)
        return real_imshow(self, *args, **kwargs)

    def spy_text(self, x, y, s, *args, **kwargs):
        seen["text"].append(str(s))
        return real_text(self, x, y, s, *args, **kwargs)

    def spy_xlabel(self, label, *args, **kwargs):
        seen["xlabels"].append(str(label))
        return real_xlabel(self, label, *args, **kwargs)

    def spy_ylabel(self, label, *args, **kwargs):
        seen["ylabels"].append(str(label))
        return real_ylabel(self, label, *args, **kwargs)

    def spy_colorbar(self, *args, **kwargs):
        seen["colorbars"] += 1
        return real_colorbar(self, *args, **kwargs)

    monkeypatch.setattr(figures.plt.Axes, "imshow", spy_imshow)
    monkeypatch.setattr(figures.plt.Axes, "text", spy_text)
    monkeypatch.setattr(figures.plt.Axes, "set_xlabel", spy_xlabel)
    monkeypatch.setattr(figures.plt.Axes, "set_ylabel", spy_ylabel)
    monkeypatch.setattr(figures.plt.Figure, "colorbar", spy_colorbar)

    figures.plot_latency_grid(rows, tmp_path / "grid.pdf", tmp_path / "grid.png")

    assert len(seen["images"]) == 2
    assert {kwargs.get("vmin") for kwargs in seen["images"]} == {6.0}
    assert {kwargs.get("vmax") for kwargs in seen["images"]} == {28.0}
    assert seen["colorbars"] == 1
    assert "Configured CLRT$_{new}$ (ms)" in seen["xlabels"]
    assert "$D_A$ (ms)" in seen["ylabels"]
    assert "6.0" in seen["text"]
    assert "28.0" in seen["text"]
    assert all("\n" not in label for label in seen["text"] if label != "NA")
    assert not {"R", "S", "O"} & set(seen["text"])

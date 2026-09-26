#!/usr/bin/env python3
"""Publication-style figures for the low-latency timing search.

This script reads only summarized measurements. It does not inspect captures or
invent missing grid values: unavailable cells are masked in the figure and marked
as unavailable in the exported CSV.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
from typing import Mapping, Optional, Sequence

os.environ.setdefault("MPLCONFIGDIR", "/tmp/dnp3-latency-mplconfig")

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
import numpy as np


HERE = Path(__file__).resolve().parent
DEFAULT_INPUT = Path("/tmp/dnp3-latency-pilot/measurements.json")
DEFAULT_OUTDIR = Path("/tmp/dnp3-latency-figures")
DEFAULT_ATTACKS = None
GRID_DA_MS = (5.0, 10.0, 15.0, 20.0)
GRID_GAP_MS = (1.0, 2.0, 4.0, 6.0, 8.0)
OPS = ("READ", "SELECT", "OPERATE")
SERIF = ["Times New Roman", "Nimbus Roman", "Liberation Serif", "DejaVu Serif"]
SEARCH_J = (0.25, 0.5, 1.0)
REFERENCE_J = (2.0, 6.0, 12.0)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def generator_sha256() -> str:
    return sha256_file(Path(__file__))


def _fmt_ms(v: float) -> str:
    return f"{v:g}"


def _policy_name(record: Mapping[str, object], fallback: str) -> str:
    policy = record.get("policy") or {}
    if isinstance(policy, Mapping) and policy.get("name"):
        return str(policy["name"])
    return fallback


def _policy_float(policy: Mapping[str, object], *keys: str) -> Optional[float]:
    for key in keys:
        if policy.get(key) is not None:
            return float(policy[key])
    return None


def _j_tuple(policy: Mapping[str, object]) -> tuple[float, ...]:
    vals = policy.get("j_set_ms") or ()
    return tuple(float(x) for x in vals)


def _classify_policy(policy: Mapping[str, object]) -> str:
    kind = str(policy.get("kind") or "")
    mode = str(policy.get("mode") or "")
    da = _policy_float(policy, "requested_da_ms", "da_ms")
    gap = _policy_float(policy, "requested_gap_ms", "new_clrt_ms")
    if kind == "reference" or mode == "OFF":
        return "reference"
    if da in GRID_DA_MS and gap in GRID_GAP_MS:
        return "grid"
    return "extra"


def _metric(record: Mapping[str, object], op: str, metric: str, stat: str) -> Optional[float]:
    operations = record.get("operations") or {}
    if not isinstance(operations, Mapping):
        return None
    op_data = operations.get(op) or {}
    if not isinstance(op_data, Mapping):
        return None
    metric_data = op_data.get(metric) or {}
    if not isinstance(metric_data, Mapping) or metric_data.get(stat) is None:
        return None
    return float(metric_data[stat])


def _worst_operation(record: Mapping[str, object], metric: str, stat: str) -> tuple[Optional[float], str]:
    candidates = []
    for op in OPS:
        value = _metric(record, op, metric, stat)
        if value is not None and np.isfinite(value):
            candidates.append((value, op))
    if not candidates:
        return None, ""
    value, op = max(candidates, key=lambda item: item[0])
    return float(value), op


def load_rows(measurements_path: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    doc = json.loads(measurements_path.read_text())
    rows = []
    for fallback_name, record in sorted((doc.get("policies") or {}).items()):
        if not isinstance(record, Mapping):
            continue
        policy = record.get("policy") or {}
        if not isinstance(policy, Mapping):
            policy = {}
        name = _policy_name(record, fallback_name)
        da = _policy_float(policy, "requested_da_ms", "da_ms")
        gap = _policy_float(policy, "requested_gap_ms", "new_clrt_ms")
        median_rt, median_op = _worst_operation(record, "rt_ms", "median")
        p99_rt, p99_op = _worst_operation(record, "rt_ms", "p99")
        rows.append(
            {
                "policy_name": name,
                "group": _classify_policy(policy),
                "mode": policy.get("mode", ""),
                "kind": policy.get("kind", ""),
                "requested_da_ms": da,
                "requested_gap_ms": gap,
                "j_set_ms": " ".join(_fmt_ms(v) for v in _j_tuple(policy)),
                "j_interpretation": (
                    "search_small_j"
                    if _j_tuple(policy) == SEARCH_J
                    else "historical_reference_j"
                    if _j_tuple(policy) == REFERENCE_J
                    else "other_j"
                ),
                "n_blocks": int(record.get("n_blocks") or 0),
                "n_exchanges": int(record.get("n_exchanges") or 0),
                "median_rt_worst_ms": median_rt,
                "median_rt_operation": median_op,
                "p99_rt_worst_ms": p99_rt,
                "p99_rt_operation": p99_op,
            }
        )
    return rows, doc


def _write_csv(path: Path, rows: Sequence[Mapping[str, object]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "" if row.get(key) is None else row.get(key) for key in fieldnames})


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _write_text_sidecars(outdir: Path, stem: str, text: Mapping[str, str]) -> list[Path]:
    paths = []
    for key in ("caption", "method", "limitations"):
        path = outdir / f"{stem}.{key}.md"
        path.write_text(text[key].rstrip() + "\n")
        paths.append(path)
    return paths


def _write_provenance(outdir: Path, stem: str, provenance: Mapping[str, object]) -> Path:
    path = outdir / f"{stem}.provenance.json"
    path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    return path


def write_figures_sha256(outdir: Path, outputs: Sequence[Path]) -> Path:
    path = outdir / "FIGURES.sha256"
    unique = []
    seen = set()
    for output in outputs:
        if output.exists() and output.name != path.name and output not in seen:
            unique.append(output)
            seen.add(output)
    lines = [f"{sha256_file(output)}  {output.name}" for output in sorted(unique, key=lambda p: p.name)]
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _read_json_if_exists(path: Path) -> dict[str, object]:
    return json.loads(path.read_text()) if path.exists() else {}


def _check_source_hashes(outdir: Path, measurements: Optional[Path], attacks: Optional[Path]) -> list[str]:
    mismatches = []
    provenances = [
        _read_json_if_exists(outdir / "latency_grid.provenance.json"),
        _read_json_if_exists(outdir / "latency_accuracy_tradeoff.provenance.json"),
    ]
    for provenance in provenances:
        if not provenance:
            continue
        figure = provenance.get("figure", "unknown")
        source = provenance.get("source") or {}
        expected_code = provenance.get("generator_sha256")
        if expected_code and expected_code != generator_sha256():
            mismatches.append(f"{figure}: generator hash changed")
        if measurements is not None and source.get("measurements_sha256"):
            actual = sha256_file(measurements)
            if actual != source.get("measurements_sha256"):
                mismatches.append(f"{figure}: measurements input hash changed")
        if attacks is not None and source.get("attacks_sha256"):
            actual = sha256_file(attacks)
            if actual != source.get("attacks_sha256"):
                mismatches.append(f"{figure}: attacks input hash changed")
    return mismatches


def check_figures(outdir: Path, measurements: Optional[Path] = None, attacks: Optional[Path] = None) -> list[str]:
    manifest = outdir / "FIGURES.sha256"
    if not manifest.exists():
        raise FileNotFoundError(f"missing {manifest}")
    mismatches = []
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        expected, name = line.split(None, 1)
        target = outdir / name.strip()
        if not target.exists():
            mismatches.append(f"missing {target.name}")
            continue
        actual = sha256_file(target)
        if actual != expected:
            mismatches.append(f"{target.name}: expected {expected}, got {actual}")
    mismatches.extend(_check_source_hashes(outdir, measurements, attacks))
    if mismatches:
        raise ValueError("figure hash check failed: " + "; ".join(mismatches))
    return [line.split(None, 1)[1].strip() for line in manifest.read_text().splitlines() if line.strip()]


def grid_text() -> dict[str, str]:
    return {
        "caption": (
            "Latency grid for the timing-policy search. Each cell reports the largest statistic "
            "across READ, SELECT, and OPERATE for median response time or p99 response time. "
            "The contributing operation is recorded in the CSV. Gray cells were not measured and "
            "are not interpolated."
        ),
        "method": (
            "The grid contains fixed DA by configured CLRT-gap search cells. Search policies use "
            "J={0.25,0.5,1} ms. Historical reference policies use J={2,6,12} ms and are exported "
            "in the companion CSV rather than folded into the search grid."
        ),
        "limitations": (
            "The grid is a measurement summary. It does not by itself establish attack resistance, "
            "and missing cells should be treated as unavailable data."
        ),
    }


def build_grid_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    by_cell = {}
    for row in rows:
        if row.get("group") != "grid":
            continue
        key = (float(row["requested_da_ms"]), float(row["requested_gap_ms"]))
        by_cell[key] = row
    grid_rows = []
    for da in GRID_DA_MS:
        for gap in GRID_GAP_MS:
            source = by_cell.get((da, gap))
            if source is None:
                grid_rows.append(
                    {
                        "available": False,
                        "requested_da_ms": da,
                        "requested_gap_ms": gap,
                        "policy_name": f"da{_fmt_ms(da)}_gap{_fmt_ms(gap)}",
                        "median_rt_worst_ms": None,
                        "median_rt_operation": "",
                        "p99_rt_worst_ms": None,
                        "p99_rt_operation": "",
                        "n_blocks": 0,
                        "n_exchanges": 0,
                    }
                )
            else:
                grid_rows.append({"available": True, **dict(source)})
    return grid_rows


def grid_matrix(grid_rows: Sequence[Mapping[str, object]], value_key: str) -> np.ma.MaskedArray:
    values = np.full((len(GRID_DA_MS), len(GRID_GAP_MS)), np.nan, dtype=float)
    for row in grid_rows:
        if not row.get("available"):
            continue
        da = float(row["requested_da_ms"])
        gap = float(row["requested_gap_ms"])
        if da not in GRID_DA_MS or gap not in GRID_GAP_MS:
            continue
        value = row.get(value_key)
        if value is None:
            continue
        values[GRID_DA_MS.index(da), GRID_GAP_MS.index(gap)] = float(value)
    return np.ma.masked_invalid(values)


def set_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": SERIF,
            "font.size": 8.5,
            "axes.labelsize": 8.5,
            "axes.titlesize": 9.0,
            "xtick.labelsize": 8.0,
            "ytick.labelsize": 8.0,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
            "axes.linewidth": 0.55,
            "xtick.major.width": 0.5,
            "ytick.major.width": 0.5,
            "xtick.major.size": 2.4,
            "ytick.major.size": 2.4,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "savefig.dpi": 600,
        }
    )


def _annotate_heatmap(ax, matrix: np.ma.MaskedArray, vmin: float, vmax: float) -> None:
    mask = np.ma.getmaskarray(matrix)
    for i, _da in enumerate(GRID_DA_MS):
        for j, _gap in enumerate(GRID_GAP_MS):
            if mask[i, j]:
                ax.text(j, i, "NA", ha="center", va="center", color="#6f6f6f", fontsize=7.4)
                continue
            value = float(matrix[i, j])
            label = f"{value:.1f}"
            frac = 0.0 if vmax <= vmin else (value - vmin) / (vmax - vmin)
            color = "white" if frac >= 0.62 else "#111111"
            ax.text(j, i, label, ha="center", va="center", color=color, fontsize=7.4)


def _op_matrix(grid_rows: Sequence[Mapping[str, object]], op_key: str) -> list[list[str]]:
    out = [["" for _ in GRID_GAP_MS] for _ in GRID_DA_MS]
    for row in grid_rows:
        if not row.get("available"):
            continue
        da = float(row["requested_da_ms"])
        gap = float(row["requested_gap_ms"])
        if da in GRID_DA_MS and gap in GRID_GAP_MS:
            out[GRID_DA_MS.index(da)][GRID_GAP_MS.index(gap)] = str(row.get(op_key) or "")
    return out


def plot_latency_grid(grid_rows: Sequence[Mapping[str, object]], out_pdf: Path, out_png: Path) -> None:
    set_style()
    median = grid_matrix(grid_rows, "median_rt_worst_ms")
    p99 = grid_matrix(grid_rows, "p99_rt_worst_ms")
    all_values = np.ma.concatenate([median.compressed(), p99.compressed()])
    vmin = float(all_values.min()) if all_values.size else 0.0
    vmax = float(all_values.max()) if all_values.size else 1.0
    cmap = LinearSegmentedColormap.from_list("latency_blue", ["#F7F7EF", "#A6CEE3", "#1E78B5", "#08306B"])
    cmap.set_bad("#F0F0F0")

    fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.55), constrained_layout=True)
    panels = (
        (axes[0], median, "Worst median response"),
        (axes[1], p99, "Worst p99 response"),
    )
    image = None
    for ax, matrix, title in panels:
        image = ax.imshow(matrix, cmap=cmap, aspect="auto", vmin=vmin, vmax=vmax)
        ax.set_title(title)
        ax.set_xlabel("Configured CLRT$_{new}$ (ms)")
        ax.set_xticks(range(len(GRID_GAP_MS)), [_fmt_ms(v) for v in GRID_GAP_MS])
        ax.set_yticks(range(len(GRID_DA_MS)), [_fmt_ms(v) for v in GRID_DA_MS])
        ax.set_ylabel("$D_A$ (ms)")
        ax.set_xticks(np.arange(-0.5, len(GRID_GAP_MS), 1), minor=True)
        ax.set_yticks(np.arange(-0.5, len(GRID_DA_MS), 1), minor=True)
        ax.grid(which="minor", color="white", linewidth=0.75)
        ax.tick_params(which="minor", bottom=False, left=False)
        _annotate_heatmap(ax, matrix, vmin, vmax)
    cbar = fig.colorbar(image, ax=axes, fraction=0.024, pad=0.018)
    cbar.ax.set_ylabel("Response time (ms)", rotation=90, labelpad=5)
    cbar.ax.tick_params(labelsize=8, width=0.5, length=2.2)
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_pdf)
    fig.savefig(out_png, dpi=600)
    plt.close(fig)



def _policy_records(doc: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    records = {}
    for fallback_name, record in (doc.get("policies") or {}).items():
        if not isinstance(record, Mapping):
            continue
        policy = record.get("policy") or {}
        name = fallback_name
        if isinstance(policy, Mapping) and policy.get("name"):
            name = str(policy["name"])
        records[name] = record
    return records


def _task_ops(task: str) -> tuple[str, ...]:
    if task == "read_select":
        return ("READ", "SELECT")
    return OPS


def _off_medians(records: Mapping[str, Mapping[str, object]]) -> dict[str, float]:
    off_records = []
    for name, record in records.items():
        policy = record.get("policy") or {}
        if isinstance(policy, Mapping) and str(policy.get("mode") or "") == "OFF":
            off_records.append((name, record))
    if len(off_records) != 1:
        raise ValueError(f"expected one OFF/native latency reference, found {len(off_records)}")
    _name, record = off_records[0]
    out = {}
    for op in OPS:
        value = _metric(record, op, "rt_ms", "median")
        if value is None:
            raise ValueError(f"OFF/native reference is missing {op} median response time")
        out[op] = value
    return out


def _j_interpretation_for_record(record: Mapping[str, object]) -> str:
    policy = record.get("policy") or {}
    if not isinstance(policy, Mapping):
        return "other_j"
    j = _j_tuple(policy)
    if j == SEARCH_J:
        return "search_small_j"
    if j == REFERENCE_J:
        return "historical_reference_j"
    return "other_j"


def _policy_group_for_record(record: Mapping[str, object]) -> str:
    policy = record.get("policy") or {}
    return _classify_policy(policy if isinstance(policy, Mapping) else {})


def _worst_added_latency(record: Mapping[str, object], off: Mapping[str, float], task: str) -> tuple[float, str, float, float]:
    candidates = []
    for op in _task_ops(task):
        value = _metric(record, op, "rt_ms", "median")
        if value is None or op not in off:
            continue
        candidates.append((float(value) - float(off[op]), op, float(value), float(off[op])))
    if not candidates:
        raise ValueError(f"policy is missing median response data for task {task}")
    added, op, total, base = max(candidates, key=lambda item: item[0])
    return added, op, total, base


def _analysis_partial(attacks: Mapping[str, object], doc: Mapping[str, object]) -> bool:
    if bool(attacks.get("quick")):
        return True
    if doc.get("complete_screen") is False:
        return True
    per_policy = attacks.get("per_policy") or {}
    if any(isinstance(v, Mapping) and bool(v.get("quick")) for v in per_policy.values()):
        return True
    return False


def _measured_protected_policies(records: Mapping[str, Mapping[str, object]]) -> set[str]:
    out = set()
    for name, record in records.items():
        policy = record.get("policy") or {}
        if not isinstance(policy, Mapping):
            continue
        if str(policy.get("mode") or "") == "OFF":
            continue
        if _policy_group_for_record(record) in {"grid", "extra", "reference"}:
            out.add(name)
    return out


def _coverage_info(records: Mapping[str, Mapping[str, object]], attacks: Mapping[str, object]) -> dict[str, object]:
    measured = _measured_protected_policies(records)
    per_policy = attacks.get("per_policy") or {}
    attacked = {name for name, value in per_policy.items() if name in records and isinstance(value, Mapping)}
    missing = sorted(measured - attacked)
    extra = sorted(set(per_policy) - measured)
    all_records_complete = all(
        bool(per_policy[name].get("complete_attack_coverage", not per_policy[name].get("quick", False)))
        for name in attacked
    ) if attacked else False
    exact = not missing and not extra
    return {
        "measured_protected_policies": sorted(measured),
        "attack_policies": sorted(attacked),
        "missing_attack_policies": missing,
        "extra_attack_policies": extra,
        "missing_attack_policy_count": len(missing),
        "extra_attack_policy_count": len(extra),
        "all_records_complete": all_records_complete,
        "exact_attack_policy_set": exact,
        "complete": exact and all_records_complete,
    }


def build_tradeoff_rows(
    measurement_rows: Sequence[Mapping[str, object]],
    attacks: Mapping[str, object],
    doc: Mapping[str, object],
) -> list[dict[str, object]]:
    """Join measurement summaries and attack summaries for latency/accuracy plots."""
    del measurement_rows  # The canonical per-operation medians live in measurements.json.
    records = _policy_records(doc)
    off = _off_medians(records)
    per_policy = attacks.get("per_policy") or {}
    coverage = _coverage_info(records, attacks)
    partial = _analysis_partial(attacks, doc) or not bool(coverage["complete"])
    rows: list[dict[str, object]] = []
    for policy_name, attack_record in sorted(per_policy.items()):
        if policy_name not in records:
            continue
        record = records[policy_name]
        policy = record.get("policy") or {}
        if isinstance(policy, Mapping) and str(policy.get("mode") or "") == "OFF":
            continue
        if not isinstance(attack_record, Mapping):
            continue
        tasks = attack_record.get("tasks") or {}
        for task, task_record in sorted(tasks.items()):
            if not isinstance(task_record, Mapping):
                continue
            envelopes = task_record.get("envelopes") or {}
            added, op, total, baseline = _worst_added_latency(record, off, task)
            for family in ("ack_response", "all_timing"):
                envelope = envelopes.get(family) or {}
                if not isinstance(envelope, Mapping) or envelope.get("max_accuracy") is None:
                    continue
                rows.append(
                    {
                        "policy_name": policy_name,
                        "task": task,
                        "attack_family": family,
                        "latency_metric": "added_worst_operation_median_rt_vs_off_ms",
                        "worst_added_median_rt_ms": round(float(added), 6),
                        "worst_added_operation": op,
                        "worst_total_median_rt_ms": round(float(total), 6),
                        "off_median_rt_ms": round(float(baseline), 6),
                        "max_accuracy": float(envelope["max_accuracy"]),
                        "upper_bound": float(envelope.get("upper_bound", envelope["max_accuracy"])),
                        "ucb_margin": float(envelope.get("upper_bound", envelope["max_accuracy"])) - float(envelope["max_accuracy"]),
                        "passes_screen": bool(envelope.get("passes_screen", False)),
                        "within_tested_subset_threshold": bool(envelope.get("within_tested_subset_threshold", envelope.get("passes_screen", False))),
                        "n_groups": envelope.get("n_groups", ""),
                        "chance": task_record.get("chance", ""),
                        "threshold": task_record.get("threshold", ""),
                        "analysis_partial": partial or bool(attack_record.get("quick", False)),
                        "complete_attack_coverage": bool(coverage["complete"]) and bool(attack_record.get("complete_attack_coverage", not attack_record.get("quick", False))),
                        "qualifies_for_selection": bool(attack_record.get("qualifies_for_selection", False)) and bool(coverage["complete"]),
                        "missing_attack_policy_count": coverage["missing_attack_policy_count"],
                        "extra_attack_policy_count": coverage["extra_attack_policy_count"],
                        "missing_attack_policies": " ".join(coverage["missing_attack_policies"]),
                        "extra_attack_policies": " ".join(coverage["extra_attack_policies"]),
                        "group": _policy_group_for_record(record),
                        "mode": policy.get("mode", "") if isinstance(policy, Mapping) else "",
                        "kind": policy.get("kind", "") if isinstance(policy, Mapping) else "",
                        "requested_da_ms": _policy_float(policy, "requested_da_ms", "da_ms") if isinstance(policy, Mapping) else None,
                        "requested_gap_ms": _policy_float(policy, "requested_gap_ms", "new_clrt_ms") if isinstance(policy, Mapping) else None,
                        "j_set_ms": " ".join(_fmt_ms(v) for v in _j_tuple(policy)) if isinstance(policy, Mapping) else "",
                        "j_interpretation": _j_interpretation_for_record(record),
                    }
                )
    return rows


def _task_title(task: str) -> str:
    return "READ/SELECT" if task == "read_select" else "Three-class"


def _family_label(family: str) -> str:
    return "ACK/response" if family == "ack_response" else "With request spacing"


def plot_tradeoff(rows: Sequence[Mapping[str, object]], out_pdf: Path, out_png: Path) -> None:
    if not rows:
        raise ValueError("no latency/accuracy tradeoff rows to plot")
    set_style()
    tasks = [task for task in ("three_class", "read_select") if any(r["task"] == task for r in rows)]
    if not tasks:
        tasks = sorted({str(r["task"]) for r in rows})
    fig, axes = plt.subplots(1, len(tasks), figsize=(7.16, 2.8), sharey=True)
    if len(tasks) == 1:
        axes = [axes]
    family_style = {
        "ack_response": {"color": "#1B6CA8", "dx": -0.09},
        "all_timing": {"color": "#B54632", "dx": 0.09},
    }
    marker_for_j = {"search_small_j": "o", "historical_reference_j": "^", "other_j": "s"}
    for ax, task in zip(axes, tasks):
        task_rows = [r for r in rows if r["task"] == task]
        threshold_vals = [float(r["threshold"]) for r in task_rows if r.get("threshold") not in (None, "")]
        chance_vals = [float(r["chance"]) for r in task_rows if r.get("chance") not in (None, "")]
        if chance_vals:
            ax.axhline(chance_vals[0], color="#9a9a9a", linewidth=0.65, linestyle=":", zorder=0)
        if threshold_vals:
            ax.axhline(threshold_vals[0], color="#bdbdbd", linewidth=0.65, linestyle="--", zorder=0)
        for family in ("ack_response", "all_timing"):
            family_rows = [r for r in task_rows if r["attack_family"] == family]
            if not family_rows:
                continue
            style = family_style[family]
            for row in family_rows:
                x = float(row["worst_added_median_rt_ms"]) + style["dx"]
                y = float(row["max_accuracy"])
                upper = float(row["upper_bound"])
                marker = marker_for_j.get(str(row.get("j_interpretation")), "s")
                face = style["color"] if row.get("j_interpretation") == "search_small_j" else "white"
                ax.errorbar(
                    [x],
                    [y],
                    yerr=[[0.0], [max(0.0, upper - y)]],
                    fmt=marker,
                    markersize=4.2,
                    color=style["color"],
                    markerfacecolor=face,
                    markeredgewidth=0.8,
                    elinewidth=0.7,
                    capsize=1.8,
                    alpha=0.92,
                    zorder=3,
                )
        ax.set_title(_task_title(task))
        ax.set_xlabel("Added median response latency (ms)")
        ax.grid(axis="y", color="#E7E7E7", linewidth=0.55)
        ax.tick_params(axis="both", labelsize=8)
        ax.text(0.70, 0.94, "ACK/response", transform=ax.transAxes, fontsize=7.3, color=family_style["ack_response"]["color"], va="top")
        ax.text(0.70, 0.87, "With request spacing", transform=ax.transAxes, fontsize=7.3, color=family_style["all_timing"]["color"], va="top")
    axes[0].set_ylabel("Maximum balanced accuracy")
    fig.subplots_adjust(left=0.075, right=0.985, bottom=0.22, top=0.84, wspace=0.16)
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_pdf)
    fig.savefig(out_png, dpi=600)
    plt.close(fig)


def tradeoff_text(rows: Sequence[Mapping[str, object]]) -> dict[str, str]:
    partial = any(bool(r.get("analysis_partial")) for r in rows)
    partial_sentence = "The attack analysis is marked partial/diagnostic and is not a final selection result." if partial else "The attack analysis covers the configured full development screen."
    return {
        "caption": (
            "Latency/accuracy tradeoff for candidate timing policies. The x-axis is added median "
            "response latency, computed per operation relative to the OFF baseline and then taking "
            "the worst operation for the task; it is not total response latency. Points show the "
            "maximum evaluated protected balanced accuracy and the vertical whisker shows the "
            "simultaneous development upper bound. Circle markers denote search-J policies; open "
            "triangles denote historical reference-J policies."
        ),
        "method": (
            "ACK/response uses the declared ACK and CLRT feature families. With request spacing adds "
            "the declared request-gap and ACK/CLRT/request-gap feature families; it is not a claim "
            "over every possible timing attacker. Pooled attacks group same-operation samples using "
            "the known operation class before scoring. Bounds use 97.5% per task; Bonferroni over "
            "the two tasks gives the intended approximate 95% combined development screen. The "
            "uncertainty is from five same-session acquisition repetitions and is not independent "
            "confirmation. Search policies use J={0.25,0.5,1} ms. Reference D4 policies use "
            "J={2,6,12} ms and should not be compared as if they shared the search J set."
        ),
        "limitations": partial_sentence,
    }


def write_tradeoff_manifest(
    outdir: Path,
    measurements_path: Path,
    attacks_path: Path,
    outputs: Sequence[Path],
    doc: Mapping[str, object],
    attacks: Mapping[str, object],
    rows: Sequence[Mapping[str, object]],
) -> list[Path]:
    text = tradeoff_text(rows)
    sidecars = _write_text_sidecars(outdir, "latency_accuracy_tradeoff", text)
    records = _policy_records(doc)
    coverage = _coverage_info(records, attacks)
    provenance = {
        "figure": "latency_accuracy_tradeoff",
        "generator_sha256": generator_sha256(),
        "source": {
            "measurements_json": str(measurements_path),
            "measurements_sha256": sha256_file(measurements_path),
            "attacks_json": str(attacks_path),
            "attacks_sha256": sha256_file(attacks_path),
            "attacks_source_sha256": attacks.get("source_sha256"),
            "attacks_code_sha256": attacks.get("code_sha256"),
            "phase": doc.get("phase"),
            "complete_screen": doc.get("complete_screen"),
            "n_blocks": doc.get("n_blocks"),
            "n_exchanges": doc.get("n_exchanges"),
        },
        "analysis": {
            "partial": any(bool(r.get("analysis_partial")) for r in rows),
            "complete_attack_coverage_all_rows": all(bool(r.get("complete_attack_coverage")) for r in rows) if rows else False,
            "exact_attack_policy_set": coverage["exact_attack_policy_set"],
            "missing_attack_policies": coverage["missing_attack_policies"],
            "extra_attack_policies": coverage["extra_attack_policies"],
            "missing_attack_policy_count": coverage["missing_attack_policy_count"],
            "extra_attack_policy_count": coverage["extra_attack_policy_count"],
        },
        "text_hashes": {f"{key}_sha256": _sha256_text(value) for key, value in text.items()},
        "outputs_sha256": {path.name: sha256_file(path) for path in outputs if path.exists()},
    }
    provenance_path = _write_provenance(outdir, "latency_accuracy_tradeoff", provenance)
    manifest_path = outdir / "latency_accuracy_tradeoff_manifest.json"
    manifest_path.write_text(json.dumps({**provenance, "text": text}, indent=2, sort_keys=True) + "\n")
    return [manifest_path, provenance_path] + sidecars


def write_manifest(outdir: Path, measurements_path: Path, outputs: Sequence[Path], doc: Mapping[str, object]) -> list[Path]:
    text = grid_text()
    sidecars = _write_text_sidecars(outdir, "latency_grid", text)
    provenance = {
        "figure": "latency_search_grid",
        "source": {
            "measurements_json": str(measurements_path),
            "measurements_sha256": sha256_file(measurements_path),
            "phase": doc.get("phase"),
            "complete_screen": doc.get("complete_screen"),
            "n_blocks": doc.get("n_blocks"),
            "n_exchanges": doc.get("n_exchanges"),
        },
        "interpretation": {
            "grid": "DAxCLRT fixed search cells only; missing cells are masked, not interpolated.",
            "references": "Reference policies use the historical J set {2,6,12} ms and are exported separately from the heatmap. Search-grid policies use {0.25,0.5,1} ms.",
            "metric": "Each cell is the largest statistic across READ, SELECT, and OPERATE for response time median or p99; the contributing operation is recorded in the CSV.",
        },
        "text_hashes": {f"{key}_sha256": _sha256_text(value) for key, value in text.items()},
        "outputs_sha256": {path.name: sha256_file(path) for path in outputs if path.exists()},
    }
    provenance_path = _write_provenance(outdir, "latency_grid", provenance)
    manifest_path = outdir / "latency_grid_manifest.json"
    manifest_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    return [manifest_path, provenance_path] + sidecars


def generate(measurements: Path, outdir: Path, attacks: Optional[Path] = DEFAULT_ATTACKS) -> list[Path]:
    rows, doc = load_rows(measurements)
    grid_rows = build_grid_rows(rows)
    non_grid_rows = [row for row in rows if row.get("group") != "grid"]
    grid_csv = outdir / "latency_grid_data.csv"
    non_grid_csv = outdir / "latency_non_grid_reference_data.csv"
    fields = (
        "available",
        "policy_name",
        "group",
        "mode",
        "kind",
        "requested_da_ms",
        "requested_gap_ms",
        "j_set_ms",
        "j_interpretation",
        "n_blocks",
        "n_exchanges",
        "median_rt_worst_ms",
        "median_rt_operation",
        "p99_rt_worst_ms",
        "p99_rt_operation",
    )
    _write_csv(grid_csv, grid_rows, fields)
    _write_csv(non_grid_csv, non_grid_rows, fields[1:])
    pdf = outdir / "latency_grid.pdf"
    png = outdir / "latency_grid.png"
    plot_latency_grid(grid_rows, pdf, png)
    outputs = [grid_csv, non_grid_csv, pdf, png]
    outputs = outputs + write_manifest(outdir, measurements, outputs, doc)
    if attacks is not None:
        attack_doc = json.loads(Path(attacks).read_text())
        tradeoff_rows = build_tradeoff_rows(rows, attack_doc, doc)
        tradeoff_csv = outdir / "latency_accuracy_tradeoff.csv"
        tradeoff_fields = (
            "policy_name", "task", "attack_family", "latency_metric",
            "worst_added_median_rt_ms", "worst_added_operation", "worst_total_median_rt_ms", "off_median_rt_ms",
            "max_accuracy", "upper_bound", "ucb_margin", "passes_screen", "within_tested_subset_threshold",
            "n_groups", "chance", "threshold", "analysis_partial", "complete_attack_coverage",
            "qualifies_for_selection", "missing_attack_policy_count", "extra_attack_policy_count",
            "missing_attack_policies", "extra_attack_policies", "group", "mode", "kind", "requested_da_ms", "requested_gap_ms",
            "j_set_ms", "j_interpretation",
        )
        _write_csv(tradeoff_csv, tradeoff_rows, tradeoff_fields)
        tradeoff_pdf = outdir / "latency_accuracy_tradeoff.pdf"
        tradeoff_png = outdir / "latency_accuracy_tradeoff.png"
        plot_tradeoff(tradeoff_rows, tradeoff_pdf, tradeoff_png)
        tradeoff_outputs = [tradeoff_csv, tradeoff_pdf, tradeoff_png]
        outputs.extend(tradeoff_outputs + write_tradeoff_manifest(outdir, measurements, Path(attacks), tradeoff_outputs, doc, attack_doc, tradeoff_rows))
    outputs.append(write_figures_sha256(outdir, outputs))
    return outputs


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurements", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--outdir", type=Path, default=DEFAULT_OUTDIR)
    parser.add_argument("--attacks", type=Path, default=DEFAULT_ATTACKS)
    parser.add_argument("--check", action="store_true", help="verify existing outputs against FIGURES.sha256 after generation")
    args = parser.parse_args(argv)
    if args.check:
        checked = check_figures(args.outdir, args.measurements, args.attacks)
        print(json.dumps({"outputs": [], "checked": checked}, indent=2))
        return 0
    outputs = generate(args.measurements, args.outdir, args.attacks)
    print(json.dumps({"outputs": [str(p) for p in outputs], "checked": []}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

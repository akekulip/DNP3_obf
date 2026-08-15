#!/usr/bin/env python3
"""Offline observer-transcript analysis for real size normalization.

The observer CSV is intentionally treated as public data: ciphertext bytes and
absolute nonce/counter values are not converted into attacker length features.
Only structural transcript fields are analyzed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


DEFAULT_PERMUTATIONS = 1000
DEFAULT_BOOTSTRAPS = 2000
DEFAULT_SEED = 20260814
EPSILON = 1e-9

TEXT_TRUE = {"1", "true", "t", "yes", "y", "success", "ok", "pass", "passed", "in_policy"}
TEXT_FALSE = {"0", "false", "f", "no", "n", "fail", "failed", "fault", "overflow", "error"}

PUBLIC_METADATA_CANDIDATES = {
    "version",
    "policy_id",
    "policy",
    "ethertype",
    "ether_type",
    "outer_ethertype",
    "protocol",
    "outer_flow_id",
    "flow_id",
    "src_mac",
    "dst_mac",
    "outer_src_mac",
    "outer_dst_mac",
}

COUNTER_CANDIDATES = (
    "counter",
    "cell_counter",
    "public_counter",
    "nonce_counter",
    "seq",
    "sequence",
    "cell_sequence",
)

STRUCTURAL_LENGTH_CANDIDATES = (
    "public_header_len",
    "outer_header_len",
    "cell_header_len",
    "ciphertext_len",
    "tag_len",
    "auth_tag_len",
)


class GateFailure(RuntimeError):
    """Raised when deterministic S3 observer gate criteria fail."""


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"{path} has no header")
        rows = []
        for index, row in enumerate(reader):
            normalized = {str(k).strip(): ("" if v is None else str(v).strip()) for k, v in row.items()}
            normalized["_row_order"] = str(index)
            rows.append(normalized)
        return rows


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: _csv_value(row.get(name, "")) for name in fieldnames})


def _csv_value(value: Any) -> str:
    if isinstance(value, float):
        return _stable_float(value)
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(_stable_json(value), sort_keys=True, separators=(",", ":"))
    return str(value)


def _stable_float(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    return f"{value:.12g}"


def _stable_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _stable_json(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable_json(v) for v in value]
    if isinstance(value, float):
        return float(_stable_float(value))
    if isinstance(value, np.generic):
        return value.item()
    return value


def _json_dumps(data: Mapping[str, Any]) -> str:
    return json.dumps(_stable_json(data), sort_keys=True, indent=2, separators=(",", ": ")) + "\n"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_column(rows: Sequence[Mapping[str, str]], candidates: Sequence[str]) -> Optional[str]:
    if not rows:
        return None
    columns = set(rows[0])
    lower_to_name = {name.lower(): name for name in columns}
    for candidate in candidates:
        if candidate.lower() in lower_to_name:
            return lower_to_name[candidate.lower()]
    return None


def _require_column(rows: Sequence[Mapping[str, str]], candidates: Sequence[str], description: str) -> str:
    column = _first_column(rows, candidates)
    if not column:
        raise GateFailure(f"missing required {description} column; tried {', '.join(candidates)}")
    return column


def _to_number(value: Any, *, default: float = 0.0) -> float:
    if value is None or str(value).strip() == "":
        return default
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return float(int(text, 16))
        return float(text)
    except ValueError:
        return default


def _to_int(value: Any, *, default: int = 0) -> int:
    return int(round(_to_number(value, default=float(default))))


def _flag_value(value: Any) -> int:
    text = str(value).strip().lower()
    if text in ("", "none", "null", "na"):
        return 0
    if text in TEXT_FALSE:
        return 0
    if text in TEXT_TRUE:
        return 1
    return 1 if _to_number(text, default=0.0) != 0 else 0


def _is_success_label(row: Mapping[str, str]) -> bool:
    success_col = _first_column([row], ("success", "in_policy", "is_success", "valid_epoch"))
    if success_col:
        text = row.get(success_col, "").strip().lower()
        if text in TEXT_TRUE:
            return True
        if text in TEXT_FALSE:
            return False
    status_col = _first_column([row], ("status", "result", "outcome", "epoch_status"))
    if status_col:
        text = row.get(status_col, "").strip().lower()
        if text in TEXT_FALSE:
            return False
        if any(token in text for token in ("fail", "fault", "overflow", "error", "drop", "replay")):
            return False
        return True
    return True


def _is_leakage_domain_label(row: Mapping[str, str]) -> bool:
    """Return whether an epoch belongs to the balanced RN-L leakage domain.

    Boundary, control, overflow, and captured smoke cases remain part of the
    structural invariant checks, but they must not create sparse protected
    classes in the statistical leakage experiment.
    """

    domain_col = _first_column(
        [row],
        ("primary_rn_l", "leakage_domain", "in_leakage_domain", "is_leakage_domain"),
    )
    if not domain_col:
        return True
    return bool(_flag_value(row.get(domain_col, "0")))


def _serialize_sequence(values: Iterable[Any]) -> str:
    return "|".join(str(v) for v in values)


def _serialize_counts(counter: Mapping[str, int]) -> str:
    return "|".join(f"{key}={counter[key]}" for key in sorted(counter))


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return float("nan")
    return float(np.percentile(np.asarray(values, dtype=float), percentile, method="linear"))


def empirical_categorical_mi(labels: Sequence[Any], feature_values: Sequence[Any]) -> float:
    """Return empirical discrete mutual information in bits."""
    if len(labels) != len(feature_values):
        raise ValueError("labels and feature_values length mismatch")
    n = len(labels)
    if n == 0:
        return float("nan")
    xy = Counter(zip(labels, feature_values))
    x_count = Counter(feature_values)
    y_count = Counter(labels)
    total = float(n)
    mi = 0.0
    for (label, feature), count in xy.items():
        pxy = count / total
        px = x_count[feature] / total
        py = y_count[label] / total
        mi += pxy * math.log2(pxy / (px * py))
    return max(0.0, float(mi))


def _permutation_null(
    labels: Sequence[Any],
    feature_values: Sequence[Any],
    *,
    permutations: int,
    seed: int,
) -> Dict[str, Any]:
    rng = np.random.default_rng(seed)
    labels_array = np.asarray(list(labels), dtype=object)
    null = []
    for _ in range(permutations):
        permuted = labels_array.copy()
        rng.shuffle(permuted)
        null.append(empirical_categorical_mi(permuted.tolist(), feature_values))
    return {
        "runs": permutations,
        "seed": seed,
        "median": float(np.median(null)) if null else float("nan"),
        "ci95": [_percentile(null, 2.5), _percentile(null, 97.5)],
    }


def _detect_public_metadata_columns(rows: Sequence[Mapping[str, str]]) -> List[str]:
    if not rows:
        return []
    columns = [name for name in rows[0] if not name.startswith("_")]
    public = []
    for column in columns:
        lower = column.lower()
        if lower in PUBLIC_METADATA_CANDIDATES:
            public.append(column)
    return sorted(public)


def _detect_counter_column(rows: Sequence[Mapping[str, str]]) -> Optional[str]:
    return _first_column(rows, COUNTER_CANDIDATES)


def _detect_structural_length_columns(rows: Sequence[Mapping[str, str]]) -> List[str]:
    if not rows:
        return []
    columns = set(rows[0])
    lower_to_name = {name.lower(): name for name in columns}
    found = []
    for candidate in STRUCTURAL_LENGTH_CANDIDATES:
        column = lower_to_name.get(candidate.lower())
        if column:
            found.append(column)
    return sorted(set(found))


def _safe_label_column(labels: Sequence[Mapping[str, str]], requested: Optional[str]) -> str:
    if not labels:
        raise GateFailure("analysis labels CSV has no rows")
    if requested:
        if requested not in labels[0]:
            raise GateFailure(f"requested label column {requested!r} is absent from analysis labels")
        return requested
    candidates = (
        "inner_length",
        "protected_inner_length",
        "inner_len",
        "L",
        "transaction_class",
        "class",
        "label",
    )
    return _require_column(labels, candidates, "protected label")


def _join_labels(
    cell_rows: Sequence[Mapping[str, str]],
    label_rows: Sequence[Mapping[str, str]],
) -> Dict[str, Dict[str, str]]:
    epoch_col_cells = _require_column(cell_rows, ("capture_epoch_index",), "cell epoch key")
    epoch_col_labels = _require_column(label_rows, ("capture_epoch_index",), "label epoch key")
    label_by_epoch: Dict[str, Dict[str, str]] = {}
    for row in label_rows:
        epoch = row[epoch_col_labels]
        if epoch in label_by_epoch:
            raise GateFailure(f"duplicate label row for capture_epoch_index={epoch}")
        label_by_epoch[epoch] = dict(row)
    missing = sorted({row[epoch_col_cells] for row in cell_rows} - set(label_by_epoch))
    if missing:
        preview = ", ".join(missing[:10])
        raise GateFailure(f"missing analysis label rows for epoch(s): {preview}")
    return label_by_epoch


def build_epoch_features(
    cell_rows: Sequence[Mapping[str, str]],
    label_rows: Sequence[Mapping[str, str]],
    *,
    label_column: Optional[str] = None,
    transaction_column: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if not cell_rows:
        raise GateFailure("observer outer cell CSV has no rows")

    epoch_col = _require_column(cell_rows, ("capture_epoch_index",), "capture epoch key")
    direction_col = _require_column(cell_rows, ("direction", "dir"), "direction")
    wire_len_col = _require_column(cell_rows, ("wire_len", "outer_wire_len", "packet_len", "frame_len", "len"), "wire length")
    slot_col = _first_column(cell_rows, ("slot_name", "slot", "slot_id"))
    offset_col = _first_column(cell_rows, ("slot_offset_us", "offset_us", "relative_time_us", "rel_time_us", "timestamp_rel_us"))
    cell_index_col = _first_column(cell_rows, ("cell_index", "cell_idx", "index"))
    fragment_col = _first_column(cell_rows, ("fragment_flag", "fragment", "ip_fragment", "frag"))
    retry_col = _first_column(cell_rows, ("retry_or_error_flag", "retry_error", "retry", "error_flag", "error"))
    policy_col = _first_column(cell_rows, ("policy_id", "policy"))
    counter_col = _detect_counter_column(cell_rows)
    public_meta_cols = _detect_public_metadata_columns(cell_rows)
    structural_length_cols = _detect_structural_length_columns(cell_rows)

    label_by_epoch = _join_labels(cell_rows, label_rows)
    selected_label_col = _safe_label_column(label_rows, label_column)
    if transaction_column and transaction_column not in label_rows[0]:
        raise GateFailure(f"requested transaction column {transaction_column!r} is absent from analysis labels")
    source_tx_col = transaction_column or _first_column(label_rows, ("source_transaction_id", "transaction_id", "trace_id", "session_id"))
    leakage_domain_col = _first_column(
        label_rows,
        ("primary_rn_l", "leakage_domain", "in_leakage_domain", "is_leakage_domain"),
    )

    grouped: Dict[str, List[Mapping[str, str]]] = defaultdict(list)
    for row in cell_rows:
        grouped[row[epoch_col]].append(row)

    feature_rows: List[Dict[str, Any]] = []
    for epoch in sorted(grouped, key=_sort_key):
        rows = sorted(grouped[epoch], key=lambda row: _row_sort_key(row, offset_col, cell_index_col))
        label_row = label_by_epoch[epoch]
        wire_sizes = [_to_int(row.get(wire_len_col)) for row in rows]
        directions = [row.get(direction_col, "") for row in rows]
        slots = [row.get(slot_col, "") if slot_col else "" for row in rows]
        offsets = [_to_number(row.get(offset_col), default=float(index)) if offset_col else float(index) for index, row in enumerate(rows)]
        inter_offsets = [0.0] + [round(offsets[i] - offsets[i - 1], 12) for i in range(1, len(offsets))]
        fragments = [_flag_value(row.get(fragment_col, "0")) if fragment_col else 0 for row in rows]
        retries = [_flag_value(row.get(retry_col, "0")) if retry_col else 0 for row in rows]
        dir_slot_counts = Counter(f"{direction}:{slot}" for direction, slot in zip(directions, slots))
        policy_values = sorted({row.get(policy_col, "") for row in rows}) if policy_col else []

        counter_stride_pattern = ""
        if counter_col:
            # Counters live in independent direction-specific nonce spaces.
            # Normalize each visible direction separately; a subtraction at a
            # direction transition has no protocol meaning and would leak only
            # an artifact of combining two ledgers.
            counters_by_direction: Dict[str, List[int]] = defaultdict(list)
            for row in rows:
                counters_by_direction[row.get(direction_col, "")].append(
                    _to_int(row.get(counter_col))
                )
            counter_stride_pattern = ";".join(
                "%s:%s"
                % (
                    direction,
                    _serialize_sequence(
                        values[index] - values[index - 1]
                        for index in range(1, len(values))
                    ),
                )
                for direction, values in sorted(counters_by_direction.items())
            )

        public_metadata = []
        structural_lengths = []
        for row in rows:
            public_metadata.append(tuple((column, row.get(column, "")) for column in public_meta_cols))
            structural_lengths.append(tuple((column, _to_int(row.get(column))) for column in structural_length_cols))

        count_vector = _serialize_counts(dir_slot_counts)
        size_vector = _serialize_sequence(wire_sizes)
        direction_sequence = _serialize_sequence(directions)
        slot_timing_vector = _serialize_sequence(f"{slot}@{_stable_float(offset)}" for slot, offset in zip(slots, offsets))
        relative_timing_vector = _serialize_sequence(_stable_float(offset) for offset in inter_offsets)
        public_metadata_vector = _serialize_sequence(public_metadata)
        structural_length_vector = _serialize_sequence(structural_lengths)
        whole_transcript = "||".join(
            [
                size_vector,
                count_vector,
                direction_sequence,
                slot_timing_vector,
                relative_timing_vector,
                structural_length_vector,
                public_metadata_vector,
                counter_stride_pattern,
            ]
        )

        feature_rows.append(
            {
                "capture_epoch_index": epoch,
                "analysis_label": label_row[selected_label_col],
                "source_transaction_id": label_row.get(source_tx_col, epoch) if source_tx_col else epoch,
                "is_success": int(_is_success_label(label_row)),
                "is_leakage_domain": int(_is_leakage_domain_label(label_row)),
                "policy_values": _serialize_sequence(policy_values),
                "cell_count": len(rows),
                "total_outer_bytes": sum(wire_sizes),
                "unique_wire_len_count": len(set(wire_sizes)),
                "size_vector": size_vector,
                "count_vector": count_vector,
                "direction_sequence": direction_sequence,
                "slot_timing_vector": slot_timing_vector,
                "relative_timing_vector": relative_timing_vector,
                "structural_length_vector": structural_length_vector,
                "public_metadata_vector": public_metadata_vector,
                "counter_stride_pattern": counter_stride_pattern,
                "whole_structural_transcript": whole_transcript,
                "fragment_flag_sum": sum(fragments),
                "retry_or_error_flag_sum": sum(retries),
            }
        )

    metadata = {
        "columns": {
            "epoch": epoch_col,
            "direction": direction_col,
            "wire_len": wire_len_col,
            "slot": slot_col,
            "offset": offset_col,
            "cell_index": cell_index_col,
            "fragment": fragment_col,
            "retry_or_error": retry_col,
            "policy": policy_col,
            "counter": counter_col,
            "structural_lengths": structural_length_cols,
            "label": selected_label_col,
            "source_transaction": source_tx_col,
            "leakage_domain": leakage_domain_col,
            "public_metadata": public_meta_cols,
        }
    }
    return feature_rows, metadata


def _sort_key(value: Any) -> Tuple[int, Any]:
    text = str(value)
    try:
        return (0, int(text))
    except ValueError:
        return (1, text)


def _row_sort_key(row: Mapping[str, str], offset_col: Optional[str], cell_index_col: Optional[str]) -> Tuple[float, int, int]:
    offset = _to_number(row.get(offset_col), default=0.0) if offset_col else float(_to_int(row.get("_row_order")))
    cell_index = _to_int(row.get(cell_index_col), default=_to_int(row.get("_row_order"))) if cell_index_col else _to_int(row.get("_row_order"))
    return (offset, cell_index, _to_int(row.get("_row_order")))


def check_invariants(feature_rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    success_rows = [row for row in feature_rows if int(row["is_success"]) == 1]
    if not success_rows:
        raise GateFailure("no successful in-policy epochs are available for observer leakage tests")

    checks = {
        "fixed_total_outer_bytes": _constant(success_rows, "total_outer_bytes"),
        "fixed_cell_count": _constant(success_rows, "cell_count"),
        "fixed_ordered_size_vector": _constant(success_rows, "size_vector"),
        "fixed_count_vector": _constant(success_rows, "count_vector"),
        "fixed_direction_sequence": _constant(success_rows, "direction_sequence"),
        "fixed_slot_timing_vector": _constant(success_rows, "slot_timing_vector"),
        "fixed_relative_timing_vector": _constant(success_rows, "relative_timing_vector"),
        "fixed_structural_length_vector": _constant(success_rows, "structural_length_vector"),
        "fixed_public_metadata_vector": _constant(success_rows, "public_metadata_vector"),
        "fixed_counter_stride_pattern": _constant(success_rows, "counter_stride_pattern"),
        "single_fixed_wire_size": all(int(row["unique_wire_len_count"]) == 1 for row in success_rows),
        "zero_fragment_flags": all(int(row["fragment_flag_sum"]) == 0 for row in success_rows),
        "zero_retry_or_error_flags": all(int(row["retry_or_error_flag_sum"]) == 0 for row in success_rows),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    return {
        "passed": not failed,
        "failed": failed,
        "checks": checks,
        "success_epoch_count": len(success_rows),
        "all_epoch_count": len(feature_rows),
    }


def _constant(rows: Sequence[Mapping[str, Any]], column: str) -> bool:
    return len({row[column] for row in rows}) <= 1


def mutual_information_report(
    feature_rows: Sequence[Mapping[str, Any]],
    *,
    permutations: int,
    seed: int,
) -> Dict[str, Any]:
    success_rows = [
        row
        for row in feature_rows
        if int(row["is_success"]) == 1 and int(row["is_leakage_domain"]) == 1
    ]
    if not success_rows:
        raise GateFailure("no successful epochs belong to the statistical leakage domain")
    labels = [row["analysis_label"] for row in success_rows]
    features = {
        "total_outer_bytes": [row["total_outer_bytes"] for row in success_rows],
        "size_vector": [row["size_vector"] for row in success_rows],
        "count_vector": [row["count_vector"] for row in success_rows],
        "direction_sequence": [row["direction_sequence"] for row in success_rows],
        "slot_timing_vector": [row["slot_timing_vector"] for row in success_rows],
        "whole_structural_transcript": [row["whole_structural_transcript"] for row in success_rows],
    }
    report: Dict[str, Any] = {}
    for index, (name, values) in enumerate(features.items()):
        observed = empirical_categorical_mi(labels, values)
        null = _permutation_null(labels, values, permutations=permutations, seed=seed + index + 1)
        low, high = null["ci95"]
        passed = observed <= null["median"] + EPSILON and low - EPSILON <= observed <= high + EPSILON
        report[name] = {
            "observed_bits": observed,
            "permutation_null": null,
            "passed": bool(passed),
        }
    return report


def classifier_report(
    feature_rows: Sequence[Mapping[str, Any]],
    *,
    bootstraps: int,
    seed: int,
) -> Dict[str, Any]:
    success_rows = [
        row
        for row in feature_rows
        if int(row["is_success"]) == 1 and int(row["is_leakage_domain"]) == 1
    ]
    labels = np.asarray([row["analysis_label"] for row in success_rows], dtype=object)
    groups = np.asarray([row["source_transaction_id"] for row in success_rows], dtype=object)
    classes = sorted(set(labels.tolist()))
    if len(classes) < 2:
        raise GateFailure("classifier analysis requires at least two protected label classes")

    group_count = len(set(groups.tolist()))
    min_class_count = min(Counter(labels.tolist()).values())
    if group_count < 5 or min_class_count < 5:
        raise GateFailure(
            "transaction-disjoint classifier analysis requires at least five groups and five samples per protected class"
        )
    n_splits = 5

    X_dicts = [_classifier_features(row) for row in success_rows]
    models = {
        "dummy_most_frequent": DummyClassifier(strategy="most_frequent"),
        "logistic_regression": make_pipeline(
            DictVectorizer(sparse=False),
            StandardScaler(),
            LogisticRegression(max_iter=1000, random_state=seed, class_weight="balanced"),
        ),
        "random_forest": make_pipeline(
            DictVectorizer(sparse=False),
            RandomForestClassifier(
                n_estimators=200,
                random_state=seed,
                class_weight="balanced_subsample",
                min_samples_leaf=1,
            ),
        ),
    }
    wrapped_X: Any = X_dicts
    reports: Dict[str, Any] = {}
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    chance = 1.0 / len(classes)

    for name, model in models.items():
        y_true_parts: List[Any] = []
        y_pred_parts: List[Any] = []
        fold_reports = []
        for fold_index, (train_idx, test_idx) in enumerate(splitter.split(np.zeros(len(labels)), labels, groups)):
            X_train = [wrapped_X[i] for i in train_idx]
            X_test = [wrapped_X[i] for i in test_idx]
            y_train = labels[train_idx]
            y_test = labels[test_idx]
            fitted = model.fit(X_train, y_train)
            prediction = fitted.predict(X_test)
            y_true_parts.extend(y_test.tolist())
            y_pred_parts.extend(prediction.tolist())
            fold_reports.append(
                {
                    "fold": fold_index,
                    "test_size": int(len(test_idx)),
                    "test_groups": int(len(set(groups[test_idx].tolist()))),
                    "balanced_accuracy": float(balanced_accuracy_score(y_test, prediction)),
                }
            )

        ba = float(balanced_accuracy_score(y_true_parts, y_pred_parts))
        ci = _stratified_bootstrap_ci(y_true_parts, y_pred_parts, bootstraps=bootstraps, seed=seed + len(reports) + 101)
        is_dummy = name.startswith("dummy")
        passed = (
            True
            if is_dummy
            else ci[0] - EPSILON <= chance <= ci[1] + EPSILON
        )
        reports[name] = {
            "balanced_accuracy": ba,
            "balanced_accuracy_ci95": ci,
            "passed": bool(passed),
            "folds": fold_reports,
            "is_dummy": is_dummy,
        }

    return {
        "chance": chance,
        "classes": classes,
        "n_splits": n_splits,
        "bootstraps": bootstraps,
        "seed": seed,
        "models": reports,
    }


def _classifier_features(row: Mapping[str, Any]) -> Dict[str, Any]:
    features: Dict[str, Any] = {
        "total_outer_bytes": float(row["total_outer_bytes"]),
        "cell_count": float(row["cell_count"]),
        "unique_wire_len_count": float(row["unique_wire_len_count"]),
        "fragment_flag_sum": float(row["fragment_flag_sum"]),
        "retry_or_error_flag_sum": float(row["retry_or_error_flag_sum"]),
    }
    for column in (
        "size_vector",
        "count_vector",
        "direction_sequence",
        "slot_timing_vector",
        "relative_timing_vector",
        "structural_length_vector",
        "public_metadata_vector",
        "counter_stride_pattern",
        "whole_structural_transcript",
    ):
        features[f"{column}={row[column]}"] = 1.0
    return features


def _stratified_bootstrap_ci(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    *,
    bootstraps: int,
    seed: int,
) -> List[float]:
    rng = np.random.default_rng(seed)
    y_true_arr = np.asarray(list(y_true), dtype=object)
    y_pred_arr = np.asarray(list(y_pred), dtype=object)
    by_class = {label: np.flatnonzero(y_true_arr == label) for label in sorted(set(y_true_arr.tolist()))}
    scores = []
    for _ in range(bootstraps):
        sampled_parts = []
        for indices in by_class.values():
            sampled_parts.append(rng.choice(indices, size=len(indices), replace=True))
        sample = np.concatenate(sampled_parts)
        scores.append(float(balanced_accuracy_score(y_true_arr[sample], y_pred_arr[sample])))
    return [_percentile(scores, 2.5), _percentile(scores, 97.5)]


def analyze(
    observer_outer_cells_csv: Path,
    analysis_labels_csv: Path,
    observer_features_csv: Path,
    observer_stats_json: Path,
    *,
    label_column: Optional[str],
    transaction_column: Optional[str],
    permutations: int,
    bootstraps: int,
    seed: int,
) -> Dict[str, Any]:
    cell_rows = _read_csv(observer_outer_cells_csv)
    label_rows = _read_csv(analysis_labels_csv)
    feature_rows, metadata = build_epoch_features(
        cell_rows,
        label_rows,
        label_column=label_column,
        transaction_column=transaction_column,
    )
    invariant_report = check_invariants(feature_rows)
    mi = mutual_information_report(feature_rows, permutations=permutations, seed=seed)
    classifiers = classifier_report(feature_rows, bootstraps=bootstraps, seed=seed)

    failures = []
    if not invariant_report["passed"]:
        failures.extend(f"invariant:{name}" for name in invariant_report["failed"])
    for name, result in mi.items():
        if not result["passed"]:
            failures.append(f"mutual_information:{name}")
    for name, result in classifiers["models"].items():
        if not result["passed"]:
            failures.append(f"classifier:{name}")

    fieldnames = [
        "capture_epoch_index",
        "analysis_label",
        "source_transaction_id",
        "is_success",
        "is_leakage_domain",
        "policy_values",
        "cell_count",
        "total_outer_bytes",
        "unique_wire_len_count",
        "size_vector",
        "count_vector",
        "direction_sequence",
        "slot_timing_vector",
        "relative_timing_vector",
        "structural_length_vector",
        "public_metadata_vector",
        "counter_stride_pattern",
        "whole_structural_transcript",
        "fragment_flag_sum",
        "retry_or_error_flag_sum",
    ]
    _write_csv(observer_features_csv, feature_rows, fieldnames)

    stats = {
        "schema_version": 1,
        "inputs": {
            "observer_outer_cells_csv": str(observer_outer_cells_csv),
            "analysis_labels_csv": str(analysis_labels_csv),
            "observer_outer_cells_sha256": _sha256(observer_outer_cells_csv),
            "analysis_labels_sha256": _sha256(analysis_labels_csv),
        },
        "outputs": {
            "observer_features_csv": str(observer_features_csv),
            "observer_stats_json": str(observer_stats_json),
        },
        "parameters": {
            "label_column": metadata["columns"]["label"],
            "transaction_column": metadata["columns"]["source_transaction"],
            "permutations": permutations,
            "bootstraps": bootstraps,
            "seed": seed,
            "epsilon": EPSILON,
        },
        "detected_columns": metadata["columns"],
        "invariants": invariant_report,
        "mutual_information_bits": mi,
        "classifiers": classifiers,
        "gate": {
            "passed": not failures,
            "failures": failures,
        },
        "versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "sklearn": sklearn.__version__,
        },
    }
    observer_stats_json.parent.mkdir(parents=True, exist_ok=True)
    observer_stats_json.write_text(_json_dumps(stats), encoding="utf-8")
    return stats


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze fixed-cell observer transcripts for structural size leakage."
    )
    parser.add_argument("--observer-outer-cells", required=True, type=Path, help="Input observer_outer_cells.csv")
    parser.add_argument("--analysis-labels", required=True, type=Path, help="Input analysis_labels.csv")
    parser.add_argument("--observer-features", required=True, type=Path, help="Output observer_features.csv")
    parser.add_argument("--observer-stats", required=True, type=Path, help="Output observer_stats.json")
    parser.add_argument("--label-column", help="Protected label column in analysis_labels.csv; auto-detected by default")
    parser.add_argument(
        "--transaction-column",
        help="Source transaction/session column for transaction-disjoint splits; auto-detected or epoch fallback",
    )
    parser.add_argument("--permutations", type=int, default=DEFAULT_PERMUTATIONS)
    parser.add_argument("--bootstraps", type=int, default=DEFAULT_BOOTSTRAPS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.permutations < 1000:
        raise GateFailure("at least 1000 label permutations are required for a gate-passing run")
    if args.bootstraps < 2000:
        raise GateFailure("at least 2000 bootstrap resamples are required for a gate-passing run")
    stats = analyze(
        args.observer_outer_cells,
        args.analysis_labels,
        args.observer_features,
        args.observer_stats,
        label_column=args.label_column,
        transaction_column=args.transaction_column,
        permutations=args.permutations,
        bootstraps=args.bootstraps,
        seed=args.seed,
    )
    if not stats["gate"]["passed"]:
        print(
            "observer gate FAIL: " + ", ".join(stats["gate"]["failures"]),
            file=sys.stderr,
        )
        return 1
    print(f"observer gate PASS: {stats['invariants']['success_epoch_count']} successful epochs")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as exc:
        print(f"observer gate FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Evaluate Formby et al. classifiers on the completed randomized-delay run.

This is an offline attacker evaluation; it never reads switch-selected delays as
features and never changes the running Tofino program.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import sys
from datetime import datetime

import numpy as np
import sklearn
from sklearn.impute import SimpleImputer
from sklearn.metrics import (accuracy_score, balanced_accuracy_score,
                             confusion_matrix, precision_recall_fscore_support)
from sklearn.model_selection import GridSearchCV, GroupKFold
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import analysis as timing_analysis  # noqa: E402
import evaluate as current_evaluation  # noqa: E402

RESULTS = HERE / "results/grid_random_screen_20260927T021133Z"
DEFAULT_OUTPUT = RESULTS / "formby_evaluation"
POLICIES = tuple(f"da{delay}_gap1_joint_amp0p5" for delay in (5, 10, 15, 20))
TASK_SOURCE_CLASSES = {
    "three_class": {"READ": ("READ",), "SELECT": ("SELECT",), "OPERATE": ("OPERATE",)},
    "read_select": {"READ": ("READ",), "SELECT": ("SELECT",)},
    "read_sbo": {"READ": ("READ",), "SBO": ("SELECT", "OPERATE")},
}
CLASSES = {task: tuple(class_map) for task, class_map in TASK_SOURCE_CLASSES.items()}
POOLS = (1, 5, 20)
FEATURES = ("ack_clrt", "formby_histogram")
MODELS = ("ff_ann", "multinomial_nb")
SEED = 20260928
LATE_THRESHOLD_MS = 1.0


def histogram_vector(values, h_ms: float, bins: int = 200) -> np.ndarray:
    """Formby's B-bin count signature: B-1 equal bins and a >H overflow bin."""
    values = np.asarray(values, dtype=float)
    if bins < 2 or not math.isfinite(h_ms) or h_ms <= 0:
        raise ValueError("histogram requires bins >= 2 and finite H > 0")
    if values.ndim != 1 or not len(values) or not np.isfinite(values).all():
        raise ValueError("histogram input must be a nonempty finite vector")
    if (values < 0).any():
        raise ValueError("CLRT values must be nonnegative")
    in_range = np.histogram(values[values <= h_ms], bins=bins - 1,
                            range=(0.0, h_ms))[0]
    overflow = np.asarray([np.count_nonzero(values > h_ms)], dtype=np.int64)
    return np.concatenate((in_range.astype(np.int64), overflow))


def partition_rows(rows, training_rounds, test_rounds):
    training_ids = {int(value) for value in training_rounds}
    test_ids = {int(value) for value in test_rounds}
    if not training_ids or not test_ids or training_ids & test_ids:
        raise ValueError("training and test rounds must be nonempty and disjoint")
    for row in rows:
        row["replicate"] = int(row["replicate"])
    return ([r for r in rows if r["replicate"] in training_ids],
            [r for r in rows if r["replicate"] in test_ids])


def select_arm(rows, arm: str, policy: str | None = None):
    if arm not in ("native", "obfuscated"):
        raise ValueError("arm must be native or obfuscated")
    selected = [r for r in rows if r["arm"] == arm]
    if arm == "native":
        return [r for r in selected if r["policy_name"] == "OFF"]
    if policy not in POLICIES:
        raise ValueError("obfuscated selection requires one of the four measured policies")
    return [r for r in selected if r["policy_name"] == policy]


def rows_for_task(rows, task: str):
    """Copy measured response rows with task-specific labels; SBO has one label."""
    if task not in TASK_SOURCE_CLASSES:
        raise ValueError(f"unsupported classification task: {task}")
    label_by_source = {source: label
                       for label, sources in TASK_SOURCE_CLASSES[task].items()
                       for source in sources}
    selected = []
    for row in rows:
        label = label_by_source.get(row["txn_class"])
        if label is not None:
            selected.append({**row, "txn_class": label})
    return selected


def pooled_samples(rows, feature: str, pool_size: int, h_ms: float | None = None):
    """Build nonoverlapping signatures without crossing capture/block/class boundaries."""
    if pool_size not in POOLS:
        raise ValueError(f"unsupported pool size: {pool_size}")
    if feature not in FEATURES:
        raise ValueError(f"unsupported feature representation: {feature}")
    if feature == "formby_histogram" and h_ms is None:
        raise ValueError("Formby histograms require an H value learned from training data")

    groups = {}
    for row in rows:
        key = (int(row["replicate"]), row["block"], row["arm"],
               row["policy_name"], row["txn_class"])
        groups.setdefault(key, []).append(row)
    samples = []
    for key, group in sorted(groups.items(), key=lambda item: item[0]):
        group.sort(key=lambda r: int(r["txn_index"]))
        for start in range(0, len(group) - pool_size + 1, pool_size):
            window = group[start:start + pool_size]
            base = dict(replicate=key[0], block=key[1], arm=key[2],
                        policy_name=key[3], txn_class=key[4],
                        pool_start=start, pool_size=pool_size)
            late_values = [float(r["response_minus_selected_ms"]) > LATE_THRESHOLD_MS
                           for r in window if r.get("response_minus_selected_ms") not in (None, "")]
            base["late_count"] = sum(late_values) if late_values else None
            if feature == "formby_histogram":
                base["features"] = histogram_vector(
                    [float(r["clrt_ms"]) for r in window], h_ms)
            else:
                pooled = timing_analysis.pooled_rows(window, pool_size)[0]
                base["features"] = timing_analysis._pooled_feature_matrix(
                    [pooled], feature)[0]
            samples.append(base)
    return samples


def _feature_limit(training_rows, feature):
    if feature != "formby_histogram":
        return None
    values = np.asarray([float(r["clrt_ms"]) for r in training_rows], dtype=float)
    if not len(values) or not np.isfinite(values).all() or (values < 0).any():
        raise ValueError("invalid training CLRT values for histogram bound")
    return max(float(values.max()), np.finfo(float).eps)


def make_classifier(model: str):
    if model == "ff_ann":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("mlp", MLPClassifier(hidden_layer_sizes=(100,), solver="adam",
                                   max_iter=300, early_stopping=True,
                                   n_iter_no_change=12, random_state=SEED)),
        ]), {"mlp__hidden_layer_sizes": [(32,), (100,)],
             "mlp__alpha": [0.0001, 0.01]}
    if model == "multinomial_nb":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("nb", MultinomialNB()),
        ]), {"nb__alpha": [0.1, 1.0, 10.0]}
    raise ValueError(f"unsupported Formby classifier: {model}")


def fit_classifier(model: str, training_samples):
    x = np.asarray([s["features"] for s in training_samples], dtype=float)
    y = [s["txn_class"] for s in training_samples]
    groups = [s["replicate"] for s in training_samples]
    unique_groups = sorted(set(groups))
    if len(unique_groups) < 5:
        raise ValueError("at least five training rounds are required for grouped tuning")
    estimator, params = make_classifier(model)
    search = GridSearchCV(estimator, params, scoring="balanced_accuracy",
                          cv=GroupKFold(n_splits=5), n_jobs=1,
                          refit=True, error_score="raise")
    search.fit(x, y, groups=groups)
    return search.best_estimator_, dict(search.best_params_), float(search.best_score_)


def score_classifier(estimator, samples, classes):
    x = np.asarray([s["features"] for s in samples], dtype=float)
    true = np.asarray([s["txn_class"] for s in samples])
    predicted = estimator.predict(x)
    cm = confusion_matrix(true, predicted, labels=list(classes))
    precision, recall, f1, support = precision_recall_fscore_support(
        true, predicted, labels=list(classes), zero_division=0)
    per_round = []
    for round_id in sorted({s["replicate"] for s in samples}):
        indices = [i for i, s in enumerate(samples) if s["replicate"] == round_id]
        round_true = true[indices]
        if set(round_true) == set(classes):
            round_precision, round_recall, _, _ = precision_recall_fscore_support(
                round_true, predicted[indices], labels=list(classes), zero_division=0)
            per_round.append(dict(round=round_id,
                                  accuracy=float(accuracy_score(round_true, predicted[indices])),
                                  balanced_accuracy=float(balanced_accuracy_score(
                                      round_true, predicted[indices])),
                                  mean_precision=float(round_precision.mean()),
                                  per_class_precision={name: float(round_precision[i])
                                                       for i, name in enumerate(classes)},
                                  per_class_recall={name: float(round_recall[i])
                                                    for i, name in enumerate(classes)}))
    values = np.asarray([x["balanced_accuracy"] for x in per_round], dtype=float)
    accuracies = np.asarray([x["accuracy"] for x in per_round], dtype=float)
    recalls_by_class = {
        name: np.asarray([row["per_class_recall"][name] for row in per_round], dtype=float)
        for name in classes
    }
    recalls = np.asarray([value for row in per_round
                          for value in row["per_class_recall"].values()], dtype=float)
    precisions_by_class = {
        name: np.asarray([row["per_class_precision"][name] for row in per_round], dtype=float)
        for name in classes
    }
    precisions = np.asarray([value for row in per_round
                             for value in row["per_class_precision"].values()], dtype=float)
    round_precisions = np.asarray([row["mean_precision"] for row in per_round], dtype=float)
    if len(values):
        rng = np.random.default_rng(SEED)
        draws = rng.integers(0, len(values), size=(5000, len(values)))
        means = values[draws].mean(axis=1)
        ci = [float(np.quantile(means, .025)), float(np.quantile(means, .975))]
    else:
        ci = [None, None]
    return dict(
        n_samples=len(samples), n_rounds=len(per_round),
        accuracy=float(accuracy_score(true, predicted)),
        balanced_accuracy=float(balanced_accuracy_score(true, predicted)),
        round_mean_accuracy=float(accuracies.mean()) if len(accuracies) else None,
        round_min_accuracy=float(accuracies.min()) if len(accuracies) else None,
        round_mean_precision=float(round_precisions.mean()) if len(round_precisions) else None,
        round_min_precision=float(precisions.min()) if len(precisions) else None,
        round_min_precision_round=(per_round[int(np.argmin(precisions) // len(classes))]["round"]
                                   if len(precisions) else None),
        round_min_precision_class=(list(classes)[int(np.argmin(precisions) % len(classes))]
                                   if len(precisions) else None),
        round_mean_precision_by_class={name: float(values.mean())
                                       for name, values in precisions_by_class.items()
                                       if len(values)},
        round_min_precision_by_class={name: float(values.min())
                                      for name, values in precisions_by_class.items()
                                      if len(values)},
        round_mean_recall=float(recalls.mean()) if len(recalls) else None,
        round_min_recall=float(recalls.min()) if len(recalls) else None,
        round_min_recall_round=(per_round[int(np.argmin(recalls) // len(classes))]["round"]
                                if len(recalls) else None),
        round_min_recall_class=(list(classes)[int(np.argmin(recalls) % len(classes))]
                                if len(recalls) else None),
        round_mean_recall_by_class={name: float(values.mean())
                                    for name, values in recalls_by_class.items()
                                    if len(values)},
        round_min_recall_by_class={name: float(values.min())
                                   for name, values in recalls_by_class.items()
                                   if len(values)},
        round_mean_balanced_accuracy=float(values.mean()) if len(values) else None,
        round_balanced_accuracy_ci95=ci,
        confusion_matrix=cm.tolist(), class_order=list(classes),
        per_class={name: dict(precision=float(precision[i]), recall=float(recall[i]),
                              f1=float(f1[i]), support=int(support[i]))
                   for i, name in enumerate(classes)},
        round_scores=per_round)


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_dataset(csv_path, measurements_path, protocol_path):
    measurements = json.loads(Path(measurements_path).read_text())
    protocol = json.loads(Path(protocol_path).read_text())
    actual_hash = _sha(csv_path)
    if measurements.get("status") != "ok":
        raise ValueError("only a completed, restored acquisition can be analyzed")
    if measurements.get("primary_csv_sha256") != actual_hash:
        raise ValueError("transaction CSV does not match the frozen measurement hash")
    if measurements.get("row_count") != 240000:
        raise ValueError("unexpected transaction row count")
    if protocol.get("delays_ms") != [5, 10, 15, 20] or protocol.get("center_gap_ms") != 1.0:
        raise ValueError("this analysis expects the measured DA grid and DR center of 1 ms")
    if protocol.get("amplitude_ms") != 0.5:
        raise ValueError("unexpected randomized-delay amplitude")
    run_dir = Path(measurements["run_dir"])
    final_status_path = run_dir / "final_status.json"
    if not final_status_path.exists():
        raise ValueError("hardware-run restoration record is missing")
    final_status = json.loads(final_status_path.read_text())
    if final_status.get("configuration_restored") is not True or final_status.get("error"):
        raise ValueError("hardware run did not finish with restored configuration")
    program_identity = json.loads((run_dir / "program_identity.json").read_text())
    if program_identity.get("ingress_stages") != 7:
        raise ValueError("the long run did not use the expected seven-ingress-stage program")
    before = json.loads((run_dir / "live_identity_before.json").read_text())
    after = json.loads((run_dir / "live_identity_after.json").read_text())
    expected_artifacts = program_identity.get("artifact_sha256")
    if not expected_artifacts or before.get("artifact_sha256") != expected_artifacts or \
       after.get("artifact_sha256") != expected_artifacts:
        raise ValueError("live program artifacts changed during the long run")
    captures = sorted((run_dir / "collected_blocks").glob("*/raw_pcaps/*.pcapng"))
    if len(captures) != 800:
        raise ValueError(f"expected 800 archived captures; found {len(captures)}")
    times = []
    for capture in captures:
        stamp = capture.stem.rsplit("_", 1)[-1]
        times.append(datetime.strptime(stamp, "%Y%m%dT%H%M%S%fZ"))
    span_hours = (max(times) - min(times)).total_seconds() / 3600.0
    if span_hours < 20.0:
        raise ValueError(f"archived captures span only {span_hours:.2f} hours")
    return measurements, protocol, actual_hash, len(captures), span_hours


def _read_rows(path):
    rows = current_evaluation.read_rows(Path(path))
    for row in rows:
        row["replicate"] = int(row["replicate"])
        for field in ("selected_da_ms", "selected_gap_ms", "selected_r_ms",
                      "response_minus_selected_ms"):
            value = row.get(field)
            row[field] = float(value) if value not in (None, "") else None
    return rows


def _build_samples(rows, feature, pool, h):
    return pooled_samples(rows, feature, pool, h)


def _record_result(result, *, feature, model, task, scenario, policy, pool,
                   h_ms, parameters, cv_score):
    return dict(feature=feature, model=model, task=task, scenario=scenario,
                policy=policy, da_ms=(int(policy[2:].split("_", 1)[0])
                                     if policy != "native" else None),
                pool_size=pool, histogram_h_ms=h_ms, chosen_parameters=parameters,
                training_cv_balanced_accuracy=cv_score, **result)


def fit_saved_classifier(model, training_samples, parameters):
    """Refit the frozen hyperparameter choice without repeating model search."""
    estimator, _ = make_classifier(model)
    estimator.set_params(**parameters)
    estimator.fit(np.asarray([s["features"] for s in training_samples], dtype=float),
                  [s["txn_class"] for s in training_samples])
    return estimator


def _assert_same_predictions(saved, rescored):
    if saved.get("confusion_matrix") != rescored["confusion_matrix"]:
        raise ValueError("refit confusion matrix differs from frozen evaluation")
    for field in ("accuracy", "balanced_accuracy"):
        if not math.isclose(float(saved[field]), rescored[field], abs_tol=1e-12, rel_tol=0):
            raise ValueError(f"refit {field} differs from frozen evaluation")


def _write_metrics_csv(summary, output):
    fields = ["task", "feature", "model", "scenario", "policy", "da_ms", "pool_size",
              "n_samples", "n_rounds", "accuracy", "balanced_accuracy",
              "round_mean_accuracy", "round_min_accuracy", "round_mean_precision",
              "round_min_precision", "round_min_precision_round", "round_min_precision_class",
              "round_mean_precision_by_class", "round_min_precision_by_class", "round_mean_recall",
              "round_min_recall", "round_min_recall_round", "round_min_recall_class",
              "round_mean_recall_by_class", "round_min_recall_by_class",
              "round_mean_balanced_accuracy", "round_balanced_accuracy_ci95",
              "training_cv_balanced_accuracy", "histogram_h_ms", "chosen_parameters"]
    with (Path(output) / "metrics.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for record in summary["results"]:
            writer.writerow({key: json.dumps(record.get(key), sort_keys=True)
                             if isinstance(record.get(key), (dict, list)) else record.get(key)
                             for key in fields})


def refresh_round_metrics(summary_path, csv_path, measurements_path, protocol_path):
    """Re-score frozen models and add round accuracy/recall without retuning them."""
    summary_path = Path(summary_path)
    summary = json.loads(summary_path.read_text())
    _, _, csv_hash, _, _ = verify_dataset(csv_path, measurements_path, protocol_path)
    if summary.get("source", {}).get("csv_sha256") != csv_hash:
        raise ValueError("frozen result summary does not match the verified transaction table")
    rows = _read_rows(csv_path)
    training_rows, test_rows = partition_rows(rows, range(40), range(40, 100))
    records = summary["results"]
    by_key = {(r["task"], r["feature"], r["model"], r["scenario"], r["policy"], r["pool_size"]): r
              for r in records}
    groups = sorted({(r["task"], r["feature"], r["model"], r["pool_size"])
                     for r in records if r["scenario"] == "static_before"})
    refreshed = 0
    for task, feature, model, pool in groups:
        classes = CLASSES[task]
        native_training = rows_for_task(select_arm(training_rows, "native"), task)
        native_test = rows_for_task(select_arm(test_rows, "native"), task)
        baseline = by_key[(task, feature, model, "static_before", "native", pool)]
        h_native = baseline["histogram_h_ms"]
        static_train_samples = pooled_samples(native_training, feature, pool, h_native)
        static_model = fit_saved_classifier(model, static_train_samples,
                                            baseline["chosen_parameters"])
        baseline_score = score_classifier(static_model,
            pooled_samples(native_test, feature, pool, h_native), classes)
        _assert_same_predictions(baseline, baseline_score)
        baseline.update(baseline_score)
        refreshed += 1
        for policy in POLICIES:
            protected_rows = rows_for_task(select_arm(test_rows, "obfuscated", policy), task)
            protected_samples = pooled_samples(protected_rows, feature, pool, h_native)
            static_key = (task, feature, model, "static_after", policy, pool)
            static_score = score_classifier(static_model, protected_samples, classes)
            _assert_same_predictions(by_key[static_key], static_score)
            by_key[static_key].update(static_score)
            refreshed += 1

            adaptive_key = (task, feature, model, "adaptive", policy, pool)
            adaptive_result = by_key[adaptive_key]
            adaptive_rows = rows_for_task(select_arm(training_rows, "obfuscated", policy), task)
            h_adaptive = adaptive_result["histogram_h_ms"]
            adaptive_train_samples = pooled_samples(adaptive_rows, feature, pool, h_adaptive)
            adaptive_model = fit_saved_classifier(model, adaptive_train_samples,
                                                  adaptive_result["chosen_parameters"])
            adaptive_samples = pooled_samples(protected_rows, feature, pool, h_adaptive)
            adaptive_score = score_classifier(adaptive_model, adaptive_samples, classes)
            _assert_same_predictions(adaptive_result, adaptive_score)
            adaptive_result.update(adaptive_score)
            refreshed += 1
        print("REFRESHED", task, feature, model, pool, flush=True)

    for result in records:
        if result.get("scenario", "").endswith("fully_late_diagnostic"):
            result.setdefault("round_mean_accuracy", None)
            result.setdefault("round_min_accuracy", None)
            result.setdefault("round_mean_precision", None)
            result.setdefault("round_min_precision", None)
            result.setdefault("round_min_precision_round", None)
            result.setdefault("round_min_precision_class", None)
            result.setdefault("round_mean_precision_by_class", {})
            result.setdefault("round_min_precision_by_class", {})
            result.setdefault("round_mean_recall", None)
            result.setdefault("round_min_recall", None)
            result.setdefault("round_min_recall_round", None)
            result.setdefault("round_min_recall_class", None)
            result.setdefault("round_mean_recall_by_class", {})
            result.setdefault("round_min_recall_by_class", {})
    summary["metric_notes"] = {
        "round_accuracy": "Accuracy is computed separately for each held-out acquisition round; round mean and minimum summarize those scores.",
        "round_precision": "Precision is computed for every class in each held-out round. Mean precision averages class-round precision values; minimum precision is the lowest observed class-round precision. Per-class round means and minima are retained.",
        "round_recall": "Recall is computed for every class in each held-out round. Mean recall averages all class-round recalls; minimum recall is the lowest class-round recall. Per-class round means and minima are also retained.",
        "uncertainty": "Round minima are observed worst cases, not confidence bounds. Existing balanced-accuracy bootstrap intervals remain separate.",
    }
    summary_path.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    _write_metrics_csv(summary, summary_path.parent)
    return refreshed


def run_analysis(csv_path, measurements_path, protocol_path, output, tasks=None):
    measurements, protocol, csv_hash, capture_count, capture_span_hours = verify_dataset(
        csv_path, measurements_path, protocol_path)
    rows = _read_rows(csv_path)
    if len(rows) != 240000:
        raise ValueError("CSV row count differs from its measurement manifest")
    training_rows, test_rows = partition_rows(rows, range(40), range(40, 100))
    if {r["replicate"] for r in training_rows} != set(range(40)) or \
       {r["replicate"] for r in test_rows} != set(range(40, 100)):
        raise ValueError("the frozen 40/60 round split is incomplete")
    from collections import Counter
    counts = Counter((r["arm"], r["policy_name"], int(r["replicate"]), r["txn_class"])
                     for r in rows)
    for policy in POLICIES:
        for round_id in range(100):
            for operation in CLASSES["three_class"]:
                if counts[("obfuscated", policy, round_id, operation)] != 100:
                    raise ValueError(f"incomplete protected block {policy}/r{round_id}/{operation}")
    for round_id in range(100):
        for operation in CLASSES["three_class"]:
            if counts[("native", "OFF", round_id, operation)] != 400:
                raise ValueError(f"incomplete native reference r{round_id}/{operation}")
    policy_diagnostics = {}
    for policy in POLICIES:
        policy_diagnostics[policy] = {}
        for operation in CLASSES["three_class"]:
            selected = [r for r in test_rows if r["arm"] == "obfuscated" and
                        r["policy_name"] == policy and r["txn_class"] == operation]
            target_misses = [r for r in selected if r["response_minus_selected_ms"] is not None and
                             r["response_minus_selected_ms"] > LATE_THRESHOLD_MS]
            policy_diagnostics[policy][operation] = dict(
                heldout_responses=len(selected),
                selected_target_miss_count=len(target_misses),
                selected_target_miss_fraction=(len(target_misses) / len(selected) if selected else None),
                definition="Observed request-to-response time exceeded the selected response target by >1 ms; this is not packet loss.")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    selected_tasks = tuple(tasks or TASK_SOURCE_CLASSES)
    if not selected_tasks or len(set(selected_tasks)) != len(selected_tasks) or \
       any(task not in TASK_SOURCE_CLASSES for task in selected_tasks):
        raise ValueError("tasks must be a nonempty list of known, unique classification tasks")
    records = []
    for task in selected_tasks:
        classes = CLASSES[task]
        for feature in FEATURES:
            for pool in POOLS:
                for model in MODELS:
                    native_training = rows_for_task(select_arm(training_rows, "native"), task)
                    native_test = rows_for_task(select_arm(test_rows, "native"), task)
                    h_native = _feature_limit(native_training, feature)
                    static_training = _build_samples(native_training, feature, pool, h_native)
                    frozen, params, cv = fit_classifier(model, static_training)
                    before = _build_samples(native_test, feature, pool, h_native)
                    result = score_classifier(frozen, before, classes)
                    records.append(_record_result(result, feature=feature, model=model,
                        task=task, scenario="static_before", policy="native", pool=pool,
                        h_ms=h_native, parameters=params, cv_score=cv))
                    for policy in POLICIES:
                        obfuscated_test = rows_for_task(
                            select_arm(test_rows, "obfuscated", policy), task)
                        after = _build_samples(obfuscated_test, feature, pool, h_native)
                        result = score_classifier(frozen, after, classes)
                        records.append(_record_result(result, feature=feature, model=model,
                            task=task, scenario="static_after", policy=policy, pool=pool,
                            h_ms=h_native, parameters=params, cv_score=cv))

                        obfuscated_training = rows_for_task(
                            select_arm(training_rows, "obfuscated", policy), task)
                        h_adaptive = _feature_limit(obfuscated_training, feature)
                        adaptive_samples = _build_samples(obfuscated_training, feature, pool, h_adaptive)
                        adaptive, adaptive_params, adaptive_cv = fit_classifier(model, adaptive_samples)
                        adaptive_test = _build_samples(obfuscated_test, feature, pool, h_adaptive)
                        result = score_classifier(adaptive, adaptive_test, classes)
                        records.append(_record_result(result, feature=feature, model=model,
                            task=task, scenario="adaptive", policy=policy, pool=pool,
                            h_ms=h_adaptive, parameters=adaptive_params, cv_score=adaptive_cv))

                        # These are diagnostics on windows containing only responses that
                        # missed the selected release point by the established 1 ms margin.
                        fully_late = [s for s in adaptive_test if s["late_count"] == pool]
                        if len(fully_late) and {s["txn_class"] for s in fully_late} == set(classes):
                            late_result = score_classifier(adaptive, fully_late, classes)
                        else:
                            late_result = dict(n_samples=len(fully_late), n_rounds=0,
                                accuracy=None, balanced_accuracy=None,
                                round_mean_accuracy=None, round_min_accuracy=None,
                                round_mean_precision=None, round_min_precision=None,
                                round_min_precision_round=None, round_min_precision_class=None,
                                round_mean_precision_by_class={}, round_min_precision_by_class={},
                                round_mean_recall=None, round_min_recall=None,
                                round_min_recall_round=None, round_min_recall_class=None,
                                round_mean_recall_by_class={}, round_min_recall_by_class={},
                                round_mean_balanced_accuracy=None,
                                round_balanced_accuracy_ci95=[None, None],
                                confusion_matrix=None, class_order=list(classes), per_class=None,
                                round_scores=[])
                        records.append(_record_result(late_result, feature=feature, model=model,
                            task=task, scenario="adaptive_fully_late_diagnostic", policy=policy,
                            pool=pool, h_ms=h_adaptive, parameters=adaptive_params,
                            cv_score=adaptive_cv))
                        print("SCORED", task, feature, model, pool, policy, flush=True)
    summary = dict(
        source=dict(csv=str(Path(csv_path).resolve()), csv_sha256=csv_hash,
                    measurements_sha256=_sha(measurements_path),
                    protocol_sha256=_sha(protocol_path), row_count=len(rows),
                    archived_capture_count=capture_count,
                    archived_capture_span_hours=capture_span_hours,
                    capture_drops=measurements.get("capture_drops"),
                    missing_primary_responses=measurements.get("missing_primary_responses")),
        protocol=dict(delays_ms=protocol["delays_ms"], configured_dr_center_ms=protocol["center_gap_ms"],
                      randomized_amplitude_ms=protocol["amplitude_ms"],
                      training_rounds=list(range(40)), test_rounds=list(range(40, 100)),
                      tasks=CLASSES, pools=list(POOLS), feature_representations=list(FEATURES),
                      models=list(MODELS), late_threshold_ms=LATE_THRESHOLD_MS),
        model_notes={"ff_ann": "One-hidden-layer feed-forward network trained with backpropagation; 100-unit default, grouped tuning on training rounds only.",
                     "multinomial_nb": "Multinomial naïve Bayes; histogram counts match its count-vector interpretation. On ACK/CLRT summary values it is a nonnegative-feature adaptation, not Formby's original histogram input."},
        feature_notes={"ack_clrt": "Existing primary ACK and CLRT inputs; pooled mean, standard deviation, minimum, and maximum for pools greater than one.",
                       "formby_histogram": "200 CLRT bins, with 199 equal-width in-range bins and one >H overflow bin; H is fitted on training data only."},
        metric_notes={"round_accuracy": "Accuracy is computed separately for each held-out acquisition round; round mean and minimum summarize those scores.",
                      "round_precision": "Precision is computed for every class in each held-out round. Mean precision averages class-round precision values; minimum precision is the lowest observed class-round precision. Per-class round means and minima are retained.",
                      "round_recall": "Recall is computed for every class in each held-out round. Mean recall averages all class-round recalls; minimum recall is the lowest class-round recall. Per-class round means and minima are also retained.",
                      "uncertainty": "Round minima are observed worst cases, not confidence bounds. Existing balanced-accuracy bootstrap intervals remain separate."},
        delay_policy_diagnostics=policy_diagnostics,
        caveats=["Operation-class labels and the measured relay workload differ from Formby et al.'s device-type fingerprinting labels.",
                 "The static/adaptive split is grouped by acquisition round; it is not Formby's random 75/25 split.",
                 "late diagnostic contains only windows for which every constituent response exceeded its selected release point by more than 1 ms; small subsets are descriptive only."],
        results=records)
    results_path = output / "results.json"
    if set(selected_tasks) != set(TASK_SOURCE_CLASSES) and results_path.exists():
        previous = json.loads(results_path.read_text())
        retained = [record for record in previous.get("results", [])
                    if record["task"] not in selected_tasks]
        summary["results"] = retained + records
        summary["caveats"] = list(dict.fromkeys(previous.get("caveats", []) + summary["caveats"]))
    results_path.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    with (output / "metrics.csv").open("w", newline="") as stream:
        fields = ["task", "feature", "model", "scenario", "policy", "da_ms", "pool_size",
                  "n_samples", "n_rounds", "accuracy", "balanced_accuracy",
                  "round_mean_accuracy", "round_min_accuracy", "round_mean_precision",
                  "round_min_precision", "round_min_precision_round", "round_min_precision_class",
                  "round_mean_precision_by_class", "round_min_precision_by_class", "round_mean_recall",
                  "round_min_recall", "round_min_recall_round", "round_min_recall_class",
                  "round_mean_recall_by_class", "round_min_recall_by_class",
                  "round_mean_balanced_accuracy", "round_balanced_accuracy_ci95",
                  "training_cv_balanced_accuracy", "histogram_h_ms", "chosen_parameters"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for record in summary["results"]:
            writer.writerow({k: json.dumps(record[k], sort_keys=True)
                             if isinstance(record[k], (dict, list)) else record[k]
                             for k in fields})
    return summary


def append_static_late_diagnostics(summary_path, csv_path, output):
    """Score frozen native-trained Formby FF-ANNs on fully target-missed observations."""
    summary_path = Path(summary_path)
    summary = json.loads(summary_path.read_text())
    rows = _read_rows(csv_path)
    training_rows, test_rows = partition_rows(rows, range(40), range(40, 100))
    extra = []
    for task, classes in CLASSES.items():
        baseline = next(r for r in summary["results"] if r["task"] == task and
                        r["feature"] == "formby_histogram" and r["model"] == "ff_ann" and
                        r["scenario"] == "static_before" and r["pool_size"] == 1)
        native_train = rows_for_task(select_arm(training_rows, "native"), task)
        training_samples = pooled_samples(native_train, "formby_histogram", 1,
                                           baseline["histogram_h_ms"])
        estimator, _ = make_classifier("ff_ann")
        estimator.set_params(**baseline["chosen_parameters"])
        estimator.fit(np.asarray([s["features"] for s in training_samples], dtype=float),
                      [s["txn_class"] for s in training_samples])
        for policy in POLICIES:
            protected = rows_for_task(select_arm(test_rows, "obfuscated", policy), task)
            samples = pooled_samples(protected, "formby_histogram", 1,
                                     baseline["histogram_h_ms"])
            late = [s for s in samples if s["late_count"] == 1]
            if late and {s["txn_class"] for s in late} == set(classes):
                metrics = score_classifier(estimator, late, classes)
            else:
                metrics = dict(n_samples=len(late), n_rounds=0, accuracy=None,
                    balanced_accuracy=None, round_mean_balanced_accuracy=None,
                    round_mean_accuracy=None, round_min_accuracy=None,
                    round_mean_precision=None, round_min_precision=None,
                    round_min_precision_round=None, round_min_precision_class=None,
                    round_mean_precision_by_class={}, round_min_precision_by_class={},
                    round_mean_recall=None, round_min_recall=None,
                    round_min_recall_round=None, round_min_recall_class=None,
                    round_mean_recall_by_class={}, round_min_recall_by_class={},
                    round_balanced_accuracy_ci95=[None, None], confusion_matrix=None,
                    class_order=list(classes), per_class=None, round_scores=[])
            extra.append(_record_result(metrics, feature="formby_histogram", model="ff_ann",
                task=task, scenario="static_fully_late_diagnostic", policy=policy, pool=1,
                h_ms=baseline["histogram_h_ms"], parameters=baseline["chosen_parameters"],
                cv_score=baseline["training_cv_balanced_accuracy"]))
    summary["results"] = [r for r in summary["results"]
                           if r["scenario"] != "static_fully_late_diagnostic"] + extra
    caveat = ("Static fully-late diagnostics use the frozen native-trained FF-ANN and only held-out individual responses whose observed total time exceeded the selected response target by >1 ms.")
    if caveat not in summary["caveats"]:
        summary["caveats"].append(caveat)
    summary_path.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    output = Path(output)
    with (output / "metrics.csv").open("w", newline="") as stream:
        fields = ["task", "feature", "model", "scenario", "policy", "da_ms", "pool_size",
                  "n_samples", "n_rounds", "accuracy", "balanced_accuracy",
                  "round_mean_accuracy", "round_min_accuracy", "round_mean_precision",
                  "round_min_precision", "round_min_precision_round", "round_min_precision_class",
                  "round_mean_precision_by_class", "round_min_precision_by_class", "round_mean_recall",
                  "round_min_recall", "round_min_recall_round", "round_min_recall_class",
                  "round_mean_recall_by_class", "round_min_recall_by_class",
                  "round_mean_balanced_accuracy", "round_balanced_accuracy_ci95",
                  "training_cv_balanced_accuracy", "histogram_h_ms", "chosen_parameters"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for record in summary["results"]:
            writer.writerow({k: json.dumps(record[k], sort_keys=True)
                             if isinstance(record[k], (dict, list)) else record[k]
                             for k in fields})
    return len(extra)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--transactions", type=Path, default=RESULTS / "final/primarytransactions.csv")
    parser.add_argument("--measurements", type=Path, default=RESULTS / "final/measurements.json")
    parser.add_argument("--protocol", type=Path,
                        default=HERE / "evidence/delay_grid/random_screen_20260927T021133Z/protocol.json")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--append-static-late-diagnostics", action="store_true")
    parser.add_argument("--refresh-round-metrics", action="store_true",
                        help="rescore frozen models and add per-round accuracy/recall summaries")
    parser.add_argument("--task", action="append", choices=tuple(TASK_SOURCE_CLASSES),
                        help="run only this task; selected-task records replace prior records for that task")
    args = parser.parse_args()
    if args.refresh_round_metrics:
        count = refresh_round_metrics(args.out / "results.json", args.transactions,
                                      args.measurements, args.protocol)
        print(json.dumps(dict(output=str(args.out), refreshed_results=count), indent=2))
    elif args.append_static_late_diagnostics:
        count = append_static_late_diagnostics(args.out / "results.json", args.transactions, args.out)
        print(json.dumps(dict(output=str(args.out), appended_records=count), indent=2))
    else:
        summary = run_analysis(args.transactions, args.measurements, args.protocol, args.out,
                               tasks=args.task)
        print(json.dumps(dict(output=str(args.out), result_rows=len(summary["results"])), indent=2))


if __name__ == "__main__":
    main()

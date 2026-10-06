#!/usr/bin/env python3
"""Offline tests for the latency-search development evaluator."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import evaluate  # noqa: E402


def _rows(*, sessions=5, per_class=100, policies=("candidate",)):
    rows = []
    for session_idx in range(sessions):
        session = f"replicate_{session_idx:02}"
        for arm, policy_names in (("native", ("ref_off",)), ("obfuscated", policies)):
            for policy_name in policy_names:
                for class_idx, cls in enumerate(evaluate.a.CLASSES):
                    for txn_idx in range(per_class):
                        rows.append(
                            {
                                "session": session,
                                "block": f"{session}_{policy_name}",
                                "arm": arm,
                                "policy_name": policy_name,
                                "txn_class": cls,
                                "txn_index": txn_idx,
                                "ack_ms": class_idx + txn_idx * 0.001,
                                "clrt_ms": class_idx + 0.25 + txn_idx * 0.001,
                                "rt_ms": 2 * class_idx + 0.25 + txn_idx * 0.002,
                                "request_gap_ms": None if txn_idx == 0 else 0.4 + class_idx * 0.01,
                            }
                        )
    return rows


def _patch_fast_models(monkeypatch):
    train_calls = []
    score_calls = []

    def fake_train(model, rows, features, tune):
        rows = list(rows)
        train_calls.append(
            {
                "model": model,
                "rows": rows,
                "features": features,
                "tune": tune,
                "sessions": {r["session"] for r in rows},
                "arms": {r["arm"] for r in rows},
            }
        )
        return object(), {"chosen": model} if tune else {}

    def fake_score(estimator, rows, features):
        rows = list(rows)
        score_calls.append(
            {
                "rows": rows,
                "features": features,
                "sessions": {r["session"] for r in rows},
                "arms": {r["arm"] for r in rows},
            }
        )
        return 0.25 if features == "request_gap" else 0.4

    monkeypatch.setattr(evaluate, "train", fake_train)
    monkeypatch.setattr(evaluate, "score", fake_score)
    return train_calls, score_calls


def test_evaluate_requires_complete_native_and_candidate_classes_per_group(monkeypatch):
    """Each paired replicate must have all three classes in both native and protected arms."""
    _patch_fast_models(monkeypatch)
    rows = _rows()
    rows = [
        r
        for r in rows
        if not (
            r["session"] == "replicate_03"
            and r["policy_name"] == "candidate"
            and r["txn_class"] == "OPERATE"
            and r["txn_index"] == 99
        )
    ]

    with pytest.raises(ValueError, match="Incomplete paired group: replicate_03"):
        evaluate.evaluate(rows, "candidate", quick=True)


def test_evaluate_uses_paired_groups_and_disjoint_outer_train_test(monkeypatch):
    """Outer folds leave out one paired replicate for both fixed and adaptive attacks."""
    train_calls, score_calls = _patch_fast_models(monkeypatch)

    result = evaluate.evaluate(_rows(per_class=100), "candidate", quick=True)

    assert result["groups"] == [f"replicate_{i:02}" for i in range(5)]
    assert result["quick"] is True
    for call in train_calls:
        assert len(call["sessions"]) == 4
        assert call["arms"] in ({"native"}, {"obfuscated"})
    for call in score_calls:
        assert len(call["sessions"]) == 1
        assert call["arms"] in ({"native"}, {"obfuscated"})
    for group in result["groups"]:
        assert any(group not in call["sessions"] for call in train_calls)
        assert any(call["sessions"] == {group} for call in score_calls)


def test_train_tunes_with_leave_one_training_group_out(monkeypatch):
    """Nested tuning must split only within the outer training rows, grouped by session."""
    captured = {}

    class FakeEstimator:
        def fit(self, x, y):
            captured["direct_fit"] = True
            return self

    class FakeGridSearch:
        def __init__(self, estimator, params, scoring, cv, n_jobs, refit, error_score):
            captured["params"] = params
            captured["cv"] = cv
            captured["scoring"] = scoring
            self.best_params_ = {"best": 1}

        def fit(self, x, y, groups):
            captured["x_shape"] = x.shape
            captured["y"] = list(y)
            captured["groups"] = list(groups)
            return self

        def predict(self, x):  # pragma: no cover - train() only returns this fake.
            return []

    monkeypatch.setattr(evaluate.a, "_model", lambda _model: FakeEstimator())
    monkeypatch.setattr(evaluate, "GridSearchCV", FakeGridSearch)
    rows = [
        {
            "session": session,
            "txn_class": cls,
            "ack_ms": idx + 0.1,
            "clrt_ms": idx + 0.2,
            "rt_ms": idx + 0.3,
            "request_gap_ms": idx + 0.4,
        }
        for idx, (session, cls) in enumerate(
            [("s1", "READ"), ("s1", "SELECT"), ("s2", "READ"), ("s2", "SELECT")]
        )
    ]

    _estimator, chosen = evaluate.train("logistic", rows, "ack_clrt", tune=True)

    assert chosen == {"best": 1}
    assert type(captured["cv"]).__name__ == "LeaveOneGroupOut"
    assert captured["groups"] == ["s1", "s1", "s2", "s2"]
    assert captured["y"] == ["READ", "SELECT", "READ", "SELECT"]
    assert captured["x_shape"] == (4, 2)
    assert "direct_fit" not in captured


def test_bounds_exclude_native_diagnostic_and_preserve_shared_group_bootstrap():
    """The envelope is over protected attacks only and resamples the same fold indices."""
    records = [
        {
            "model": "native_model",
            "feature": "ack_clrt",
            "pool": 1,
            "scenario": "fixed_on_native",
            "fold_scores": [1.0, 1.0, 1.0],
        },
        {
            "model": "fixed",
            "feature": "ack_clrt",
            "pool": 1,
            "scenario": "fixed_on_obfuscated",
            "fold_scores": [0.2, 0.5, 0.8],
        },
        {
            "model": "adaptive",
            "feature": "request_gap",
            "pool": 1,
            "scenario": "adaptive_on_obfuscated",
            "fold_scores": [0.8, 0.5, 0.2],
        },
    ]

    ack = evaluate.bounds(records, "ack_response", confidence=0.5)
    all_timing = evaluate.bounds(records, "all_timing", confidence=0.5)

    assert ack["strongest_attack"]["scenario"] == "fixed_on_obfuscated"
    assert ack["max_accuracy"] == pytest.approx(0.5)
    assert all_timing["strongest_attack"]["scenario"] != "fixed_on_native"
    assert all_timing["max_accuracy"] == pytest.approx(0.5)
    assert all_timing["n_groups"] == 3
    assert "paired-group bootstrap" in all_timing["method"]


def test_quick_mode_marks_incomplete_coverage_and_full_mode_covers_grid(monkeypatch):
    """Quick runs are diagnostics; full runs cover every model/feature/pool combination."""
    _patch_fast_models(monkeypatch)

    quick = evaluate.evaluate(_rows(), "candidate", quick=True)
    quick_records = quick["tasks"]["three_class"]["records"]
    assert {(r["model"], r["feature"], r["pool"]) for r in quick_records} == {("rf", "ack_clrt", 1)}
    assert quick["complete_attack_coverage"] is False
    assert quick["qualifies_for_selection"] is False
    quick_envelope = quick["tasks"]["three_class"]["envelopes"]["ack_response"]
    assert quick_envelope["within_tested_subset_threshold"] in (False, True)
    assert quick_envelope["passes_screen"] is False

    full = evaluate.evaluate(_rows(), "candidate", quick=False)
    full_records = full["tasks"]["three_class"]["records"]
    assert {r["pool"] for r in full_records} == {1, 5, 20}
    assert {r["feature"] for r in full_records} == set(evaluate.a.FEATURE_SETS)
    assert {r["model"] for r in full_records} == set(evaluate.PARAMS)
    assert full["complete_attack_coverage"] is True
    assert isinstance(full["qualifies_for_selection"], bool)
    full_envelope = full["tasks"]["three_class"]["envelopes"]["ack_response"]
    assert "within_tested_subset_threshold" in full_envelope
    assert "passes_screen" in full_envelope

import importlib.util
from pathlib import Path

import numpy as np


MODULE_PATH = Path(__file__).resolve().parents[1] / "formby_evaluation.py"
SPEC = importlib.util.spec_from_file_location("formby_evaluation", MODULE_PATH)
formby = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(formby)


def test_formby_histogram_has_199_in_range_bins_and_overflow():
    vector = formby.histogram_vector([0.0, 5.0, 10.0, 10.1], h_ms=10.0)

    assert vector.shape == (200,)
    assert vector.sum() == 4
    assert vector[0] == 1
    assert vector[99] == 1
    assert vector[-2] == 1  # H itself is retained in the last in-range bin.
    assert vector[-1] == 1  # Values above H go to Formby's overflow bin.


def test_pooled_samples_never_cross_round_or_block_boundaries():
    rows = [
        dict(replicate=0, session="replicate_00", block="a", arm="native", policy_name="OFF", txn_class="READ",
             txn_index=i, ack_ms=1.0, clrt_ms=float(i + 1))
        for i in range(5)
    ] + [
        dict(replicate=1, session="replicate_01", block="b", arm="native", policy_name="OFF", txn_class="READ",
             txn_index=i, ack_ms=1.0, clrt_ms=float(i + 11))
        for i in range(5)
    ]

    samples = formby.pooled_samples(rows, feature="formby_histogram", pool_size=5, h_ms=20.0)

    assert [sample["replicate"] for sample in samples] == [0, 1]
    assert all(sample["features"].sum() == 5 for sample in samples)


def test_round_partition_is_disjoint_and_preserves_requested_policy():
    rows = [
        dict(replicate=round_id, arm=arm, policy_name=policy, txn_class="READ")
        for round_id in range(3)
        for arm, policy in (("native", "OFF"), ("obfuscated", "da5_gap1_joint_amp0p5"))
    ]

    train, test = formby.partition_rows(rows, training_rounds=range(2), test_rounds=[2])

    assert {row["replicate"] for row in train}.isdisjoint({row["replicate"] for row in test})
    assert len(train) == 4
    assert len(test) == 2
    assert formby.select_arm(train, arm="native") == [row for row in train if row["arm"] == "native"]
    assert formby.select_arm(train, arm="obfuscated", policy="da5_gap1_joint_amp0p5") == [
        row for row in train if row["arm"] == "obfuscated"
    ]


def test_read_sbo_task_combines_select_and_operate_under_one_physical_function_label():
    rows = [
        dict(replicate=0, txn_class=operation, txn_index=index, clrt_ms=index + 1)
        for index, operation in enumerate(("READ", "SELECT", "OPERATE", "READ"))
    ]

    task_rows = formby.rows_for_task(rows, "read_sbo")

    assert [(row["txn_class"], row["txn_index"]) for row in task_rows] == [
        ("READ", 0), ("SBO", 1), ("SBO", 2), ("READ", 3)
    ]
    assert [row["txn_class"] for row in rows] == ["READ", "SELECT", "OPERATE", "READ"]


def test_sbo_signature_pool_keeps_select_and_operate_responses_together():
    rows = [
        dict(replicate=0, session="r0", block="a", arm="native", policy_name="OFF",
             txn_class=operation, txn_index=index, ack_ms=1.0, clrt_ms=float(index + 1))
        for index, operation in enumerate(("SELECT", "OPERATE") * 10)
    ]

    task_rows = formby.rows_for_task(rows, "read_sbo")
    samples = formby.pooled_samples(task_rows, feature="formby_histogram", pool_size=5,
                                    h_ms=10.0)

    assert len(samples) == 4
    assert all(sample["txn_class"] == "SBO" for sample in samples)
    assert [sample["features"].sum() for sample in samples] == [5, 5, 5, 5]


def test_score_classifier_summarizes_accuracy_and_recall_across_rounds():
    class EncodedPrediction:
        def predict(self, features):
            return np.asarray(["READ" if value == 0 else "SBO" for value in features[:, 0]])

    labels = ("READ", "READ", "SBO", "SBO")
    predictions = ((0, 0, 1, 0), (0, 1, 1, 1))
    samples = [
        {"replicate": round_id, "txn_class": label, "features": np.asarray([predicted])}
        for round_id, round_predictions in enumerate(predictions)
        for label, predicted in zip(labels, round_predictions)
    ]

    result = formby.score_classifier(EncodedPrediction(), samples, ("READ", "SBO"))

    assert result["round_mean_accuracy"] == 0.75
    assert result["round_min_accuracy"] == 0.75
    assert result["round_mean_recall"] == 0.75
    assert result["round_min_recall"] == 0.5
    assert result["round_min_recall_round"] == 0
    assert result["round_min_recall_class"] == "SBO"
    assert result["round_mean_recall_by_class"] == {"READ": 0.75, "SBO": 0.75}
    assert result["round_min_recall_by_class"] == {"READ": 0.5, "SBO": 0.5}
    assert np.isclose(result["round_mean_precision"], 5 / 6)
    assert result["round_min_precision"] == 2 / 3
    assert result["round_min_precision_round"] == 0
    assert result["round_min_precision_class"] == "READ"
    assert all(np.isclose(value, 5 / 6)
               for value in result["round_mean_precision_by_class"].values())
    assert result["round_min_precision_by_class"] == {"READ": 2 / 3, "SBO": 2 / 3}
    assert np.isclose(result["round_scores"][0]["per_class_precision"]["READ"], 2 / 3)
    assert result["round_scores"][0]["per_class_precision"]["SBO"] == 1.0

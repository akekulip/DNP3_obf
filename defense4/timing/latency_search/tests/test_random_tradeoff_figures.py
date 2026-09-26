"""Synthetic unit fixtures only; never acquisition or publication data."""
import csv
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import figures_random_tradeoff as f


@pytest.fixture
def inputs(tmp_path):
    rows = []
    for repeat in range(5):
        for arm, start in (("native", 1000), ("obfuscated", 5000)):
            for i, op in enumerate(f.shared.OPS):
                for n in range(100):
                    rows.append(dict(session=f"r{repeat}", block=f"r{repeat}_{arm}", arm=arm,
                        policy_name="candidate" if arm == "obfuscated" else "OFF",
                        txn_class=op, txn_index=i*100+n, t_req_ns=repeat*10000+start+i*100+n,
                        ack_ms=1, clrt_ms=1, request_gap_ms=1,
                        rt_ms=(10+i) if arm == "obfuscated" else (2+2*i)))
    csv_path = tmp_path/"primarytransactions.csv"
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, list(rows[0])); writer.writeheader(); writer.writerows(rows)
    plan = tmp_path/"plans/candidate.json"; plan.parent.mkdir()
    plan.write_text(json.dumps(dict(amplitude_ms=.5, mode="gap", center_da_ms=5, center_gap_ms=1)))
    measurement = tmp_path/"measurements.json"
    measurement.write_text(json.dumps(dict(status="ok", row_count=len(rows),
        primary_csv_sha256=f.shared.sha256_file(csv_path),
        inputs_sha256={str(plan):f.shared.sha256_file(plan)})))
    tasks = {}
    for task, chance in (("three_class", 1/3), ("read_select", .5)):
        tasks[task] = dict(chance=chance, threshold=chance+.05,
            envelopes={family:dict(max_accuracy=chance, upper_bound=chance+.1, passes_screen=False)
                       for family in ("ack_response", "all_timing")})
    _, chosen = f.evaluate_random.paired_rows(rows, "candidate")
    attack = tmp_path/"attacks.json"
    attack.write_text(json.dumps(dict(source_sha256=f.shared.sha256_file(csv_path),
        measurements_sha256=f.shared.sha256_file(measurement), quick=False,
        complete_attack_coverage=True, off_pairing={"candidate":chosen},
        per_policy={"candidate":dict(quick=False, complete_attack_coverage=True,
                                   tasks=tasks, qualifies_for_selection=False)})))
    return measurement, csv_path, attack


def test_added_operation_is_not_assumed_to_have_largest_total(inputs):
    rows = f.build_rows(*inputs)
    three = next(r for r in rows if r["task"] == "three_class")
    assert three["added_operation"] == "READ"
    assert three["added_median_ms"] == 8
    assert three["protected_median_at_added_operation_ms"] == 10
    assert three["off_median_at_added_operation_ms"] == 2
    assert three["worst_total_median_ms"] == 12
    assert three["worst_p99_ms"] == 12


def test_incomplete_attack_coverage_is_rejected(inputs):
    path = inputs[2]; doc = json.loads(path.read_text()); doc["complete_attack_coverage"] = False
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="full attack"):
        f.build_rows(*inputs)


def test_changed_installed_plan_is_rejected(inputs):
    path = inputs[0].parent/"plans/candidate.json"
    path.write_text(path.read_text()+"\n")
    with pytest.raises(ValueError, match="installed plan changed"):
        f.build_rows(*inputs)


def test_changed_off_pairing_is_rejected(inputs):
    path = inputs[2]; doc = json.loads(path.read_text()); doc["off_pairing"]["candidate"] = {}
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="OFF pairing"):
        f.build_rows(*inputs)

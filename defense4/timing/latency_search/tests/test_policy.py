import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
LATENCY = ROOT / "defense4" / "timing" / "latency_search"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defense4.timing.latency_search import configure, policy  # noqa: E402


def test_fixed_grid_has_requested_twenty_two_candidates_and_separate_refs():
    plan = policy.build_search_plan()

    fixed = [p for p in plan if p.kind == "fixed"]
    refs = [p for p in plan if p.kind == "reference"]

    assert len(fixed) == 22
    assert {(p.requested_da_ms, p.requested_gap_ms) for p in fixed} == {
        *((da, gap) for da in (5, 10, 15, 20) for gap in (1, 2, 4, 6, 8)),
        (4, 4),
        (12, 4),
    }
    assert {(p.name, p.mode, p.requested_da_ms, p.requested_gap_ms) for p in refs} == {
        ("ref_off_20_4", "OFF", 20, 4),
        ("ref_d4_20_4", "D4", 20, 4),
        ("ref_d4_20_8", "D4", 20, 8),
    }


def test_quantization_records_realized_values_and_setup_uses_realized_operate_times():
    p = policy.make_policy("da5_gap1", "fixed", "D4", 5, 1)

    assert p.da.word == 4_999_936
    assert p.gap.word == 999_936
    assert p.op_a_ms == pytest.approx(4.999936)
    assert p.op_r_ms == pytest.approx(5.999872)

    args = policy.setup_args(p)
    assert args[0:3] == ["python3", str(policy.DEFAULT_CONFIGURE), "plan-policy"]
    assert args[args.index("--da-ms") + 1] == "4.999936"
    assert args[args.index("--gap-ms") + 1] == "0.999936"


def test_default_large_j_codebook_invalidates_low_delay_but_small_shared_codebook_passes():
    default_j = (2, 6, 12)
    small_j = (0.25, 0.5, 1)

    low = policy.make_policy("da4_gap4", "fixed", "D4", 4, 4, j_set_ms=small_j)
    assert policy.validate_operate_guards(low).ok

    low_large_j = policy.make_policy("da4_gap4_large_j", "fixed", "D4", 4, 4, j_set_ms=default_j)
    bad = policy.validate_operate_guards(low_large_j)
    assert not bad.ok
    assert any("J_max" in reason and "native_ACK" in reason for reason in bad.reasons)

    ref = policy.make_policy("ref_d4_20_4", "reference", "D4", 20, 4, j_set_ms=default_j)
    assert policy.validate_operate_guards(ref).ok
    assert policy.validate_operate_guards(ref).risk == "reference_large_j"


def test_preflight_snapshot_detects_codebook_overlap_and_restore_is_not_valid_policy():
    snapshot = LATENCY / "evidence" / "preflight" / "switch.json"
    snap = configure.load_snapshot(snapshot)

    audit = configure.audit_codebook_snapshot(snap)
    assert audit.entry_count == 9
    assert audit.overlap_entry_count == 9
    assert audit.overlap_pair_count == 7
    assert not audit.valid_policy

    restore = configure.restore_plan_from_snapshot(snap)
    assert restore.restoration_only
    assert len(restore.codebook_entries) == 9
    assert restore.params_default.d_ticks == 20_000_000
    assert restore.bor_params_default.a_ticks == 20_000_000
    assert restore.bor_params_default.r_ticks == 24_000_000
    assert restore.notes[0].startswith("historical restoration exemption")


def test_codebook_repair_plan_covers_256_buckets_with_no_overlap_or_extra_entries():
    plan = configure.build_codebook_plan((0.25, 0.5, 1))

    audit = configure.audit_entries(plan.codebook_entries)
    assert audit.valid_policy
    assert audit.entry_count == 3
    assert audit.overlap_pair_count == 0
    assert plan.delete_existing_first
    assert plan.params_default is None
    assert plan.bor_params_default is None
    assert {bucket for e in plan.codebook_entries for bucket in range(e.low, e.high + 1)} == set(range(256))


def test_policy_plan_includes_read_lane_and_bor_defaults_for_exact_readback():
    p = policy.make_policy("da5_gap1", "fixed", "D4", 5, 1)
    plan = configure.build_policy_plan(p)

    assert plan.params_default.mode == 4
    assert plan.params_default.d_ticks == 4_999_936
    assert plan.params_default.da_dr == 5_999_872
    assert plan.bor_params_default.a_ticks == 4_999_936
    assert plan.bor_params_default.r_ticks == 5_999_872
    assert plan.bor_params_default.anchor_req == 1


def test_apply_validator_rejects_crafted_overlap_and_guard_bypass_before_live_write():
    good = configure.build_policy_plan(policy.make_policy("da5_gap1", "fixed", "D4", 5, 1))
    assert configure.validate_plan_for_apply(good).valid_policy

    overlapping = configure.ConfigPlan(
        codebook_entries=good.codebook_entries + (good.codebook_entries[0],),
        params_default=good.params_default,
        bor_params_default=good.bor_params_default,
    )
    with pytest.raises(ValueError, match="invalid codebook"):
        configure.validate_plan_for_apply(overlapping)

    bypass = configure.build_policy_plan(
        policy.make_policy("bad", "manual", "D4", 4, 4, j_set_ms=(2, 6, 12))
    )
    with pytest.raises(ValueError, match="native_ACK guard failed"):
        configure.validate_plan_for_apply(bypass)

    restore = configure.restore_plan_from_snapshot(
        configure.load_snapshot(LATENCY / "evidence" / "preflight" / "switch.json")
    )
    assert not configure.validate_plan_for_apply(restore).valid_policy


def test_policy_cli_dry_run_outputs_json_with_invalid_default_j_and_recommendation():
    result = subprocess.run(
        [sys.executable, str(LATENCY / "policy.py"), "--json"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    doc = json.loads(result.stdout)

    assert doc["counts"]["fixed"] == 22
    assert doc["recommendation"]["fixed_search_j_set_ms"] == [0.25, 0.5, 1.0]
    assert any(p["name"] == "da4_gap4" and p["guard"]["ok"] for p in doc["policies"])
    assert doc["references"][0]["name"].startswith("ref_")

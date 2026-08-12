"""Unit tests for the Defense-4 timing-policy analysis toolkit.

Exercises the policy model at the C<H / C=H / C>H boundaries and the D2 (D_A=0)
and D3 (D_R=0) edge policies, release-error inclusion, and every guardrail the
registry must enforce: a missing dataset, mixed time units, incompatible timing
definitions / pooling, the domain-common selector contract, and UNPINNED handling.

Audit-corrected regression tests are grouped at the end and cover: a late response
C>H (L_master uses a+C, not a+H), a request-to-ack latency a>0 in L_master, the
response-timeout margin using a+max(C,H), a MALFORMED NON-FIRST row being caught,
an unmeasured policy carrying an ESTIMATED (labelled) release error, a measured
policy labelled measured, a target-band tolerance derived from |eps_R-eps_A|, and
an UNKNOWN ACK/RTO/fail-open constraint staying UNKNOWN.

FIX-5 tests (grouped last) FAIL if: a DIFFERENTIAL eps is used as an ABSOLUTE one in
L_master; a POINT-ESTIMATE selection is MISLABELLED as confidence-qualified; an
UNPROVEN timeout (2000 ms) enters a numeric margin. Plus FIX-2 (conditional-vs-total
tolerance) and FIX-4 (timeout provenance) and a results.json schema check.

Runs under pytest if available, and standalone otherwise (a minimal shim +
runner). Standalone reports every test name with PASS/FAIL and exits non-zero on
any failure.

Run:  $RESEARCH_PYTHON tests/test_timing_policy.py        (standalone)
  or: $RESEARCH_PYTHON -m pytest tests/ -v                (if pytest installed)
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tpa import policy, registry, repo  # noqa: E402
import timing_policy_analysis as cli  # noqa: E402

# --- pytest or a minimal shim ------------------------------------------------
try:
    import pytest  # type: ignore
    HAVE_PYTEST = True
except ImportError:  # standalone shim
    HAVE_PYTEST = False
    import re
    from contextlib import contextmanager

    class _Approx:
        def __init__(self, v, abs=1e-6, rel=1e-6):
            self.v, self.abs, self.rel = float(v), abs, rel

        def __eq__(self, other):
            return abs(float(other) - self.v) <= max(self.abs, self.rel * abs(self.v))

        def __repr__(self):
            return f"approx({self.v})"

    class _Pytest:
        @staticmethod
        def approx(v, abs=1e-6, rel=1e-6):
            return _Approx(v, abs=abs, rel=rel)

        @staticmethod
        @contextmanager
        def raises(exc, match=None):
            try:
                yield
            except exc as e:  # noqa: B902
                if match and not re.search(match, str(e)):
                    raise AssertionError(f"raised {exc.__name__} but message "
                                         f"{str(e)!r} does not match {match!r}")
                return
            except Exception as e:  # noqa: B902
                raise AssertionError(f"expected {exc.__name__}, got {type(e).__name__}: {e}")
            raise AssertionError(f"expected {exc.__name__} to be raised, none was")

    pytest = _Pytest()  # type: ignore

import yaml  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures: synthetic block files + registries in a tmp tree with a .git marker.
# ---------------------------------------------------------------------------


def _write_block(path: Path, rows_clrt_ms, mode="OFF", label="X", da="-", dr="-",
                 a_ms=0.5):
    """Write a block whose t_ack/t_resp are consistent with clrt_ms and whose
    t_read/read_to_ack_ms/read_to_resp_ms are consistent with a (seconds base)."""
    rows = []
    t0 = 1_000_000.0
    for i, c in enumerate(rows_clrt_ms):
        t_ack = t0 + i
        t_resp = t_ack + c / 1000.0
        rows.append({
            "poll": i, "app_seq_sent": "0xC0", "t_read": t_ack - a_ms / 1000.0,
            "t_ack": t_ack, "t_resp": t_resp, "resp_len": 134, "resp_segments": 1,
            "read_to_ack_ms": a_ms, "read_to_resp_ms": a_ms + c, "clrt_ms": c,
            "ack_before_resp": True, "order_inconclusive": False,
            "rst": False, "fin": False,
        })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "label": label, "mode": mode, "d_a_ms": da, "d_r_ms": dr,
        "N": len(rows), "n_rows": len(rows), "rows": rows,
    }))


def _repo(tmp_path: Path) -> Path:
    (tmp_path / ".git").write_text("gitdir: fake\n")  # worktree-style marker
    return tmp_path


def _base_dataset(dsid, relpath, sha, measures, da, dr, n, poolable=None, **over):
    d = {
        "id": dsid, "campaign": "t", "measures": measures, "device": "SEL-751",
        "state": "steady", "traffic_class": "READ", "capture_point": "master_facing",
        "timestamp_source": "libpcap", "unit_clrt": "ms",
        "t_A_def": "tcp ack", "t_R_def": "first resp byte", "C_def": "cdef",
        "binary_sha256": "aa", "d_a_ms": da, "d_r_ms": dr, "budget": 18000,
        "role": "test", "notes": "", "firmware": "UNPINNED x",
        "poolable_with": poolable or [],
        "blocks": [{"path": relpath, "sha256": sha, "n": n}],
    }
    d.update(over)
    return d


def _write_registry(root: Path, datasets, constraints=None):
    reg = {
        "registry_version": "test", "protection_domain": "test",
        "evidenced_constraints": constraints or {
            "poll_period_ms": 400.0, "fail_open_horizon_ms_at_budget_18000": 30.8,
            "dnp3_response_timeout_ms": 2000.0,
        },
        "datasets": datasets,
    }
    p = root / "registry.yaml"
    p.write_text(yaml.safe_dump(reg, sort_keys=False))
    return p


# ---------------------------------------------------------------------------
# Policy model: C < H, C = H, C > H
# ---------------------------------------------------------------------------


def test_C_less_than_H_all_covered():
    C = np.array([5.0, 6.0, 7.0])
    ev = policy.eval_policy(C, D_A=4, D_R=10, tol_ms=0.1)
    assert ev["H_ms"] == 14
    assert ev["native_tail_coverage"] == 1.0
    assert ev["n_late_safe_release"] == 0
    assert ev["visible_clrt_target_ms"] == 10
    assert ev["residual_tail_fraction"] == 0.0
    assert ev["added_resp_latency_max_ms"] == pytest.approx(14 - 5)


def test_C_equal_H_is_covered_boundary():
    C = np.array([14.0])
    ev = policy.eval_policy(C, D_A=4, D_R=10, tol_ms=0.1)
    assert ev["native_tail_coverage"] == 1.0             # C <= H inclusive
    assert ev["n_late_safe_release"] == 0
    assert ev["target_band_coverage"] == 1.0             # max(14-4,10)=10 on target
    assert ev["added_resp_latency_max_ms"] == pytest.approx(0.0)


def test_C_greater_than_H_is_late_safe_release():
    C = np.array([20.0])
    ev = policy.eval_policy(C, D_A=4, D_R=10, tol_ms=0.1)
    assert ev["native_tail_coverage"] == 0.0
    assert ev["n_late_safe_release"] == 1
    assert ev["residual_tail_fraction"] == 1.0           # visible 16 > D_R
    assert ev["target_band_coverage"] == 0.0


def test_D2_D_A_zero_no_ack_delay():
    C = np.array([5.0, 15.0])
    ev = policy.eval_policy(C, D_A=0, D_R=10, tol_ms=0.1)
    assert ev["ack_delay_ms"] == 0
    assert ev["H_ms"] == 10
    assert ev["native_tail_coverage"] == 0.5             # C=5 covered, C=15 late
    assert ev["n_late_safe_release"] == 1


def test_D3_D_R_zero_collapses_to_zero():
    C = np.array([2.0, 10.0])
    ev = policy.eval_policy(C, D_A=4, D_R=0, tol_ms=0.1)
    assert ev["H_ms"] == 4
    assert ev["visible_clrt_target_ms"] == 0
    assert ev["target_band_coverage"] == 0.5             # only max(2-4,0)=0 in band


def test_release_error_inclusion_shifts_prediction():
    C = np.array([5.0, 6.0])
    base = policy.eval_policy(C, 4, 10, tol_ms=0.1, eps_ms=0.0)
    shifted = policy.eval_policy(C, 4, 10, tol_ms=0.1, eps_ms=0.5)
    assert base["target_band_coverage"] == 1.0
    assert shifted["target_band_coverage"] == 0.0        # +0.5 leaves the 0.1 band
    assert shifted["release_error_eps_ms"] == 0.5


def test_measured_release_error_from_defended():
    out = np.array([10.001, 9.999, 10.000, 10.002])
    eps = policy.measured_release_error(out, D_R=10.0)
    assert eps == pytest.approx(0.0005, abs=1e-6)


# ---------------------------------------------------------------------------
# Registry guardrails
# ---------------------------------------------------------------------------


def test_missing_dataset_file_raises(tmp_path):
    root = _repo(tmp_path)
    ds = _base_dataset("d1", "does/not/exist.json", "deadbeef", "native_clrt",
                       "native", "native", 3)
    reg = registry.load_registry(_write_registry(root, [ds]))
    with pytest.raises(registry.RegistryError, match="missing raw file"):
        registry.validate(reg, root, verify_sha=False)


def test_sha256_mismatch_raises(tmp_path):
    root = _repo(tmp_path)
    _write_block(root / "b.json", [3.0, 4.0])
    ds = _base_dataset("d1", "b.json", "0" * 64, "native_clrt", "native", "native", 2)
    reg = registry.load_registry(_write_registry(root, [ds]))
    with pytest.raises(registry.RegistryError, match="sha256 mismatch"):
        registry.validate(reg, root, verify_sha=True)


def test_mixed_time_units_rejected(tmp_path):
    root = _repo(tmp_path)
    blk = root / "b.json"
    # 10 s apart (=> 10000 ms) but clrt_ms mislabeled as 10 (ms-vs-s mixing)
    blk.write_text(json.dumps({
        "label": "X", "mode": "OFF", "d_a_ms": "-", "d_r_ms": "-", "n_rows": 1,
        "rows": [{"poll": 0, "t_ack": 1000.0, "t_resp": 1010.0, "clrt_ms": 10.0,
                  "read_to_ack_ms": 0.5, "ack_before_resp": True}],
    }))
    ds = _base_dataset("d1", "b.json", repo.sha256_file(blk), "native_clrt",
                       "native", "native", 1)
    reg = registry.load_registry(_write_registry(root, [ds]))
    with pytest.raises(registry.RegistryError, match="unit/timing-def mismatch"):
        registry.validate(reg, root, verify_sha=True)


def test_unit_seconds_declaration_rejected(tmp_path):
    root = _repo(tmp_path)
    _write_block(root / "b.json", [3.0])
    ds = _base_dataset("d1", "b.json", repo.sha256_file(root / "b.json"),
                       "native_clrt", "native", "native", 1, unit_clrt="s")
    reg = registry.load_registry(_write_registry(root, [ds]))
    with pytest.raises(registry.RegistryError, match="unit_clrt='s' unsupported"):
        registry.validate(reg, root, verify_sha=True)


def test_incompatible_pooling_native_with_defended_raises(tmp_path):
    root = _repo(tmp_path)
    _write_block(root / "n.json", [3.0, 4.0])
    _write_block(root / "d.json", [10.0, 10.0], mode="D4", da=4, dr=10)
    nat = _base_dataset("nat", "n.json", repo.sha256_file(root / "n.json"),
                        "native_clrt", "native", "native", 2, poolable=["def"])
    dfd = _base_dataset("def", "d.json", repo.sha256_file(root / "d.json"),
                        "defended_clrt_out", 4, 10, 2, poolable=["nat"])
    reg = registry.load_registry(_write_registry(root, [nat, dfd]))
    with pytest.raises(registry.RegistryError, match="INCOMPATIBLE"):
        registry.validate(reg, root, verify_sha=True)


def test_poolable_rejects_different_timing_definition():
    a = _base_dataset("a", "x", "s", "native_clrt", "native", "native", 1,
                      C_def="C = t_R - t_A")
    b = _base_dataset("b", "y", "s", "native_clrt", "native", "native", 1,
                      C_def="C = something else")
    ok, reason = registry.poolable(a, b)
    assert not ok and "C_def" in reason


def test_poolable_accepts_identical_conditions():
    a = _base_dataset("a", "x", "s", "native_clrt", "native", "native", 1)
    b = _base_dataset("b", "y", "s", "native_clrt", "native", "native", 1)
    ok, _ = registry.poolable(a, b)
    assert ok


def test_different_policies_not_poolable():
    a = _base_dataset("a", "x", "s", "defended_clrt_out", 4, 10, 1)
    b = _base_dataset("b", "y", "s", "defended_clrt_out", 0, 10, 1)     # D2 vs D4
    ok, reason = registry.poolable(a, b)
    assert not ok and "d_a_ms" in reason


# ---------------------------------------------------------------------------
# Common-policy selector contract + UNPINNED handling
# ---------------------------------------------------------------------------


def test_common_policy_rejects_per_device_mapping():
    with pytest.raises(policy.SelectorError, match="domain-level"):
        policy.select_common_policy({"devA": np.array([1.0])}, [], coverage_min=0.9)


def test_common_policy_selects_single_policy():
    C = np.concatenate([np.full(99, 3.0), np.array([13.0])])
    grid = [(4, 10), (4, 12), (0, 10)]
    evals = [policy.eval_policy(C, da, dr, tol_ms=0.1, fail_open_horizon_ms=30.8)
             for da, dr in grid]
    sel = policy.select_common_policy(C, evals, coverage_min=0.99,
                                      require_fail_open_margin_ms=5.0)
    assert sel["selected"] is not None
    assert (sel["selected"]["D_A_ms"], sel["selected"]["D_R_ms"]) in grid
    assert len(sel["co_optimal_at_min_H"]) >= 1


def test_selector_excludes_D_R_zero():
    C = np.full(100, 2.0)
    evals = [policy.eval_policy(C, 4, 0, tol_ms=0.1, fail_open_horizon_ms=30.8)]  # D3
    sel = policy.select_common_policy(C, evals, coverage_min=0.5,
                                      require_fail_open_margin_ms=0.0)
    assert sel["selected"] is None            # D_R=0 gives no visible target


def test_unpinned_pool_key_blocks_pooling_and_is_reported(tmp_path):
    root = _repo(tmp_path)
    _write_block(root / "a.json", [3.0, 4.0])
    _write_block(root / "b.json", [3.0, 4.0])
    a = _base_dataset("a", "a.json", repo.sha256_file(root / "a.json"),
                      "native_clrt", "native", "native", 2,
                      device="UNPINNED unknown relay")
    b = _base_dataset("b", "b.json", repo.sha256_file(root / "b.json"),
                      "native_clrt", "native", "native", 2)
    ok, reason = registry.poolable(a, b)
    assert not ok and "UNPINNED" in reason
    reg = registry.load_registry(_write_registry(root, [a, b]))
    fields = {(u["dataset"], u["field"]) for u in registry.collect_unpinned(reg)}
    assert ("a", "device") in fields          # surfaced, not silently used
    assert ("a", "firmware") in fields


def test_entropy_and_summary_shapes():
    from tpa import stats
    h, eff = stats.entropy_bits(np.array([10.0, 10.0, 10.0, 10.0]))
    assert h == pytest.approx(0.0)            # one bin -> zero entropy
    assert eff == pytest.approx(1.0)
    s = stats.summary(np.arange(1, 201, dtype=float))
    assert s["n"] == 200 and s["p99"] is not None


# ---------------------------------------------------------------------------
# AUDIT-CORRECTION regression tests
# ---------------------------------------------------------------------------


def test_late_response_latency_uses_a_plus_C_not_a_plus_H():
    """C>H: L_master = a + C (late-safe release), NOT a + H."""
    C = np.array([20.0])
    a = np.array([1.0])
    ev = policy.eval_policy(C, D_A=4, D_R=10, tol_ms=0.1, a=a)   # H=14, C=20>H
    assert ev["L_master_max_ms"] == pytest.approx(1.0 + 20.0)    # a + C
    assert ev["L_master_max_ms"] != pytest.approx(1.0 + 14.0)    # NOT a + H
    assert ev["added_resp_latency_max_ms"] == pytest.approx(0.0)  # no added hold when late


def test_request_to_ack_latency_a_included_in_L_master():
    """a>0 enters L_master; covered txn L_master = a + H."""
    C = np.array([5.0])                       # covered under H=14
    ev0 = policy.eval_policy(C, 4, 10, tol_ms=0.1, a=np.array([0.0]))
    ev2 = policy.eval_policy(C, 4, 10, tol_ms=0.1, a=np.array([2.0]))
    assert ev0["L_master_max_ms"] == pytest.approx(14.0)         # 0 + max(5,14)
    assert ev2["L_master_max_ms"] == pytest.approx(16.0)         # 2 + max(5,14)
    assert ev2["a_read_to_ack_max_ms"] == pytest.approx(2.0)


def test_timeout_margin_uses_a_plus_max_C_H():
    """Response-timeout margin = timeout - max(a+max(C,H)); NOT timeout - H."""
    C = np.array([20.0]); a = np.array([1.0])          # late; L_master = 21
    ev = policy.eval_policy(C, 4, 10, tol_ms=0.1, a=a, response_timeout_ms=2000.0,
                            poll_period_ms=400.0)
    assert ev["margin_response_timeout_ms"] == pytest.approx(2000.0 - 21.0)
    assert ev["margin_response_timeout_ms"] != pytest.approx(2000.0 - 14.0)  # not vs H
    assert ev["margin_poll_period_ms"] == pytest.approx(400.0 - 21.0)


def test_malformed_nonfirst_row_is_caught(tmp_path):
    """A malformed row at index>0 (bad clrt) must be caught, not only row 0."""
    root = _repo(tmp_path)
    blk = root / "b.json"
    t0 = 1_000_000.0
    rows = []
    for i, c in enumerate([3.0, 4.0, 5.0]):
        t_ack = t0 + i
        rows.append({"poll": i, "t_read": t_ack - 0.0005, "t_ack": t_ack,
                     "t_resp": t_ack + c / 1000.0, "read_to_ack_ms": 0.5,
                     "clrt_ms": c, "ack_before_resp": True})
    rows[2]["clrt_ms"] = 999.0                        # inconsistent NON-FIRST row
    blk.write_text(json.dumps({"label": "X", "mode": "OFF", "d_a_ms": "-",
                               "d_r_ms": "-", "n_rows": 3, "rows": rows}))
    ds = _base_dataset("d1", "b.json", repo.sha256_file(blk), "native_clrt",
                       "native", "native", 3)
    reg = registry.load_registry(_write_registry(root, [ds]))
    with pytest.raises(registry.RegistryError, match="mismatch at row 2"):
        registry.validate(reg, root, verify_sha=True)


def test_unmeasured_policy_uses_estimated_release_error_labeled():
    """A grid pair with no measured evidence carries an ESTIMATE, labelled so."""
    C = np.full(100, 3.0)
    est = {(4.0, 10.0): [("def_D4", 0.001, 100)]}     # only (4,10) measured
    lookup, pooled = cli.build_eps_lookup(est)
    evals = cli.evaluate_grid(C, [(4, 10), (2, 12)], lookup, pooled,
                              obs_lm_design={}, tol_ms=0.1, a_design=None,
                              constraints={})
    m = next(e for e in evals if (e["D_A_ms"], e["D_R_ms"]) == (2, 12))  # unmeasured
    assert m["hardware_measured"] is False
    assert m["release_error_source"].startswith("estimate")
    assert m["policy_status"] == "analysis-selected, hardware-unmeasured"
    assert m["release_error_eps_ms"] == pytest.approx(pooled)


def test_measured_policy_release_error_labeled_measured():
    """A grid pair with measured evidence is labelled measured + hardware_measured."""
    C = np.full(100, 3.0)
    est = {(4.0, 10.0): [("def_D4_frA", 0.001, 60), ("probe_da4_dr10", 0.0009, 40)]}
    lookup, pooled = cli.build_eps_lookup(est)
    evals = cli.evaluate_grid(C, [(4, 10)], lookup, pooled, obs_lm_design={},
                              tol_ms=0.1, a_design=None, constraints={})
    e = evals[0]
    assert e["hardware_measured"] is True
    assert e["release_error_source"].startswith("measured:")
    assert "def_D4_frA" in e["release_error_source"]
    assert e["policy_status"] == "hardware-measured"


def test_target_tolerance_from_abs_release_error(tmp_path):
    """Target-band tol is a reported quantile of |CLRT_out - D_R| over covered txns."""
    root = _repo(tmp_path)
    # covered CLRT_out around D_R=10 with |residual| = [0,0.02,0.02,0.04,0.04]
    _write_block(root / "d.json", [10.0, 10.02, 9.98, 10.04, 9.96],
                 mode="D4", da=4, dr=10)
    ds = _base_dataset("def_D4", "d.json", repo.sha256_file(root / "d.json"),
                       "defended_clrt_out", 4, 10, 5)
    reg = registry.load_registry(_write_registry(root, [ds]))
    tol, meta = policy.target_band_tolerance(reg, root, quantile=95.0)
    assert meta["quantile"] == 95.0
    assert meta["n_covered_transactions"] == 5
    assert tol == pytest.approx(0.04, abs=1e-6)          # p95 (nearest) of |residual|
    assert "eps_R - eps_A" in meta["definition"] or "CLRT_out - D_R" in meta["definition"]


def test_unknown_ack_rto_and_failopen_constraints_stay_unknown():
    """With RTO/fail-open unavailable and no a, the dependent margins are UNKNOWN."""
    C = np.array([5.0, 6.0])
    ev = policy.eval_policy(C, 4, 10, tol_ms=0.1,
                            tcp_rto_ms=None, fail_open_horizon_ms=None,
                            reservoir_horizon_ms=None, response_timeout_ms=None)
    assert ev["margin_ack_delay_vs_rto_ms"] == "UNKNOWN"   # RTO unknown -> vs D_A UNKNOWN
    assert ev["margin_fail_open_ms"] == "UNKNOWN"
    assert ev["margin_reservoir_ms"] == "UNKNOWN"
    assert ev["tcp_rto_ms"] == "UNKNOWN"
    assert ev["fail_open_horizon_ms"] == "UNKNOWN"
    # no a and no observation -> latency-dependent margin UNKNOWN, L_master UNKNOWN
    assert ev["L_master_max_ms"] == "UNKNOWN"
    assert ev["margin_response_timeout_ms"] == "UNKNOWN"


def test_numeric_constraint_parses_unknown_and_numbers():
    assert registry.numeric_constraint(400.0) == 400.0
    assert registry.numeric_constraint("UNKNOWN (not anchored)") is None
    assert registry.numeric_constraint("400.0 (from gap_s)") == 400.0
    assert registry.numeric_constraint(None) is None


# ---------------------------------------------------------------------------
# FIX-5 tests (each FAILS if the corresponding defect is reintroduced)
# ---------------------------------------------------------------------------


def test_fix1_differential_eps_not_used_as_absolute_in_L_master():
    """FIX 1: a DIFFERENTIAL eps must NOT enter the ABSOLUTE L_master. Measured
    policies take L_master from the direct observation; analysis-only from the floor."""
    C = np.array([5.0, 6.0, 7.0]); a = np.array([1.0, 1.0, 1.0])
    eps = 0.5                                    # differential (eps_R - eps_A)
    # Analysis-only (no observation): L_master is the modelled floor, NO eps added.
    ev = policy.eval_policy(C, 4, 10, tol_ms=0.1, a=a, eps_ms=eps, observed_l_master=None)
    assert ev["L_master_is_floor"] is True
    assert ev["L_master_max_ms"] == pytest.approx(1.0 + 14.0)          # a + H
    assert ev["L_master_max_ms"] != pytest.approx(1.0 + 14.0 + eps)    # NOT + differential
    assert "UNKNOWN" in str(ev["L_master_release_error_ms"])
    assert ev["release_error_eps_ms"] == pytest.approx(eps)            # still in CLRT_out
    # Measured policy: L_master DIRECTLY from observed read_to_resp, not the model.
    obs = np.array([14.6, 14.4, 23.0])
    evm = policy.eval_policy(C, 4, 10, tol_ms=0.1, a=a, eps_ms=eps, observed_l_master=obs)
    assert evm["L_master_is_floor"] is False
    assert evm["L_master_max_ms"] == pytest.approx(23.0)               # observed max
    assert evm["L_master_median_ms"] == pytest.approx(14.6)            # observed median
    assert evm["L_master_max_ms"] != pytest.approx(1.0 + 14.0 + eps)   # not the differential model
    assert "measured_direct" in evm["L_master_source"]


def test_fix1_observed_l_master_pulls_read_to_resp_direct(tmp_path):
    """FIX 1: observed_l_master reads the raw read_to_resp_ms of the defended dataset."""
    root = _repo(tmp_path)
    _write_block(root / "d.json", [10.0, 10.0, 12.0], mode="D4", da=4, dr=10, a_ms=4.5)
    ds = _base_dataset("def_D4", "d.json", repo.sha256_file(root / "d.json"),
                       "defended_clrt_out", 4, 10, 3, role="paper_accepted")
    reg = registry.load_registry(_write_registry(root, [ds]))
    v, ids = policy.observed_l_master(reg, root, 4, 10, roles=("paper_accepted",))
    assert ids == ["def_D4"]
    assert set(round(float(x), 3) for x in v) == {14.5, 16.5}   # a_ms + clrt


def test_fix3_point_estimate_candidate_not_confidence_qualified():
    """FIX 3: 238/240 covered -> point 0.9917 clears 0.99 but Wilson lower (~0.970)
    does NOT. The selector must NOT label it confidence-qualified."""
    C = np.concatenate([np.full(238, 3.0), np.full(2, 100.0)])
    ev = policy.eval_policy(C, 2, 12, tol_ms=0.1)      # H=14 covers the 238
    assert ev["native_tail_coverage"] == pytest.approx(238 / 240)
    sel = policy.select_common_policy(C, [ev], coverage_min=0.99)
    assert sel["selected"] is not None                       # point-estimate admissible
    assert sel["selected_confidence_qualified"] is False     # but NOT at confidence
    assert sel["confidence_qualified_selected"] is None
    assert sel["n_confidence_qualified"] == 0
    assert "NO candidate establishes" in sel["coverage_verdict"]
    assert "ANALYSIS CANDIDATE" in sel["note"]
    assert sel["max_wilson_lower_over_admissible"] < 0.99


def test_fix3_confidence_qualified_when_wilson_lower_meets_min():
    """FIX 3 positive control: 1000/1000 covered -> Wilson lower >= 0.99 -> qualified."""
    C = np.full(1000, 3.0)
    ev = policy.eval_policy(C, 4, 10, tol_ms=0.1)
    sel = policy.select_common_policy(C, [ev], coverage_min=0.99)
    assert sel["confidence_qualified_selected"] is not None
    assert sel["selected_confidence_qualified"] is True
    assert sel["n_confidence_qualified"] == 1
    assert "CONFIDENCE-QUALIFIED" in sel["coverage_verdict"]


def test_fix4_unproven_timeout_not_in_numeric_margin():
    """FIX 4: the unproven 2000 ms DNP3 timeout must NOT enter a numeric margin;
    the DNP3 app-timeout margin is UNKNOWN, and the evidenced 4000 ms recv timeout
    is the numeric ceiling."""
    C = np.array([5.0, 6.0]); a = np.array([0.5, 0.5])
    ev = policy.eval_policy(C, 4, 10, tol_ms=0.1, a=a,
                            response_timeout_ms=None, master_recv_timeout_ms=4000.0)
    assert ev["margin_response_timeout_ms"] == "UNKNOWN"     # DNP3 app timeout unproven
    assert ev["response_timeout_ms"] == "UNKNOWN"
    lmax = ev["L_master_max_ms"]
    forbidden = 2000.0 - float(lmax)                          # a 2000-derived margin
    for k, val in ev.items():
        if k.startswith("margin_") and isinstance(val, (int, float)):
            assert abs(val - forbidden) > 1e-9, f"{k} looks 2000-derived"
    assert ev["margin_master_recv_timeout_ms"] == pytest.approx(4000.0 - float(lmax))


def test_fix4_real_registry_timeout_provenance():
    """FIX 4: the generated registry sets the DNP3 app timeout UNKNOWN and pins the
    evidenced raw-socket recv/connect timeouts and poll period with provenance."""
    here = Path(__file__).resolve().parents[1]
    reg_path = here / "registry.yaml"
    assert reg_path.exists(), "registry.yaml must be generated before this test runs"
    reg = registry.load_registry(reg_path)
    ec = reg["evidenced_constraints"]
    assert registry.numeric_constraint(ec["dnp3_response_timeout_ms"]) is None   # UNKNOWN
    assert "OpenDNP3" in str(ec["dnp3_response_timeout_ms"])
    assert registry.numeric_constraint(ec["master_socket_recv_timeout_ms"]) == 4000.0
    assert "campaign_driver.py" in str(ec["master_socket_recv_timeout_ms"])
    assert registry.numeric_constraint(ec["poll_period_ms"]) == 400.0
    assert registry.numeric_constraint(ec["tcp_rto_ms"]) is None
    assert registry.numeric_constraint(ec["fail_open_horizon_ms_at_budget_18000"]) is None


def test_fix2_target_band_conditional_not_total_coverage(tmp_path):
    """FIX 2: the +/-1ms band statistic is labelled a normalized-band CONDITIONAL
    jitter (never total coverage); the UNTRUNCATED tail and the dropped fraction are
    reported, and native P(C<=H) pairs each policy."""
    root = _repo(tmp_path)
    # 8 normalized near D_R=10 + 2 late-safe at 15 (out of the +/-1ms band)
    vals = [10.0, 10.02, 9.98, 10.03, 9.97, 10.01, 9.99, 10.0, 15.0, 15.0]
    _write_block(root / "d.json", vals, mode="D4", da=4, dr=10)
    ds = _base_dataset("def_D4", "d.json", repo.sha256_file(root / "d.json"),
                       "defended_clrt_out", 4, 10, 10)
    reg = registry.load_registry(_write_registry(root, [ds]))
    native_C = np.array([3.0] * 9 + [20.0])                  # 9/10 have C <= H=14
    tol, meta = policy.target_band_tolerance(reg, root, quantile=95.0, native_C=native_C)
    assert meta["is_total_coverage"] is False and meta["conditional"] is True
    # the conditional band statistic HIDES the 5 ms tail; the untruncated one reports it
    assert meta["abs_err_p95_ms_untruncated_pooled"] == pytest.approx(5.0, abs=1e-6)
    assert meta["abs_err_p95_ms_untruncated_pooled"] > tol
    assert meta["frac_outside_normalized_band_pooled"] == pytest.approx(0.2)
    pv = meta["per_dataset"]["def_D4"]
    assert pv["frac_outside_normalized_band"] == pytest.approx(0.2)
    assert pv["native_covered_fraction"] == pytest.approx(0.9)   # paired with native P(C<=H)


def test_fix1_read_to_resp_provenance_mismatch_caught(tmp_path):
    """FIX 1 provenance: a read_to_resp_ms that disagrees with (t_resp - t_read) is
    caught by the registry validator (L_master must trace to raw timestamps)."""
    root = _repo(tmp_path)
    blk = root / "b.json"
    t_ack = 1_000_000.0
    row = {"poll": 0, "t_read": t_ack - 0.0005, "t_ack": t_ack,
           "t_resp": t_ack + 0.010, "read_to_ack_ms": 0.5,
           "read_to_resp_ms": 99.0,                    # WRONG: should be ~10.5
           "clrt_ms": 10.0, "ack_before_resp": True}
    blk.write_text(json.dumps({"label": "X", "mode": "OFF", "d_a_ms": "-",
                               "d_r_ms": "-", "n_rows": 1, "rows": [row]}))
    ds = _base_dataset("d1", "b.json", repo.sha256_file(blk), "native_clrt",
                       "native", "native", 1)
    reg = registry.load_registry(_write_registry(root, [ds]))
    with pytest.raises(registry.RegistryError, match="read-to-resp"):
        registry.validate(reg, root, verify_sha=True)


def test_results_json_schema_and_no_unproven_timeout():
    """Schema check on the generated results.json: required keys/types present, the
    confidence-aware selector fields present, every DNP3 app-timeout margin UNKNOWN,
    and L_master kind consistent (measured -> not floor, analysis -> floor)."""
    here = Path(__file__).resolve().parents[1]
    rj = here / "results.json"
    assert rj.exists(), "results.json must be generated before this test runs"
    r = json.loads(rj.read_text())
    for key in ("meta", "evidenced_constraints_effective", "policy_evaluations",
                "pareto_table", "selector", "observed_l_master_pairs"):
        assert key in r, f"results.json missing {key}"
    sel = r["selector"]
    for key in ("coverage_verdict", "confidence_qualified_selected",
                "analysis_candidate_point_estimate", "n_confidence_qualified",
                "analysis_candidate_confidence_qualified"):
        assert key in sel, f"selector missing {key}"
    # the DNP3 application response timeout must be UNKNOWN, never a numeric margin
    assert r["evidenced_constraints_effective"]["dnp3_response_timeout_ms"].startswith("UNKNOWN")
    for ev in r["policy_evaluations"]:
        assert ev["margin_response_timeout_ms"] == "UNKNOWN"
        assert isinstance(ev["L_master_is_floor"], bool)
        if ev["L_master_is_floor"]:
            assert ev["hardware_measured"] is False          # only analysis-only uses the floor
        # every numeric margin must not be a 2000-derived DNP3 timeout margin
        lmax = ev["L_master_max_ms"]
        if isinstance(lmax, (int, float)):
            assert abs(float(ev["margin_master_recv_timeout_ms"]) - (2000.0 - lmax)) > 1e-9


# ---------------------------------------------------------------------------
# Standalone runner (used only when pytest is absent).
# ---------------------------------------------------------------------------


def _run_standalone() -> int:
    import inspect
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed, failed = 0, []
    for name, fn in tests:
        needs_tmp = "tmp_path" in inspect.signature(fn).parameters
        try:
            if needs_tmp:
                with tempfile.TemporaryDirectory() as td:
                    fn(Path(td))
            else:
                fn()
            print(f"PASS {name}")
            passed += 1
        except Exception as e:  # noqa: B902
            print(f"FAIL {name}: {type(e).__name__}: {e}")
            failed.append(name)
    print(f"\n{passed}/{len(tests)} passed"
          + (f"; FAILED: {', '.join(failed)}" if failed else "; all green"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())

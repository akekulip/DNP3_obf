"""Unit tests for the Defense-4 timing-policy analysis toolkit.

Exercises the policy model at the C<H / C=H / C>H boundaries and the D2 (D_A=0)
and D3 (D_R=0) edge policies, release-error inclusion, and every guardrail the
registry must enforce: a missing dataset, mixed time units, incompatible timing
definitions / pooling, the domain-common selector contract, and UNPINNED handling.

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


def _write_block(path: Path, rows_clrt_ms, mode="OFF", label="X", da="-", dr="-"):
    """Write a block whose t_ack/t_resp are consistent with clrt_ms (seconds base)."""
    rows = []
    t0 = 1_000_000.0
    for i, c in enumerate(rows_clrt_ms):
        t_ack = t0 + i
        t_resp = t_ack + c / 1000.0
        rows.append({
            "poll": i, "app_seq_sent": "0xC0", "t_read": t_ack - 0.0005,
            "t_ack": t_ack, "t_resp": t_resp, "resp_len": 134, "resp_segments": 1,
            "read_to_ack_ms": 0.5, "read_to_resp_ms": 0.5 + c, "clrt_ms": c,
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

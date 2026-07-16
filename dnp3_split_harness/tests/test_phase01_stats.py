"""Unit tests for phase01_stats.py (numpy-only distribution statistics)."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import phase01_stats as st  # noqa: E402


def test_describe_basic():
    d = st.describe([1, 2, 3, 4, 5])
    assert d["n"] == 5
    assert d["mean"] == 3.0
    assert d["median"] == 3.0
    assert d["min"] == 1.0 and d["max"] == 5.0
    assert d["cv"] is not None


def test_describe_empty_and_none_filtered():
    d = st.describe([None, None])
    assert d["n"] == 0 and d["mean"] is None
    d2 = st.describe([1.0, None, 3.0])
    assert d2["n"] == 2 and d2["mean"] == 2.0


def test_bootstrap_deterministic_and_brackets():
    vals = [float(x) for x in range(1, 101)]
    a = st.bootstrap_ci(vals, "mean", n_boot=1000, seed=7)
    b = st.bootstrap_ci(vals, "mean", n_boot=1000, seed=7)
    assert a == b                                  # deterministic under a fixed seed
    assert a["lo"] <= a["point"] <= a["hi"]        # CI brackets the point estimate


def test_bootstrap_single_value():
    r = st.bootstrap_ci([42.0], "mean")
    assert r["point"] == r["lo"] == r["hi"] == 42.0
    assert r["n"] == 1


def test_ks_identical_and_disjoint():
    assert st.ks_2samp_stat([1, 2, 3, 4], [1, 2, 3, 4]) == 0.0
    assert st.ks_2samp_stat([0, 1, 2, 3], [10, 11, 12, 13]) == 1.0


def test_wasserstein_shift():
    a = [0.0, 1.0, 2.0, 3.0]
    b = [10.0, 11.0, 12.0, 13.0]     # pure +10 shift -> W1 == 10
    assert st.wasserstein1(a, b) == 10.0
    assert st.wasserstein1(a, a) == 0.0


def test_cliffs_delta_extremes():
    assert st.cliffs_delta([5, 6, 7], [1, 2, 3]) == 1.0
    assert st.cliffs_delta([1, 2, 3], [5, 6, 7]) == -1.0
    assert st.cliffs_delta([1, 2, 3], [1, 2, 3]) == 0.0


def test_cohens_d():
    assert st.cohens_d([1, 2, 3, 4], [1, 2, 3, 4]) == 0.0
    d = st.cohens_d([2, 3, 4, 5], [1, 2, 3, 4])
    assert 0.77 <= d <= 0.78


def test_compare_bundle_keys():
    c = st.compare_distributions([1, 2, 3, 4], [2, 3, 4, 5])
    for k in ("n_a", "n_b", "ks", "wasserstein1", "cliffs_delta", "cohens_d"):
        assert k in c
